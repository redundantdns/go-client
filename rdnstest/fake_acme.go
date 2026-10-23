package rdnstest

import (
	"cmp"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	redundantdns "github.com/redundantdns/go-client"
)

// acmeValueRegex is the API's rule for a challenge value: 1..255 base64url
// characters (the key authorization digest is 43).
var acmeValueRegex = regexp.MustCompile(`^[A-Za-z0-9_-]{1,255}$`)

// fakeACME is the ACME DNS-01 state of the fake.
type fakeACME struct {
	challenges map[string]*fakeChallenge
	// pollsUntilPropagated is how many status reads answer pending before
	// a challenge is propagated (0: propagated at the first read).
	pollsUntilPropagated int
	// failReason, when set, makes every status read answer failed.
	failReason string
	// zoneIDs restricts the token like an acme:challenge token (nil: every
	// zone of the organization).
	zoneIDs []string
}

// fakeChallenge is one presented value.
type fakeChallenge struct {
	id     string
	zoneID string
	// name is relative to the zone; fqdn absolute with a trailing dot.
	name   string
	fqdn   string
	value  string
	serial int64
	polls  int
}

// ACMEChallengeInfo is a presented challenge as the fake holds it.
type ACMEChallengeInfo struct {
	ChallengeID string
	ZoneID      string
	Name        string
	FQDN        string
	Value       string
}

func newFakeACME() fakeACME {
	return fakeACME{challenges: map[string]*fakeChallenge{}}
}

// SetACMEPropagation makes each challenge answer pending for the given
// number of status reads before it is propagated (0, the default:
// propagated at the first read).
func (fake *Fake) SetACMEPropagation(pollsUntilPropagated int) {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	fake.acme.pollsUntilPropagated = max(pollsUntilPropagated, 0)
}

// FailACMEChallenges makes every status read answer failed with the reason
// ("" restores normal propagation).
func (fake *Fake) FailACMEChallenges(reason string) {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	fake.acme.failReason = reason
}

// RestrictACMEZones behaves like a token restricted to these zones: the
// ACME routes of other zones answer 403 zoneNotAllowed and GET
// /v1/acme/zones lists only these. No argument lifts the restriction.
func (fake *Fake) RestrictACMEZones(zoneIDs ...string) {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	if len(zoneIDs) == 0 {
		fake.acme.zoneIDs = nil
		return
	}
	fake.acme.zoneIDs = slices.Clone(zoneIDs)
}

// ACMEValues returns the challenge values presented at an absolute name
// (case and the trailing dot do not matter), sorted. A test DNS server
// answers TXT queries with them.
func (fake *Fake) ACMEValues(fqdn string) []string {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	wanted := canonicalFQDN(fqdn)
	values := []string{}
	for _, challenge := range fake.acme.challenges {
		if challenge.fqdn == wanted {
			values = append(values, challenge.value)
		}
	}
	slices.Sort(values)
	return values
}

// ACMEChallenges returns the live challenges, sorted by id.
func (fake *Fake) ACMEChallenges() []ACMEChallengeInfo {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	infos := make([]ACMEChallengeInfo, 0, len(fake.acme.challenges))
	for _, challenge := range fake.acme.challenges {
		infos = append(infos, ACMEChallengeInfo{
			ChallengeID: challenge.id, ZoneID: challenge.zoneID, Name: challenge.name, FQDN: challenge.fqdn, Value: challenge.value,
		})
	}
	slices.SortFunc(infos, func(left, right ACMEChallengeInfo) int { return strings.Compare(left.ChallengeID, right.ChallengeID) })
	return infos
}

// mountACME serves the ACME DNS-01 routes: present (adds the value to the
// zone's TXT set), status (propagated after SetACMEPropagation reads),
// clean-up by id or by name and value (idempotent) and the zone list.
func (fake *Fake) mountACME(handle func(string, handler)) {
	handle("GET /v1/acme/zones", func(writer http.ResponseWriter, _ *http.Request) {
		zones := []redundantdns.ACMEZone{}
		for _, zone := range fake.zones {
			if fake.acmeZoneAllowed(zone.ZoneID) {
				zones = append(zones, redundantdns.ACMEZone{ZoneID: zone.ZoneID, Name: redundantdns.NormalizeZoneName(zone.Name)})
			}
		}
		slices.SortFunc(zones, func(left, right redundantdns.ACMEZone) int { return strings.Compare(left.Name, right.Name) })
		writeJSON(writer, http.StatusOK, map[string]any{"zones": zones})
	})
	handle("POST /v1/zones/{zoneId}/acme/challenges", fake.withACMEZone(fake.presentChallenge))
	handle("GET /v1/zones/{zoneId}/acme/challenges/{challengeId}", fake.withACMEZone(func(writer http.ResponseWriter, request *http.Request, zone *redundantdns.Zone) {
		challenge, ok := fake.acme.challenges[request.PathValue("challengeId")]
		if !ok || challenge.zoneID != zone.ZoneID {
			writeError(writer, http.StatusNotFound, redundantdns.CodeACMEChallengeNotFound, "challenge not found")
			return
		}
		challenge.polls++
		writeJSON(writer, http.StatusOK, fake.challengeStatus(zone, challenge))
	}))
	handle("DELETE /v1/zones/{zoneId}/acme/challenges/{challengeId}", fake.withACMEZone(func(writer http.ResponseWriter, request *http.Request, zone *redundantdns.Zone) {
		if challenge, ok := fake.acme.challenges[request.PathValue("challengeId")]; ok && challenge.zoneID == zone.ZoneID {
			fake.removeChallenge(zone, challenge)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	handle("DELETE /v1/zones/{zoneId}/acme/challenges", fake.withACMEZone(func(writer http.ResponseWriter, request *http.Request, zone *redundantdns.Zone) {
		name, ok := acmeName(zone.Name, request.URL.Query().Get("name"))
		if !ok {
			writeError(writer, http.StatusBadRequest, redundantdns.CodeACMENameInvalid, "not an _acme-challenge name in this zone")
			return
		}
		value := request.URL.Query().Get("value")
		for _, challenge := range fake.acme.challenges {
			if challenge.zoneID == zone.ZoneID && challenge.name == name && challenge.value == value {
				fake.removeChallenge(zone, challenge)
			}
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
}

// withACMEZone loads {zoneId} like withZone and applies the token's zone
// restriction (403 zoneNotAllowed).
func (fake *Fake) withACMEZone(serve func(http.ResponseWriter, *http.Request, *redundantdns.Zone)) handler {
	return func(writer http.ResponseWriter, request *http.Request) {
		if !fake.acmeZoneAllowed(request.PathValue("zoneId")) {
			writeError(writer, http.StatusForbidden, redundantdns.CodeZoneNotAllowed, "this token is not allowed to address this zone")
			return
		}
		fake.withZone(serve)(writer, request)
	}
}

func (fake *Fake) acmeZoneAllowed(zoneID string) bool {
	return fake.acme.zoneIDs == nil || slices.Contains(fake.acme.zoneIDs, zoneID)
}

func (fake *Fake) presentChallenge(writer http.ResponseWriter, request *http.Request, zone *redundantdns.Zone) {
	var input redundantdns.ACMEChallengeInput
	if !decode(writer, request, &input) {
		return
	}
	name, ok := acmeName(zone.Name, input.Name)
	if !ok {
		writeError(writer, http.StatusBadRequest, redundantdns.CodeACMENameInvalid, "not an _acme-challenge name in this zone")
		return
	}
	if !acmeValueRegex.MatchString(input.Value) {
		writeError(writer, http.StatusBadRequest, redundantdns.CodeACMEValueInvalid, "the value must be 1 to 255 base64url characters")
		return
	}
	for _, set := range zone.RecordSets {
		if set.Name == name && set.Type == "CNAME" {
			writeError(writer, http.StatusConflict, redundantdns.CodeCnameConflict,
				"a CNAME sits at this name: present the challenge in the target zone (cert-manager cnameStrategy: Follow)")
			return
		}
		if set.Name == name && set.Type == "TXT" && set.ManagedBy != "" {
			writeError(writer, http.StatusConflict, redundantdns.CodeRecordSetManaged, "this record set is managed by the platform")
			return
		}
	}
	for _, challenge := range fake.acme.challenges {
		if challenge.zoneID == zone.ZoneID && challenge.name == name && challenge.value == input.Value {
			writeJSON(writer, http.StatusAccepted, viewChallenge(challenge, true))
			return
		}
	}
	ttl := cmp.Or(input.TTL, redundantdns.DefaultACMEChallengeTTL)
	quoted := `"` + input.Value + `"`
	index := slices.IndexFunc(zone.RecordSets, func(set redundantdns.RecordSet) bool { return set.Name == name && set.Type == "TXT" })
	if index >= 0 {
		zone.RecordSets[index].Values = redundantdns.NormalizeRecordValues("TXT", append(slices.Clone(zone.RecordSets[index].Values), quoted))
	} else {
		zone.RecordSets = append(zone.RecordSets, redundantdns.RecordSet{Name: name, Type: "TXT", TTL: ttl, Values: []string{quoted}})
	}
	zone.Serial++
	challenge := &fakeChallenge{
		id: fake.nextID("ach"), zoneID: zone.ZoneID, name: name, fqdn: canonicalFQDN(name + "." + zone.Name),
		value: input.Value, serial: zone.Serial,
	}
	fake.acme.challenges[challenge.id] = challenge
	writeJSON(writer, http.StatusAccepted, viewChallenge(challenge, false))
}

// removeChallenge drops one value from the TXT set (and the set with its
// last value) and bumps the serial.
func (fake *Fake) removeChallenge(zone *redundantdns.Zone, challenge *fakeChallenge) {
	delete(fake.acme.challenges, challenge.id)
	index := slices.IndexFunc(zone.RecordSets, func(set redundantdns.RecordSet) bool { return set.Name == challenge.name && set.Type == "TXT" })
	if index >= 0 {
		quoted := `"` + challenge.value + `"`
		values := slices.DeleteFunc(slices.Clone(zone.RecordSets[index].Values), func(value string) bool { return value == quoted })
		if len(values) == 0 {
			zone.RecordSets = slices.Delete(zone.RecordSets, index, index+1)
		} else {
			zone.RecordSets[index].Values = values
		}
	}
	zone.Serial++
}

func viewChallenge(challenge *fakeChallenge, existing bool) redundantdns.ACMEChallenge {
	return redundantdns.ACMEChallenge{
		ChallengeID: challenge.id, Name: challenge.name, FQDN: challenge.fqdn, Serial: challenge.serial,
		Propagation: redundantdns.ACMEStatePending, Existing: existing,
	}
}

// challengeStatus answers pending until the challenge was read
// pollsUntilPropagated times, then propagated, with one provider entry per
// attachment (every attachment active, every nameserver matching).
func (fake *Fake) challengeStatus(zone *redundantdns.Zone, challenge *fakeChallenge) redundantdns.ACMEChallengeStatus {
	state := redundantdns.ACMEStatePending
	if challenge.polls > fake.acme.pollsUntilPropagated {
		state = redundantdns.ACMEStatePropagated
	}
	status := redundantdns.ACMEChallengeStatus{
		ChallengeID: challenge.id, Name: challenge.name, FQDN: challenge.fqdn, Serial: challenge.serial,
		State: state, CheckedAt: time.Now().UTC().Truncate(time.Second), Providers: []redundantdns.ACMEProviderStatus{},
	}
	if fake.acme.failReason != "" {
		status.State, status.Reason = redundantdns.ACMEStateFailed, fake.acme.failReason
	}
	propagated := status.State == redundantdns.ACMEStatePropagated
	for _, attachment := range zone.Attachments {
		served := propagated
		provider := redundantdns.ACMEProviderStatus{
			AttachmentID: attachment.AttachmentID, Provider: attachment.Provider, Label: attachment.Label,
			Role: redundantdns.ACMERoleActive, Applied: propagated, Served: &served, NameServers: []redundantdns.ACMENameServerAnswer{},
		}
		if status.State == redundantdns.ACMEStateFailed {
			provider.Error = fake.acme.failReason
		}
		for _, host := range attachment.NameServers {
			answer := redundantdns.ACMEAnswerMissing
			if propagated {
				answer = redundantdns.ACMEAnswerMatch
			}
			provider.NameServers = append(provider.NameServers, redundantdns.ACMENameServerAnswer{Host: host, Answer: answer})
		}
		status.Providers = append(status.Providers, provider)
	}
	return status
}

// acmeName returns the challenge name relative to the zone, and whether it
// is an _acme-challenge name inside it. An absolute name (trailing dot, or
// ending with the zone name) must be in the zone.
func acmeName(zoneName, name string) (string, bool) {
	zone := redundantdns.NormalizeZoneName(zoneName)
	raw := strings.ToLower(strings.TrimSpace(name))
	absolute := strings.HasSuffix(raw, ".")
	raw = strings.TrimRight(raw, ".")
	switch {
	case raw == zone:
		return "", false
	case strings.HasSuffix(raw, "."+zone):
		raw = strings.TrimSuffix(raw, "."+zone)
	case absolute:
		return "", false
	}
	if raw != "_acme-challenge" && !strings.HasPrefix(raw, "_acme-challenge.") {
		return "", false
	}
	return raw, true
}

// canonicalFQDN lowercases a name and gives it a trailing dot.
func canonicalFQDN(name string) string {
	return strings.TrimRight(strings.ToLower(strings.TrimSpace(name)), ".") + "."
}
