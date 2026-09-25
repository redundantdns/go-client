package rdnstest

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	redundantdns "github.com/redundantdns/go-client"
)

// DefaultToken is the bearer token the fake accepts unless configured
// otherwise.
const DefaultToken = "rdns_test_token" //nolint:gosec // a test-only placeholder, not a credential

// DefaultOrgID is the fake's organization.
const DefaultOrgID = "org-test"

// Fake is an in-memory, stateful stand-in for the /v1 API: zones, record
// sets, provider connections (the "fake" provider), attachments, sync jobs,
// delegation checks, subdomain redundancy (parent delegation), the Managed
// Provider Terms acceptance, alert rules, channels, events and the OAuth
// endpoints (registration, an auto-approving authorize, token). It
// validates the essentials (auth, org, not found, apex NS, confirmName,
// managed terms) and answers with the same shapes as the real API; it is
// not a full re-implementation.
type Fake struct {
	*httptest.Server

	// Token is the accepted bearer token; OrgID the token's organization.
	Token string
	OrgID string

	mutex       sync.Mutex
	sequence    int
	zones       map[string]*redundantdns.Zone
	connections map[string]*redundantdns.Connection
	credentials map[string]map[string]string
	channels    map[string]*redundantdns.AlertChannel
	events      map[string]*redundantdns.AlertEvent
	rules       []redundantdns.AlertRule
	failures    []int
	requests    []Request

	// managedTerms is the organization's acceptance of the Managed
	// Provider Terms (nil until accepted).
	managedTerms *redundantdns.ManagedTermsAcceptance
	// parentDelegations maps a child zone id to its parent zone id while
	// the platform manages the delegation.
	parentDelegations map[string]string
	oauth             fakeOAuth
	// plan is the organization's plan ("free" by default), shown by /v1/me
	// and enforced by the domains module (one domain on Free).
	plan string
	// domainState is the domains module: domains, contacts, the Domain
	// Registration Terms acceptance and the simulated registrar.
	domainState fakeDomains
	// ops holds licenses, org exports, compliance reports and the audit
	// stream.
	ops fakeOps
}

// NewFake starts a fake API server closed when the test ends.
func NewFake(tb testing.TB) *Fake {
	tb.Helper()
	fake := &Fake{
		Token: DefaultToken, OrgID: DefaultOrgID,
		zones:       map[string]*redundantdns.Zone{},
		connections: map[string]*redundantdns.Connection{},
		credentials: map[string]map[string]string{},
		channels:    map[string]*redundantdns.AlertChannel{},
		events:      map[string]*redundantdns.AlertEvent{},

		parentDelegations: map[string]string{},
		oauth:             newFakeOAuth(),
		plan:              "free",
		domainState:       newFakeDomains(),
		ops:               newFakeOps(),
	}
	_, rules := MustFixture(tb, "alert_rules")
	if err := json.Unmarshal(rules, &fake.rules); err != nil {
		tb.Fatal(err)
	}
	fake.Server = httptest.NewServer(fake.routes())
	tb.Cleanup(fake.Close)
	return fake
}

// FailNext makes the next requests answer the given statuses, in order
// (for example 429 then 503), before being served normally.
func (fake *Fake) FailNext(statuses ...int) {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	fake.failures = append(fake.failures, statuses...)
}

// AddEvent seeds an alert event (for example a firing drift alert).
func (fake *Fake) AddEvent(event redundantdns.AlertEvent) {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	if event.OrgID == "" {
		event.OrgID = fake.OrgID
	}
	fake.events[event.EventID] = &event
}

// Requests returns a copy of the requests received so far.
func (fake *Fake) Requests() []Request {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	return append([]Request(nil), fake.requests...)
}

// ZoneCount returns how many zones exist (to check clean-ups).
func (fake *Fake) ZoneCount() int {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	return len(fake.zones)
}

// ConnectionCount returns how many connections exist.
func (fake *Fake) ConnectionCount() int {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	return len(fake.connections)
}

// ChannelCount returns how many alert channels exist.
func (fake *Fake) ChannelCount() int {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	return len(fake.channels)
}

func (fake *Fake) nextID(prefix string) string {
	fake.sequence++
	return fmt.Sprintf("%s-%04d", prefix, fake.sequence)
}

// handler is a route body run under the fake's lock.
type handler func(writer http.ResponseWriter, request *http.Request)

func (fake *Fake) routes() http.Handler {
	mux := http.NewServeMux()
	handle := func(pattern string, serve handler) {
		mux.HandleFunc(pattern, func(writer http.ResponseWriter, request *http.Request) {
			fake.mutex.Lock()
			defer fake.mutex.Unlock()
			body := readBody(request)
			fake.requests = append(fake.requests, Request{
				Method: request.Method, Path: request.URL.Path, Query: request.URL.RawQuery,
				Header: request.Header.Clone(), Body: body, Pattern: pattern,
			})
			if len(fake.failures) > 0 {
				status := fake.failures[0]
				fake.failures = fake.failures[1:]
				if status == http.StatusTooManyRequests {
					writer.Header().Set("Retry-After", "0")
				}
				writeError(writer, status, "injected", "injected failure")
				return
			}
			// The fake checkout page is opened in a browser, without a token.
			// The plan catalog is public; an export download link carries its
			// own one-time token.
			public := request.URL.Path == "/v1/legal/versions" || request.URL.Path == fakeCheckoutPath ||
				strings.HasPrefix(request.URL.Path, "/oauth/") || request.URL.Path == "/v1/plans" || isExportDownload(request.URL.Path)
			if !public {
				if request.Header.Get("Authorization") != "Bearer "+fake.Token {
					writeError(writer, http.StatusUnauthorized, "unauthorized", "missing or invalid token")
					return
				}
				if org := request.Header.Get(redundantdns.OrgHeader); org != "" && org != fake.OrgID {
					writeError(writer, http.StatusForbidden, "forbidden", "this token belongs to another organization")
					return
				}
			}
			request.Body = newBody(body)
			serve(writer, request)
		})
	}
	fake.mountAccount(handle)
	fake.mountZones(handle)
	fake.mountConnections(handle)
	fake.mountAlerts(handle)
	fake.mountLegal(handle)
	fake.mountOAuth(handle)
	fake.mountDomains(handle)
	fake.mountOps(handle)
	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writeError(writer, http.StatusNotFound, "notFound", "route not found")
	})
	return mux
}

func (fake *Fake) mountAccount(handle func(string, handler)) {
	handle("GET /v1/legal/versions", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, redundantdns.LegalVersions{
			Terms: "2026-09-23", Privacy: "2026-09-23", ManagedTerms: ManagedTermsVersion, DomainTerms: DomainTermsVersion,
		})
	})
	handle("GET /v1/me", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, redundantdns.Me{
			User: redundantdns.User{UserID: "usr-test", Email: "test@example.com", Kind: "pat"},
			Orgs: []redundantdns.OrgSummary{{OrgID: fake.OrgID, Name: "Test org", Plan: fake.plan, Role: "owner"}},
		})
	})
	handle("GET /v1/orgs", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, []redundantdns.OrgSummary{{OrgID: fake.OrgID, Name: "Test org", Plan: fake.plan, Role: "owner"}})
	})
	handle("GET /v1/providers", func(writer http.ResponseWriter, _ *http.Request) {
		status, body, _ := Fixture("providers")
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(status)
		_, _ = writer.Write(body)
	})
	handle("GET /v1/audit", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, []redundantdns.AuditEntry{})
	})
}

func (fake *Fake) mountZones(handle func(string, handler)) {
	handle("GET /v1/zones", func(writer http.ResponseWriter, _ *http.Request) {
		zones := make([]redundantdns.Zone, 0, len(fake.zones))
		for _, zone := range fake.zones {
			listed := *zone
			listed.RecordSets = nil
			zones = append(zones, listed)
		}
		slices.SortFunc(zones, func(left, right redundantdns.Zone) int { return strings.Compare(left.Name, right.Name) })
		writeJSON(writer, http.StatusOK, zones)
	})
	handle("POST /v1/zones", func(writer http.ResponseWriter, request *http.Request) {
		var input redundantdns.ZoneCreate
		if !decode(writer, request, &input) {
			return
		}
		name := redundantdns.NormalizeZoneName(input.Name)
		if strings.Count(name, ".") < 1 || strings.ContainsAny(name, " /") {
			writeError(writer, http.StatusBadRequest, "invalidZoneName", "invalid zone name")
			return
		}
		for _, zone := range fake.zones {
			if zone.Name == name {
				writeError(writer, http.StatusConflict, "zoneExists", "a zone with this name already exists")
				return
			}
		}
		ttl := input.DefaultTTL
		if ttl == 0 {
			ttl = 300
		}
		now := time.Now().UTC().Truncate(time.Second)
		zone := &redundantdns.Zone{
			ZoneID: fake.nextID("zone"), Name: name, Serial: 2026092301,
			Settings: redundantdns.ZoneSettings{DefaultTTL: ttl}, NSPlan: []string{},
			RecordSets: []redundantdns.RecordSet{}, Attachments: []redundantdns.Attachment{},
			CreatedAt: now, UpdatedAt: now,
		}
		fake.zones[zone.ZoneID] = zone
		// Like the API: delegate from the parent zone unless the caller
		// said no (the dashboard checkbox is on by default).
		if parent := fake.parentOf(name); parent != nil && (input.ParentDelegation == nil || *input.ParentDelegation) {
			fake.parentDelegations[zone.ZoneID] = parent.ZoneID
			fake.writeDelegation(zone)
		}
		writeJSON(writer, http.StatusCreated, fake.viewZone(zone))
	})
	handle("GET /v1/zones/{zoneId}", fake.withZone(func(writer http.ResponseWriter, _ *http.Request, zone *redundantdns.Zone) {
		writeJSON(writer, http.StatusOK, fake.viewZone(zone))
	}))
	handle("DELETE /v1/zones/{zoneId}", fake.withZone(func(writer http.ResponseWriter, _ *http.Request, zone *redundantdns.Zone) {
		fake.removeDelegation(zone)
		for childID, parentID := range fake.parentDelegations {
			if parentID == zone.ZoneID {
				delete(fake.parentDelegations, childID)
			}
		}
		delete(fake.zones, zone.ZoneID)
		writeJSON(writer, http.StatusOK, map[string]bool{"ok": true})
	}))
	handle("GET /v1/zones/{zoneId}/records", fake.withZone(func(writer http.ResponseWriter, _ *http.Request, zone *redundantdns.Zone) {
		writeJSON(writer, http.StatusOK, zone.RecordSets)
	}))
	handle("PUT /v1/zones/{zoneId}/records", fake.withZone(fake.upsertRecord))
	handle("DELETE /v1/zones/{zoneId}/records", fake.withZone(func(writer http.ResponseWriter, request *http.Request, zone *redundantdns.Zone) {
		name := redundantdns.NormalizeRecordName(zone.Name, request.URL.Query().Get("name"))
		recordType := strings.ToUpper(request.URL.Query().Get("type"))
		index := slices.IndexFunc(zone.RecordSets, func(set redundantdns.RecordSet) bool { return set.Name == name && set.Type == recordType })
		if index < 0 {
			writeError(writer, http.StatusNotFound, "recordSetNotFound", "record not found")
			return
		}
		if zone.RecordSets[index].ManagedBy != "" {
			writeError(writer, http.StatusConflict, redundantdns.CodeRecordSetManaged, "this record set is managed by the platform")
			return
		}
		zone.RecordSets = slices.Delete(zone.RecordSets, index, index+1)
		zone.Serial++
		writeJSON(writer, http.StatusOK, map[string]any{"ok": true, "serial": zone.Serial})
	}))
	handle("POST /v1/zones/{zoneId}/attachments", fake.withZone(fake.attach))
	handle("DELETE /v1/zones/{zoneId}/attachments/{attachmentId}", fake.withZone(func(writer http.ResponseWriter, request *http.Request, zone *redundantdns.Zone) {
		index := slices.IndexFunc(zone.Attachments, func(attachment redundantdns.Attachment) bool {
			return attachment.AttachmentID == request.PathValue("attachmentId")
		})
		if index < 0 {
			writeError(writer, http.StatusNotFound, "attachmentNotFound", "attachment not found")
			return
		}
		if request.URL.Query().Get("deleteRemote") == "true" && redundantdns.NormalizeZoneName(request.URL.Query().Get("confirmName")) != zone.Name {
			writeError(writer, http.StatusBadRequest, "confirmNameMismatch", "type the zone name to confirm")
			return
		}
		zone.Attachments = slices.Delete(zone.Attachments, index, index+1)
		fake.refreshNSPlan(zone)
		fake.writeDelegation(zone)
		writeJSON(writer, http.StatusOK, map[string]bool{"ok": true})
	}))
	jobs := func(writer http.ResponseWriter, _ *http.Request, _ *redundantdns.Zone) {
		writeJSON(writer, http.StatusAccepted, redundantdns.Jobs{JobIDs: []string{fake.nextID("job")}})
	}
	handle("POST /v1/zones/{zoneId}/reconcile", fake.withZone(jobs))
	handle("POST /v1/zones/{zoneId}/verify", fake.withZone(jobs))
	handle("POST /v1/zones/{zoneId}/attachments/{attachmentId}/adopt", fake.withZone(jobs))
	handle("GET /v1/zones/{zoneId}/status", fake.withZone(func(writer http.ResponseWriter, _ *http.Request, zone *redundantdns.Zone) {
		writeJSON(writer, http.StatusOK, fake.status(zone))
	}))
	handle("POST /v1/zones/{zoneId}/delegation/check", fake.withZone(func(writer http.ResponseWriter, _ *http.Request, zone *redundantdns.Zone) {
		writeJSON(writer, http.StatusOK, fake.delegation(zone))
	}))
	handle("GET /v1/zones/{zoneId}/journal", fake.withZone(func(writer http.ResponseWriter, _ *http.Request, _ *redundantdns.Zone) {
		writeJSON(writer, http.StatusOK, []redundantdns.JournalEntry{})
	}))
	handle("GET /v1/zones/{zoneId}/export", fake.withZone(func(writer http.ResponseWriter, _ *http.Request, zone *redundantdns.Zone) {
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = writer.Write([]byte(zoneFile(zone)))
	}))
}

// zoneFile renders a zone as a minimal RFC 1035 zone file.
func zoneFile(zone *redundantdns.Zone) string {
	var file strings.Builder
	_, _ = fmt.Fprintf(&file, "$ORIGIN %s.\n", zone.Name)
	for _, set := range zone.RecordSets {
		for _, value := range set.Values {
			_, _ = fmt.Fprintf(&file, "%s %d IN %s %s\n", set.Name, set.TTL, set.Type, value)
		}
	}
	return file.String()
}

func (fake *Fake) upsertRecord(writer http.ResponseWriter, request *http.Request, zone *redundantdns.Zone) {
	var input redundantdns.RecordUpsert
	if !decode(writer, request, &input) {
		return
	}
	set := redundantdns.RecordSet{
		Name:   redundantdns.NormalizeRecordName(zone.Name, input.Name),
		Type:   strings.ToUpper(strings.TrimSpace(input.Type)),
		TTL:    input.TTL,
		Values: redundantdns.NormalizeRecordValues(input.Type, input.Values),
	}
	if set.TTL == 0 {
		set.TTL = zone.Settings.DefaultTTL
	}
	switch {
	case set.Type == "":
		writeError(writer, http.StatusBadRequest, "recordTypeInvalid", "unsupported record type")
		return
	case len(set.Values) == 0:
		writeError(writer, http.StatusBadRequest, "recordSetEmpty", "provide at least one value")
		return
	case set.Name == "@" && set.Type == "NS":
		writeError(writer, http.StatusBadRequest, "apexNsManaged", "the apex NS set is managed by the platform")
		return
	}
	previous := set
	if input.Previous != nil {
		previous = redundantdns.RecordSet{Name: redundantdns.NormalizeRecordName(zone.Name, input.Previous.Name), Type: strings.ToUpper(input.Previous.Type)}
	}
	for _, candidate := range zone.RecordSets {
		if candidate.ManagedBy != "" && ((candidate.Name == set.Name && candidate.Type == set.Type) || (candidate.Name == previous.Name && candidate.Type == previous.Type)) {
			writeError(writer, http.StatusConflict, redundantdns.CodeRecordSetManaged, "this record set is managed by the platform")
			return
		}
	}
	index := slices.IndexFunc(zone.RecordSets, func(candidate redundantdns.RecordSet) bool {
		return candidate.Name == previous.Name && candidate.Type == previous.Type
	})
	if input.Previous != nil && index < 0 {
		writeError(writer, http.StatusNotFound, "recordSetNotFound", "record not found")
		return
	}
	if index >= 0 {
		zone.RecordSets[index] = set
	} else {
		zone.RecordSets = append(zone.RecordSets, set)
	}
	zone.Serial++
	writeJSON(writer, http.StatusOK, redundantdns.RecordUpsertResult{RecordSet: set, Serial: zone.Serial})
}

func (fake *Fake) attach(writer http.ResponseWriter, request *http.Request, zone *redundantdns.Zone) {
	var input redundantdns.AttachmentCreate
	if !decode(writer, request, &input) {
		return
	}
	connection, ok := fake.connections[input.ConnectionID]
	if !ok {
		writeError(writer, http.StatusNotFound, "connectionNotFound", "connection not found")
		return
	}
	for _, attachment := range zone.Attachments {
		if attachment.ConnectionID == input.ConnectionID {
			writeError(writer, http.StatusConflict, "alreadyAttached", "this connection is already attached")
			return
		}
	}
	if connection.Mode == redundantdns.ModeManaged && !fake.managedTermsAccepted() {
		fake.writeManagedTermsRequired(writer)
		return
	}
	token := fake.credentials[connection.ConnectionID]["token"]
	if token == "" {
		token = "managed"
	}
	providerZoneID := input.ProviderZoneID
	if providerZoneID == "" {
		providerZoneID = fake.nextID("fakezone")
	}
	attachment := redundantdns.Attachment{
		AttachmentID: fake.nextID("att"), ConnectionID: connection.ConnectionID, Provider: connection.Provider,
		Label: cmp.Or(input.Label, connection.Label), AccessLevel: connection.AccessLevel, ProviderZoneID: providerZoneID,
		NameServers:   []string{"ns1." + token + ".fake-dns.test.", "ns2." + token + ".fake-dns.test."},
		CreatedRemote: input.ProviderZoneID == "", CreatedAt: time.Now().UTC(),
	}
	zone.Attachments = append(zone.Attachments, attachment)
	fake.refreshNSPlan(zone)
	fake.writeDelegation(zone)
	writeJSON(writer, http.StatusCreated, redundantdns.AttachResult{Attachment: attachment, NSPlan: zone.NSPlan})
}

func (fake *Fake) refreshNSPlan(zone *redundantdns.Zone) {
	plan := []string{}
	for _, attachment := range zone.Attachments {
		for _, nameServer := range attachment.NameServers {
			if !slices.Contains(plan, nameServer) {
				plan = append(plan, nameServer)
			}
		}
	}
	slices.Sort(plan)
	zone.NSPlan = plan
}

func (fake *Fake) status(zone *redundantdns.Zone) redundantdns.ZoneStatus {
	now := time.Now().UTC()
	status := redundantdns.ZoneStatus{OrgID: fake.OrgID, ZoneID: zone.ZoneID, Attachments: map[string]redundantdns.AttachmentStatus{}, UpdatedAt: now}
	for _, attachment := range zone.Attachments {
		status.Attachments[attachment.AttachmentID] = redundantdns.AttachmentStatus{
			AttachmentID: attachment.AttachmentID, State: redundantdns.StateInSync, AppliedSerial: zone.Serial,
			Health: "ok", LastSyncAt: &now, LastVerifyAt: &now, UpdatedAt: now,
		}
	}
	delegation := fake.delegation(zone)
	status.Delegation = &delegation
	return status
}

func (fake *Fake) delegation(zone *redundantdns.Zone) redundantdns.Delegation {
	return redundantdns.Delegation{
		State: redundantdns.StatePending, SeenNS: []string{}, Missing: append([]string{}, zone.NSPlan...),
		Extra: []string{}, NSPlan: append([]string{}, zone.NSPlan...), CheckedAt: time.Now().UTC(),
	}
}

func (fake *Fake) viewZone(zone *redundantdns.Zone) redundantdns.Zone {
	view := *zone
	status := fake.status(zone)
	view.Status = &status
	if parentID, ok := fake.parentDelegations[zone.ZoneID]; ok {
		view.ParentDelegation = &redundantdns.ParentDelegation{Enabled: true, ParentZoneID: parentID}
		if parent, ok := fake.zones[parentID]; ok {
			view.ParentDelegation.ParentZoneName = parent.Name
		}
	}
	if len(zone.Attachments) > 0 {
		_, body, _ := Fixture("zone_get")
		var recorded redundantdns.Zone
		if json.Unmarshal(body, &recorded) == nil && recorded.Capabilities != nil {
			capabilities := *recorded.Capabilities
			capabilities.Providers = nil
			for _, attachment := range zone.Attachments {
				capabilities.Providers = append(capabilities.Providers, attachment.Provider)
			}
			view.Capabilities = &capabilities
		}
	}
	return view
}

// withZone loads {zoneId} or answers zoneNotFound.
func (fake *Fake) withZone(serve func(http.ResponseWriter, *http.Request, *redundantdns.Zone)) handler {
	return func(writer http.ResponseWriter, request *http.Request) {
		zone, ok := fake.zones[request.PathValue("zoneId")]
		if !ok {
			writeError(writer, http.StatusNotFound, "zoneNotFound", "zone not found")
			return
		}
		serve(writer, request, zone)
	}
}

func (fake *Fake) mountConnections(handle func(string, handler)) {
	handle("GET /v1/connections", func(writer http.ResponseWriter, _ *http.Request) {
		connections := make([]redundantdns.Connection, 0, len(fake.connections))
		for _, connection := range fake.connections {
			connections = append(connections, *connection)
		}
		slices.SortFunc(connections, func(left, right redundantdns.Connection) int {
			return strings.Compare(left.ConnectionID, right.ConnectionID)
		})
		writeJSON(writer, http.StatusOK, connections)
	})
	handle("POST /v1/connections", func(writer http.ResponseWriter, request *http.Request) {
		var input redundantdns.ConnectionCreate
		if !decode(writer, request, &input) {
			return
		}
		if input.Provider != "fake" {
			writeError(writer, http.StatusBadRequest, "providerUnavailable", "unknown provider")
			return
		}
		mode := input.Mode
		if mode == "" {
			mode = redundantdns.ModeBYO
		}
		if mode == redundantdns.ModeManaged && input.AcceptManagedTerms != "" {
			if input.AcceptManagedTerms != ManagedTermsVersion {
				writeError(writer, http.StatusConflict, "legalVersionMismatch", "the managed terms version is not the current one")
				return
			}
			fake.acceptManagedTerms()
		}
		if mode == redundantdns.ModeManaged && !fake.managedTermsAccepted() {
			fake.writeManagedTermsRequired(writer)
			return
		}
		if mode == redundantdns.ModeBYO && input.Credentials["token"] == "" {
			writeError(writer, http.StatusBadRequest, "credentialsIncomplete", "missing credential fields: token")
			return
		}
		accessLevel := input.AccessLevel
		switch {
		case mode == redundantdns.ModeManaged:
			accessLevel = redundantdns.AccessLevelZoneAdmin
		case accessLevel != redundantdns.AccessLevelZoneAdmin && accessLevel != redundantdns.AccessLevelZoneEditor:
			// Like the API: BYO credentials need an explicit access level.
			writeError(writer, http.StatusBadRequest, "invalidAccessLevel", "invalid access level")
			return
		}
		now := time.Now().UTC()
		token := input.Credentials["token"]
		hint := token
		if len(hint) > 4 {
			hint = hint[len(hint)-4:]
		}
		connection := &redundantdns.Connection{
			ConnectionID: fake.nextID("conn"), Provider: input.Provider, Mode: mode, Label: input.Label,
			AccessLevel: accessLevel, ScopeHints: map[string]string{}, CredentialsHint: hint, Status: "ok",
			LastCheckedAt: &now, CreatedAt: now,
		}
		for key, value := range input.ScopeHints {
			connection.ScopeHints[key] = value
		}
		fake.connections[connection.ConnectionID] = connection
		fake.credentials[connection.ConnectionID] = input.Credentials
		writeJSON(writer, http.StatusCreated, redundantdns.ConnectionCreateResult{Connection: *connection})
	})
	handle("POST /v1/connections/{connectionId}/test", func(writer http.ResponseWriter, request *http.Request) {
		connection, ok := fake.connections[request.PathValue("connectionId")]
		if !ok {
			writeError(writer, http.StatusNotFound, "connectionNotFound", "connection not found")
			return
		}
		writeJSON(writer, http.StatusOK, redundantdns.ConnectionTestResult{Connection: *connection, Result: redundantdns.TestResult{OK: true}})
	})
	handle("DELETE /v1/connections/{connectionId}", func(writer http.ResponseWriter, request *http.Request) {
		connectionID := request.PathValue("connectionId")
		if _, ok := fake.connections[connectionID]; !ok {
			writeError(writer, http.StatusNotFound, "connectionNotFound", "connection not found")
			return
		}
		for _, zone := range fake.zones {
			for _, attachment := range zone.Attachments {
				if attachment.ConnectionID == connectionID {
					writeError(writer, http.StatusConflict, "connectionInUse", "a zone uses this connection")
					return
				}
			}
		}
		delete(fake.connections, connectionID)
		delete(fake.credentials, connectionID)
		writeJSON(writer, http.StatusOK, map[string]bool{"ok": true})
	})
}

func (fake *Fake) mountAlerts(handle func(string, handler)) {
	handle("GET /v1/alerts/rules", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, fake.rules)
	})
	handle("PUT /v1/alerts/rules/{rule}", func(writer http.ResponseWriter, request *http.Request) {
		var input redundantdns.AlertRuleUpdate
		if !decode(writer, request, &input) {
			return
		}
		index := slices.IndexFunc(fake.rules, func(rule redundantdns.AlertRule) bool { return rule.Kind == request.PathValue("rule") })
		if index < 0 {
			writeError(writer, http.StatusNotFound, "alertRuleNotFound", "unknown rule")
			return
		}
		if input.Enabled != nil {
			fake.rules[index].Enabled = *input.Enabled
		}
		if input.Threshold != nil {
			fake.rules[index].Threshold = *input.Threshold
		}
		writeJSON(writer, http.StatusOK, fake.rules[index])
	})
	handle("GET /v1/alerts/channels", func(writer http.ResponseWriter, _ *http.Request) {
		channels := make([]redundantdns.AlertChannel, 0, len(fake.channels))
		for _, channel := range fake.channels {
			channels = append(channels, *channel)
		}
		slices.SortFunc(channels, func(left, right redundantdns.AlertChannel) int {
			return strings.Compare(left.ChannelID, right.ChannelID)
		})
		writeJSON(writer, http.StatusOK, channels)
	})
	handle("POST /v1/alerts/channels", func(writer http.ResponseWriter, request *http.Request) {
		var input redundantdns.AlertChannelCreate
		if !decode(writer, request, &input) {
			return
		}
		if !slices.Contains([]string{redundantdns.ChannelEmail, redundantdns.ChannelWebhook, redundantdns.ChannelSlack}, input.Kind) {
			writeError(writer, http.StatusBadRequest, "invalidChannelKind", "unknown channel kind")
			return
		}
		channel := &redundantdns.AlertChannel{
			ChannelID: fake.nextID("ch"), Kind: input.Kind, Label: input.Label, Target: input.Target,
			Enabled: true, CreatedAt: time.Now().UTC(),
		}
		result := redundantdns.AlertChannelCreateResult{}
		if input.Kind == redundantdns.ChannelWebhook {
			channel.HasSecret = true
			result.Secret = input.Secret
			if result.Secret == "" {
				result.Secret = "whsec_" + strconv.Itoa(fake.sequence) + "generatedsecret"
			}
		}
		if input.Kind == redundantdns.ChannelSlack {
			channel.Target = maskSlack(input.Target)
		}
		fake.channels[channel.ChannelID] = channel
		result.Channel = *channel
		writeJSON(writer, http.StatusCreated, result)
	})
	handle("DELETE /v1/alerts/channels/{channelId}", func(writer http.ResponseWriter, request *http.Request) {
		if _, ok := fake.channels[request.PathValue("channelId")]; !ok {
			writeError(writer, http.StatusNotFound, "channelNotFound", "channel not found")
			return
		}
		delete(fake.channels, request.PathValue("channelId"))
		writeJSON(writer, http.StatusOK, map[string]bool{"ok": true})
	})
	handle("POST /v1/alerts/channels/{channelId}/test", func(writer http.ResponseWriter, request *http.Request) {
		if _, ok := fake.channels[request.PathValue("channelId")]; !ok {
			writeError(writer, http.StatusNotFound, "channelNotFound", "channel not found")
			return
		}
		writeJSON(writer, http.StatusOK, redundantdns.AlertTestResult{OK: true, Attempts: 1})
	})
	handle("GET /v1/alerts/events", func(writer http.ResponseWriter, request *http.Request) {
		query := request.URL.Query()
		events := []redundantdns.AlertEvent{}
		for _, event := range fake.events {
			if (query.Get("zoneId") == "" || query.Get("zoneId") == event.ZoneID) &&
				(query.Get("rule") == "" || query.Get("rule") == event.Rule) &&
				(query.Get("state") == "" || query.Get("state") == event.State) {
				events = append(events, *event)
			}
		}
		slices.SortFunc(events, func(left, right redundantdns.AlertEvent) int { return right.FirstSeenAt.Compare(left.FirstSeenAt) })
		if limit, err := strconv.Atoi(query.Get("limit")); err == nil && limit > 0 && limit < len(events) {
			events = events[:limit]
		}
		writeJSON(writer, http.StatusOK, events)
	})
	transition := func(resolve bool) handler {
		return func(writer http.ResponseWriter, request *http.Request) {
			event, ok := fake.events[request.PathValue("eventId")]
			if !ok || event.State != "firing" {
				writeError(writer, http.StatusNotFound, "alertNotFound", "no firing alert with this id")
				return
			}
			now := time.Now().UTC()
			if resolve {
				event.State, event.ResolvedAt, event.ResolvedBy = "resolved", &now, "usr-test"
			} else {
				event.AckedAt, event.AckedBy = &now, "usr-test"
			}
			writeJSON(writer, http.StatusOK, event)
		}
	}
	handle("POST /v1/alerts/events/{eventId}/resolve", transition(true))
	handle("POST /v1/alerts/events/{eventId}/ack", transition(false))
}

func maskSlack(target string) string {
	if len(target) <= 12 {
		return "…"
	}
	return target[:len(target)-12] + "…"
}

func decode(writer http.ResponseWriter, request *http.Request, out any) bool {
	if err := json.NewDecoder(request.Body).Decode(out); err != nil {
		writeError(writer, http.StatusBadRequest, "invalidBody", "invalid JSON body")
		return false
	}
	return true
}
