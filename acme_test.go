package redundantdns_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	redundantdns "github.com/redundantdns/go-client"
	"github.com/redundantdns/go-client/rdnstest"
)

// acmeDigest is a typical key authorization digest (43 base64url chars).
const acmeDigest = "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"

func acmeZone(t *testing.T, client *redundantdns.Client, name string) *redundantdns.Zone {
	t.Helper()
	zone, err := client.Zones.Create(context.Background(), redundantdns.ZoneCreate{Name: name})
	if err != nil {
		t.Fatal(err)
	}
	return zone
}

func TestACMEPresentStatusCleanUp(t *testing.T) {
	ctx := context.Background()
	fake := rdnstest.NewFake(t)
	client := newClient(t, fake.URL)
	zone := acmeZone(t, client, "example.com")

	challenge, err := client.ACME.Present(ctx, zone.ZoneID, redundantdns.ACMEChallengeInput{Name: "_acme-challenge.www.example.com.", Value: acmeDigest})
	if err != nil {
		t.Fatal(err)
	}
	if challenge.ChallengeID == "" || challenge.Name != "_acme-challenge.www" || challenge.FQDN != "_acme-challenge.www.example.com." ||
		challenge.Propagation != redundantdns.ACMEStatePending || challenge.Existing || challenge.Serial == 0 {
		t.Errorf("challenge = %+v", challenge)
	}
	requests := fake.Requests()
	last := requests[len(requests)-1]
	if last.Method != http.MethodPost || last.Path != "/v1/zones/"+zone.ZoneID+"/acme/challenges" {
		t.Errorf("present request = %s %s", last.Method, last.Path)
	}
	var body map[string]any
	if err := json.Unmarshal(last.Body, &body); err != nil || body["value"] != acmeDigest || body["name"] != "_acme-challenge.www.example.com." {
		t.Errorf("present body = %s", last.Body)
	}
	if _, hasTTL := body["ttl"]; hasTTL {
		t.Errorf("a zero TTL must be omitted: %s", last.Body)
	}

	// Idempotent: the same name (relative this time) and value.
	again, err := client.ACME.Present(ctx, zone.ZoneID, redundantdns.ACMEChallengeInput{Name: "_acme-challenge.www", Value: acmeDigest, TTL: 120})
	if err != nil {
		t.Fatal(err)
	}
	if again.ChallengeID != challenge.ChallengeID || !again.Existing {
		t.Errorf("second present = %+v", again)
	}
	if values := fake.ACMEValues("_acme-challenge.WWW.example.com"); !slices.Equal(values, []string{acmeDigest}) {
		t.Errorf("served values = %v", values)
	}

	status, err := client.ACME.Status(ctx, zone.ZoneID, challenge.ChallengeID)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Propagated() || status.Failed() || status.FQDN != challenge.FQDN || status.CheckedAt.IsZero() || status.Providers == nil {
		t.Errorf("status = %+v", status)
	}

	if err := client.ACME.CleanUp(ctx, zone.ZoneID, challenge.ChallengeID); err != nil {
		t.Fatal(err)
	}
	if values := fake.ACMEValues("_acme-challenge.www.example.com."); len(values) != 0 {
		t.Errorf("values after clean-up = %v", values)
	}
	// Idempotent: already gone.
	if err := client.ACME.CleanUp(ctx, zone.ZoneID, challenge.ChallengeID); err != nil {
		t.Errorf("second clean-up: %v", err)
	}
	if _, err := client.ACME.Status(ctx, zone.ZoneID, challenge.ChallengeID); !redundantdns.HasCode(err, redundantdns.CodeACMEChallengeNotFound) || !redundantdns.IsNotFound(err) {
		t.Errorf("status after clean-up: %v", err)
	}
}

func TestACMEApexAndWildcardShareTheName(t *testing.T) {
	ctx := context.Background()
	fake := rdnstest.NewFake(t)
	client := newClient(t, fake.URL)
	zone := acmeZone(t, client, "example.com")

	other := "Xh3e0VnBHsQ_mK6ihAVQx5-4y7wtLqo0fbCqvxJ2gTs"
	first, err := client.ACME.Present(ctx, zone.ZoneID, redundantdns.ACMEChallengeInput{Name: "_acme-challenge", Value: acmeDigest})
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.ACME.Present(ctx, zone.ZoneID, redundantdns.ACMEChallengeInput{Name: "_acme-challenge.example.com", Value: other})
	if err != nil {
		t.Fatal(err)
	}
	if first.ChallengeID == second.ChallengeID || second.Existing {
		t.Errorf("two values must be two challenges: %+v %+v", first, second)
	}
	want := []string{acmeDigest, other}
	slices.Sort(want)
	if values := fake.ACMEValues("_acme-challenge.example.com."); !slices.Equal(values, want) {
		t.Errorf("served values = %v", values)
	}
	records, err := client.Records.List(ctx, zone.ZoneID)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Name != "_acme-challenge" || records[0].Type != "TXT" || len(records[0].Values) != 2 {
		t.Errorf("records = %+v", records)
	}

	// Clean-up by name and value removes only that value.
	if err := client.ACME.CleanUpValue(ctx, zone.ZoneID, "_acme-challenge.example.com.", acmeDigest); err != nil {
		t.Fatal(err)
	}
	requests := fake.Requests()
	last := requests[len(requests)-1]
	if last.Method != http.MethodDelete || last.Path != "/v1/zones/"+zone.ZoneID+"/acme/challenges" ||
		last.Query != "name=_acme-challenge.example.com.&value="+acmeDigest {
		t.Errorf("clean-up request = %s %s?%s", last.Method, last.Path, last.Query)
	}
	if values := fake.ACMEValues("_acme-challenge.example.com"); !slices.Equal(values, []string{other}) {
		t.Errorf("values after the first clean-up = %v", values)
	}
	if err := client.ACME.CleanUpValue(ctx, zone.ZoneID, "_acme-challenge", other); err != nil {
		t.Fatal(err)
	}
	if err := client.ACME.CleanUpValue(ctx, zone.ZoneID, "_acme-challenge", other); err != nil {
		t.Errorf("clean-up of a value already gone: %v", err)
	}
	if records, _ := client.Records.List(ctx, zone.ZoneID); len(records) != 0 {
		t.Errorf("the TXT set must go with its last value: %+v", records)
	}
	if len(fake.ACMEChallenges()) != 0 {
		t.Errorf("challenges left: %+v", fake.ACMEChallenges())
	}
}

func TestACMEPresentRefusals(t *testing.T) {
	ctx := context.Background()
	fake := rdnstest.NewFake(t)
	client := newClient(t, fake.URL)
	zone := acmeZone(t, client, "example.com")
	if _, err := client.Records.Upsert(ctx, zone.ZoneID, redundantdns.RecordUpsert{
		Name: "_acme-challenge.app", Type: "CNAME", Values: []string{"app.acme.example.net."},
	}); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		input redundantdns.ACMEChallengeInput
		code  string
		is    error
	}{
		{"not an acme name", redundantdns.ACMEChallengeInput{Name: "www", Value: acmeDigest}, redundantdns.CodeACMENameInvalid, redundantdns.ErrBadRequest},
		{"another zone", redundantdns.ACMEChallengeInput{Name: "_acme-challenge.example.org.", Value: acmeDigest}, redundantdns.CodeACMENameInvalid, redundantdns.ErrBadRequest},
		{"bad value", redundantdns.ACMEChallengeInput{Name: "_acme-challenge", Value: "not base64url!"}, redundantdns.CodeACMEValueInvalid, redundantdns.ErrBadRequest},
		{"cname", redundantdns.ACMEChallengeInput{Name: "_acme-challenge.app", Value: acmeDigest}, redundantdns.CodeCnameConflict, redundantdns.ErrConflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := client.ACME.Present(ctx, zone.ZoneID, tc.input)
			if !redundantdns.HasCode(err, tc.code) || !errors.Is(err, tc.is) {
				t.Errorf("err = %v, want %s", err, tc.code)
			}
		})
	}
	if _, err := client.ACME.Present(ctx, "zone-missing", redundantdns.ACMEChallengeInput{Name: "_acme-challenge", Value: acmeDigest}); !redundantdns.HasCode(err, redundantdns.CodeZoneNotFound) {
		t.Errorf("missing zone: %v", err)
	}
	// A clean-up in a zone that does not exist is an error (only a missing
	// challenge is tolerated).
	if err := client.ACME.CleanUp(ctx, "zone-missing", "ach-1"); !redundantdns.HasCode(err, redundantdns.CodeZoneNotFound) {
		t.Errorf("clean-up in a missing zone: %v", err)
	}
}

func TestACMEZonesAndRestriction(t *testing.T) {
	ctx := context.Background()
	fake := rdnstest.NewFake(t)
	client := newClient(t, fake.URL)
	allowed := acmeZone(t, client, "Example.COM")
	other := acmeZone(t, client, "example.org")

	zones, err := client.ACME.Zones(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 2 || zones[0].Name != "example.com" || zones[1].Name != "example.org" {
		t.Errorf("zones = %+v", zones)
	}

	fake.RestrictACMEZones(allowed.ZoneID)
	zones, err = client.ACME.Zones(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 1 || zones[0] != (redundantdns.ACMEZone{ZoneID: allowed.ZoneID, Name: "example.com"}) {
		t.Errorf("restricted zones = %+v", zones)
	}
	_, err = client.ACME.Present(ctx, other.ZoneID, redundantdns.ACMEChallengeInput{Name: "_acme-challenge", Value: acmeDigest})
	if !redundantdns.HasCode(err, redundantdns.CodeZoneNotAllowed) || !errors.Is(err, redundantdns.ErrForbidden) {
		t.Errorf("present outside the restriction: %v", err)
	}
}

func TestACMEWaitPropagated(t *testing.T) {
	ctx := context.Background()
	fake := rdnstest.NewFake(t)
	client := newClient(t, fake.URL)
	zone := acmeZone(t, client, "example.com")
	if _, err := client.Connections.Create(ctx, redundantdns.ConnectionCreate{
		Provider: "fake", Label: "one", AccessLevel: redundantdns.AccessLevelZoneAdmin, Credentials: map[string]string{"token": "one"},
	}); err != nil {
		t.Fatal(err)
	}
	connections, _ := client.Connections.List(ctx)
	if _, err := client.Attachments.Create(ctx, zone.ZoneID, redundantdns.AttachmentCreate{ConnectionID: connections[0].ConnectionID}); err != nil {
		t.Fatal(err)
	}

	fake.SetACMEPropagation(2)
	challenge, err := client.ACME.Present(ctx, zone.ZoneID, redundantdns.ACMEChallengeInput{Name: "_acme-challenge", Value: acmeDigest})
	if err != nil {
		t.Fatal(err)
	}
	var states []string
	status, err := client.ACME.WaitPropagated(ctx, zone.ZoneID, challenge.ChallengeID, redundantdns.ACMEWaitOptions{
		Interval: time.Millisecond,
		OnStatus: func(status *redundantdns.ACMEChallengeStatus) { states = append(states, status.State) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(states, []string{"pending", "pending", "propagated"}) {
		t.Errorf("states = %v", states)
	}
	if len(status.Providers) != 1 {
		t.Fatalf("providers = %+v", status.Providers)
	}
	provider := status.Providers[0]
	if provider.Role != redundantdns.ACMERoleActive || !provider.Applied || provider.Served == nil || !*provider.Served ||
		len(provider.NameServers) != 2 || provider.NameServers[0].Answer != redundantdns.ACMEAnswerMatch {
		t.Errorf("provider = %+v", provider)
	}

	fake.FailACMEChallenges("route53: credentials rejected")
	status, err = client.ACME.WaitPropagated(ctx, zone.ZoneID, challenge.ChallengeID, redundantdns.ACMEWaitOptions{Interval: time.Millisecond})
	if !errors.Is(err, redundantdns.ErrACMEChallengeFailed) || status == nil || status.Reason != "route53: credentials rejected" {
		t.Errorf("failed wait: status %+v, err %v", status, err)
	}

	fake.FailACMEChallenges("")
	fake.SetACMEPropagation(1000)
	second, err := client.ACME.Present(ctx, zone.ZoneID, redundantdns.ACMEChallengeInput{Name: "_acme-challenge.www", Value: acmeDigest})
	if err != nil {
		t.Fatal(err)
	}
	deadline, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	status, err = client.ACME.WaitPropagated(deadline, zone.ZoneID, second.ChallengeID, redundantdns.ACMEWaitOptions{Interval: 5 * time.Millisecond})
	if !errors.Is(err, context.DeadlineExceeded) || status == nil || status.State != redundantdns.ACMEStatePending {
		t.Errorf("timed-out wait: status %+v, err %v", status, err)
	}
}

func TestACMEDecodesTheContract(t *testing.T) {
	// The documented status answer, verbatim, so a field rename in the
	// models is caught even where the fake does not fill the field.
	const answer = `{"challengeId":"ach-1","name":"_acme-challenge.www","fqdn":"_acme-challenge.www.example.com.","serial":2026102301,
"state":"failed","reason":"verify-mode attachment in the NS plan","checkedAt":"2026-10-23T10:00:00Z",
"providers":[{"attachmentId":"att-1","provider":"route53","label":"aws","role":"standby","applied":true,"served":null,
"skipped":"verify","error":"","nameServers":[{"host":"ns-1.awsdns-00.com.","answer":"error","error":"timeout"}]}]}`
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/zones/zon-1/acme/challenges/ach-1":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(answer))
		case "/v1/acme/zones":
			_, _ = writer.Write([]byte(`{"zones":null}`))
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	client := newClient(t, server.URL)

	status, err := client.ACME.Status(context.Background(), "zon-1", "ach-1")
	if err != nil {
		t.Fatal(err)
	}
	if !status.Failed() || status.Reason == "" || status.Serial != 2026102301 || !status.CheckedAt.Equal(time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("status = %+v", status)
	}
	provider := status.Providers[0]
	if provider.Role != redundantdns.ACMERoleStandby || provider.Served != nil || provider.Skipped != redundantdns.ACMESkippedVerify ||
		provider.NameServers[0] != (redundantdns.ACMENameServerAnswer{Host: "ns-1.awsdns-00.com.", Answer: redundantdns.ACMEAnswerError, Error: "timeout"}) {
		t.Errorf("provider = %+v", provider)
	}
	zones, err := client.ACME.Zones(context.Background())
	if err != nil || zones == nil || len(zones) != 0 {
		t.Errorf("zones = %#v, %v", zones, err)
	}
}

func TestTokenCreateZoneRestriction(t *testing.T) {
	input := redundantdns.TokenCreate{Name: "cert-manager", Scopes: []string{redundantdns.ScopeACMEChallenge}, ZoneIDs: []string{"zon-1"}}
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"name":"cert-manager","scopes":["acme:challenge"],"zoneIds":["zon-1"]}` {
		t.Errorf("token create = %s", encoded)
	}
	var token redundantdns.Token
	if err := json.Unmarshal([]byte(`{"tokenId":"tok-1","scopes":["acme:challenge"],"restrictions":{"zoneIds":["zon-1","zon-2"]}}`), &token); err != nil {
		t.Fatal(err)
	}
	if token.Restrictions == nil || !slices.Equal(token.Restrictions.ZoneIDs, []string{"zon-1", "zon-2"}) {
		t.Errorf("token = %+v", token)
	}
	if slices.Contains(redundantdns.AllScopes, redundantdns.ScopeACMEChallenge) {
		t.Error("acme:challenge must not be in AllScopes (it needs a zone list)")
	}
}
