package redundantdns_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"testing"
	"time"

	redundantdns "github.com/redundantdns/go-client"
	"github.com/redundantdns/go-client/rdnstest"
)

func TestReplayManagedTermsAndParentDelegation(t *testing.T) {
	server := rdnstest.NewReplayServer(t, map[string]string{
		"GET /v1/legal/versions":                   "legal_versions",
		"GET /v1/legal/managed":                    "legal_managed_status",
		"POST /v1/legal/managed/accept":            "legal_managed_accept",
		"POST /v1/connections":                     "managed_terms_required",
		"POST /v1/zones":                           "zone_create_child",
		"POST /v1/zones/{zoneId}/delegation/check": "synthetic_delegation_cloudflare_registrar",
	})
	client := newClient(t, server.URL)
	ctx := context.Background()

	versions, err := client.Account.LegalVersions(ctx)
	if err != nil || versions.ManagedTerms != "2026-09-24" {
		t.Fatalf("versions = %+v, %v", versions, err)
	}
	status, err := client.Legal.ManagedStatus(ctx)
	if err != nil || !status.Required || status.Accepted != nil || status.Current != "2026-09-24" || status.URL == "" {
		t.Fatalf("managed status = %+v, %v", status, err)
	}

	_, err = client.Connections.Create(ctx, redundantdns.ConnectionCreate{Provider: "fake", Mode: redundantdns.ModeManaged})
	if !errors.Is(err, redundantdns.ErrManagedTermsRequired) {
		t.Fatalf("managed connection err = %v", err)
	}
	if errors.Is(err, redundantdns.ErrLegalAcceptanceRequired) {
		t.Error("managed_terms_required must not match ErrLegalAcceptanceRequired")
	}
	requirement, ok := redundantdns.ManagedTermsRequired(err)
	if !ok || requirement.Version != "2026-09-24" || requirement.URL != "https://app.redundantdns.com/legal/managed-terms" {
		t.Fatalf("requirement = %+v, %v", requirement, ok)
	}
	if _, ok := redundantdns.ManagedTermsRequired(errors.New("other")); ok {
		t.Error("a plain error is not a managed terms requirement")
	}

	accepted, err := client.Legal.AcceptManaged(ctx, " 2026-09-24 ")
	if err != nil || accepted.Required || accepted.Accepted == nil || accepted.Accepted.Version != "2026-09-24" {
		t.Fatalf("accept = %+v, %v", accepted, err)
	}
	var body map[string]string
	if err := json.Unmarshal(server.LastRequest().Body, &body); err != nil || body["version"] != "2026-09-24" {
		t.Errorf("accept body = %s", server.LastRequest().Body)
	}

	zone, err := client.Zones.Create(ctx, redundantdns.ZoneCreate{Name: "api.fixtures-1790272800.example.com", ParentDelegation: redundantdns.Bool(true)})
	if err != nil || zone.ParentDelegation == nil || !zone.ParentDelegation.Enabled || zone.ParentDelegation.ParentZoneName != "fixtures-1790272800.example.com" {
		t.Fatalf("child zone = %+v, %v", zone, err)
	}
	var sent map[string]any
	_ = json.Unmarshal(server.LastRequest().Body, &sent)
	if sent["parentDelegation"] != true {
		t.Errorf("zone create body = %s", server.LastRequest().Body)
	}

	delegation, err := client.Delegation.Check(ctx, zone.ZoneID)
	if err != nil || delegation.Hint != redundantdns.DelegationHintCloudflareRegistrar || delegation.Registrar == nil ||
		!delegation.Registrar.IsCloudflare || delegation.Registrar.IANAID != "1910" {
		t.Fatalf("delegation = %+v, %v", delegation, err)
	}
}

func TestParentDelegationDecoding(t *testing.T) {
	for raw, want := range map[string]redundantdns.ParentDelegation{
		`true`:  {Enabled: true},
		`false`: {},
		`{"enabled":true,"parentZoneId":"zone-1","parentZoneName":"example.com"}`: {Enabled: true, ParentZoneID: "zone-1", ParentZoneName: "example.com"},
	} {
		var zone redundantdns.Zone
		if err := json.Unmarshal([]byte(`{"zoneId":"zone-2","parentDelegation":`+raw+`}`), &zone); err != nil || zone.ParentDelegation == nil || *zone.ParentDelegation != want {
			t.Errorf("%s: %+v, %v", raw, zone.ParentDelegation, err)
		}
	}
	var registrar redundantdns.Registrar
	if err := json.Unmarshal([]byte(`{"name":"X","ianaId":"146"}`), &registrar); err != nil || registrar.IANAID != "146" {
		t.Errorf("string ianaId = %+v, %v", registrar, err)
	}
	if err := json.Unmarshal([]byte(`{"name":"X","ianaId":null}`), &registrar); err != nil || registrar.IANAID != "" {
		t.Errorf("null ianaId = %+v, %v", registrar, err)
	}
}

func TestFakeManagedTermsAndParentDelegation(t *testing.T) {
	fake := rdnstest.NewFake(t)
	client := newClient(t, fake.URL)
	ctx := context.Background()

	// Without an acceptance a managed connection is refused.
	_, err := client.Connections.Create(ctx, redundantdns.ConnectionCreate{Provider: "fake", Mode: redundantdns.ModeManaged})
	if requirement, ok := redundantdns.ManagedTermsRequired(err); !ok || requirement.Version != rdnstest.ManagedTermsVersion {
		t.Fatalf("managed without terms err = %v", err)
	}
	// An outdated version is a conflict, the current one is recorded.
	_, err = client.Connections.Create(ctx, redundantdns.ConnectionCreate{Provider: "fake", Mode: redundantdns.ModeManaged, AcceptManagedTerms: "2020-01-01"})
	if !redundantdns.HasCode(err, redundantdns.CodeLegalVersionMismatch) {
		t.Fatalf("old version err = %v", err)
	}
	managed, err := client.Connections.Create(ctx, redundantdns.ConnectionCreate{
		Provider: "fake", Mode: redundantdns.ModeManaged, AcceptManagedTerms: rdnstest.ManagedTermsVersion,
	})
	if err != nil || managed.Connection.AccessLevel != redundantdns.AccessLevelZoneAdmin {
		t.Fatalf("managed = %+v, %v", managed, err)
	}
	status, err := client.Legal.ManagedStatus(ctx)
	if err != nil || status.Required || status.Accepted == nil {
		t.Fatalf("status after create = %+v, %v", status, err)
	}
	if _, err := client.Legal.AcceptManaged(ctx, "2020-01-01"); !errors.Is(err, redundantdns.ErrConflict) {
		t.Fatalf("accept old version err = %v", err)
	}

	// Subdomain redundancy: the child's NS plan lands in the parent.
	parent, err := client.Zones.Create(ctx, redundantdns.ZoneCreate{Name: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	child, err := client.Zones.Create(ctx, redundantdns.ZoneCreate{Name: "api.example.com", ParentDelegation: redundantdns.Bool(true)})
	if err != nil || child.ParentDelegation == nil || child.ParentDelegation.ParentZoneID != parent.ZoneID {
		t.Fatalf("child = %+v, %v", child, err)
	}
	optedOut, err := client.Zones.Create(ctx, redundantdns.ZoneCreate{Name: "www.example.com", ParentDelegation: redundantdns.Bool(false)})
	if err != nil || optedOut.ParentDelegation != nil {
		t.Fatalf("opted-out child = %+v, %v", optedOut, err)
	}
	attached, err := client.Attachments.Create(ctx, child.ZoneID, redundantdns.AttachmentCreate{ConnectionID: managed.Connection.ConnectionID, Label: "managed"})
	if err != nil || attached.Attachment.Label != "managed" {
		t.Fatalf("attach = %+v, %v", attached, err)
	}
	records, err := client.Records.List(ctx, parent.ZoneID)
	if err != nil {
		t.Fatal(err)
	}
	index := slices.IndexFunc(records, func(set redundantdns.RecordSet) bool { return set.Name == "api" && set.Type == "NS" })
	if index < 0 || records[index].ManagedBy != redundantdns.ManagedByDelegation || len(records[index].Values) != 2 {
		t.Fatalf("parent records = %+v", records)
	}
	if _, err := client.Records.Upsert(ctx, parent.ZoneID, redundantdns.RecordUpsert{Name: "api", Type: "NS", Values: []string{"ns.example.net."}}); !redundantdns.HasCode(err, redundantdns.CodeRecordSetManaged) {
		t.Fatalf("edit a delegation set err = %v", err)
	}
	if err := client.Zones.Delete(ctx, child.ZoneID); err != nil {
		t.Fatal(err)
	}
	if records, _ := client.Records.List(ctx, parent.ZoneID); len(records) != 0 {
		t.Fatalf("the delegation must go with the child: %+v", records)
	}
}

func TestFakeManagedAttachNeedsTerms(t *testing.T) {
	fake := rdnstest.NewFake(t)
	client := newClient(t, fake.URL)
	ctx := context.Background()
	fake.AcceptManagedTerms()
	managed, err := client.Connections.Create(ctx, redundantdns.ConnectionCreate{Provider: "fake", Mode: redundantdns.ModeManaged})
	if err != nil {
		t.Fatal(err)
	}
	zone, err := client.Zones.Create(ctx, redundantdns.ZoneCreate{Name: "example.org"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Attachments.Create(ctx, zone.ZoneID, redundantdns.AttachmentCreate{ConnectionID: managed.Connection.ConnectionID}); err != nil {
		t.Fatalf("attach with terms accepted: %v", err)
	}
}

func TestOAuthRegisterAuthorizeRefresh(t *testing.T) {
	fake := rdnstest.NewFake(t)
	ctx := context.Background()
	anonymous, err := redundantdns.New(redundantdns.WithBaseURL(fake.URL), redundantdns.WithRetryPolicy(fastRetry))
	if err != nil {
		t.Fatal(err)
	}
	redirect := "http://127.0.0.1:53682/callback"
	registered, err := anonymous.OAuth.Register(ctx, redundantdns.OAuthClientRegistration{
		ClientName: "Terraform", RedirectURIs: []string{redirect}, TokenEndpointAuthMethod: "none",
		SoftwareID: redundantdns.SoftwareIDTerraform, SoftwareVersion: "0.1.0",
	})
	if err != nil || registered.ClientID == "" || registered.SoftwareID != redundantdns.SoftwareIDTerraform {
		t.Fatalf("register = %+v, %v", registered, err)
	}
	if got := fake.OAuthRegistrations()[registered.ClientID]; got.SoftwareID != redundantdns.SoftwareIDTerraform ||
		!slices.Equal(got.GrantTypes, []string{redundantdns.GrantAuthorizationCode, redundantdns.GrantRefreshToken}) {
		t.Errorf("registration sent = %+v", got)
	}

	pkce, err := redundantdns.NewPKCE()
	if err != nil || pkce.Verifier == pkce.Challenge {
		t.Fatal(err)
	}
	state, _ := redundantdns.RandomState()
	authorize := anonymous.OAuth.AuthorizationURL(redundantdns.AuthorizationRequest{
		ClientID: registered.ClientID, RedirectURI: redirect, State: state, CodeChallenge: pkce.Challenge, Scope: "zones:read",
	})
	// The fake approves at once and redirects to the loopback URI: read the
	// Location instead of following it.
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	answer, err := noFollow.Get(authorize) //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	_ = answer.Body.Close()
	location, err := url.Parse(answer.Header.Get("Location"))
	if err != nil || location.Query().Get("state") != state {
		t.Fatalf("redirect = %q, %v", answer.Header.Get("Location"), err)
	}
	if _, err := anonymous.OAuth.ExchangeCode(ctx, registered.ClientID, location.Query().Get("code"), redirect, "wrong-verifier"); !redundantdns.HasCode(err, "invalid_grant") {
		t.Fatalf("wrong verifier err = %v", err)
	}
	// A code is single use; ask for another one.
	answer, _ = noFollow.Get(authorize) //nolint:noctx // test
	_ = answer.Body.Close()
	location, _ = url.Parse(answer.Header.Get("Location"))
	token, err := anonymous.OAuth.ExchangeCode(ctx, registered.ClientID, location.Query().Get("code"), redirect, pkce.Verifier)
	if err != nil || token.AccessToken != rdnstest.DefaultToken || token.RefreshToken == "" || token.Expiry.Before(time.Now()) {
		t.Fatalf("exchange = %+v, %v", token, err)
	}

	// Credentials saved to a file are refreshed when expired, and the
	// rotated refresh token is written back.
	path := filepath.Join(t.TempDir(), "creds", "oauth.json")
	credentials := &redundantdns.OAuthCredentials{BaseURL: fake.URL, ClientID: registered.ClientID, SoftwareID: redundantdns.SoftwareIDTerraform}
	credentials.Apply(token)
	credentials.Expiry = time.Now().Add(-time.Minute)
	if err := credentials.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := redundantdns.LoadOAuthCredentials(path)
	if err != nil {
		t.Fatal(err)
	}
	refreshed, err := redundantdns.RefreshOAuthCredentials(ctx, path, loaded, 5*time.Minute, redundantdns.WithRetryPolicy(fastRetry))
	if err != nil || !refreshed || loaded.RefreshToken == token.RefreshToken {
		t.Fatalf("refresh = %v, %v, %+v", refreshed, err, loaded)
	}
	again, _ := redundantdns.LoadOAuthCredentials(path)
	if again.RefreshToken != loaded.RefreshToken || again.Expired(time.Now(), time.Minute) {
		t.Errorf("saved after refresh = %+v", again)
	}
	if refreshed, err := redundantdns.RefreshOAuthCredentials(ctx, path, again, time.Minute); err != nil || refreshed {
		t.Errorf("a fresh token must not be refreshed: %v, %v", refreshed, err)
	}
	// The spent refresh token is refused.
	if _, err := anonymous.OAuth.Refresh(ctx, registered.ClientID, token.RefreshToken); !redundantdns.HasCode(err, "invalid_grant") {
		t.Errorf("spent refresh token err = %v", err)
	}
}

func TestTokenCreateSendsClient(t *testing.T) {
	var sent redundantdns.TokenCreate
	server := http.NewServeMux()
	server.HandleFunc("POST /v1/tokens", func(writer http.ResponseWriter, request *http.Request) {
		_ = json.NewDecoder(request.Body).Decode(&sent)
		writer.WriteHeader(http.StatusCreated)
		_, _ = writer.Write([]byte(`{"record":{"tokenId":"tok-1","client":"cli"},"token":"rdns_x"}`))
	})
	test := httptest.NewServer(server)
	t.Cleanup(test.Close)
	client := newClient(t, test.URL)
	result, err := client.Tokens.Create(context.Background(), redundantdns.TokenCreate{Name: "cli", Scopes: redundantdns.AllScopes, Client: redundantdns.TokenClientCLI})
	if err != nil || sent.Client != redundantdns.TokenClientCLI || result.Record.Client != redundantdns.TokenClientCLI {
		t.Fatalf("token = %+v, sent %+v, %v", result, sent, err)
	}
}
