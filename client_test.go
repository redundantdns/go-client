package redundantdns_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	redundantdns "github.com/redundantdns/go-client"
	"github.com/redundantdns/go-client/rdnstest"
)

// fastRetry keeps retry tests quick.
var fastRetry = redundantdns.RetryPolicy{MaxRetries: 3, BaseDelay: time.Millisecond, MaxDelay: 5 * time.Millisecond}

func newClient(t *testing.T, baseURL string, options ...redundantdns.Option) *redundantdns.Client {
	t.Helper()
	all := append([]redundantdns.Option{
		redundantdns.WithBaseURL(baseURL),
		redundantdns.WithToken(rdnstest.DefaultToken),
		redundantdns.WithRetryPolicy(fastRetry),
	}, options...)
	client, err := redundantdns.New(all...)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestNewValidatesBaseURL(t *testing.T) {
	for _, raw := range []string{"ftp://example.com", "http://", "::bad"} {
		if _, err := redundantdns.New(redundantdns.WithBaseURL(raw)); err == nil {
			t.Errorf("base URL %q: expected an error", raw)
		}
	}
	client, err := redundantdns.New()
	if err != nil {
		t.Fatal(err)
	}
	if client.BaseURL() != redundantdns.DefaultBaseURL {
		t.Errorf("default base URL = %q", client.BaseURL())
	}
}

func TestReplayZonesAndRecords(t *testing.T) {
	server := rdnstest.NewReplayServer(t, map[string]string{
		"GET /v1/zones":                     "zone_list",
		"POST /v1/zones":                    "zone_create",
		"GET /v1/zones/{zoneId}":            "zone_get",
		"DELETE /v1/zones/{zoneId}":         "zone_delete",
		"GET /v1/zones/{zoneId}/records":    "record_list",
		"PUT /v1/zones/{zoneId}/records":    "record_upsert",
		"DELETE /v1/zones/{zoneId}/records": "record_delete",
		"GET /v1/zones/{zoneId}/export":     "zone_export.txt",
		"GET /v1/zones/{zoneId}/status":     "zone_status",
		"GET /v1/zones/{zoneId}/journal":    "journal",
	})
	client := newClient(t, server.URL, redundantdns.WithOrg("org-w3qlj324qqyouqbh"), redundantdns.WithUserAgent("tests/1"))
	ctx := context.Background()

	zones, err := client.Zones.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 1 || zones[0].RecordSets != nil || len(zones[0].Attachments) != 1 {
		t.Fatalf("unexpected list: %+v", zones)
	}
	last := server.LastRequest()
	if last.Header.Get("Authorization") != "Bearer "+rdnstest.DefaultToken {
		t.Errorf("authorization header = %q", last.Header.Get("Authorization"))
	}
	if last.Header.Get(redundantdns.OrgHeader) != "org-w3qlj324qqyouqbh" {
		t.Errorf("org header = %q", last.Header.Get(redundantdns.OrgHeader))
	}
	if !strings.HasPrefix(last.Header.Get("User-Agent"), "tests/1 redundantdns-go-client/") {
		t.Errorf("user agent = %q", last.Header.Get("User-Agent"))
	}

	created, err := client.Zones.Create(ctx, redundantdns.ZoneCreate{Name: "Fixtures.Example.com.", DefaultTTL: 600})
	if err != nil {
		t.Fatal(err)
	}
	if created.ZoneID == "" || created.Settings.DefaultTTL != 300 {
		t.Errorf("created zone = %+v", created)
	}
	if body := string(server.LastRequest().Body); body != `{"name":"Fixtures.Example.com.","defaultTtl":600}` {
		t.Errorf("create body = %s", body)
	}

	zone, err := client.Zones.Get(ctx, zones[0].ZoneID)
	if err != nil {
		t.Fatal(err)
	}
	if zone.Capabilities == nil || !slices.Contains(zone.Capabilities.Providers, "fake") || zone.Capabilities.MaxTTL != 604800 {
		t.Errorf("capabilities = %+v", zone.Capabilities)
	}
	if len(zone.NSPlan) != 2 || zone.Status == nil || len(zone.RecordSets) != 1 {
		t.Errorf("zone = %+v", zone)
	}

	upserted, err := client.Records.Upsert(ctx, zone.ZoneID, redundantdns.RecordUpsert{Name: "www", Type: "A", TTL: 300, Values: []string{"192.0.2.10"}})
	if err != nil {
		t.Fatal(err)
	}
	if upserted.Serial == 0 || upserted.RecordSet.Name != "www" {
		t.Errorf("upsert = %+v", upserted)
	}
	if last := server.LastRequest(); last.Method != http.MethodPut || last.Path != "/v1/zones/"+zone.ZoneID+"/records" {
		t.Errorf("upsert request = %s %s", last.Method, last.Path)
	}

	records, err := client.Records.List(ctx, zone.ZoneID)
	if err != nil || len(records) != 1 || records[0].Values[0] != "192.0.2.10" {
		t.Fatalf("records = %+v, %v", records, err)
	}
	found, err := client.Records.Get(ctx, zone.ZoneID, zone.Name, "WWW."+zone.Name+".", "a")
	if err != nil || found.TTL != 300 {
		t.Fatalf("records get = %+v, %v", found, err)
	}
	if _, err := client.Records.Get(ctx, zone.ZoneID, zone.Name, "missing", "A"); !redundantdns.HasCode(err, redundantdns.CodeRecordSetNotFound) {
		t.Errorf("missing record err = %v", err)
	}

	serial, err := client.Records.Delete(ctx, zone.ZoneID, "www", "A")
	if err != nil || serial == 0 {
		t.Fatalf("delete record = %d, %v", serial, err)
	}
	if query := server.LastRequest().Query; query != "name=www&type=A" {
		t.Errorf("delete query = %q", query)
	}

	export, err := client.Zones.Export(ctx, zone.ZoneID)
	if err != nil || !strings.Contains(export, "$ORIGIN "+zone.Name+".") {
		t.Fatalf("export = %q, %v", export, err)
	}
	if accept := server.LastRequest().Header.Get("Accept"); accept != "text/plain" {
		t.Errorf("export accept = %q", accept)
	}

	status, err := client.Zones.Status(ctx, zone.ZoneID)
	if err != nil {
		t.Fatal(err)
	}
	for _, attachment := range status.Attachments {
		if attachment.State != redundantdns.StateInSync || attachment.LastDiff == nil {
			t.Errorf("attachment status = %+v", attachment)
		}
	}
	if len(status.Probes) != 2 || status.Delegation == nil || status.Delegation.State != "pending" {
		t.Errorf("status = %+v", status)
	}

	journal, err := client.Zones.Journal(ctx, zone.ZoneID)
	if err != nil || len(journal) == 0 {
		t.Fatalf("journal = %+v, %v", journal, err)
	}

	if err := client.Zones.Delete(ctx, zone.ZoneID); err != nil {
		t.Fatal(err)
	}
}

func TestReplayConnectionsAttachmentsSync(t *testing.T) {
	server := rdnstest.NewReplayServer(t, map[string]string{
		"GET /v1/connections":                                      "connection_list",
		"POST /v1/connections":                                     "connection_create",
		"POST /v1/connections/{connectionId}/test":                 "connection_test",
		"DELETE /v1/connections/{connectionId}":                    "connection_delete",
		"POST /v1/zones/{zoneId}/attachments":                      "attachment_create",
		"DELETE /v1/zones/{zoneId}/attachments/{attachmentId}":     "attachment_delete",
		"POST /v1/zones/{zoneId}/attachments/{attachmentId}/adopt": "adopt",
		"POST /v1/zones/{zoneId}/reconcile":                        "reconcile",
		"POST /v1/zones/{zoneId}/verify":                           "verify",
		"POST /v1/zones/{zoneId}/delegation/check":                 "delegation_check",
		"GET /v1/providers":                                        "providers",
		"GET /v1/me":                                               "me",
		"GET /v1/audit":                                            "audit",
	})
	client := newClient(t, server.URL)
	ctx := context.Background()

	created, err := client.Connections.Create(ctx, redundantdns.ConnectionCreate{
		Provider: "fake", Label: "Fixture fake", AccessLevel: redundantdns.AccessLevelZoneAdmin,
		Credentials: map[string]string{"token": "fixture-token"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Connection.Status != "ok" || created.Connection.CredentialsHint != "oken" {
		t.Errorf("connection = %+v", created.Connection)
	}
	var sent map[string]any
	if err := json.Unmarshal(server.LastRequest().Body, &sent); err != nil || sent["credentials"] == nil || sent["mode"] != nil {
		t.Errorf("create body = %s", server.LastRequest().Body)
	}
	connectionID := created.Connection.ConnectionID

	fetched, err := client.Connections.Get(ctx, connectionID)
	if err != nil || fetched.Label != "Fixture fake" {
		t.Fatalf("get connection = %+v, %v", fetched, err)
	}
	if _, err := client.Connections.Get(ctx, "conn-missing"); !errors.Is(err, redundantdns.ErrNotFound) {
		t.Errorf("missing connection err = %v", err)
	}
	tested, err := client.Connections.Test(ctx, connectionID)
	if err != nil || !tested.Result.OK {
		t.Fatalf("test = %+v, %v", tested, err)
	}

	attached, err := client.Attachments.Create(ctx, "zone-1", redundantdns.AttachmentCreate{ConnectionID: connectionID})
	if err != nil {
		t.Fatal(err)
	}
	if len(attached.NSPlan) != 2 || !attached.Attachment.CreatedRemote {
		t.Errorf("attach = %+v", attached)
	}
	attachmentID := attached.Attachment.AttachmentID

	for name, run := range map[string]func() (*redundantdns.Jobs, error){
		"reconcile": func() (*redundantdns.Jobs, error) { return client.Sync.Reconcile(ctx, "zone-1", "") },
		"verify":    func() (*redundantdns.Jobs, error) { return client.Sync.Verify(ctx, "zone-1", attachmentID) },
		"adopt":     func() (*redundantdns.Jobs, error) { return client.Attachments.Adopt(ctx, "zone-1", attachmentID) },
	} {
		jobs, err := run()
		if err != nil || len(jobs.JobIDs) != 1 {
			t.Errorf("%s = %+v, %v", name, jobs, err)
		}
	}

	delegation, err := client.Delegation.Check(ctx, "zone-1")
	if err != nil || delegation.State != "pending" || len(delegation.Missing) != 2 || len(delegation.Answers) != 2 {
		t.Fatalf("delegation = %+v, %v", delegation, err)
	}

	if err := client.Attachments.Delete(ctx, "zone-1", attachmentID, redundantdns.DetachOptions{DeleteRemote: true, ConfirmName: "example.com"}); err != nil {
		t.Fatal(err)
	}
	if query := server.LastRequest().Query; query != "confirmName=example.com&deleteRemote=true" {
		t.Errorf("detach query = %q", query)
	}
	if err := client.Connections.Delete(ctx, connectionID); err != nil {
		t.Fatal(err)
	}

	providers, err := client.Account.Providers(ctx)
	if err != nil || len(providers) < 3 {
		t.Fatalf("providers = %+v, %v", providers, err)
	}
	me, err := client.Account.Me(ctx)
	if err != nil || me.User.Kind != "pat" || len(me.Orgs) != 1 {
		t.Fatalf("me = %+v, %v", me, err)
	}
	audit, err := client.Audit.List(ctx, "zone-1")
	if err != nil || len(audit) == 0 {
		t.Fatalf("audit = %+v, %v", audit, err)
	}
	if query := server.LastRequest().Query; query != "zoneId=zone-1" {
		t.Errorf("audit query = %q", query)
	}
}

func TestReplayAlerts(t *testing.T) {
	server := rdnstest.NewReplayServer(t, map[string]string{
		"GET /v1/alerts/rules":                       "alert_rules",
		"GET /v1/alerts/channels":                    "alert_channels",
		"POST /v1/alerts/channels":                   "alert_channel_create",
		"DELETE /v1/alerts/channels/{channelId}":     "alert_channel_delete",
		"GET /v1/alerts/events":                      "synthetic_alert_firing",
		"POST /v1/alerts/events/{eventId}/resolve":   "synthetic_alert_resolved",
		"POST /v1/alerts/events/evt-missing/resolve": "alert_resolve_missing",
	})
	client := newClient(t, server.URL)
	ctx := context.Background()

	rules, err := client.Alerts.Rules(ctx)
	if err != nil || len(rules) != 5 {
		t.Fatalf("rules = %+v, %v", rules, err)
	}
	created, err := client.Alerts.CreateChannel(ctx, redundantdns.AlertChannelCreate{Kind: redundantdns.ChannelWebhook, Label: "Fixture hook", Target: "https://hooks.example.com/rdns"})
	if err != nil || created.Secret == "" || !created.Channel.HasSecret {
		t.Fatalf("create channel = %+v, %v", created, err)
	}
	channel, err := client.Alerts.Channel(ctx, created.Channel.ChannelID)
	if err != nil || channel.Kind != redundantdns.ChannelWebhook {
		t.Fatalf("channel = %+v, %v", channel, err)
	}
	events, err := client.Alerts.ListEvents(ctx, redundantdns.AlertEventFilter{State: "firing", Rule: "drift", Limit: 10})
	if err != nil || len(events) != 1 || events[0].State != "firing" {
		t.Fatalf("events = %+v, %v", events, err)
	}
	if query := server.LastRequest().Query; query != "limit=10&rule=drift&state=firing" {
		t.Errorf("events query = %q", query)
	}
	resolved, err := client.Alerts.Resolve(ctx, events[0].EventID)
	if err != nil || resolved.State != "resolved" || resolved.ResolvedAt == nil {
		t.Fatalf("resolve = %+v, %v", resolved, err)
	}
	_, err = client.Alerts.Resolve(ctx, "evt-missing")
	var apiError *redundantdns.APIError
	if !errors.As(err, &apiError) || apiError.Code != redundantdns.CodeAlertNotFound || apiError.StatusCode != http.StatusNotFound {
		t.Fatalf("resolve missing err = %v", err)
	}
	if err := client.Alerts.DeleteChannel(ctx, created.Channel.ChannelID); err != nil {
		t.Fatal(err)
	}
}

func TestAPIErrors(t *testing.T) {
	server := rdnstest.NewReplayServer(t, map[string]string{"GET /v1/zones/{zoneId}": "zone_missing"})
	client := newClient(t, server.URL)
	_, err := client.Zones.Get(context.Background(), "zone-missing")
	if !errors.Is(err, redundantdns.ErrNotFound) || !redundantdns.IsNotFound(err) || !redundantdns.HasCode(err, redundantdns.CodeZoneNotFound) {
		t.Fatalf("err = %v", err)
	}
	if errors.Is(err, redundantdns.ErrConflict) {
		t.Error("a 404 must not match ErrConflict")
	}
	if !strings.Contains(err.Error(), "GET /v1/zones/zone-missing: 404 zoneNotFound: zone not found") {
		t.Errorf("message = %q", err.Error())
	}

	// A non-JSON error body keeps an excerpt and gets a status-derived code.
	plain := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Error(writer, "upstream exploded", http.StatusConflict)
	}))
	defer plain.Close()
	_, err = newClient(t, plain.URL).Zones.List(context.Background())
	var apiError *redundantdns.APIError
	if !errors.As(err, &apiError) || apiError.Code != redundantdns.CodeConflict || apiError.Message != "upstream exploded" {
		t.Fatalf("plain error = %#v", err)
	}
}

func TestRetries(t *testing.T) {
	fake := rdnstest.NewFake(t)
	client := newClient(t, fake.URL)
	ctx := context.Background()

	fake.FailNext(http.StatusTooManyRequests, http.StatusServiceUnavailable, http.StatusBadGateway)
	if _, err := client.Zones.List(ctx); err != nil {
		t.Fatalf("GET should succeed after retries: %v", err)
	}
	if got := len(fake.Requests()); got != 4 {
		t.Errorf("GET attempts = %d, want 4", got)
	}

	// A POST is not retried on 5xx: it may have taken effect.
	fake.FailNext(http.StatusServiceUnavailable)
	_, err := client.Zones.Create(ctx, redundantdns.ZoneCreate{Name: "retry.example.com"})
	if !errors.Is(err, redundantdns.ErrServer) {
		t.Fatalf("POST 503 err = %v", err)
	}
	// ...but it is retried on 429.
	fake.FailNext(http.StatusTooManyRequests)
	if _, err := client.Zones.Create(ctx, redundantdns.ZoneCreate{Name: "retry.example.com"}); err != nil {
		t.Fatalf("POST after 429: %v", err)
	}

	// Retries give up after MaxRetries.
	fake.FailNext(500, 500, 500, 500, 500)
	_, err = client.Zones.List(ctx)
	if !errors.Is(err, redundantdns.ErrServer) {
		t.Fatalf("exhausted err = %v", err)
	}
	// MaxRetries 3 means 4 attempts: the fifth injected failure is still
	// queued; drain it.
	_, _ = newClient(t, fake.URL, redundantdns.WithRetryPolicy(redundantdns.NoRetry())).Zones.List(ctx)

	// Opting in retries POST on 5xx.
	fake.FailNext(http.StatusBadGateway)
	optIn := fastRetry
	optIn.RetryNonIdempotent = true
	if _, err := newClient(t, fake.URL, redundantdns.WithRetryPolicy(optIn)).Zones.Create(ctx, redundantdns.ZoneCreate{Name: "optin.example.com"}); err != nil {
		t.Fatalf("POST with RetryNonIdempotent: %v", err)
	}
}

func TestContextCancellation(t *testing.T) {
	blocked := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		select {
		case <-blocked:
		case <-request.Context().Done():
		}
	}))
	defer server.Close()
	defer close(blocked)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := newClient(t, server.URL).Zones.List(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Error("a cancelled context must not be retried")
	}
}

func TestVerifyCodeReturnsSession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/auth/code":
			_, _ = writer.Write([]byte(`{"ok":true}`))
		case "/auth/verify":
			var body map[string]string
			_ = json.NewDecoder(request.Body).Decode(&body)
			if body["code"] != "123456" {
				writer.WriteHeader(http.StatusUnauthorized)
				_, _ = writer.Write([]byte(`{"error":"invalidCode","message":"invalid or expired code"}`))
				return
			}
			http.SetCookie(writer, &http.Cookie{Name: redundantdns.SessionCookie, Value: "jwt-value", Expires: time.Now().Add(time.Hour)})
			status, fixture := rdnstest.MustFixture(t, "auth_verify")
			writer.WriteHeader(status)
			_, _ = writer.Write(fixture)
		case "/v1/tokens":
			if cookie, err := request.Cookie(redundantdns.SessionCookie); err != nil || cookie.Value != "jwt-value" {
				writer.WriteHeader(http.StatusForbidden)
				_, _ = writer.Write([]byte(`{"error":"sessionRequired","message":"manage tokens from the dashboard"}`))
				return
			}
			status, fixture := rdnstest.MustFixture(t, "token_create")
			writer.WriteHeader(status)
			_, _ = writer.Write(fixture)
		}
	}))
	defer server.Close()
	client := newClient(t, server.URL, redundantdns.WithToken(""))
	ctx := context.Background()
	if err := client.Auth.RequestCode(ctx, "user@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Auth.VerifyCode(ctx, "user@example.com", "000000"); !redundantdns.HasCode(err, redundantdns.CodeInvalidCode) {
		t.Fatalf("bad code err = %v", err)
	}
	session, err := client.Auth.VerifyCode(ctx, "user@example.com", "123456")
	if err != nil {
		t.Fatal(err)
	}
	if session.Token != "jwt-value" || len(session.Orgs) != 1 || session.User.Email == "" {
		t.Fatalf("session = %+v", session)
	}
	sessionClient := newClient(t, server.URL, redundantdns.WithToken(""), redundantdns.WithSession(session.Token))
	minted, err := sessionClient.Tokens.Create(ctx, redundantdns.TokenCreate{Name: "cli", Scopes: redundantdns.AllScopes})
	if err != nil || minted.Token == "" || minted.Record.TokenID == "" {
		t.Fatalf("mint = %+v, %v", minted, err)
	}
	if _, err := client.Tokens.Create(ctx, redundantdns.TokenCreate{Name: "cli"}); !errors.Is(err, redundantdns.ErrForbidden) {
		t.Fatalf("mint without session err = %v", err)
	}
}

func TestFakeRoundTripAndWait(t *testing.T) {
	fake := rdnstest.NewFake(t)
	client := newClient(t, fake.URL)
	ctx := context.Background()

	_, err := client.Connections.Create(ctx, redundantdns.ConnectionCreate{Provider: "fake", Label: "one", Credentials: map[string]string{"token": "abcdef"}})
	if !redundantdns.HasCode(err, redundantdns.CodeInvalidAccessLevel) {
		t.Fatalf("a BYO connection without an access level err = %v", err)
	}
	connection, err := client.Connections.Create(ctx, redundantdns.ConnectionCreate{
		Provider: "fake", Label: "one", AccessLevel: redundantdns.AccessLevelZoneAdmin, Credentials: map[string]string{"token": "abcdef"},
	})
	if err != nil {
		t.Fatal(err)
	}
	zone, err := client.Zones.Create(ctx, redundantdns.ZoneCreate{Name: "Example.com."})
	if err != nil || zone.Name != "example.com" {
		t.Fatalf("zone = %+v, %v", zone, err)
	}
	if _, err := client.Zones.Create(ctx, redundantdns.ZoneCreate{Name: "example.com"}); !errors.Is(err, redundantdns.ErrConflict) {
		t.Fatalf("duplicate zone err = %v", err)
	}
	attached, err := client.Attachments.Create(ctx, zone.ZoneID, redundantdns.AttachmentCreate{ConnectionID: connection.Connection.ConnectionID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Records.Upsert(ctx, zone.ZoneID, redundantdns.RecordUpsert{Name: "@", Type: "NS", Values: []string{"ns.example.net"}}); !redundantdns.HasCode(err, redundantdns.CodeApexNsManaged) {
		t.Fatalf("apex NS err = %v", err)
	}
	if _, err := client.Records.Upsert(ctx, zone.ZoneID, redundantdns.RecordUpsert{Name: "mail", Type: "mx", Values: []string{"10 MX.Example.net"}}); err != nil {
		t.Fatal(err)
	}
	renamed, err := client.Records.Upsert(ctx, zone.ZoneID, redundantdns.RecordUpsert{
		Name: "smtp", Type: "MX", Values: []string{"10 mx.example.net."}, Previous: &redundantdns.RecordSetRef{Name: "mail", Type: "MX"},
	})
	if err != nil || renamed.RecordSet.Name != "smtp" || renamed.RecordSet.Values[0] != "10 mx.example.net." || renamed.RecordSet.TTL != 300 {
		t.Fatalf("rename = %+v, %v", renamed, err)
	}
	status, err := client.Zones.WaitInSync(ctx, zone.ZoneID, redundantdns.WaitOptions{Interval: time.Millisecond})
	if err != nil || status.Attachments[attached.Attachment.AttachmentID].State != redundantdns.StateInSync {
		t.Fatalf("wait = %+v, %v", status, err)
	}
	byName, err := client.Zones.Resolve(ctx, "EXAMPLE.com")
	if err != nil || byName.ZoneID != zone.ZoneID || len(byName.RecordSets) != 1 {
		t.Fatalf("resolve by name = %+v, %v", byName, err)
	}
	if _, err := client.Zones.Resolve(ctx, "nope.example.org"); !redundantdns.HasCode(err, redundantdns.CodeZoneNotFound) {
		t.Fatalf("resolve missing err = %v", err)
	}
	if err := client.Connections.Delete(ctx, connection.Connection.ConnectionID); !redundantdns.HasCode(err, redundantdns.CodeConnectionInUse) {
		t.Fatalf("delete in-use connection err = %v", err)
	}
	if err := client.Attachments.Delete(ctx, zone.ZoneID, attached.Attachment.AttachmentID, redundantdns.DetachOptions{DeleteRemote: true, ConfirmName: "wrong.example"}); !redundantdns.HasCode(err, redundantdns.CodeConfirmNameMismatch) {
		t.Fatalf("detach with wrong name err = %v", err)
	}
	if err := client.Attachments.Delete(ctx, zone.ZoneID, attached.Attachment.AttachmentID, redundantdns.DetachOptions{DeleteRemote: true, ConfirmName: zone.Name}); err != nil {
		t.Fatal(err)
	}
	if err := client.Zones.Delete(ctx, zone.ZoneID); err != nil {
		t.Fatal(err)
	}
	if err := client.Connections.Delete(ctx, connection.Connection.ConnectionID); err != nil {
		t.Fatal(err)
	}
	if fake.ZoneCount() != 0 || fake.ConnectionCount() != 0 {
		t.Error("fake not empty after clean-up")
	}

	// A token bound to another org is refused.
	other := client.WithOrg("org-other")
	if _, err := other.Zones.List(ctx); !errors.Is(err, redundantdns.ErrForbidden) {
		t.Fatalf("other org err = %v", err)
	}
	if client.OrgID() != "" || other.OrgID() != "org-other" {
		t.Error("WithOrg must return an independent copy")
	}
}

func TestPaginationHelpers(t *testing.T) {
	fake := rdnstest.NewFake(t)
	client := newClient(t, fake.URL)
	ctx := context.Background()
	for _, name := range []string{"a.example", "b.example", "c.example"} {
		if _, err := client.Zones.Create(ctx, redundantdns.ZoneCreate{Name: name}); err != nil {
			t.Fatal(err)
		}
	}
	var names []string
	for zone, err := range client.Zones.All(ctx) {
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, zone.Name)
		if len(names) == 2 {
			break
		}
	}
	if !slices.Equal(names, []string{"a.example", "b.example"}) {
		t.Errorf("early break names = %v", names)
	}
	all, err := redundantdns.Collect(client.Zones.All(ctx))
	if err != nil || len(all) != 3 {
		t.Fatalf("collect = %d, %v", len(all), err)
	}
	var sizes []int
	for page := range redundantdns.Chunk(all, 2) {
		sizes = append(sizes, len(page))
	}
	if !slices.Equal(sizes, []int{2, 1}) {
		t.Errorf("chunk sizes = %v", sizes)
	}
	unauthorized := newClient(t, fake.URL, redundantdns.WithToken("rdns_wrong"))
	if _, err := redundantdns.Collect(unauthorized.Zones.All(ctx)); !errors.Is(err, redundantdns.ErrUnauthorized) {
		t.Errorf("collect error = %v", err)
	}
}
