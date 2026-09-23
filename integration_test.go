//go:build integration

// Integration tests against a real RedundantDNS deployment.
//
//	RDNS_BASE_URL=http://192.168.16.40:8080 go test -tags integration -v ./...
//
// With RDNS_TOKEN set they use that personal access token (it needs every
// scope and an admin role). Without it they sign in through the API with
// RDNS_E2E_EMAIL (default go-client-integration@example.com, reused so runs
// do not pile up users) and the fixed e2e code (RDNS_E2E_CODE, default
// 123456; the deployment must run with RDNS_E2E=1), accept the legal
// documents when needed, mint a short-lived token and revoke it at the end.
// They need the "fake" provider (e2e mode). Everything created is deleted,
// also when a step fails.
package redundantdns_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	redundantdns "github.com/redundantdns/go-client"
)

func integrationClient(t *testing.T) *redundantdns.Client {
	t.Helper()
	baseURL := os.Getenv("RDNS_BASE_URL")
	if baseURL == "" {
		t.Skip("RDNS_BASE_URL is not set")
	}
	token := os.Getenv("RDNS_TOKEN")
	if token == "" {
		token = bootstrapToken(t, baseURL)
	}
	client, err := redundantdns.New(redundantdns.WithBaseURL(baseURL), redundantdns.WithToken(token), redundantdns.WithUserAgent("go-client-integration"))
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// bootstrapToken signs in with the e2e code, accepts the legal documents
// and mints a one-day token, revoked when the test ends.
func bootstrapToken(t *testing.T, baseURL string) string {
	t.Helper()
	ctx := context.Background()
	anonymous, err := redundantdns.New(redundantdns.WithBaseURL(baseURL))
	if err != nil {
		t.Fatal(err)
	}
	email := os.Getenv("RDNS_E2E_EMAIL")
	if email == "" {
		email = "go-client-integration@example.com"
	}
	code := os.Getenv("RDNS_E2E_CODE")
	if code == "" {
		code = "123456"
	}
	if err := anonymous.Auth.RequestCode(ctx, email); err != nil {
		t.Fatalf("request code: %v", err)
	}
	session, err := anonymous.Auth.VerifyCode(ctx, email, code)
	if err != nil {
		t.Fatalf("verify code (is the deployment in e2e mode?): %v", err)
	}
	if len(session.Orgs) == 0 {
		t.Fatal("the new user has no organization")
	}
	sessionClient, err := redundantdns.New(redundantdns.WithBaseURL(baseURL), redundantdns.WithSession(session.Token), redundantdns.WithOrg(session.Orgs[0].OrgID))
	if err != nil {
		t.Fatal(err)
	}
	legal, err := sessionClient.Account.Legal(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if legal.Required {
		// Before the acceptance every other /v1 route answers 428.
		if _, err := sessionClient.Zones.List(ctx); !errors.Is(err, redundantdns.ErrLegalAcceptanceRequired) {
			t.Fatalf("expected legal_acceptance_required before accepting, got %v", err)
		}
		status, err := sessionClient.Account.AcceptLegal(ctx, legal.Current)
		if err != nil || status.Required {
			t.Fatalf("accept legal = %+v, %v", status, err)
		}
		t.Logf("accepted terms %s / privacy %s", legal.Current.Terms, legal.Current.Privacy)
	}
	minted, err := sessionClient.Tokens.Create(ctx, redundantdns.TokenCreate{Name: "go-client integration", Scopes: redundantdns.AllScopes, ExpiresInDays: 1})
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}
	t.Cleanup(func() {
		if err := sessionClient.Tokens.Revoke(context.Background(), minted.Record.TokenID); err != nil {
			t.Errorf("revoke token: %v", err)
		}
	})
	t.Logf("signed in as %s (org %s), token %s", email, session.Orgs[0].OrgID, minted.Record.TokenID)
	return minted.Token
}

func TestIntegrationRoundTrip(t *testing.T) {
	client := integrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	me, err := client.Account.Me(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if me.User.Kind != "pat" || len(me.Orgs) != 1 {
		t.Fatalf("me = %+v", me)
	}
	orgID := me.Orgs[0].OrgID
	t.Logf("org %s role %s", orgID, me.Orgs[0].Role)

	// A token is bound to its org.
	if _, err := client.WithOrg("org-someoneelse").Zones.List(ctx); !errors.Is(err, redundantdns.ErrForbidden) {
		t.Fatalf("cross-org call err = %v", err)
	}
	if _, err := client.Zones.Get(ctx, "zone-doesnotexist"); !redundantdns.HasCode(err, redundantdns.CodeZoneNotFound) {
		t.Fatalf("missing zone err = %v", err)
	}

	providers, err := client.Account.Providers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hasFake := false
	for _, provider := range providers {
		hasFake = hasFake || provider.ID == "fake"
	}
	if !hasFake {
		t.Skip("the deployment has no fake provider (not in e2e mode)")
	}

	// Connection (fake provider, BYO credentials).
	suffix := time.Now().UnixNano()
	connection, err := client.Connections.Create(ctx, redundantdns.ConnectionCreate{
		Provider: "fake", Label: "go-client integration", AccessLevel: redundantdns.AccessLevelZoneAdmin,
		Credentials: map[string]string{"token": fmt.Sprintf("it%d", suffix%100000)},
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}
	connectionID := connection.Connection.ConnectionID
	t.Cleanup(func() {
		if err := client.Connections.Delete(context.Background(), connectionID); err != nil && !redundantdns.IsNotFound(err) {
			t.Errorf("clean-up connection %s: %v", connectionID, err)
		}
	})
	tested, err := client.Connections.Test(ctx, connectionID)
	if err != nil || !tested.Result.OK {
		t.Fatalf("test connection = %+v, %v", tested, err)
	}

	// Zone.
	zoneName := fmt.Sprintf("go-client-it-%d.example.com", suffix)
	zone, err := client.Zones.Create(ctx, redundantdns.ZoneCreate{Name: zoneName, DefaultTTL: 600})
	if err != nil {
		t.Fatalf("create zone: %v", err)
	}
	t.Cleanup(func() {
		if err := client.Zones.Delete(context.Background(), zone.ZoneID); err != nil && !redundantdns.IsNotFound(err) {
			t.Errorf("clean-up zone %s: %v", zone.ZoneID, err)
		}
	})
	if zone.Settings.DefaultTTL != 600 {
		t.Errorf("default TTL = %d", zone.Settings.DefaultTTL)
	}
	if _, err := client.Zones.Create(ctx, redundantdns.ZoneCreate{Name: zoneName}); err == nil {
		t.Error("creating the same zone twice must fail")
	}

	// Attachment.
	attached, err := client.Attachments.Create(ctx, zone.ZoneID, redundantdns.AttachmentCreate{ConnectionID: connectionID})
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	attachmentID := attached.Attachment.AttachmentID
	t.Cleanup(func() {
		err := client.Attachments.Delete(context.Background(), zone.ZoneID, attachmentID, redundantdns.DetachOptions{DeleteRemote: true, ConfirmName: zoneName})
		if err != nil && !redundantdns.IsNotFound(err) {
			t.Errorf("clean-up attachment %s: %v", attachmentID, err)
		}
	})
	if len(attached.NSPlan) != 2 {
		t.Errorf("NS plan = %v", attached.NSPlan)
	}
	if err := client.Connections.Delete(ctx, connectionID); !redundantdns.HasCode(err, redundantdns.CodeConnectionInUse) {
		t.Errorf("deleting an attached connection err = %v", err)
	}

	// Records: create, rename, normalization, apex NS guard.
	upserted, err := client.Records.Upsert(ctx, zone.ZoneID, redundantdns.RecordUpsert{Name: "www", Type: "A", Values: []string{"192.0.2.10", "192.0.2.011"}})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if upserted.RecordSet.TTL != 600 || !redundantdns.EqualRecordValues("A", upserted.RecordSet.Values, []string{"192.0.2.11", "192.0.2.10"}) {
		t.Errorf("upserted = %+v", upserted.RecordSet)
	}
	if _, err := client.Records.Upsert(ctx, zone.ZoneID, redundantdns.RecordUpsert{Name: "mail", Type: "MX", TTL: 300, Values: []string{"10 MX1.Example.net"}}); err != nil {
		t.Fatalf("upsert MX: %v", err)
	}
	renamed, err := client.Records.Upsert(ctx, zone.ZoneID, redundantdns.RecordUpsert{
		Name: "smtp", Type: "MX", TTL: 300, Values: []string{"10 mx1.example.net."},
		Previous: &redundantdns.RecordSetRef{Name: "mail", Type: "MX"},
	})
	if err != nil {
		t.Fatalf("rename: %v", err)
	}
	if renamed.RecordSet.Name != "smtp" || renamed.RecordSet.Values[0] != "10 mx1.example.net." {
		t.Errorf("renamed = %+v", renamed.RecordSet)
	}
	if _, err := client.Records.Upsert(ctx, zone.ZoneID, redundantdns.RecordUpsert{Name: "@", Type: "NS", Values: []string{"ns.example.net."}}); !redundantdns.HasCode(err, redundantdns.CodeApexNsManaged) {
		t.Errorf("apex NS err = %v", err)
	}
	txt, err := client.Records.Upsert(ctx, zone.ZoneID, redundantdns.RecordUpsert{Name: "@", Type: "TXT", Values: []string{"v=spf1 -all"}})
	if err != nil {
		t.Fatalf("upsert TXT: %v", err)
	}
	if !redundantdns.EqualRecordValues("TXT", txt.RecordSet.Values, []string{"v=spf1 -all"}) {
		t.Errorf("TXT normalization differs from the client's: %v", txt.RecordSet.Values)
	}

	// Sync jobs and status.
	if _, err := client.Sync.Reconcile(ctx, zone.ZoneID, ""); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if _, err := client.Sync.Verify(ctx, zone.ZoneID, attachmentID); err != nil {
		t.Fatalf("verify: %v", err)
	}
	waitCtx, waitCancel := context.WithTimeout(ctx, 60*time.Second)
	status, err := client.Zones.WaitInSync(waitCtx, zone.ZoneID, redundantdns.WaitOptions{Interval: 500 * time.Millisecond, MinSerial: txt.Serial})
	waitCancel()
	if err != nil {
		t.Fatalf("wait in sync: %v", err)
	}
	t.Logf("attachment %s in sync at serial %d", attachmentID, status.Attachments[attachmentID].AppliedSerial)

	full, err := client.Zones.Resolve(ctx, strings.ToUpper(zoneName)+".")
	if err != nil {
		t.Fatalf("resolve by name: %v", err)
	}
	if len(full.RecordSets) != 3 || full.Capabilities == nil || len(full.Attachments) != 1 {
		t.Errorf("zone = %+v", full)
	}
	found, err := client.Records.Get(ctx, zone.ZoneID, zoneName, "smtp."+zoneName+".", "mx")
	if err != nil || found.TTL != 300 {
		t.Errorf("get record = %+v, %v", found, err)
	}
	export, err := client.Zones.Export(ctx, zone.ZoneID)
	if err != nil || !strings.Contains(export, "$ORIGIN "+zoneName+".") || !strings.Contains(export, "smtp") {
		t.Errorf("export = %q, %v", export, err)
	}
	journal, err := client.Zones.Journal(ctx, zone.ZoneID)
	if err != nil || len(journal) == 0 {
		t.Errorf("journal = %d entries, %v", len(journal), err)
	}

	// Delegation: the example.com children are not delegated.
	delegation, err := client.Delegation.Check(ctx, zone.ZoneID)
	if err != nil {
		t.Fatalf("delegation: %v", err)
	}
	if len(delegation.NSPlan) != 2 {
		t.Errorf("delegation = %+v", delegation)
	}
	t.Logf("delegation state %s (missing %d)", delegation.State, len(delegation.Missing))

	serial, err := client.Records.Delete(ctx, zone.ZoneID, "www", "A")
	if err != nil || serial <= txt.Serial {
		t.Errorf("delete record = %d, %v", serial, err)
	}
	if _, err := client.Records.Delete(ctx, zone.ZoneID, "www", "A"); !redundantdns.HasCode(err, redundantdns.CodeRecordSetNotFound) {
		t.Errorf("delete missing record err = %v", err)
	}

	// Adopt runs last: the import job is asynchronous and would race with
	// the record changes above.
	adopted, err := client.Sync.Adopt(ctx, zone.ZoneID, attachmentID)
	if err != nil || len(adopted.JobIDs) == 0 {
		t.Fatalf("adopt = %+v, %v", adopted, err)
	}

	// Alerts: rules, a channel, events, audit.
	rules, err := client.Alerts.Rules(ctx)
	if err != nil || len(rules) < 5 {
		t.Fatalf("rules = %+v, %v", rules, err)
	}
	channel, err := client.Alerts.CreateChannel(ctx, redundantdns.AlertChannelCreate{Kind: redundantdns.ChannelEmail, Label: "go-client integration", Target: "alerts@example.com"})
	if err != nil {
		t.Fatalf("create channel: %v", err)
	}
	t.Cleanup(func() {
		if err := client.Alerts.DeleteChannel(context.Background(), channel.Channel.ChannelID); err != nil && !redundantdns.IsNotFound(err) {
			t.Errorf("clean-up channel: %v", err)
		}
	})
	if _, err := client.Alerts.Channel(ctx, channel.Channel.ChannelID); err != nil {
		t.Errorf("get channel: %v", err)
	}
	result, err := client.Alerts.TestChannel(ctx, channel.Channel.ChannelID)
	if err != nil {
		t.Errorf("test channel: %v", err)
	} else {
		t.Logf("test notification: ok=%v attempts=%d error=%q", result.OK, result.Attempts, result.Error)
	}
	events, err := client.Alerts.ListEvents(ctx, redundantdns.AlertEventFilter{ZoneID: zone.ZoneID, Limit: 20})
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	t.Logf("%d alert events for the zone", len(events))
	if _, err := client.Alerts.Resolve(ctx, "evt-doesnotexist"); !redundantdns.HasCode(err, redundantdns.CodeAlertNotFound) {
		t.Errorf("resolve missing alert err = %v", err)
	}
	audit, err := client.Audit.List(ctx, zone.ZoneID)
	if err != nil || len(audit) == 0 {
		t.Errorf("audit = %d entries, %v", len(audit), err)
	}
}
