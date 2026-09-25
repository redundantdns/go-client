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
// They need the "fake" provider (e2e mode). The bootstrap also puts the
// org on the Starter plan through the e2e hook POST /e2e/billing/plan;
// managed-mode tests need a paid plan and skip on a Free org when the hook
// is not available. Everything created is deleted, also when a step fails.
package redundantdns_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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
	orgID := session.Orgs[0].OrgID
	// Managed mode needs a paid plan; on a non-e2e deployment the org keeps
	// its plan and the managed tests skip on Free.
	applied, err := setE2EPlan(ctx, baseURL, orgID, "starter")
	if err != nil {
		t.Fatal(err)
	}
	if !applied {
		t.Logf("POST /e2e/billing/plan is not available on %s; org %s keeps its plan", baseURL, orgID)
	}
	sessionClient, err := redundantdns.New(redundantdns.WithBaseURL(baseURL), redundantdns.WithSession(session.Token), redundantdns.WithOrg(orgID))
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

// setE2EPlan sets an organization's plan with the e2e hook, like the
// Terraform provider's acceptance tests. It reports false (no error) when
// the hook is not mounted: a non-e2e deployment answers 404 or the SPA's
// HTML instead of JSON.
func setE2EPlan(ctx context.Context, baseURL, orgID, plan string) (bool, error) {
	body, err := json.Marshal(map[string]string{"orgId": orgID, "plan": plan, "status": "active"})
	if err != nil {
		return false, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+"/e2e/billing/plan", bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	request.Header.Set("Content-Type", "application/json")
	answer, err := http.DefaultClient.Do(request)
	if err != nil {
		return false, fmt.Errorf("set the %s plan: %w", plan, err)
	}
	defer func() { _ = answer.Body.Close() }()
	if answer.StatusCode == http.StatusNotFound || answer.StatusCode == http.StatusMethodNotAllowed ||
		!strings.HasPrefix(answer.Header.Get("Content-Type"), "application/json") {
		return false, nil
	}
	if answer.StatusCode != http.StatusOK {
		excerpt, _ := io.ReadAll(io.LimitReader(answer.Body, 512))
		return false, fmt.Errorf("set the %s plan: %d %s", plan, answer.StatusCode, excerpt)
	}
	return true, nil
}

// requirePaidPlan skips the test when the token's org is on the Free plan
// and the e2e plan hook cannot move it to Starter (non-e2e deployment).
// It also covers RDNS_TOKEN runs, where the bootstrap did not run.
func requirePaidPlan(ctx context.Context, t *testing.T, client *redundantdns.Client, baseURL string) {
	t.Helper()
	me, err := client.Account.Me(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(me.Orgs) == 0 {
		t.Fatal("the token has no organization")
	}
	org := me.Orgs[0]
	if org.Plan != "free" {
		return
	}
	applied, err := setE2EPlan(ctx, baseURL, org.OrgID, "starter")
	if err != nil {
		t.Fatal(err)
	}
	if !applied {
		t.Skipf("org %s is on the Free plan and POST /e2e/billing/plan is not available on %s: managed mode needs a paid plan (run against an e2e deployment, RDNS_E2E=1, or set the org's plan with the admin override)", org.OrgID, baseURL)
	}
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

// TestIntegrationManagedTermsAndParentDelegation covers G4b (managed terms,
// subdomain redundancy). It skips on deployments that do not serve the
// managed terms version yet.
func TestIntegrationManagedTermsAndParentDelegation(t *testing.T) {
	baseURL := os.Getenv("RDNS_BASE_URL")
	if baseURL == "" {
		t.Skip("RDNS_BASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	anonymous, err := redundantdns.New(redundantdns.WithBaseURL(baseURL))
	if err != nil {
		t.Fatal(err)
	}
	versions, err := anonymous.Account.LegalVersions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if versions.ManagedTerms == "" {
		t.Skip("the deployment does not serve managedTerms yet (G4b platform not deployed)")
	}
	client := integrationClient(t)
	requirePaidPlan(ctx, t, client, baseURL)

	status, err := client.Legal.ManagedStatus(ctx)
	if err != nil || status.Current != versions.ManagedTerms {
		t.Fatalf("managed status = %+v, %v", status, err)
	}
	if status.Required {
		_, err := client.Connections.Create(ctx, redundantdns.ConnectionCreate{Provider: "fake", Mode: redundantdns.ModeManaged, Label: "go-client it managed"})
		if requirement, ok := redundantdns.ManagedTermsRequired(err); !ok || requirement.Version != versions.ManagedTerms {
			t.Fatalf("managed connection before acceptance err = %v", err)
		}
	}
	accepted, err := client.Legal.AcceptManaged(ctx, versions.ManagedTerms)
	if err != nil || accepted.Required || accepted.Accepted == nil {
		t.Fatalf("accept managed terms = %+v, %v", accepted, err)
	}

	// Subdomain redundancy with the fake provider.
	suffix := time.Now().UnixNano()
	connection, err := client.Connections.Create(ctx, redundantdns.ConnectionCreate{
		Provider: "fake", Label: "go-client it delegation", AccessLevel: redundantdns.AccessLevelZoneAdmin,
		Credentials: map[string]string{"token": fmt.Sprintf("pd%d", suffix%100000)},
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}
	t.Cleanup(func() { _ = client.Connections.Delete(context.Background(), connection.Connection.ConnectionID) })
	parentName := fmt.Sprintf("go-client-pd-%d.example.com", suffix)
	parent, err := client.Zones.Create(ctx, redundantdns.ZoneCreate{Name: parentName})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Zones.Delete(context.Background(), parent.ZoneID) })
	child, err := client.Zones.Create(ctx, redundantdns.ZoneCreate{Name: "api." + parentName, ParentDelegation: redundantdns.Bool(true)})
	if err != nil {
		t.Fatal(err)
	}
	childDeleted := false
	t.Cleanup(func() {
		if !childDeleted {
			_ = client.Zones.Delete(context.Background(), child.ZoneID)
		}
	})
	if child.ParentDelegation == nil || !child.ParentDelegation.Enabled {
		t.Errorf("child parentDelegation = %+v", child.ParentDelegation)
	}
	attached, err := client.Attachments.Create(ctx, child.ZoneID, redundantdns.AttachmentCreate{ConnectionID: connection.Connection.ConnectionID})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = client.Attachments.Delete(context.Background(), child.ZoneID, attached.Attachment.AttachmentID,
			redundantdns.DetachOptions{DeleteRemote: true, ConfirmName: "api." + parentName})
	})
	records, err := client.Records.List(ctx, parent.ZoneID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, set := range records {
		if set.Name == "api" && set.Type == "NS" {
			found = set.ManagedBy == redundantdns.ManagedByDelegation && len(set.Values) == len(attached.NSPlan)
		}
	}
	if !found {
		t.Errorf("no managed api NS set in the parent: %+v", records)
	}
	if err := client.Attachments.Delete(ctx, child.ZoneID, attached.Attachment.AttachmentID,
		redundantdns.DetachOptions{DeleteRemote: true, ConfirmName: "api." + parentName}); err != nil {
		t.Fatal(err)
	}
	if err := client.Zones.Delete(ctx, child.ZoneID); err != nil {
		t.Fatal(err)
	}
	childDeleted = true
	records, _ = client.Records.List(ctx, parent.ZoneID)
	for _, set := range records {
		if set.Name == "api" && set.Type == "NS" {
			t.Errorf("the delegation must be removed with the child: %+v", set)
		}
	}
}

// TestIntegrationDomainRegistration covers the registration of a new
// domain against a deployment with the fake registrar (RDNS_REGISTRAR=fake)
// and the fake payment gateway (RDNS_BILLING=fake): check, the refusals,
// register (a checkout opens) and cancel, which releases the name. With
// RDNS_IT_PAY_DOMAIN=1 it also pays a registration through the fake
// checkout and waits for it to become active; that domain stays in the
// organization (a paid registration is never removed), so it is opt-in. It
// skips on deployments that do not serve domain registration or have no
// registrar or payment gateway.
func TestIntegrationDomainRegistration(t *testing.T) {
	baseURL := os.Getenv("RDNS_BASE_URL")
	if baseURL == "" {
		t.Skip("RDNS_BASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	anonymous, err := redundantdns.New(redundantdns.WithBaseURL(baseURL))
	if err != nil {
		t.Fatal(err)
	}
	versions, err := anonymous.Account.LegalVersions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if versions.DomainTerms == "" {
		t.Skip("the deployment does not serve domainTerms (domains module not deployed)")
	}
	client := integrationClient(t)
	requirePaidPlan(ctx, t, client, baseURL)

	suffix := time.Now().UnixNano()
	name := fmt.Sprintf("go-client-it-%d.tools", suffix)
	quotes, err := client.Domains.Check(ctx, []string{name, "taken-go-client.tools", "premium-go-client.tools"}, 1)
	switch {
	case redundantdns.IsNotFound(err):
		t.Skip("the deployment does not serve GET /v1/domains/check (registration not deployed)")
	case redundantdns.HasCode(err, redundantdns.CodeRegistrarUnavailable):
		t.Skip("the deployment has no registrar (RDNS_REGISTRAR=none)")
	case err != nil:
		t.Fatalf("check: %v", err)
	}
	if len(quotes) != 3 || !quotes[0].Available || quotes[0].PriceCents <= 0 || quotes[1].Available || !quotes[2].Premium {
		t.Fatalf("quotes = %+v (is the registrar the fake one?)", quotes)
	}

	if _, err := client.Legal.AcceptDomain(ctx, versions.DomainTerms); err != nil {
		t.Fatalf("accept domain terms: %v", err)
	}
	if profile, err := client.Domains.RegistrantProfile(ctx); err != nil {
		t.Fatal(err)
	} else if profile == nil {
		if _, err := client.Domains.SetRegistrantProfile(ctx, redundantdns.ContactFields{
			FirstName: "Ada", LastName: "Lovelace", Email: "go-client-integration@example.com", Phone: "+44.2071234567",
			Street: "Main Street", City: "London", PostalCode: "SW1A 1AA", Country: "GB",
		}); err != nil {
			t.Fatalf("registrant profile: %v", err)
		}
	}

	checkout, err := client.Domains.Register(ctx, redundantdns.DomainRegisterCreate{Name: name})
	if redundantdns.HasCode(err, redundantdns.CodeBillingUnavailable) {
		t.Skip("the deployment has no payment gateway (RDNS_BILLING=off)")
	}
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	cancelled := false
	t.Cleanup(func() {
		if !cancelled {
			_ = client.Domains.CancelRegistration(context.Background(), name)
		}
	})
	if !checkout.NeedsPayment() || !checkout.Domain.PaymentPending() || checkout.Domain.Registration == nil ||
		checkout.Domain.Registration.PriceCents != quotes[0].PriceCents {
		t.Fatalf("checkout = %+v", checkout)
	}
	if _, err := client.Domains.Register(ctx, redundantdns.DomainRegisterCreate{Name: "taken-go-client.tools"}); !redundantdns.HasCode(err, redundantdns.CodeDomainUnavailable) {
		t.Errorf("taken name err = %v", err)
	}
	if _, err := client.Domains.Register(ctx, redundantdns.DomainRegisterCreate{Name: "premium-go-client.tools"}); !redundantdns.HasCode(err, redundantdns.CodeDomainPremium) {
		t.Errorf("premium name err = %v", err)
	}
	if err := client.Domains.CancelRegistration(ctx, name); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	cancelled = true
	if _, err := client.Domains.Get(ctx, name); !redundantdns.IsNotFound(err) {
		t.Errorf("cancelled registration err = %v", err)
	}
	if again, err := client.Domains.Check(ctx, []string{name}, 1); err != nil || !again[0].Available {
		t.Errorf("released name = %+v, %v", again, err)
	}

	if os.Getenv("RDNS_IT_PAY_DOMAIN") != "1" {
		t.Log("RDNS_IT_PAY_DOMAIN is not 1: the paid registration is skipped (it would leave a domain in the organization)")
		return
	}
	paidName := fmt.Sprintf("go-client-it-paid-%d.tools", suffix)
	paid, err := client.Domains.Register(ctx, redundantdns.DomainRegisterCreate{Name: paidName})
	if err != nil {
		t.Fatalf("register to pay: %v", err)
	}
	// The fake checkout pays at once and redirects to the dashboard.
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, paid.CheckoutURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := noRedirect.Do(request)
	if err != nil {
		t.Fatalf("pay the fake checkout: %v", err)
	}
	_ = answer.Body.Close()
	if answer.StatusCode >= 400 {
		t.Fatalf("pay the fake checkout: %d", answer.StatusCode)
	}
	for {
		domain, err := client.Domains.Get(ctx, paidName)
		if err != nil {
			t.Fatal(err)
		}
		if domain.Status == redundantdns.DomainStatusActive {
			if !domain.Registration.Paid() || domain.Registration.PaidBy != redundantdns.PaidByStripe {
				t.Errorf("registration = %+v", domain.Registration)
			}
			return
		}
		if domain.Status == redundantdns.DomainStatusRegistrationFailed {
			t.Fatalf("the registration failed: %s", domain.LastError)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("the registration is still %s", domain.Status)
		case <-time.After(2 * time.Second):
		}
	}
}

// TestIntegrationComplianceAndAuditStream reads the organization's
// compliance posture, the plan catalog and verifies its audit stream (the
// bootstrap user owns its organization). A deployment without a compliance
// checker or an audit stream answers 503: that part is skipped.
func TestIntegrationComplianceAndAuditStream(t *testing.T) {
	client := integrationClient(t)
	ctx := context.Background()

	catalog, err := client.Plans.Catalog(ctx)
	if err != nil {
		t.Fatalf("plans: %v", err)
	}
	if catalog.Trial.Days <= 0 || !catalog.IntervalOnSale(redundantdns.IntervalMonthly) || catalog.Plan("trial") != nil {
		t.Errorf("catalog trial = %+v, intervals = %v", catalog.Trial, catalog.Intervals)
	}

	report, err := client.Compliance.Report(ctx, redundantdns.ComplianceBaseline, "")
	switch {
	case redundantdns.HasCode(err, redundantdns.CodeComplianceUnavailable):
		t.Log("compliance is not available on this deployment")
	case err != nil:
		t.Fatalf("compliance report: %v", err)
	default:
		if report.Profile != redundantdns.ComplianceBaseline || report.Scope != redundantdns.ComplianceScopeOrg || len(report.Controls) == 0 || report.CheckedAt.IsZero() {
			t.Errorf("compliance report = %+v", report)
		}
		counted := report.Summary.Pass + report.Summary.Warn + report.Summary.Fail + report.Summary.NotApplicable
		if counted != len(report.Controls) {
			t.Errorf("summary %+v does not count %d controls", report.Summary, len(report.Controls))
		}
		t.Logf("compliance %s: %s (%+v)", report.Profile, report.Status, report.Summary)
		if _, err := client.Compliance.Report(ctx, "no-such-profile", ""); !redundantdns.HasCode(err, redundantdns.CodeUnknownProfile) {
			t.Errorf("unknown profile err = %v", err)
		}
	}

	verify, err := client.Audit.Verify(ctx, "", "")
	if redundantdns.HasCode(err, redundantdns.CodeAuditStreamUnavailable) {
		t.Skip("no audit stream on this deployment")
	}
	if err != nil {
		t.Fatalf("audit verify: %v", err)
	}
	if verify.Org == "" || verify.From == "" || verify.To == "" {
		t.Errorf("audit verify = %+v", verify)
	}
	if !verify.OK {
		t.Errorf("audit stream verification failed: %+v", verify.Problems)
	}
	t.Logf("audit stream: %d segments, %d lines, %d sealed", verify.Segments, verify.Lines, verify.Sealed)
}
