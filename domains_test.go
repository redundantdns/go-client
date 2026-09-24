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

// validContact is a contact the fake accepts.
func validContact(label string) redundantdns.ContactFields {
	return redundantdns.ContactFields{
		Label: label, CompanyName: "Example Ltd", FirstName: "Ada", LastName: "Lovelace", Email: "ada@example.com",
		Phone: "+44.2071234567", Street: "Main Street", HouseNumber: "1", City: "London", PostalCode: "SW1A 1AA", Country: "gb",
	}
}

func TestFakeDomainTransferLifecycle(t *testing.T) {
	fake := rdnstest.NewFake(t)
	client := newClient(t, fake.URL)
	ctx := context.Background()

	versions, err := client.Account.LegalVersions(ctx)
	if err != nil || versions.DomainTerms != rdnstest.DomainTermsVersion {
		t.Fatalf("versions = %+v, %v", versions, err)
	}
	transfer := redundantdns.DomainTransferCreate{Name: "Example.COM.", AuthCode: "secret-code", ApplyZoneNS: true}

	// The terms come first, then the registrant profile.
	_, err = client.Domains.TransferIn(ctx, transfer)
	if !errors.Is(err, redundantdns.ErrDomainTermsRequired) || errors.Is(err, redundantdns.ErrLegalAcceptanceRequired) || errors.Is(err, redundantdns.ErrManagedTermsRequired) {
		t.Fatalf("transfer without terms err = %v", err)
	}
	requirement, ok := redundantdns.DomainTermsRequired(err)
	if !ok || requirement.Version != rdnstest.DomainTermsVersion || !strings.HasSuffix(requirement.URL, "/legal/domain-terms") {
		t.Fatalf("requirement = %+v, %v", requirement, ok)
	}
	if _, ok := redundantdns.ManagedTermsRequired(err); ok {
		t.Error("domain terms are not managed terms")
	}
	transfer.AcceptDomainTerms = "2020-01-01"
	if _, err := client.Domains.TransferIn(ctx, transfer); !redundantdns.HasCode(err, redundantdns.CodeLegalVersionMismatch) {
		t.Fatalf("old terms err = %v", err)
	}
	transfer.AcceptDomainTerms = rdnstest.DomainTermsVersion
	if _, err := client.Domains.TransferIn(ctx, transfer); !redundantdns.HasCode(err, redundantdns.CodeRegistrantProfileRequired) {
		t.Fatalf("no profile err = %v", err)
	}
	status, err := client.Legal.DomainStatus(ctx)
	if err != nil || status.Required || status.Accepted == nil || status.Accepted.Version != rdnstest.DomainTermsVersion {
		t.Fatalf("terms status = %+v, %v", status, err)
	}

	if profile, err := client.Domains.RegistrantProfile(ctx); err != nil || profile != nil {
		t.Fatalf("empty profile = %+v, %v", profile, err)
	}
	if _, err := client.Domains.SetRegistrantProfile(ctx, redundantdns.ContactFields{FirstName: "Ada"}); !redundantdns.HasCode(err, redundantdns.CodeInvalidContact) {
		t.Fatalf("invalid profile err = %v", err)
	}
	profile, err := client.Domains.SetRegistrantProfile(ctx, validContact("Headquarters"))
	if err != nil || !profile.Default || profile.Country != "GB" || profile.Handles["openprovider"] == "" {
		t.Fatalf("profile = %+v, %v", profile, err)
	}

	// A zone with the same name gives the NS plan applied on completion.
	zone := zoneWithAttachment(t, client, "example.com")

	created, err := client.Domains.TransferIn(ctx, transfer)
	if err != nil {
		t.Fatal(err)
	}
	if created.Domain.Name != "example.com" || created.Domain.Status != redundantdns.DomainStatusTransferPending ||
		created.Domain.Transfer == nil || !created.Domain.Transfer.ApplyZoneNS || created.Domain.OwnerContactID != profile.ContactID ||
		created.Job.Op != redundantdns.DomainOpTransfer || created.Queued() {
		t.Fatalf("created = %+v", created)
	}
	if created.Domain.Zone == nil || created.Domain.Zone.ZoneID != zone.ZoneID || created.Domain.Zone.NameserversMatch {
		t.Errorf("zone link = %+v", created.Domain.Zone)
	}
	if _, err := client.Domains.SetNameservers(ctx, "example.com", []string{"a.example.net", "b.example.net"}); !redundantdns.HasCode(err, redundantdns.CodeDomainTransferInProgress) {
		t.Errorf("change while pending err = %v", err)
	}

	// Two reads complete it; WaitTransfer sees the completion.
	pending, err := client.Domains.TransferStatus(ctx, "example.com")
	if err != nil || !pending.Pending() || pending.Failed() {
		t.Fatalf("first read = %+v, %v", pending, err)
	}
	done, err := client.Domains.WaitTransfer(ctx, "example.com", redundantdns.WaitTransferOptions{Interval: time.Millisecond, Sync: true})
	if err != nil || done.Pending() || done.Transfer.State != redundantdns.TransferStateCompleted || done.Status != redundantdns.DomainStatusActive {
		t.Fatalf("wait = %+v, %v", done, err)
	}
	domain, err := client.Domains.Get(ctx, "example.com")
	if err != nil || domain.Zone == nil || !domain.Zone.NameserversMatch || domain.ExpiresAt == nil || !domain.Locked {
		t.Fatalf("domain after transfer = %+v, %v", domain, err)
	}

	// The Free plan holds one domain.
	second := redundantdns.DomainTransferCreate{Name: "example.org", AuthCode: "x"}
	_, err = client.Domains.TransferIn(ctx, second)
	var apiError *redundantdns.APIError
	if !errors.Is(err, redundantdns.ErrPaymentRequired) || !errors.As(err, &apiError) || !strings.Contains(string(apiError.Details), `"domain.transfer"`) {
		t.Fatalf("second domain on free err = %v", err)
	}
	fake.SetPlan("starter")
	if me, err := client.Account.Me(ctx); err != nil || me.Orgs[0].Plan != "starter" {
		t.Fatalf("me = %+v, %v", me, err)
	}

	// A rejected auth code leaves a failed domain that can be removed.
	_, err = client.Domains.TransferIn(ctx, redundantdns.DomainTransferCreate{Name: "example.org", AuthCode: "invalid-code"})
	if !redundantdns.HasCode(err, redundantdns.CodeRegistrarRejected) || !errors.Is(err, redundantdns.ErrUnprocessable) {
		t.Fatalf("rejected err = %v", err)
	}
	failed, err := client.Domains.Get(ctx, "example.org")
	if err != nil || failed.Status != redundantdns.DomainStatusTransferFailed || len(failed.PendingJobs) != 1 || failed.PendingJobs[0].Status != redundantdns.JobStatusFailed {
		t.Fatalf("failed domain = %+v, %v", failed, err)
	}
	if err := client.Domains.Delete(ctx, "example.com"); !redundantdns.HasCode(err, redundantdns.CodeDomainNotRemovable) {
		t.Errorf("delete active err = %v", err)
	}
	if err := client.Domains.Delete(ctx, "example.org"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Domains.Get(ctx, "example.org"); !redundantdns.HasCode(err, redundantdns.CodeDomainNotFound) || !redundantdns.IsNotFound(err) {
		t.Errorf("deleted domain err = %v", err)
	}

	// An auth code starting with "fail" is accepted and the transfer fails.
	fake.SetTransferReads(1)
	if _, err := client.Domains.TransferIn(ctx, redundantdns.DomainTransferCreate{Name: "example.net", AuthCode: "fail-later", AutoRenew: redundantdns.Bool(false)}); err != nil {
		t.Fatal(err)
	}
	status2, err := client.Domains.WaitTransfer(ctx, "example.net", redundantdns.WaitTransferOptions{Interval: time.Millisecond})
	if !errors.Is(err, redundantdns.ErrTransferFailed) || status2 == nil || !status2.Failed() {
		t.Fatalf("failing transfer = %+v, %v", status2, err)
	}
}

func TestFakeDomainChanges(t *testing.T) {
	fake := rdnstest.NewFake(t)
	client := newClient(t, fake.URL)
	ctx := context.Background()
	seeded := fake.SeedDomain(redundantdns.Domain{Name: "example.com"})
	if seeded.Status != redundantdns.DomainStatusActive || !seeded.Locked || len(seeded.Nameservers) != 2 {
		t.Fatalf("seeded = %+v", seeded)
	}

	// The exit routes work without the terms.
	code, err := client.Domains.AuthCode(ctx, "example.com")
	if err != nil || code.AuthCode == "" || code.Name != "example.com" {
		t.Fatalf("auth code = %+v, %v", code, err)
	}
	unlocked, err := client.Domains.SetLock(ctx, "example.com", false)
	if err != nil || unlocked.Domain.Locked || unlocked.Job.Op != redundantdns.DomainOpLock {
		t.Fatalf("unlock = %+v, %v", unlocked, err)
	}
	synced, err := client.Domains.Sync(ctx, "example.com")
	if err != nil || synced.Domain.LastSyncAt == nil {
		t.Fatalf("sync = %+v, %v", synced, err)
	}
	export, err := client.Domains.Export(ctx)
	if err != nil || len(export.Domains) != 1 || export.ExportedAt.IsZero() || !strings.Contains(string(export.Org), rdnstest.DefaultOrgID) {
		t.Fatalf("export = %+v, %v", export, err)
	}
	if _, err := client.Domains.SetLock(ctx, "example.com", true); !errors.Is(err, redundantdns.ErrDomainTermsRequired) {
		t.Fatalf("lock without terms err = %v", err)
	}
	if _, err := client.Legal.AcceptDomain(ctx, " "+rdnstest.DomainTermsVersion+" "); err != nil {
		t.Fatal(err)
	}

	if _, err := client.Domains.SetNameservers(ctx, "example.com", []string{"only.example.net"}); !redundantdns.HasCode(err, redundantdns.CodeInvalidNameservers) {
		t.Errorf("one nameserver err = %v", err)
	}
	result, err := client.Domains.SetNameservers(ctx, "example.com", []string{"NS1.Example.NET.", "ns2.example.net"})
	if err != nil || !slices.Equal(result.Domain.Nameservers, []string{"ns1.example.net", "ns2.example.net"}) {
		t.Fatalf("nameservers = %+v, %v", result, err)
	}
	if _, err := client.Domains.ApplyZoneNS(ctx, "example.com", ""); !redundantdns.HasCode(err, redundantdns.CodeZoneNotFound) {
		t.Errorf("apply without zone err = %v", err)
	}
	empty, err := client.Zones.Create(ctx, redundantdns.ZoneCreate{Name: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Domains.ApplyZoneNS(ctx, "example.com", empty.ZoneID); !redundantdns.HasCode(err, redundantdns.CodeZoneNSPlanEmpty) {
		t.Errorf("apply empty plan err = %v", err)
	}
	other := zoneWithAttachment(t, client, "other.example")
	applied, err := client.Domains.ApplyZoneNS(ctx, "example.com", other.ZoneID)
	if err != nil || len(applied.Domain.Nameservers) != 2 || strings.HasSuffix(applied.Domain.Nameservers[0], ".") {
		t.Fatalf("apply other zone = %+v, %v", applied, err)
	}
	var sent map[string]string
	_ = json.Unmarshal(lastRequest(t, fake, "POST /v1/domains/{name}/nameservers/apply-zone").Body, &sent)
	if sent["zoneId"] != other.ZoneID {
		t.Errorf("apply body = %v", sent)
	}

	locked, err := client.Domains.SetLock(ctx, "example.com", true)
	if err != nil || !locked.Domain.Locked {
		t.Fatalf("lock = %+v, %v", locked, err)
	}
	renewed, err := client.Domains.SetAutoRenew(ctx, "example.com", false)
	if err != nil || renewed.Domain.AutoRenew {
		t.Fatalf("autorenew = %+v, %v", renewed, err)
	}
	before := *seeded.ExpiresAt
	extended, err := client.Domains.Renew(ctx, "example.com", 2)
	if err != nil || !extended.Domain.ExpiresAt.Equal(before.AddDate(2, 0, 0)) {
		t.Fatalf("renew = %+v, %v", extended, err)
	}
	if _, err := client.Domains.Renew(ctx, "example.com", 11); !errors.Is(err, redundantdns.ErrBadRequest) {
		t.Errorf("renew 11 years err = %v", err)
	}

	// Contacts and the registrant change.
	contact, err := client.Domains.CreateContact(ctx, validContact("Legal"))
	if err != nil || contact.ContactID == "" || contact.Default {
		t.Fatalf("contact = %+v, %v", contact, err)
	}
	fields := contact.ContactFields
	fields.City = "Paris"
	updated, err := client.Domains.UpdateContact(ctx, contact.ContactID, fields)
	if err != nil || updated.City != "Paris" {
		t.Fatalf("update contact = %+v, %v", updated, err)
	}
	if got, err := client.Domains.Contact(ctx, contact.ContactID); err != nil || got.City != "Paris" {
		t.Fatalf("get contact = %+v, %v", got, err)
	}
	if _, err := client.Domains.Contact(ctx, "ctc-missing"); !redundantdns.HasCode(err, redundantdns.CodeContactNotFound) {
		t.Errorf("missing contact err = %v", err)
	}
	if _, err := client.Domains.ChangeRegistrant(ctx, "example.com", contact.ContactID, "example.org"); !redundantdns.HasCode(err, redundantdns.CodeConfirmNameMismatch) {
		t.Errorf("registrant mismatch err = %v", err)
	}
	traded, err := client.Domains.ChangeRegistrant(ctx, "example.com", contact.ContactID, "EXAMPLE.com")
	if err != nil || traded.Domain.OwnerContactID != contact.ContactID || traded.Domain.Registrant == nil || traded.Domain.Contacts.Owner == "" {
		t.Fatalf("registrant = %+v, %v", traded, err)
	}
	if err := client.Domains.DeleteContact(ctx, contact.ContactID); !redundantdns.HasCode(err, redundantdns.CodeContactInUse) {
		t.Errorf("delete used contact err = %v", err)
	}
	spare, _ := client.Domains.CreateContact(ctx, validContact("Spare"))
	if err := client.Domains.DeleteContact(ctx, spare.ContactID); err != nil {
		t.Fatal(err)
	}
	contacts, err := client.Domains.Contacts(ctx)
	if err != nil || len(contacts) != 1 {
		t.Fatalf("contacts = %+v, %v", contacts, err)
	}

	domains := 0
	for domain, err := range client.Domains.All(ctx) {
		if err != nil || domain.Name != "example.com" {
			t.Fatalf("all = %+v, %v", domain, err)
		}
		domains++
	}
	if domains != 1 {
		t.Errorf("domains = %d", domains)
	}
}

func TestFakeDomainAdmin(t *testing.T) {
	fake := rdnstest.NewFake(t)
	client := newClient(t, fake.URL)
	ctx := context.Background()
	fake.SeedDomain(redundantdns.Domain{Name: "held.example"})
	fake.SeedUnassignedDomain("loose.example")
	fake.AcceptDomainTerms()
	fake.SeedContact(validContact("HQ"), true)
	fake.SetPlan("pro")

	if _, err := client.Domains.TransferIn(ctx, redundantdns.DomainTransferCreate{Name: "loose.example", AuthCode: "x"}); !redundantdns.HasCode(err, redundantdns.CodeDomainNameTaken) {
		t.Errorf("taken err = %v", err)
	}
	if _, err := client.Domains.TransferIn(ctx, redundantdns.DomainTransferCreate{Name: "held.example", AuthCode: "x"}); !redundantdns.HasCode(err, redundantdns.CodeDomainExists) {
		t.Errorf("exists err = %v", err)
	}
	all, err := client.Domains.AdminList(ctx)
	if err != nil || len(all) != 2 || all[0].OrgID != rdnstest.DefaultOrgID || all[1].OrgID != "" {
		t.Fatalf("admin list = %+v, %v", all, err)
	}
	assigned, err := client.Domains.AdminAssign(ctx, "loose.example", rdnstest.DefaultOrgID)
	if err != nil || assigned.Name != "loose.example" || fake.DomainCount() != 2 {
		t.Fatalf("assign = %+v, %v", assigned, err)
	}
}

func TestDomainDecoding(t *testing.T) {
	var answers = map[string]string{
		// A mutation queued for a retry.
		"PUT /v1/domains/{name}/lock": `{"domain":{"name":"example.com","status":"active","locked":false,"registrarDomainId":123},"job":{"jobId":"job-1","op":"lock","status":"queued","attempts":2,"lastError":"timeout"}}`,
		// A route that answers the bare domain.
		"POST /v1/domains/{name}/sync":       `{"name":"example.com","status":"active","locked":true}`,
		"GET /v1/domains/registrant-profile": `{"contactId":"ctc-1","default":true,"firstName":"Ada","handles":{"openprovider":"AL1-GB"}}`,
	}
	mux := http.NewServeMux()
	for pattern, body := range answers {
		status := http.StatusOK
		if strings.HasSuffix(pattern, "/lock") {
			status = http.StatusAccepted
		}
		mux.HandleFunc(pattern, func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(status)
			_, _ = writer.Write([]byte(body))
		})
	}
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	client := newClient(t, server.URL)
	ctx := context.Background()

	queued, err := client.Domains.SetLock(ctx, "example.com", false)
	if err != nil || !queued.Queued() || queued.Job.Attempts != 2 || queued.Domain.RegistrarDomainID != "123" {
		t.Fatalf("queued = %+v, %v", queued, err)
	}
	synced, err := client.Domains.Sync(ctx, "Example.com.")
	if err != nil || synced.Domain.Name != "example.com" || synced.Queued() || synced.Job.Status != redundantdns.JobStatusDone {
		t.Fatalf("bare sync = %+v, %v", synced, err)
	}
	profile, err := client.Domains.RegistrantProfile(ctx)
	if err != nil || profile == nil || profile.FirstName != "Ada" || profile.Handles["openprovider"] != "AL1-GB" {
		t.Fatalf("bare profile = %+v, %v", profile, err)
	}
	if !slices.Contains(redundantdns.AllScopes, redundantdns.ScopeDomainsWrite) || !slices.Contains(redundantdns.AllScopes, redundantdns.ScopeDomainsRead) {
		t.Errorf("AllScopes = %v", redundantdns.AllScopes)
	}
}

// zoneWithAttachment creates a zone attached to a new fake connection, so
// its NS plan is not empty.
func zoneWithAttachment(t *testing.T, client *redundantdns.Client, name string) *redundantdns.Zone {
	t.Helper()
	ctx := context.Background()
	connection, err := client.Connections.Create(ctx, redundantdns.ConnectionCreate{
		Provider: "fake", AccessLevel: redundantdns.AccessLevelZoneAdmin, Credentials: map[string]string{"token": "dom" + strings.ReplaceAll(name, ".", "")},
	})
	if err != nil {
		t.Fatal(err)
	}
	zone, err := client.Zones.Create(ctx, redundantdns.ZoneCreate{Name: name})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Attachments.Create(ctx, zone.ZoneID, redundantdns.AttachmentCreate{ConnectionID: connection.Connection.ConnectionID}); err != nil {
		t.Fatal(err)
	}
	return zone
}

// lastRequest returns the last request the fake served for a pattern.
func lastRequest(t *testing.T, fake *rdnstest.Fake, pattern string) rdnstest.Request {
	t.Helper()
	requests := fake.Requests()
	for index := len(requests) - 1; index >= 0; index-- {
		if requests[index].Pattern == pattern {
			return requests[index]
		}
	}
	t.Fatalf("no request %s", pattern)
	return rdnstest.Request{}
}
