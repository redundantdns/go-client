package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	redundantdns "github.com/redundantdns/go-client"
	"github.com/redundantdns/go-client/rdnstest"
)

// contactArgs are the flags of a valid contact.
var contactArgs = []string{
	"--first-name", "Ada", "--last-name", "Lovelace", "--email", "ada@example.com", "--phone", "+44.2071234567",
	"--street", "Main Street", "--city", "London", "--postal-code", "SW1A 1AA", "--country", "GB", "--company", "Example Ltd",
}

func TestDomainsTransferCommands(t *testing.T) {
	h, fake := fakeHarness(t)

	if out := h.ok("domains", "--help"); !strings.Contains(out, "apply-zone-ns") || !strings.Contains(out, "registrant-profile") {
		t.Errorf("domains help = %s", out)
	}
	// The terms first: the error says how to accept them.
	out := h.run("", "domains", "transfer", "example.com", "--auth-code", "secret")
	if out.code != 1 || !strings.Contains(out.stderr, "domain_terms_required") || !strings.Contains(out.stderr, "--accept-terms "+rdnstest.DomainTermsVersion) {
		t.Fatalf("transfer without terms = %+v", out)
	}
	if out := h.ok("domains", "terms", "status"); !strings.Contains(out, "Not accepted") || !strings.Contains(out, "/legal/domain-terms") {
		t.Errorf("terms status = %s", out)
	}
	if out := h.run("", "domains", "terms", "accept"); out.code != 2 || !strings.Contains(out.stderr, "accept "+rdnstest.DomainTermsVersion) {
		t.Errorf("accept without version = %+v", out)
	}
	// Then the registrant profile.
	out = h.run("", "domains", "transfer", "example.com", "--auth-code", "secret", "--accept-terms", rdnstest.DomainTermsVersion)
	if out.code != 1 || !strings.Contains(out.stderr, "registrant-profile set") {
		t.Fatalf("transfer without profile = %+v", out)
	}
	if out := h.ok("domains", "terms", "status", "--json"); !strings.Contains(out, `"required": false`) {
		t.Errorf("terms accepted by the transfer body = %s", out)
	}
	if out := h.ok("domains", "registrant-profile", "get"); !strings.Contains(out, "No registrant profile") {
		t.Errorf("empty profile = %s", out)
	}
	if out := h.run("", append([]string{"domains", "registrant-profile", "set"}, contactArgs[:4]...)...); out.code != 1 || !strings.Contains(out.stderr, "invalidContact") {
		t.Errorf("incomplete profile = %+v", out)
	}
	if out := h.ok(append([]string{"domains", "registrant-profile", "set"}, contactArgs...)...); !strings.Contains(out, "Ada Lovelace, Example Ltd") {
		t.Errorf("profile set = %s", out)
	}
	// Changing one field keeps the others.
	h.ok("domains", "registrant-profile", "set", "--city", "Paris")
	var profile struct {
		Profile redundantdns.Contact `json:"profile"`
	}
	if err := json.Unmarshal([]byte(h.ok("domains", "registrant-profile", "get", "--json")), &profile); err != nil || profile.Profile.City != "Paris" || profile.Profile.Email != "ada@example.com" {
		t.Fatalf("profile after partial set = %+v, %v", profile, err)
	}

	// The auth code is prompted when not given; --wait polls until done.
	fake.SetTransferReads(2)
	out = h.run("secret-code\n", "domains", "transfer", "example.com", "--nameservers", "ns1.example.net,ns2.example.net",
		"--auto-renew=false", "--wait", "--interval", "1ms")
	if out.code != 0 || !strings.Contains(out.stderr, "Auth code:") || !strings.Contains(out.stdout, "completed; the domain is active") {
		t.Fatalf("transfer --wait = %+v", out)
	}
	body := lastBody(t, fake, "POST /v1/domains/transfer")
	if body["authCode"] != "secret-code" || body["autoRenew"] != false || len(body["nameservers"].([]any)) != 2 {
		t.Errorf("transfer body = %v", body)
	}
	if out := h.ok("domains", "list"); !strings.Contains(out, "example.com") || !strings.Contains(out, "ns1.example.net,ns2.example.net") {
		t.Errorf("list = %s", out)
	}
	if out := h.ok("domains", "transfer-status", "example.com"); !strings.Contains(out, "Transfer: completed") {
		t.Errorf("transfer-status = %s", out)
	}

	// A rejected transfer is forgotten with domains delete.
	fake.SetPlan("starter")
	out = h.run("", "domains", "transfer", "example.org", "--auth-code", "invalid-code")
	if out.code != 1 || !strings.Contains(out.stderr, "registrarRejected") {
		t.Fatalf("rejected transfer = %+v", out)
	}
	if out := h.ok("domains", "get", "example.org"); !strings.Contains(out, "Transfer: failed") || !strings.Contains(out, "rdnsctl domains delete example.org") {
		t.Errorf("failed domain = %s", out)
	}
	if out := h.run("nope\n", "domains", "delete", "example.org"); out.code != 2 || fake.DomainCount() != 2 {
		t.Errorf("delete without confirmation = %+v", out)
	}
	if out := h.run("example.org\n", "domains", "delete", "example.org"); out.code != 0 || fake.DomainCount() != 1 {
		t.Errorf("delete = %+v", out)
	}
	out = h.run("", "domains", "transfer", "example.net", "--auth-code", "x", "--json")
	var result redundantdns.DomainMutationResult
	if out.code != 0 || json.Unmarshal([]byte(out.stdout), &result) != nil || result.Domain.Status != redundantdns.DomainStatusTransferPending {
		t.Errorf("transfer --json = %+v", out)
	}
}

func TestDomainsChangeCommands(t *testing.T) {
	h, fake := fakeHarness(t)
	fake.SeedDomain(redundantdns.Domain{Name: "example.com"})

	// Exit routes work without the terms.
	if out := h.ok("domains", "authcode", "example.com"); strings.TrimSpace(out) == "" {
		t.Error("empty auth code")
	}
	if out := h.ok("domains", "unlock", "example.com"); !strings.Contains(out, "transfer lock off") {
		t.Errorf("unlock = %s", out)
	}
	if out := h.ok("domains", "sync", "example.com"); !strings.Contains(out, "synced") {
		t.Errorf("sync = %s", out)
	}
	if out := h.run("", "domains", "lock", "example.com"); out.code != 1 || !strings.Contains(out.stderr, "domains terms accept") {
		t.Errorf("lock without terms = %+v", out)
	}
	if out := h.ok("domains", "terms", "accept", rdnstest.DomainTermsVersion); !strings.Contains(out, "Accepted the Domain Registration Terms") {
		t.Errorf("accept = %s", out)
	}
	h.ok("domains", "lock", "example.com")
	if out := h.ok("domains", "autorenew", "example.com", "off"); !strings.Contains(out, "auto-renewal off") {
		t.Errorf("autorenew = %s", out)
	}
	if out := h.run("", "domains", "autorenew", "example.com", "maybe"); out.code != 2 {
		t.Errorf("autorenew maybe = %+v", out)
	}
	if out := h.ok("domains", "renew", "example.com", "--years", "3"); !strings.Contains(out, "renewed for 3 years") {
		t.Errorf("renew = %s", out)
	}
	if out := h.run("", "domains", "nameservers", "set", "example.com", "ns1.example.net"); out.code != 2 {
		t.Errorf("one nameserver = %+v", out)
	}
	if out := h.ok("domains", "nameservers", "set", "example.com", "NS1.example.net.", "ns2.example.net"); !strings.Contains(out, "ns1.example.net ns2.example.net") {
		t.Errorf("nameservers set = %s", out)
	}

	// Apply the NS plan of the zone with the same name, then of another.
	h.ok("connections", "create", "--provider", "fake", "--cred", "token=dom1")
	var connections []redundantdns.Connection
	_ = json.Unmarshal([]byte(h.ok("connections", "list", "--json")), &connections)
	h.ok("zones", "create", "example.com")
	h.ok("attach", "example.com", "--connection", connections[0].ConnectionID)
	if out := h.ok("domains", "get", "example.com"); !strings.Contains(out, "differ") || !strings.Contains(out, "rdnsctl domains apply-zone-ns example.com") {
		t.Errorf("get before apply = %s", out)
	}
	if out := h.ok("domains", "apply-zone-ns", "example.com"); !strings.Contains(out, "ns1.dom1.fake-dns.test") {
		t.Errorf("apply-zone-ns = %s", out)
	}
	if out := h.ok("domains", "list"); !strings.Contains(out, "match") {
		t.Errorf("list after apply = %s", out)
	}
	h.ok("zones", "create", "empty.example")
	if out := h.run("", "domains", "apply-zone-ns", "example.com", "--zone", "empty.example"); out.code != 1 || !strings.Contains(out.stderr, "zoneNsPlanEmpty") {
		t.Errorf("apply empty zone = %+v", out)
	}
	if body := lastBody(t, fake, "POST /v1/domains/{name}/nameservers/apply-zone"); body["zoneId"] == nil {
		t.Errorf("apply body = %v", body)
	}

	// Contacts and the registrant change.
	out := h.ok(append([]string{"domains", "contacts", "create", "--label", "Legal", "--json"}, contactArgs...)...)
	var contact redundantdns.Contact
	if err := json.Unmarshal([]byte(out), &contact); err != nil || contact.ContactID == "" {
		t.Fatalf("contact create = %s, %v", out, err)
	}
	if out := h.ok("domains", "contacts", "update", contact.ContactID, "--city", "Paris"); !strings.Contains(out, "Updated contact") {
		t.Errorf("contact update = %s", out)
	}
	if body := lastBody(t, fake, "PUT /v1/domains/{name}/{field}"); body["city"] != "Paris" || body["firstName"] != "Ada" {
		t.Errorf("update body keeps the other fields = %v", body)
	}
	if out := h.ok("domains", "contacts", "list"); !strings.Contains(out, contact.ContactID) || !strings.Contains(out, "Legal") {
		t.Errorf("contacts list = %s", out)
	}
	if out := h.run("", "domains", "contacts", "nope"); out.code != 2 || !strings.Contains(out.stderr, "contact flags") {
		t.Errorf("contacts nope = %+v", out)
	}
	if out := h.run("example.org\n", "domains", "registrant", "set", "example.com", "--contact", contact.ContactID); out.code != 2 {
		t.Errorf("registrant without matching confirmation = %+v", out)
	}
	if out := h.run("Example.com\n", "domains", "registrant", "set", "example.com", "--contact", contact.ContactID); out.code != 0 || !strings.Contains(out.stdout, "registrant changed") {
		t.Errorf("registrant set = %+v", out)
	}
	if out := h.run("", "domains", "contacts", "delete", contact.ContactID, "--yes"); out.code != 1 || !strings.Contains(out.stderr, "contactInUse") {
		t.Errorf("delete used contact = %+v", out)
	}
	spare := fake.SeedContact(redundantdns.ContactFields{FirstName: "Spare"}, false)
	if out := h.run("", "domains", "contacts", "delete", spare.ContactID, "--yes"); out.code != 0 || fake.ContactCount() != 1 {
		t.Errorf("delete spare = %+v", out)
	}

	// Export to a private file.
	file := filepath.Join(t.TempDir(), "export.json")
	if out := h.ok("domains", "export", "--out", file); !strings.Contains(out, file) {
		t.Errorf("export = %s", out)
	}
	info, err := os.Stat(file)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("export file = %v, %v", info, err)
	}
	var export redundantdns.DomainExport
	raw, _ := os.ReadFile(file)
	if err := json.Unmarshal(raw, &export); err != nil || len(export.Domains) != 1 || len(export.Zones) != 2 || len(export.Contacts) != 1 {
		t.Errorf("export content = %+v, %v", export, err)
	}
	if out := h.ok("domains", "export"); !strings.Contains(out, `"zoneFile"`) {
		t.Errorf("export to stdout = %s", out)
	}
}

func TestLoginOnDeploymentWithoutDomainScopes(t *testing.T) {
	// A server older than the domains module refuses its scopes; rdnsctl
	// mints again with the scopes it knows.
	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/code", func(writer http.ResponseWriter, _ *http.Request) { _, _ = writer.Write([]byte(`{"ok":true}`)) })
	mux.HandleFunc("POST /auth/verify", func(writer http.ResponseWriter, _ *http.Request) {
		http.SetCookie(writer, &http.Cookie{Name: redundantdns.SessionCookie, Value: "session-jwt"})
		_, _ = writer.Write([]byte(`{"user":{"userId":"usr-1","email":"dev@example.com"},"orgs":[{"orgId":"org-a","name":"Alpha","role":"owner"}]}`))
	})
	mux.HandleFunc("GET /v1/me/legal", func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`{"current":{"terms":"2026-09-23","privacy":"2026-09-23"},"required":false}`))
	})
	var scopesSeen [][]string
	mux.HandleFunc("POST /v1/tokens", func(writer http.ResponseWriter, request *http.Request) {
		var body redundantdns.TokenCreate
		_ = json.NewDecoder(request.Body).Decode(&body)
		scopesSeen = append(scopesSeen, body.Scopes)
		if slices.Contains(body.Scopes, redundantdns.ScopeDomainsRead) {
			writer.WriteHeader(http.StatusBadRequest)
			_, _ = writer.Write([]byte(`{"error":"invalidScope","message":"unknown scope domains:read"}`))
			return
		}
		writer.WriteHeader(http.StatusCreated)
		_, _ = writer.Write([]byte(`{"record":{"tokenId":"tok-7","scopes":["zones:read"]},"token":"rdns_old"}`))
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	h := newHarness(t, map[string]string{"RDNS_BASE_URL": server.URL})
	out := h.run("", "login", "--email", "dev@example.com", "--code", "123456")
	if out.code != 0 || len(scopesSeen) != 2 || len(scopesSeen[1]) != 4 || !strings.Contains(out.stdout, "tok-7") {
		t.Fatalf("login without domain scopes = %+v (scopes %v)", out, scopesSeen)
	}
	// Explicit scopes are never changed behind the user's back.
	scopesSeen = nil
	out = h.run("", "login", "--email", "dev@example.com", "--code", "123456", "--scopes", "zones:read,domains:read")
	if out.code != 1 || len(scopesSeen) != 1 {
		t.Fatalf("explicit scopes = %+v (scopes %v)", out, scopesSeen)
	}
}
