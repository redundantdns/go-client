package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	redundantdns "github.com/redundantdns/go-client"
	"github.com/redundantdns/go-client/rdnstest"
)

func TestManagedTermsCommands(t *testing.T) {
	h, _ := fakeHarness(t)

	// Without --accept-managed-terms a managed connection is refused
	// before any write, with the text URL and the version to accept.
	out := h.run("", "connections", "create", "--provider", "fake", "--mode", "managed")
	if out.code != 2 || !strings.Contains(out.stderr, "--accept-managed-terms "+rdnstest.ManagedTermsVersion) || !strings.Contains(out.stderr, "/legal/managed-terms") {
		t.Fatalf("managed without terms = %+v", out)
	}
	if out := h.ok("legal", "managed", "status"); !strings.Contains(out, "Not accepted") || !strings.Contains(out, rdnstest.ManagedTermsVersion) {
		t.Errorf("status before = %s", out)
	}
	if out := h.run("", "legal", "managed", "accept"); out.code != 2 || !strings.Contains(out.stderr, "accept "+rdnstest.ManagedTermsVersion) {
		t.Errorf("accept without version = %+v", out)
	}
	if out := h.run("", "legal", "managed", "accept", "2020-01-01"); out.code != 1 || !strings.Contains(out.stderr, redundantdns.CodeLegalVersionMismatch) {
		t.Errorf("accept old version = %+v", out)
	}
	if out := h.run("", "legal", "managed", "nope"); out.code != 2 {
		t.Errorf("unknown legal action = %+v", out)
	}
	out = h.run("", "connections", "create", "--provider", "fake", "--mode", "managed", "--accept-managed-terms", rdnstest.ManagedTermsVersion, "--label", "Managed")
	if out.code != 0 || !strings.Contains(out.stdout, "Created connection") {
		t.Fatalf("managed with terms = %+v", out)
	}
	var status redundantdns.ManagedTermsStatus
	if err := json.Unmarshal([]byte(h.ok("legal", "managed", "status", "--json")), &status); err != nil || status.Required || status.Accepted == nil {
		t.Errorf("status after = %+v, %v", status, err)
	}
	if out := h.ok("legal", "managed", "accept", rdnstest.ManagedTermsVersion); !strings.Contains(out, "Accepted the Managed Provider Terms") {
		t.Errorf("accept = %s", out)
	}
}

func TestDescribeManagedTermsError(t *testing.T) {
	err := &redundantdns.APIError{
		StatusCode: http.StatusPreconditionRequired, Code: redundantdns.CodeManagedTermsRequired, Message: "accept first",
		Details: json.RawMessage(`{"version":"2026-09-24","url":"https://app.example/legal/managed-terms"}`),
	}
	text := describeError(err)
	if !strings.Contains(text, "rdnsctl legal managed accept 2026-09-24") || !strings.Contains(text, "https://app.example/legal/managed-terms") {
		t.Errorf("describe = %s", text)
	}
}

func TestZonesCreateParentDelegation(t *testing.T) {
	h, fake := fakeHarness(t)
	h.ok("connections", "create", "--provider", "fake", "--cred", "token=abcd1234")
	h.ok("zones", "create", "example.com")
	out := h.ok("zones", "create", "api.example.com", "--parent-delegation")
	if !strings.Contains(out, "Delegated from example.com") {
		t.Fatalf("zones create --parent-delegation = %s", out)
	}
	if body := lastBody(t, fake, "POST /v1/zones"); body["parentDelegation"] != true {
		t.Errorf("create body = %v", body)
	}
	var connections []redundantdns.Connection
	_ = json.Unmarshal([]byte(h.ok("connections", "list", "--json")), &connections)
	h.ok("attach", "api.example.com", "--connection", connections[0].ConnectionID)
	if out := h.ok("zones", "get", "api.example.com"); !strings.Contains(out, "Delegated from example.com (RedundantDNS-managed NS set in the parent zone)") {
		t.Errorf("zones get child = %s", out)
	}
	if out := h.ok("records", "list", "example.com"); !strings.Contains(out, "api") || !strings.Contains(out, "ns1.abcd1234.fake-dns.test.") {
		t.Errorf("parent records = %s", out)
	}
	if out := h.ok("zones", "create", "www.example.com", "--parent-delegation=false"); strings.Contains(out, "Delegated") {
		t.Errorf("opted out = %s", out)
	}
	if body := lastBody(t, fake, "POST /v1/zones"); body["parentDelegation"] != false {
		t.Errorf("opt-out body = %v", body)
	}
	h.ok("zones", "create", "example.org")
	if body := lastBody(t, fake, "POST /v1/zones"); body["parentDelegation"] != nil {
		t.Errorf("unset flag must not send parentDelegation: %v", body)
	}
}

func TestDelegationCloudflareRegistrarHint(t *testing.T) {
	server := rdnstest.NewReplayServer(t, map[string]string{
		"POST /v1/zones/{zoneId}/delegation/check": "synthetic_delegation_cloudflare_registrar",
	})
	h := newHarness(t, map[string]string{"RDNS_BASE_URL": server.URL, "RDNS_TOKEN": rdnstest.DefaultToken})
	out := h.ok("delegation", "check", "zone-1")
	for _, want := range []string{"Registrar: Cloudflare, Inc.", "registered at Cloudflare Registrar", "Subdomain redundancy", "/guides/cloudflare-registrar"} {
		if !strings.Contains(out, want) {
			t.Errorf("delegation check lacks %q:\n%s", want, out)
		}
	}
}

func TestTerraformLogin(t *testing.T) {
	fake := rdnstest.NewFake(t)
	h := newHarness(t, map[string]string{"RDNS_BASE_URL": fake.URL})
	// The "browser" follows the consent URL: the fake approves at once and
	// redirects to rdnsctl's loopback callback.
	h.openBrowser = func(target string) error {
		answer, err := http.Get(target) //nolint:gosec,noctx // test browser
		if err != nil {
			return err
		}
		return answer.Body.Close()
	}
	out := h.run("", "terraform", "login", "--port", "0")
	if out.code != 0 || !strings.Contains(out.stdout, "Terraform credentials for test@example.com") || !strings.Contains(out.stderr, "/oauth/authorize?") {
		t.Fatalf("terraform login = %+v", out)
	}
	path := filepath.Join(h.env["XDG_CONFIG_HOME"], "redundantdns", "terraform-oauth.json")
	credentials, err := redundantdns.LoadOAuthCredentials(path)
	if err != nil || credentials.AccessToken != rdnstest.DefaultToken || credentials.RefreshToken == "" ||
		credentials.SoftwareID != redundantdns.SoftwareIDTerraform || credentials.OrgID != rdnstest.DefaultOrgID || credentials.BaseURL != fake.URL {
		t.Fatalf("credentials = %+v, %v", credentials, err)
	}
	registration, ok := fake.OAuthRegistrations()[credentials.ClientID]
	if !ok || registration.SoftwareID != redundantdns.SoftwareIDTerraform || registration.TokenEndpointAuthMethod != "none" {
		t.Errorf("registration = %+v", registration)
	}

	// An answer that does not carry this login's state is refused.
	h.openBrowser = func(target string) error {
		consent, err := url.Parse(target)
		if err != nil {
			return err
		}
		answer, err := http.Get(consent.Query().Get("redirect_uri") + "?code=stolen&state=other") //nolint:gosec,noctx // test browser
		if err != nil {
			return err
		}
		return answer.Body.Close()
	}
	if out := h.run("", "terraform", "login", "--port", "0", "--file", filepath.Join(t.TempDir(), "x.json")); out.code != 1 || !strings.Contains(out.stderr, "state mismatch") {
		t.Errorf("state mismatch = %+v", out)
	}
}

// lastBody decodes the body of the last request matching a pattern.
func lastBody(t *testing.T, fake *rdnstest.Fake, pattern string) map[string]any {
	t.Helper()
	requests := fake.Requests()
	for index := len(requests) - 1; index >= 0; index-- {
		if requests[index].Pattern == pattern {
			var body map[string]any
			if err := json.Unmarshal(requests[index].Body, &body); err != nil {
				t.Fatal(err)
			}
			return body
		}
	}
	t.Fatalf("no request %s", pattern)
	return nil
}
