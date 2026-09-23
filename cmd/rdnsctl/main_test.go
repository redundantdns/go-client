package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	redundantdns "github.com/redundantdns/go-client"
	"github.com/redundantdns/go-client/rdnstest"
)

// result is one CLI run.
type result struct {
	code   int
	stdout string
	stderr string
}

// harness runs the CLI in process with a private config directory.
type harness struct {
	t   *testing.T
	env map[string]string
}

func newHarness(t *testing.T, env map[string]string) *harness {
	t.Helper()
	merged := map[string]string{"XDG_CONFIG_HOME": t.TempDir()}
	for key, value := range env {
		merged[key] = value
	}
	return &harness{t: t, env: merged}
}

func (h *harness) run(stdin string, args ...string) result {
	h.t.Helper()
	var stdout, stderr bytes.Buffer
	cli := &app{stdin: strings.NewReader(stdin), stdout: &stdout, stderr: &stderr, getenv: func(key string) string { return h.env[key] }}
	code := cli.run(context.Background(), args)
	return result{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

// ok runs a command that must succeed.
func (h *harness) ok(args ...string) string {
	h.t.Helper()
	out := h.run("", args...)
	if out.code != 0 {
		h.t.Fatalf("rdnsctl %s: exit %d\nstdout: %s\nstderr: %s", strings.Join(args, " "), out.code, out.stdout, out.stderr)
	}
	return out.stdout
}

func (h *harness) configFile() string {
	return filepath.Join(h.env["XDG_CONFIG_HOME"], "rdnsctl", "config.json")
}

func fakeHarness(t *testing.T) (*harness, *rdnstest.Fake) {
	fake := rdnstest.NewFake(t)
	return newHarness(t, map[string]string{"RDNS_BASE_URL": fake.URL, "RDNS_TOKEN": rdnstest.DefaultToken}), fake
}

func TestHelpAndUsageErrors(t *testing.T) {
	h := newHarness(t, nil)
	if out := h.ok("help"); !strings.Contains(out, "zones") || !strings.Contains(out, "--json") {
		t.Errorf("help = %s", out)
	}
	if out := h.ok("records", "--help"); !strings.Contains(out, "upsert") {
		t.Errorf("records help = %s", out)
	}
	if out := h.ok("records", "upsert", "--help"); !strings.Contains(out, "--previous-name") {
		t.Errorf("records upsert help = %s", out)
	}
	if out := h.run("", "nope"); out.code != 2 || !strings.Contains(out.stderr, `unknown command "nope"`) {
		t.Errorf("unknown command = %+v", out)
	}
	if out := h.run("", "zones", "get"); out.code != 2 || !strings.Contains(out.stderr, "usage: rdnsctl zones get <zone>") {
		t.Errorf("missing argument = %+v", out)
	}
	if out := h.run("", "zones", "list"); out.code != 1 || !strings.Contains(out.stderr, "not signed in") {
		t.Errorf("no token = %+v", out)
	}
	if out := h.ok("version"); !strings.HasPrefix(out, "rdnsctl dev") {
		t.Errorf("version = %s", out)
	}
}

func TestZoneLifecycle(t *testing.T) {
	h, fake := fakeHarness(t)

	if out := h.ok("providers", "list"); !strings.Contains(out, "route53") || !strings.Contains(out, "accessKeyId,secretAccessKey") {
		t.Errorf("providers = %s", out)
	}
	out := h.ok("connections", "create", "--provider", "fake", "--label", "Lab fake", "--cred", "token=abcd1234", "--json")
	var created redundantdns.ConnectionCreateResult
	if err := json.Unmarshal([]byte(out), &created); err != nil {
		t.Fatalf("connection JSON: %v\n%s", err, out)
	}
	connectionID := created.Connection.ConnectionID
	if out := h.ok("connections", "list"); !strings.Contains(out, connectionID) || !strings.Contains(out, "...1234") {
		t.Errorf("connections list = %s", out)
	}
	if out := h.ok("connections", "test", connectionID); !strings.Contains(out, "works") {
		t.Errorf("connections test = %s", out)
	}
	if out := h.run("", "connections", "create", "--provider", "fake", "--cred", "novalue"); out.code != 2 {
		t.Errorf("bad --cred = %+v", out)
	}

	if out := h.ok("zones", "create", "example.com", "--default-ttl", "600"); !strings.Contains(out, "Created zone example.com") {
		t.Errorf("zones create = %s", out)
	}
	// Flags after positionals, zone referenced by name.
	if out := h.ok("attach", "example.com", "--connection", connectionID); !strings.Contains(out, "ns1.abcd1234.fake-dns.test.") {
		t.Errorf("attach = %s", out)
	}
	if out := h.ok("records", "upsert", "example.com", "--name", "www", "--type", "a", "--value", "192.0.2.10", "--value", "192.0.2.011"); !strings.Contains(out, "192.0.2.10 | 192.0.2.11") {
		t.Errorf("records upsert = %s", out)
	}
	h.ok("records", "upsert", "example.com", "--name", "mail", "--type", "MX", "--value", "10 mx.example.net", "--ttl", "300")
	if out := h.ok("records", "upsert", "example.com", "--name", "smtp", "--type", "MX", "--value", "10 mx.example.net", "--previous-name", "mail"); !strings.Contains(out, "Saved smtp MX TTL 600") {
		t.Errorf("rename = %s", out)
	}
	records := h.ok("records", "list", "example.com")
	if !strings.Contains(records, "smtp") || strings.Contains(records, "mail ") || !strings.Contains(records, "10 mx.example.net.") {
		t.Errorf("records list = %s", records)
	}
	zoneOut := h.ok("zones", "get", "example.com")
	for _, want := range []string{"Zone example.com", "NS plan: ns1.abcd1234.fake-dns.test.", "in_sync", "www"} {
		if !strings.Contains(zoneOut, want) {
			t.Errorf("zones get lacks %q:\n%s", want, zoneOut)
		}
	}
	var zones []redundantdns.Zone
	if err := json.Unmarshal([]byte(h.ok("zones", "list", "--json")), &zones); err != nil || len(zones) != 1 {
		t.Fatalf("zones list JSON = %v, %v", zones, err)
	}
	zoneID := zones[0].ZoneID
	attachmentID := zones[0].Attachments[0].AttachmentID
	if out := h.ok("zones", "export", zoneID); !strings.Contains(out, "$ORIGIN example.com.") {
		t.Errorf("export = %s", out)
	}
	if out := h.ok("sync", "reconcile", "example.com", "--wait"); !strings.Contains(out, "All attachments are in sync") || !strings.Contains(out, attachmentID) {
		t.Errorf("sync reconcile --wait = %s", out)
	}
	if out := h.ok("sync", "verify", "example.com", "--attachment", attachmentID); !strings.Contains(out, "Queued verify") {
		t.Errorf("sync verify = %s", out)
	}
	if out := h.ok("sync", "adopt", "example.com", attachmentID); !strings.Contains(out, "Queued adopt") {
		t.Errorf("sync adopt = %s", out)
	}
	if out := h.ok("sync", "status", "example.com"); !strings.Contains(out, "in_sync") {
		t.Errorf("sync status = %s", out)
	}
	if out := h.ok("delegation", "check", "example.com"); !strings.Contains(out, "Delegation: pending") {
		t.Errorf("delegation = %s", out)
	}
	if out := h.ok("records", "delete", "example.com", "--name", "www", "--type", "A"); !strings.Contains(out, "Deleted www A") {
		t.Errorf("records delete = %s", out)
	}
	if out := h.run("", "records", "delete", "example.com", "--name", "www", "--type", "A"); out.code != 1 || !strings.Contains(out.stderr, "recordSetNotFound") {
		t.Errorf("delete missing = %+v", out)
	}

	// Destructive commands ask for the zone name unless --yes.
	if out := h.run("wrong.example\n", "detach", "example.com", attachmentID, "--delete-remote"); out.code != 2 {
		t.Errorf("detach with a wrong confirmation = %+v", out)
	}
	if out := h.ok("detach", "example.com", attachmentID, "--delete-remote", "--yes"); !strings.Contains(out, "deleted the provider zone") {
		t.Errorf("detach = %s", out)
	}
	if out := h.run("example.com\n", "zones", "delete", "example.com"); out.code != 0 || !strings.Contains(out.stdout, "Deleted zone example.com") {
		t.Errorf("zones delete = %+v", out)
	}
	h.ok("connections", "delete", connectionID)
	if fake.ZoneCount() != 0 || fake.ConnectionCount() != 0 {
		t.Error("the fake still has resources")
	}
}

func TestAlerts(t *testing.T) {
	h, fake := fakeHarness(t)
	fake.AddEvent(redundantdns.AlertEvent{
		EventID: "evt-1", Rule: "drift", State: "firing", ZoneID: "zone-x", ZoneName: "example.com",
		Summary: "Route 53 differs from the canonical zone", FirstSeenAt: time.Date(2026, 9, 23, 20, 0, 0, 0, time.UTC),
	})
	if out := h.ok("alerts", "list", "--state", "firing"); !strings.Contains(out, "evt-1") || !strings.Contains(out, "drift") {
		t.Errorf("alerts list = %s", out)
	}
	if out := h.ok("alerts", "ack", "evt-1"); !strings.Contains(out, "Acknowledged evt-1") {
		t.Errorf("alerts ack = %s", out)
	}
	if out := h.ok("alerts", "resolve", "evt-1"); !strings.Contains(out, "now resolved") {
		t.Errorf("alerts resolve = %s", out)
	}
	if out := h.run("", "alerts", "resolve", "evt-1"); out.code != 1 || !strings.Contains(out.stderr, "alertNotFound") {
		t.Errorf("resolve twice = %+v", out)
	}
	if out := h.ok("alerts", "list", "--state", "firing"); !strings.Contains(out, "No alerts.") {
		t.Errorf("alerts list after resolve = %s", out)
	}
	if out := h.ok("alerts", "rules"); !strings.Contains(out, "provider_down") || !strings.Contains(out, "2 (1-20)") {
		t.Errorf("alerts rules = %s", out)
	}
	if out := h.ok("alerts", "channels"); !strings.Contains(out, "CHANNEL ID") {
		t.Errorf("alerts channels = %s", out)
	}
}

func TestOrgFlagAndErrors(t *testing.T) {
	h, _ := fakeHarness(t)
	out := h.run("", "zones", "list", "--org", "org-other")
	if out.code != 1 || !strings.Contains(out.stderr, "forbidden") {
		t.Errorf("--org of another org = %+v", out)
	}
	h.env["RDNS_TOKEN"] = "rdns_wrong"
	out = h.run("", "whoami")
	if out.code != 1 || !strings.Contains(out.stderr, "rdnsctl login") {
		t.Errorf("bad token = %+v", out)
	}
}

// loginServer implements the session side of the API used by login.
func loginServer(t *testing.T) *httptest.Server {
	t.Helper()
	accepted := false
	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/code", func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("POST /auth/verify", func(writer http.ResponseWriter, request *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(request.Body).Decode(&body)
		if body["code"] != "123456" {
			writer.WriteHeader(http.StatusUnauthorized)
			_, _ = writer.Write([]byte(`{"error":"invalidCode","message":"invalid or expired code"}`))
			return
		}
		http.SetCookie(writer, &http.Cookie{Name: redundantdns.SessionCookie, Value: "session-jwt"})
		_, _ = writer.Write([]byte(`{"user":{"userId":"usr-1","email":"` + body["email"] + `"},"orgs":[{"orgId":"org-a","name":"Alpha","role":"owner"},{"orgId":"org-b","name":"Beta","role":"admin"}]}`))
	})
	requireSession := func(writer http.ResponseWriter, request *http.Request) bool {
		if cookie, err := request.Cookie(redundantdns.SessionCookie); err != nil || cookie.Value != "session-jwt" {
			writer.WriteHeader(http.StatusUnauthorized)
			_, _ = writer.Write([]byte(`{"error":"notLoggedIn","message":"sign in"}`))
			return false
		}
		return true
	}
	mux.HandleFunc("GET /v1/me/legal", func(writer http.ResponseWriter, request *http.Request) {
		if requireSession(writer, request) {
			_, _ = writer.Write([]byte(`{"current":{"terms":"2026-09-23","privacy":"2026-09-23"},"accepted":null,"required":` + map[bool]string{true: "false", false: "true"}[accepted] + `}`))
		}
	})
	mux.HandleFunc("POST /v1/me/legal/accept", func(writer http.ResponseWriter, request *http.Request) {
		if requireSession(writer, request) {
			accepted = true
			_, _ = writer.Write([]byte(`{"current":{"terms":"2026-09-23","privacy":"2026-09-23"},"required":false}`))
		}
	})
	mux.HandleFunc("POST /v1/tokens", func(writer http.ResponseWriter, request *http.Request) {
		if !requireSession(writer, request) {
			return
		}
		if !accepted {
			writer.WriteHeader(http.StatusPreconditionRequired)
			_, _ = writer.Write([]byte(`{"error":"legal_acceptance_required","message":"accept first"}`))
			return
		}
		org := request.Header.Get(redundantdns.OrgHeader)
		writer.WriteHeader(http.StatusCreated)
		_, _ = writer.Write([]byte(`{"record":{"tokenId":"tok-1","name":"cli","scopes":["zones:read","zones:write"],"userId":"usr-1"},"token":"rdns_` + org + `_secret"}`))
	})
	mux.HandleFunc("GET /v1/me", func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer rdns_org-b_secret" {
			writer.WriteHeader(http.StatusUnauthorized)
			_, _ = writer.Write([]byte(`{"error":"unauthorized","message":"bad token"}`))
			return
		}
		_, _ = writer.Write([]byte(`{"user":{"userId":"usr-1","email":"dev@example.com","kind":"pat"},"orgs":[{"orgId":"org-b","name":"Beta","role":"admin","plan":"free"}]}`))
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func TestLoginFlow(t *testing.T) {
	server := loginServer(t)
	h := newHarness(t, map[string]string{"RDNS_BASE_URL": server.URL})

	// Declining the terms saves nothing.
	out := h.run("dev@example.com\n123456\n2\nn\n", "login")
	if out.code != 1 || !strings.Contains(out.stderr, "were not accepted") {
		t.Fatalf("declined login = %+v", out)
	}
	if _, err := os.Stat(h.configFile()); !os.IsNotExist(err) {
		t.Fatal("a declined login must not write the config")
	}
	// Wrong code.
	out = h.run("", "login", "--email", "dev@example.com", "--code", "000000")
	if out.code != 1 || !strings.Contains(out.stderr, "invalidCode") {
		t.Fatalf("wrong code = %+v", out)
	}
	// Prompted e-mail and code, org chosen by number, terms accepted.
	out = h.run("dev@example.com\n123456\n2\ny\n", "login", "--token-name", "cli")
	if out.code != 0 || !strings.Contains(out.stdout, "organization Beta (org-b)") || !strings.Contains(out.stderr, "/terms") {
		t.Fatalf("login = %+v", out)
	}
	info, err := os.Stat(h.configFile())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("config mode = %v, want 0600", info.Mode().Perm())
	}
	dirInfo, _ := os.Stat(filepath.Dir(h.configFile()))
	if dirInfo.Mode().Perm() != 0o700 {
		t.Errorf("config dir mode = %v, want 0700", dirInfo.Mode().Perm())
	}
	saved, err := loadConfig(h.configFile())
	if err != nil || saved.Token != "rdns_org-b_secret" || saved.OrgID != "org-b" || saved.BaseURL != server.URL || saved.TokenID != "tok-1" {
		t.Fatalf("saved config = %+v, %v", saved, err)
	}
	// The saved token is used by later commands (no RDNS_TOKEN set).
	if out := h.ok("whoami"); !strings.Contains(out, "dev@example.com") || !strings.Contains(out, "org-b") {
		t.Errorf("whoami = %s", out)
	}
	// --org with an org the user is not in.
	out = h.run("", "login", "--email", "dev@example.com", "--code", "123456", "--org", "org-zzz", "--accept-terms")
	if out.code != 1 || !strings.Contains(out.stderr, "not a member") {
		t.Errorf("login --org unknown = %+v", out)
	}
	if out := h.ok("logout"); !strings.Contains(out, "tok-1 is still valid") {
		t.Errorf("logout = %s", out)
	}
	if _, err := os.Stat(h.configFile()); !os.IsNotExist(err) {
		t.Error("logout must remove the config")
	}
	// login --token checks and stores an existing token.
	if out := h.ok("login", "--token", "rdns_org-b_secret"); !strings.Contains(out, "saved to") {
		t.Errorf("login --token = %s", out)
	}
	if out := h.run("", "login", "--token", "rdns_bad"); out.code != 1 {
		t.Errorf("login with a bad token = %+v", out)
	}
}

func TestParseArgsInterleaved(t *testing.T) {
	shared := &globals{}
	flags := newFlagSet("x", shared)
	name := flags.String("name", "", "")
	positionals, err := parseArgs(flags, []string{"a", "--name", "n", "b", "--json", "--", "--c"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(positionals, ",") != "a,b,--c" || *name != "n" || !shared.jsonOutput {
		t.Errorf("positionals = %v name = %q json = %v", positionals, *name, shared.jsonOutput)
	}
}
