package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	redundantdns "github.com/redundantdns/go-client"
	"github.com/redundantdns/go-client/rdnstest"
)

func TestConnectionsUpdate(t *testing.T) {
	h, fake := fakeHarness(t)
	var created redundantdns.ConnectionCreateResult
	if err := json.Unmarshal([]byte(h.ok("connections", "create", "--provider", "fake", "--label", "Lab", "--cred", "token=old-1234", "--scope", "region=eu", "--json")), &created); err != nil {
		t.Fatal(err)
	}
	connectionID := created.Connection.ConnectionID
	h.ok("zones", "create", "rotate.example.com")
	h.ok("attach", "rotate.example.com", "--connection", connectionID)

	// Text output: the hint and the reconcile jobs, never the secret.
	out := h.ok("connections", "update", connectionID, "--cred", "token=secret-5678")
	if !strings.Contains(out, "Replaced the credentials of connection "+connectionID) || !strings.Contains(out, "...5678") ||
		!strings.Contains(out, "Reconciling its attachments: job-") || strings.Contains(out, "secret-5678") {
		t.Errorf("update = %s", out)
	}
	if got := fake.ConnectionCredentials(connectionID)["token"]; got != "secret-5678" {
		t.Errorf("stored token = %q", got)
	}
	var connections []redundantdns.Connection
	_ = json.Unmarshal([]byte(h.ok("connections", "list", "--json")), &connections)
	if len(connections) != 1 || connections[0].Label != "Lab" || connections[0].ScopeHints["region"] != "eu" {
		t.Errorf("label and scope hints must be kept: %+v", connections)
	}

	// --json, a new label, scope hints and a credential read from a file.
	keyFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(keyFile, []byte("file-0000"), 0o600); err != nil {
		t.Fatal(err)
	}
	var result redundantdns.ConnectionUpdateResult
	raw := h.ok("--json", "connections", "update", connectionID, "--cred-file", "token="+keyFile, "--label", "Rotated", "--scope", "region=us")
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		t.Fatalf("json = %s: %v", raw, err)
	}
	if result.Connection.Label != "Rotated" || result.Connection.ScopeHints["region"] != "us" || len(result.JobIDs) != 1 || strings.Contains(raw, "file-0000") {
		t.Errorf("json update = %s", raw)
	}
	h.ok("connections", "update", connectionID, "--cred", "token=clear-1111", "--clear-scopes")
	connections = nil
	_ = json.Unmarshal([]byte(h.ok("connections", "list", "--json")), &connections)
	if len(connections[0].ScopeHints) != 0 {
		t.Errorf("--clear-scopes left %v", connections[0].ScopeHints)
	}

	// A refusal saves nothing and says so.
	refused := h.run("", "connections", "update", connectionID, "--cred", "token=invalid")
	if refused.code != 1 || !strings.Contains(refused.stderr, "providerRejected") || !strings.Contains(refused.stderr, "stored credentials keep working") {
		t.Errorf("refused = %+v", refused)
	}
	if got := fake.ConnectionCredentials(connectionID)["token"]; got != "clear-1111" {
		t.Errorf("stored token after a refusal = %q", got)
	}

	// Usage errors: no credentials, a malformed --cred (its value is not
	// echoed), --scope with --clear-scopes, no id.
	for _, args := range [][]string{
		{"connections", "update", connectionID},
		{"connections", "update", connectionID, "--cred", "leakedsecret"},
		{"connections", "update", connectionID, "--cred", "token=x", "--scope", "a=b", "--clear-scopes"},
		{"connections", "update", "--cred", "token=x"},
	} {
		out := h.run("", args...)
		if out.code != 2 || strings.Contains(out.stderr, "leakedsecret") {
			t.Errorf("%v = %+v", args, out)
		}
	}
	if out := h.run("", "connections", "update", connectionID, "--cred", "token=x", "--label", " "); out.code != 1 || !strings.Contains(out.stderr, "labelRequired") {
		t.Errorf("empty label = %+v", out)
	}
	if out := h.run("", "connections", "update", "conn-missing", "--cred", "token=x"); out.code != 1 || !strings.Contains(out.stderr, "connectionNotFound") {
		t.Errorf("missing = %+v", out)
	}

	// A managed connection is refused with a hint.
	fake.AcceptManagedTerms()
	var managed redundantdns.ConnectionCreateResult
	_ = json.Unmarshal([]byte(h.ok("connections", "create", "--provider", "fake", "--mode", "managed", "--accept-managed-terms", rdnstest.ManagedTermsVersion, "--json")), &managed)
	out = h.run("", "connections", "update", managed.Connection.ConnectionID, "--cred", "token=x").stderr
	if !strings.Contains(out, "connectionManaged") || !strings.Contains(out, "rdnsctl connections create") {
		t.Errorf("managed = %s", out)
	}
	if help := h.ok("connections", "update", "--help"); !strings.Contains(help, "--clear-scopes") {
		t.Errorf("help = %s", help)
	}
}
