package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	redundantdns "github.com/redundantdns/go-client"
)

func TestLicensesCommands(t *testing.T) {
	h, fake := fakeHarness(t)
	dir := t.TempDir()

	if out := h.ok("licenses", "list"); !strings.Contains(out, "No licenses.") {
		t.Errorf("empty list = %s", out)
	}
	if out := h.ok("admin", "licenses", "--help"); !strings.Contains(out, "--data-planes N") || !strings.Contains(out, "status <lid> active|suspended|revoked") {
		t.Errorf("admin licenses help = %s", out)
	}
	if out := h.run("", "admin", "licenses", "issue"); out.code != 2 || !strings.Contains(out.stderr, "--acct") {
		t.Errorf("issue without --acct = %+v", out)
	}
	if out := h.run("", "admin", "licenses", "issue", "--acct", fake.OrgID, "--expires", "soon"); out.code != 2 || !strings.Contains(out.stderr, "--expires") {
		t.Errorf("issue bad expiry = %+v", out)
	}
	issued := filepath.Join(dir, "issued.license")
	out := h.ok("admin", "licenses", "issue", "--acct", fake.OrgID, "--mode", "online", "--term", "monthly", "--feature", "selfHosted", "--feature", "sso",
		"--zones", "100", "--grace", "5", "--expires", "2027-10-01", "--out", issued)
	if !strings.Contains(out, "Issued license lic-") || !strings.Contains(out, "online, monthly, expires 2027-10-01") || !strings.Contains(out, "Attestation published.") {
		t.Errorf("issue = %s", out)
	}
	body := lastBody(t, fake, "POST /v1/admin/licenses")
	claims := body["claims"].(map[string]any)
	if claims["acct"] != fake.OrgID || claims["grace"] != float64(5) || claims["exp"] != "2027-10-01T00:00:00Z" || len(claims["features"].([]any)) != 2 ||
		claims["limits"].(map[string]any)["zones"] != float64(100) {
		t.Errorf("issue claims = %v", claims)
	}
	token, err := os.ReadFile(issued)
	if err != nil || !strings.HasPrefix(string(token), "v4.public.") {
		t.Fatalf("issued file = %q, %v", token, err)
	}
	if info, _ := os.Stat(issued); info.Mode().Perm() != 0o600 {
		t.Errorf("license file mode = %v", info.Mode())
	}
	var licenses []redundantdns.AdminLicense
	if err := json.Unmarshal([]byte(h.ok("admin", "licenses", "list", "--acct", fake.OrgID, "--json")), &licenses); err != nil || len(licenses) != 1 {
		t.Fatalf("admin list = %+v, %v", licenses, err)
	}
	lid := licenses[0].LID

	if out := h.ok("licenses", "list"); !strings.Contains(out, lid) || !strings.Contains(out, "online") || !strings.Contains(out, "2027-10-01") || !strings.Contains(out, "ok") {
		t.Errorf("list = %s", out)
	}
	// The default file name is <lid>.license in the working directory; an
	// existing file is never overwritten.
	target := filepath.Join(dir, "customer.license")
	h.ok("licenses", "download", lid, "--out", target)
	if saved, _ := os.ReadFile(target); string(saved) != string(token) {
		t.Errorf("downloaded = %q", saved)
	}
	if out := h.run("", "licenses", "download", lid, "--out", target); out.code != 1 || !strings.Contains(out.stderr, "already exists") {
		t.Errorf("overwrite = %+v", out)
	}
	if out := h.ok("licenses", "download", lid, "--out", "-"); out != string(token) {
		t.Errorf("stdout download = %q", out)
	}
	if out := h.run("", "licenses", "download", "lic-missing"); out.code != 1 || !strings.Contains(out.stderr, "licenseNotFound") {
		t.Errorf("missing = %+v", out)
	}

	if out := h.ok("admin", "licenses", "status", lid, "revoked"); !strings.Contains(out, "License "+lid+" is revoked.") {
		t.Errorf("status = %s", out)
	}
	if out := h.run("", "admin", "licenses", "status", lid, "paused"); out.code != 1 || !strings.Contains(out.stderr, "invalidLicenseStatus") {
		t.Errorf("bad status = %+v", out)
	}
	if out := h.ok("admin", "licenses", "token", lid, "--out", "-"); out != string(token) {
		t.Errorf("admin token = %q", out)
	}
	if out := h.run("", "admin", "licenses", "nope"); out.code != 2 {
		t.Errorf("unknown admin action = %+v", out)
	}
}

func TestExportCommands(t *testing.T) {
	h, fake := fakeHarness(t)
	fake.SetExportReads(2)
	dir := t.TempDir()
	passphraseFile := filepath.Join(dir, "passphrase")
	if err := os.WriteFile(passphraseFile, []byte("correct horse battery\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if out := h.run("", "export", "request"); out.code != 2 || !strings.Contains(out.stderr, "--passphrase-file") {
		t.Errorf("request without passphrase = %+v", out)
	}
	if out := h.run("short\n", "export", "request", "--passphrase-file", "-"); out.code != 2 || !strings.Contains(out.stderr, "at least 12") {
		t.Errorf("short passphrase = %+v", out)
	}
	out := h.ok("export", "request", "--passphrase-file", passphraseFile)
	if !strings.Contains(out, ": queued") || !strings.Contains(out, "rdnsctl export status job-") || !strings.Contains(out, "Keep the passphrase") {
		t.Fatalf("request = %s", out)
	}
	if body := lastBody(t, fake, "POST /v1/orgs/{orgId}/export"); body["passphrase"] != "correct horse battery" {
		t.Errorf("request body = %v", body)
	}
	jobID := strings.Fields(strings.TrimPrefix(out, "Export "))[0]
	if out := h.run("", "export", "request", "--passphrase-file", passphraseFile); out.code != 1 || !strings.Contains(out.stderr, "exportInProgress") {
		t.Errorf("second request = %+v", out)
	}
	if out := h.run("", "export", "download", jobID, "--out", filepath.Join(dir, "early.tar")); out.code != 1 || !strings.Contains(out.stderr, "not ready") {
		t.Errorf("early download = %+v", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "early.tar")); !os.IsNotExist(err) {
		t.Errorf("early download left a file: %v", err)
	}
	var export redundantdns.OrgExport
	if err := json.Unmarshal([]byte(h.ok("export", "status", jobID, "--json")), &export); err != nil || export.Status != redundantdns.ExportReady || export.DownloadPath != "" {
		t.Fatalf("status --json = %+v, %v", export, err)
	}
	if out := h.ok("export", "status", jobID); !strings.Contains(out, "ready") || !strings.Contains(out, "sha256 "+export.SHA256) {
		t.Errorf("status = %s", out)
	}
	bundle := filepath.Join(dir, "bundle.tar")
	result := h.run("", "export", "download", jobID, "--out", bundle)
	if result.code != 0 || !strings.Contains(result.stderr, "sha256 "+export.SHA256+" verified") {
		t.Fatalf("download = %+v", result)
	}
	data, err := os.ReadFile(bundle)
	sum := sha256.Sum256(data)
	if err != nil || hex.EncodeToString(sum[:]) != export.SHA256 {
		t.Errorf("bundle digest mismatch (%v)", err)
	}

	// --wait polls until the export is done.
	exportPollInterval = 0
	fake.SetExportReads(3)
	failFile := filepath.Join(dir, "fail")
	_ = os.WriteFile(failFile, []byte("fail on purpose please"), 0o600)
	if out := h.ok("export", "request", "--passphrase-file", failFile, "--wait"); !strings.Contains(out, ": failed") || !strings.Contains(out, "error: ") {
		t.Errorf("request --wait = %s", out)
	}
}

func TestComplianceCommand(t *testing.T) {
	h, fake := fakeHarness(t)

	out := h.run("", "compliance")
	if out.code != 0 || !strings.Contains(out.stdout, "(baseline) for organization "+fake.OrgID+": PASS") || !strings.Contains(out.stdout, "encryption.at_rest") ||
		strings.Contains(out.stdout, "To fix:") {
		t.Fatalf("compliance = %+v", out)
	}
	fake.SetCompliance(redundantdns.ComplianceWarn)
	out = h.run("", "compliance", "--profile", "soc2", "--scope", "platform")
	if out.code != 1 || !strings.Contains(out.stdout, "for the installation: WARN") || !strings.Contains(out.stdout, "audit.signed: Set RDNS_AUDIT_SIGNING_KEY.") {
		t.Errorf("compliance warn = %+v", out)
	}
	if request := lastRequestOf(t, fake, "GET /v1/compliance"); request.Query != "profile=soc2&scope=platform" {
		t.Errorf("query = %q", request.Query)
	}
	fake.SetCompliance(redundantdns.ComplianceFail)
	out = h.run("", "compliance", "run", "--profile", "iso27001", "--json")
	var report redundantdns.ComplianceReport
	if out.code != 2 || json.Unmarshal([]byte(out.stdout), &report) != nil || report.Status != redundantdns.ComplianceFail || report.Profile != "iso27001" {
		t.Errorf("compliance run = %+v", out)
	}
	if out := h.run("", "compliance", "last"); out.code != 2 || !strings.Contains(out.stdout, "FAIL") {
		t.Errorf("compliance last = %+v", out)
	}
	if out := h.run("", "compliance", "last", "--scope", "platform"); out.code != 0 || !strings.Contains(out.stdout, "No compliance report yet") {
		t.Errorf("compliance last platform = %+v", out)
	}
	// Usage and API errors exit 3, like rdns compliance.
	if out := h.run("", "compliance", "--profile", "hipaa"); out.code != 3 || !strings.Contains(out.stderr, "unknownProfile") {
		t.Errorf("unknown profile = %+v", out)
	}
	if out := h.run("", "compliance", "audit"); out.code != 3 || !strings.Contains(out.stderr, "unknown compliance command") {
		t.Errorf("unknown action = %+v", out)
	}
	if out := h.run("", "compliance", "--bogus"); out.code != 3 {
		t.Errorf("bad flag = %+v", out)
	}
	if out := h.ok("compliance", "--help"); !strings.Contains(out, "exit 0 pass, 1 warn, 2 fail, 3 error") {
		t.Errorf("help = %s", out)
	}
}

func TestAuditCommands(t *testing.T) {
	h, fake := fakeHarness(t)
	dir := t.TempDir()

	if out := h.ok("audit", "verify", "--from", "2026-09-01", "--to", "2026-09-24"); !strings.Contains(out, "2026-09-01 to 2026-09-24: OK") || !strings.Contains(out, "2 segments (1 sealed") {
		t.Errorf("verify = %s", out)
	}
	fake.TamperAuditStream()
	out := h.run("", "audit", "verify", "--json")
	var report redundantdns.AuditStreamReport
	if out.code != 1 || json.Unmarshal([]byte(out.stdout), &report) != nil || report.OK {
		t.Errorf("tampered verify --json = %+v", out)
	}
	if out := h.run("", "audit", "verify"); out.code != 1 || !strings.Contains(out.stdout, "FAILED") || !strings.Contains(out.stdout, "problem line_hash_mismatch") {
		t.Errorf("tampered verify = %+v", out)
	}
	if out := h.run("", "audit", "verify", "--from", "2026-09-24", "--to", "2026-09-01"); out.code != 1 || !strings.Contains(out.stderr, "invalidRange") {
		t.Errorf("reversed range = %+v", out)
	}

	if out := h.run("", "audit", "export", "--out", filepath.Join(dir, "a.tar")); out.code != 1 || !strings.Contains(out.stderr, "plan_limit_reached") {
		t.Errorf("export on free = %+v", out)
	}
	fake.SetPlan("business")
	target := filepath.Join(dir, "evidence.tar")
	if out := h.run("", "audit", "export", "--from", "2026-09-01", "--to", "2026-09-24", "--out", target); out.code != 0 || !strings.Contains(out.stderr, "verify.sh") {
		t.Fatalf("export = %+v", out)
	}
	if data, err := os.ReadFile(target); err != nil || !strings.Contains(string(data), "verify.sh") {
		t.Errorf("evidence bundle = %d bytes, %v", len(data), err)
	}
}

func TestOpsHelp(t *testing.T) {
	h := newHarness(t, nil)
	out := h.ok("help")
	for _, want := range []string{"licenses", "export", "audit", "compliance"} {
		if !strings.Contains(out, want) {
			t.Errorf("help lacks %s:\n%s", want, out)
		}
	}
	if out := h.ok("export", "--help"); !strings.Contains(out, "--passphrase-file FILE|-") || !strings.Contains(out, "download <jobId> [--out FILE|-]") {
		t.Errorf("export help = %s", out)
	}
	if out := h.ok("audit", "--help"); !strings.Contains(out, "verify [--from YYYY-MM-DD]") {
		t.Errorf("audit help = %s", out)
	}
}

func TestSafeName(t *testing.T) {
	cases := map[string]string{
		"rdns-org-20260925.tar": "rdns-org-20260925.tar",
		"../../etc/passwd":      "passwd",
		`..\..\evil.tar`:        "evil.tar",
		"/abs/path/x.license":   "x.license",
		"":                      "fallback",
		"..":                    "fallback",
		".hidden":               "fallback",
	}
	for name, want := range cases {
		if got := safeName(name, "fallback"); got != want {
			t.Errorf("safeName(%q) = %q, want %q", name, got, want)
		}
	}
}
