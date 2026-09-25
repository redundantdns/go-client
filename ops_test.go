package redundantdns_test

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	redundantdns "github.com/redundantdns/go-client"
	"github.com/redundantdns/go-client/rdnstest"
)

func TestFakeLicenses(t *testing.T) {
	fake := rdnstest.NewFake(t)
	client := newClient(t, fake.URL)
	ctx := context.Background()

	if licenses, err := client.Licenses.List(ctx); err != nil || len(licenses) != 0 {
		t.Fatalf("empty list = %+v, %v", licenses, err)
	}
	issued, err := client.Licenses.AdminIssue(ctx, redundantdns.LicenseClaims{Acct: " " + fake.OrgID + " ", Mode: redundantdns.LicenseModeOnline, Features: []string{"selfHosted"}})
	if err != nil {
		t.Fatal(err)
	}
	body := requestBody(t, fake, "POST /v1/admin/licenses")
	claims, _ := body["claims"].(map[string]any)
	if claims["acct"] != fake.OrgID || claims["mode"] != "online" || claims["exp"] != nil || claims["lid"] != nil {
		t.Errorf("issue body = %v", body)
	}
	license := issued.License
	if license.LID == "" || license.Acct != fake.OrgID || license.Status != redundantdns.LicenseActive || license.Claims.Product != "rdns-enterprise" ||
		license.Claims.Term != redundantdns.LicenseTermYearly || license.Claims.Expires == nil || license.AcctHash == "" || license.AttestationName == "" {
		t.Errorf("issued = %+v", license)
	}
	if !strings.HasPrefix(issued.Token, "v4.public.") || issued.Published == nil || !*issued.Published || len(issued.Publish) == 0 {
		t.Errorf("issue result = %+v", issued)
	}
	offline := fake.SeedLicense(redundantdns.LicenseClaims{Term: redundantdns.LicenseTermMonthly})

	licenses, err := client.Licenses.List(ctx)
	if err != nil || len(licenses) != 2 {
		t.Fatalf("list = %+v, %v", licenses, err)
	}
	if online := licenses[0]; online.LID != license.LID || online.Attestation == nil || online.Attestation.State != "ok" || online.GraceDays != 30 || online.ExpiresAt.IsZero() {
		t.Errorf("online license = %+v", online)
	}
	if monthly := licenses[1]; monthly.LID != offline || monthly.Attestation != nil || monthly.GraceDays != 10 {
		t.Errorf("offline license = %+v", monthly)
	}

	file, err := client.Licenses.Download(ctx, license.LID)
	if err != nil || file.Token != issued.Token || file.Filename != license.LID+".license" {
		t.Errorf("download = %+v, %v", file, err)
	}
	if _, err := client.Licenses.Download(ctx, "lic-missing"); !redundantdns.HasCode(err, redundantdns.CodeLicenseNotFound) || !errors.Is(err, redundantdns.ErrNotFound) {
		t.Errorf("download missing err = %v", err)
	}

	// Admin: list by account, status, token.
	if all, err := client.Licenses.AdminList(ctx, fake.OrgID); err != nil || len(all) != 2 || lastRequest(t, fake, "GET /v1/admin/licenses").Query != "acct="+fake.OrgID {
		t.Errorf("admin list = %d, %v", len(all), err)
	}
	if other, err := client.Licenses.AdminList(ctx, "org-other"); err != nil || len(other) != 0 {
		t.Errorf("admin list other = %+v, %v", other, err)
	}
	suspended, err := client.Licenses.AdminSetStatus(ctx, license.LID, redundantdns.LicenseSuspended)
	if err != nil || suspended.License.Status != redundantdns.LicenseSuspended || suspended.Published == nil {
		t.Errorf("suspend = %+v, %v", suspended, err)
	}
	if again, err := client.Licenses.AdminSetStatus(ctx, license.LID, redundantdns.LicenseSuspended); err != nil || again.Published != nil {
		t.Errorf("same status again = %+v, %v", again, err)
	}
	if _, err := client.Licenses.AdminSetStatus(ctx, license.LID, "paused"); !redundantdns.HasCode(err, redundantdns.CodeInvalidLicenseStatus) || !errors.Is(err, redundantdns.ErrBadRequest) {
		t.Errorf("invalid status err = %v", err)
	}
	if _, err := client.Licenses.AdminSetStatus(ctx, "lic-missing", redundantdns.LicenseRevoked); !redundantdns.HasCode(err, redundantdns.CodeLicenseNotFound) {
		t.Errorf("status missing err = %v", err)
	}
	if token, err := client.Licenses.AdminToken(ctx, license.LID); err != nil || token.Token != issued.Token || token.Filename != license.LID+".license" {
		t.Errorf("admin token = %+v, %v", token, err)
	}

	// Issue errors.
	if _, err := client.Licenses.AdminIssue(ctx, redundantdns.LicenseClaims{Acct: "org-other"}); !redundantdns.HasCode(err, redundantdns.CodeOrgNotFound) {
		t.Errorf("issue other org err = %v", err)
	}
	if _, err := client.Licenses.AdminIssue(ctx, redundantdns.LicenseClaims{}); !redundantdns.HasCode(err, redundantdns.CodeInvalidClaims) {
		t.Errorf("issue without acct err = %v", err)
	}
	if _, err := client.Licenses.AdminIssue(ctx, redundantdns.LicenseClaims{Acct: fake.OrgID, LID: license.LID}); !redundantdns.HasCode(err, redundantdns.CodeLicenseExists) ||
		!errors.Is(err, redundantdns.ErrConflict) {
		t.Errorf("issue duplicate err = %v", err)
	}
	fake.SetLicenseIssuer(false)
	if _, err := client.Licenses.AdminIssue(ctx, redundantdns.LicenseClaims{Acct: fake.OrgID}); !redundantdns.HasCode(err, redundantdns.CodeLicenseIssuerUnavailable) ||
		!errors.Is(err, redundantdns.ErrServer) {
		t.Errorf("issue without signer err = %v", err)
	}
}

func TestFakeLicenseDownloadLimit(t *testing.T) {
	fake := rdnstest.NewFake(t)
	client := newClient(t, fake.URL, redundantdns.WithRetryPolicy(redundantdns.NoRetry()))
	lid := fake.SeedLicense(redundantdns.LicenseClaims{})
	for range rdnstest.LicenseDownloadsPerHour {
		if _, err := client.Licenses.Download(context.Background(), lid); err != nil {
			t.Fatal(err)
		}
	}
	_, err := client.Licenses.Download(context.Background(), lid)
	if !redundantdns.HasCode(err, redundantdns.CodeTooManyRequests) || !errors.Is(err, redundantdns.ErrRateLimited) {
		t.Errorf("11th download err = %v", err)
	}
}

func TestFakeOrgExport(t *testing.T) {
	fake := rdnstest.NewFake(t)
	fake.SetExportReads(2)
	client := newClient(t, fake.URL)
	ctx := context.Background()

	// A short passphrase is refused before any request.
	if _, err := client.Exports.Request(ctx, "short"); err == nil || len(fake.Requests()) != 0 {
		t.Fatalf("short passphrase err = %v", err)
	}
	export, err := client.Exports.Request(ctx, "correct horse battery")
	if err != nil || export.Status != redundantdns.ExportQueued || export.JobID == "" || export.OrgID != fake.OrgID {
		t.Fatalf("request = %+v, %v", export, err)
	}
	// Without WithOrg the client finds the token's only organization.
	if request := lastRequest(t, fake, "POST /v1/orgs/{orgId}/export"); request.Path != "/v1/orgs/"+fake.OrgID+"/export" {
		t.Errorf("request path = %s", request.Path)
	}
	if body := requestBody(t, fake, "POST /v1/orgs/{orgId}/export"); body["passphrase"] != "correct horse battery" {
		t.Errorf("request body = %v", body)
	}
	if _, err := client.Exports.Request(ctx, "another passphrase"); !redundantdns.HasCode(err, redundantdns.CodeExportInProgress) || !errors.Is(err, redundantdns.ErrConflict) {
		t.Errorf("second request err = %v", err)
	}

	// Queued: the download says so.
	if _, err := client.Exports.Download(ctx, export.JobID); !errors.Is(err, redundantdns.ErrExportNotReady) {
		t.Fatalf("download queued err = %v", err)
	}
	status, err := client.Exports.Status(ctx, export.JobID)
	if err != nil || status.Status != redundantdns.ExportReady || status.SHA256 == "" || status.DownloadPath == "" || status.DownloadURL != fake.URL+status.DownloadPath || status.ExpiresAt == nil {
		t.Fatalf("status = %+v, %v", status, err)
	}
	staleLink := status.DownloadURL

	bound := client.WithOrg(fake.OrgID)
	download, err := bound.Exports.Download(ctx, export.JobID)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(download)
	_ = download.Close()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != download.SHA256 || download.SHA256 != status.SHA256 || download.ContentType != "application/x-tar" ||
		!strings.HasPrefix(download.Filename, "rdns-"+fake.OrgID+"-") || download.Size != int64(len(data)) {
		t.Errorf("download = %+v (%d bytes)", download, len(data))
	}
	if names := tarNames(t, data); !strings.Contains(names, "manifest.json") {
		t.Errorf("bundle files = %s", names)
	}
	// The link of the previous status read no longer works.
	answer, err := http.Get(staleLink) //nolint:gosec,noctx // test URL from the fake
	if err != nil {
		t.Fatal(err)
	}
	_ = answer.Body.Close()
	if answer.StatusCode != http.StatusForbidden {
		t.Errorf("stale link status = %d", answer.StatusCode)
	}

	if _, err := client.Exports.Status(ctx, "job-missing"); !redundantdns.HasCode(err, redundantdns.CodeExportNotFound) {
		t.Errorf("missing export err = %v", err)
	}
	if _, err := client.WithOrg("org-other").Exports.Status(ctx, export.JobID); !errors.Is(err, redundantdns.ErrForbidden) {
		t.Errorf("other org err = %v", err)
	}

	// A failed export.
	fake.SetExportReads(1)
	failed, err := client.Exports.Request(ctx, "fail this export please")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Exports.Download(ctx, failed.JobID); !errors.Is(err, redundantdns.ErrExportNotReady) || !strings.Contains(err.Error(), "failed") {
		t.Errorf("failed download err = %v", err)
	}
}

func TestExportDownloadIsNotRetried(t *testing.T) {
	var downloads int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case strings.HasSuffix(request.URL.Path, "/download"):
			downloads++
			if request.URL.Query().Get("token") != "abc" {
				t.Errorf("token = %q", request.URL.RawQuery)
			}
			writer.WriteHeader(http.StatusBadGateway)
		case strings.Contains(request.URL.Path, "/exports/"):
			_ = json.NewEncoder(writer).Encode(map[string]any{"export": map[string]any{
				"jobId": "job-1", "status": "ready", "sha256": "ff", "downloadPath": "/v1/orgs/org-1/exports/job-1/download?token=abc",
				"downloadUrl": "https://elsewhere.example/v1/orgs/org-1/exports/job-1/download?token=abc",
			}})
		}
	}))
	defer server.Close()
	client := newClient(t, server.URL, redundantdns.WithOrg("org-1"))
	_, err := client.Exports.Download(context.Background(), "job-1")
	if !errors.Is(err, redundantdns.ErrServer) || downloads != 1 {
		t.Errorf("download err = %v after %d attempts", err, downloads)
	}
}

func TestResolveOrgNeedsOneOrganization(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`[{"orgId":"a"},{"orgId":"b"}]`))
	}))
	defer server.Close()
	client := newClient(t, server.URL)
	if _, err := client.Exports.Status(context.Background(), "job-1"); err == nil || !strings.Contains(err.Error(), "WithOrg") {
		t.Errorf("two orgs err = %v", err)
	}
}

func TestFakeCompliance(t *testing.T) {
	fake := rdnstest.NewFake(t)
	client := newClient(t, fake.URL)
	ctx := context.Background()

	if last, err := client.Compliance.Last(ctx, ""); err != nil || last != nil {
		t.Fatalf("last before a run = %+v, %v", last, err)
	}
	report, err := client.Compliance.Report(ctx, "", "")
	if err != nil || report.Profile != redundantdns.ComplianceBaseline || report.Scope != redundantdns.ComplianceScopeOrg || report.OrgID != fake.OrgID ||
		report.Status != redundantdns.CompliancePass || report.ExitCode() != 0 || len(report.Controls) != 2 || report.Summary.Pass != 1 {
		t.Fatalf("report = %+v, %v", report, err)
	}
	control := report.Controls[0]
	if !control.Required || control.Mapping.ISO27001 == "" || len(control.Evidence) != 1 || control.Evidence[0].Value != "AES-256-GCM" {
		t.Errorf("control = %+v", control)
	}
	if request := lastRequest(t, fake, "GET /v1/compliance"); request.Query != "" {
		t.Errorf("default query = %q", request.Query)
	}

	fake.SetCompliance(redundantdns.ComplianceWarn)
	if report, err := client.Compliance.Report(ctx, redundantdns.ComplianceSOC2, redundantdns.ComplianceScopePlatform); err != nil ||
		report.Status != redundantdns.ComplianceWarn || report.ExitCode() != 1 || report.Scope != redundantdns.ComplianceScopePlatform || report.OrgID != "" {
		t.Errorf("platform report = %+v, %v", report, err)
	}
	if request := lastRequest(t, fake, "GET /v1/compliance"); request.Query != "profile=soc2&scope=platform" {
		t.Errorf("query = %q", request.Query)
	}

	fake.SetCompliance(redundantdns.ComplianceFail)
	run, err := client.Compliance.Run(ctx, redundantdns.ComplianceISO27001, "")
	if err != nil || run.Status != redundantdns.ComplianceFail || run.ExitCode() != 2 || run.Summary.Fail != 1 || run.Profile != "iso27001" {
		t.Fatalf("run = %+v, %v", run, err)
	}
	if body := requestBody(t, fake, "POST /v1/compliance/run"); body["profile"] != "iso27001" {
		t.Errorf("run body = %v", body)
	}
	if last, err := client.Compliance.Last(ctx, redundantdns.ComplianceScopeOrg); err != nil || last == nil || last.Profile != "iso27001" || last.Status != redundantdns.ComplianceFail {
		t.Errorf("last = %+v, %v", last, err)
	}
	if last, err := client.Compliance.Last(ctx, redundantdns.ComplianceScopePlatform); err != nil || last != nil {
		t.Errorf("platform last = %+v, %v", last, err)
	}

	_, err = client.Compliance.Report(ctx, "hipaa", "")
	var apiError *redundantdns.APIError
	if !redundantdns.HasCode(err, redundantdns.CodeUnknownProfile) || !errors.As(err, &apiError) || !strings.Contains(string(apiError.Details), "iso27001") {
		t.Errorf("unknown profile err = %v", err)
	}
	if _, err := client.Compliance.Report(ctx, "", "galaxy"); !redundantdns.HasCode(err, redundantdns.CodeInvalidScope) {
		t.Errorf("invalid scope err = %v", err)
	}
}

func TestFakeAuditStream(t *testing.T) {
	fake := rdnstest.NewFake(t)
	client := newClient(t, fake.URL)
	ctx := context.Background()

	report, err := client.Audit.Verify(ctx, "", "")
	if err != nil || !report.OK || report.Org != fake.OrgID || report.Segments != 2 || report.From == "" || len(report.Problems) != 0 || report.LastSeal == nil {
		t.Fatalf("verify = %+v, %v", report, err)
	}
	if report, err := client.Audit.Verify(ctx, "2026-09-01", "2026-09-24"); err != nil || report.From != "2026-09-01" || report.To != "2026-09-24" {
		t.Errorf("verify period = %+v, %v", report, err)
	}
	if request := lastRequest(t, fake, "GET /v1/audit/stream/verify"); request.Query != "from=2026-09-01&to=2026-09-24" {
		t.Errorf("verify query = %q", request.Query)
	}
	if _, err := client.Audit.Verify(ctx, "2026-09-24", "2026-09-01"); !redundantdns.HasCode(err, redundantdns.CodeInvalidRange) {
		t.Errorf("reversed range err = %v", err)
	}
	fake.TamperAuditStream()
	if report, err := client.Audit.Verify(ctx, "", ""); err != nil || report.OK || len(report.Problems) != 1 || report.Problems[0].Seq == nil {
		t.Errorf("tampered verify = %+v, %v", report, err)
	}

	// The evidence bundle needs the audit-export feature.
	if _, err := client.Audit.Export(ctx, "", ""); !redundantdns.HasCode(err, redundantdns.CodePlanLimitReached) || !errors.Is(err, redundantdns.ErrPaymentRequired) {
		t.Errorf("export on free err = %v", err)
	}
	fake.SetPlan("business")
	fake.FailNext(http.StatusServiceUnavailable)
	download, err := client.Audit.Export(ctx, "2026-09-01", "2026-09-24")
	if err != nil {
		t.Fatalf("export after a 503: %v", err)
	}
	data, _ := io.ReadAll(download)
	_ = download.Close()
	if download.Filename != "rdns-audit-"+fake.OrgID+"-20260901-20260924.tar" || download.ContentType != "application/x-tar" || !strings.Contains(tarNames(t, data), "verify.sh") {
		t.Errorf("export = %+v", download)
	}
	if accept := lastRequest(t, fake, "GET /v1/audit/stream/export").Header.Get("Accept"); !strings.Contains(accept, "application/x-tar") {
		t.Errorf("export Accept = %q", accept)
	}

	fake.SetAuditStream(false)
	if _, err := client.Audit.Verify(ctx, "", ""); !redundantdns.HasCode(err, redundantdns.CodeAuditStreamUnavailable) || !errors.Is(err, redundantdns.ErrServer) {
		t.Errorf("verify without stream err = %v", err)
	}
}

func TestFakePlanCatalog(t *testing.T) {
	fake := rdnstest.NewFake(t)
	// The catalog is public: no token.
	anonymous, err := redundantdns.New(redundantdns.WithBaseURL(fake.URL), redundantdns.WithRetryPolicy(fastRetry))
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := anonymous.Plans.Catalog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if catalog.Trial.Days != 30 || catalog.Trial.Limits.Zones == nil || *catalog.Trial.Limits.Zones != 1 || !catalog.IntervalOnSale(redundantdns.IntervalYearly) ||
		catalog.Status != redundantdns.CatalogPublished || len(catalog.Plans) != 4 || catalog.Plan("trial") != nil {
		t.Errorf("catalog = %+v", catalog)
	}
	business := catalog.Plan("business")
	if business == nil || business.Limits.Zones != nil || business.PriceYearlyCents == nil || *business.AuditRetentionDays != 365 {
		t.Errorf("business = %+v", business)
	}
	if enterprise := catalog.Plan("enterprise"); enterprise == nil || enterprise.PriceMonthly != nil || !enterprise.Custom || !enterprise.AuditRetentionCustom {
		t.Errorf("enterprise = %+v", enterprise)
	}
}

func TestPlanCatalogDefaultsToMonthly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`{"source":"api","status":"coming_soon","currency":"USD","trial":{"days":30,"limits":{"zones":1,"providersPerZone":2}},"plans":[]}`))
	}))
	defer server.Close()
	catalog, err := newClient(t, server.URL).Plans.Catalog(context.Background())
	if err != nil || len(catalog.Intervals) != 1 || !catalog.IntervalOnSale(redundantdns.IntervalMonthly) || catalog.IntervalOnSale(redundantdns.IntervalYearly) {
		t.Errorf("catalog = %+v, %v", catalog, err)
	}
}

func TestOpsErrorSentinels(t *testing.T) {
	cases := []struct {
		status int
		code   string
		target error
	}{
		{http.StatusGone, redundantdns.CodeExportExpired, redundantdns.ErrGone},
		{http.StatusServiceUnavailable, redundantdns.CodeLicenseDegraded, redundantdns.ErrLicenseDegraded},
		{http.StatusServiceUnavailable, redundantdns.CodeLicenseDegraded, redundantdns.ErrServer},
		{http.StatusForbidden, redundantdns.CodeDownloadTokenInvalid, redundantdns.ErrForbidden},
	}
	for _, testCase := range cases {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(testCase.status)
			_, _ = writer.Write([]byte(`{"error":"` + testCase.code + `","message":"m"}`))
		}))
		client := newClient(t, server.URL, redundantdns.WithRetryPolicy(redundantdns.NoRetry()), redundantdns.WithOrg("org-1"))
		_, err := client.Exports.Status(context.Background(), "job-1")
		if !errors.Is(err, testCase.target) || !redundantdns.HasCode(err, testCase.code) {
			t.Errorf("%d %s: err = %v", testCase.status, testCase.code, err)
		}
		if testCase.code != redundantdns.CodeLicenseDegraded && errors.Is(err, redundantdns.ErrLicenseDegraded) {
			t.Errorf("%s matched ErrLicenseDegraded", testCase.code)
		}
		server.Close()
	}
}

// tarNames lists the file names of a tar.
func tarNames(t *testing.T, data []byte) string {
	t.Helper()
	reader := tar.NewReader(bytes.NewReader(data))
	var names []string
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return strings.Join(names, ",")
		}
		if err != nil {
			t.Fatalf("read tar: %v", err)
		}
		names = append(names, header.Name)
	}
}

// requestBody decodes the JSON body of the last request of a pattern.
func requestBody(t *testing.T, fake *rdnstest.Fake, pattern string) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(lastRequest(t, fake, pattern).Body, &body); err != nil {
		t.Fatalf("decode %s body: %v", pattern, err)
	}
	return body
}
