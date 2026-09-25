package rdnstest

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	redundantdns "github.com/redundantdns/go-client"
)

// Licenses, org exports, compliance and the audit stream of the fake, and
// the public plan catalog.
//
//   - Licenses: the caller owns the fake org and is a platform admin, so
//     both the customer routes (/v1/me/licenses) and the operator routes
//     (/v1/admin/licenses) answer. SetLicenseIssuer(false) removes the
//     signing key (503 license_issuer_unavailable); a license download is
//     limited to LicenseDownloadsPerHour.
//   - Org exports: a requested export is queued until its status has been
//     read SetExportReads(n) times (default 1: the first read finds it
//     ready); a passphrase starting with "fail" makes it fail. A ready
//     export hands out a one-time download link on every read.
//   - Compliance: every profile answers the same controls; SetCompliance
//     sets the report status (pass by default).
//   - Audit stream: TamperAuditStream makes the verification fail;
//     SetAuditStream(false) answers 503 auditStreamUnavailable. The
//     evidence bundle needs the business or enterprise plan (SetPlan).

// LicenseDownloadsPerHour is how many license files a user may download
// per hour (the platform's limit).
const LicenseDownloadsPerHour = 10

// DefaultExportReads is how many status reads a new export takes to be
// ready.
const DefaultExportReads = 1

// ComplianceProfiles are the profiles the fake knows.
var ComplianceProfiles = []string{redundantdns.ComplianceBaseline, redundantdns.ComplianceISO27001, redundantdns.ComplianceSOC2}

// fakeOps is the state of these modules.
type fakeOps struct {
	licenses         map[string]*fakeLicense
	licenseIssuer    bool
	licenseDownloads int
	exports          map[string]*fakeExport
	exportReads      int
	complianceStatus string
	lastCompliance   map[string]*redundantdns.ComplianceReport
	auditStream      bool
	auditTampered    bool
}

type fakeLicense struct {
	view  redundantdns.AdminLicense
	token string
}

type fakeExport struct {
	export    redundantdns.OrgExport
	readsLeft int
	fail      bool
	bundle    []byte
	token     string
}

func newFakeOps() fakeOps {
	return fakeOps{
		licenses: map[string]*fakeLicense{}, licenseIssuer: true,
		exports: map[string]*fakeExport{}, exportReads: DefaultExportReads,
		complianceStatus: redundantdns.CompliancePass, lastCompliance: map[string]*redundantdns.ComplianceReport{},
		auditStream: true,
	}
}

// SetLicenseIssuer turns the license signing key on (default) or off.
func (fake *Fake) SetLicenseIssuer(on bool) {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	fake.ops.licenseIssuer = on
}

// SeedLicense issues a license to the fake org without a request and
// returns its lid.
func (fake *Fake) SeedLicense(claims redundantdns.LicenseClaims) string {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	if claims.Acct == "" {
		claims.Acct = fake.OrgID
	}
	return fake.issueLicense(claims).view.LID
}

// SetExportReads sets how many status reads a new export takes to be ready
// (0 or 1: the first read).
func (fake *Fake) SetExportReads(reads int) {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	fake.ops.exportReads = reads
}

// SetCompliance sets the status of the fake's compliance reports: pass,
// warn or fail.
func (fake *Fake) SetCompliance(status string) {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	fake.ops.complianceStatus = status
}

// SetAuditStream turns the audit stream on (default) or off.
func (fake *Fake) SetAuditStream(on bool) {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	fake.ops.auditStream = on
}

// TamperAuditStream makes the next verifications find a changed line.
func (fake *Fake) TamperAuditStream() {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	fake.ops.auditTampered = true
}

func (fake *Fake) mountOps(handle func(string, handler)) {
	fake.mountLicenses(handle)
	fake.mountExports(handle)
	fake.mountCompliance(handle)
	fake.mountAuditStream(handle)
	handle("GET /v1/plans", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Cache-Control", "public, max-age=300")
		writeJSON(writer, http.StatusOK, FakePlanCatalog())
	})
}

// ------------------------------------------------------------ licenses

func (fake *Fake) mountLicenses(handle func(string, handler)) {
	handle("GET /v1/me/licenses", func(writer http.ResponseWriter, _ *http.Request) {
		licenses := []redundantdns.License{}
		for _, entry := range fake.sortedLicenses("") {
			if entry.view.Acct == fake.OrgID {
				licenses = append(licenses, customerLicense(entry.view))
			}
		}
		writeJSON(writer, http.StatusOK, licenses)
	})
	handle("GET /v1/me/licenses/{lid}/token", func(writer http.ResponseWriter, request *http.Request) {
		entry, ok := fake.ops.licenses[request.PathValue("lid")]
		if !ok || entry.view.Acct != fake.OrgID {
			writeError(writer, http.StatusNotFound, redundantdns.CodeLicenseNotFound, "license not found")
			return
		}
		if fake.ops.licenseDownloads >= LicenseDownloadsPerHour {
			writeError(writer, http.StatusTooManyRequests, redundantdns.CodeTooManyRequests, "too many license downloads; try again within the hour")
			return
		}
		fake.ops.licenseDownloads++
		writeJSON(writer, http.StatusOK, map[string]string{"lid": entry.view.LID, "token": entry.token, "filename": entry.view.LID + ".license"})
	})
	handle("GET /v1/admin/licenses", func(writer http.ResponseWriter, request *http.Request) {
		views := []redundantdns.AdminLicense{}
		for _, entry := range fake.sortedLicenses(request.URL.Query().Get("acct")) {
			views = append(views, entry.view)
		}
		writeJSON(writer, http.StatusOK, views)
	})
	handle("POST /v1/admin/licenses", func(writer http.ResponseWriter, request *http.Request) {
		if !fake.ops.licenseIssuer {
			writeError(writer, http.StatusServiceUnavailable, redundantdns.CodeLicenseIssuerUnavailable, "this control plane has no license signing key")
			return
		}
		var input struct {
			Claims *redundantdns.LicenseClaims `json:"claims"`
		}
		if !decode(writer, request, &input) {
			return
		}
		switch {
		case input.Claims == nil || strings.TrimSpace(input.Claims.Acct) == "":
			writeError(writer, http.StatusBadRequest, redundantdns.CodeInvalidClaims, "claims.acct (the customer organization id) is required")
			return
		case input.Claims.Acct != fake.OrgID:
			writeError(writer, http.StatusNotFound, redundantdns.CodeOrgNotFound, "no organization "+input.Claims.Acct)
			return
		case input.Claims.Mode != "" && input.Claims.Mode != redundantdns.LicenseModeOnline && input.Claims.Mode != redundantdns.LicenseModeOffline,
			input.Claims.Term != "" && input.Claims.Term != redundantdns.LicenseTermMonthly && input.Claims.Term != redundantdns.LicenseTermYearly:
			writeError(writer, http.StatusBadRequest, redundantdns.CodeInvalidClaims, "mode must be online or offline, term monthly or yearly")
			return
		}
		if _, exists := fake.ops.licenses[input.Claims.LID]; input.Claims.LID != "" && exists {
			writeError(writer, http.StatusConflict, redundantdns.CodeLicenseExists, "a license with this lid already exists")
			return
		}
		entry := fake.issueLicense(*input.Claims)
		answer := map[string]any{"license": entry.view, "token": entry.token}
		publishAnswer(entry.view, answer)
		writeJSON(writer, http.StatusCreated, answer)
	})
	handle("POST /v1/admin/licenses/{lid}/status", func(writer http.ResponseWriter, request *http.Request) {
		var input struct {
			Status string `json:"status"`
		}
		if !decode(writer, request, &input) {
			return
		}
		if !slices.Contains([]string{redundantdns.LicenseActive, redundantdns.LicenseSuspended, redundantdns.LicenseRevoked}, input.Status) {
			writeError(writer, http.StatusBadRequest, redundantdns.CodeInvalidLicenseStatus, "status must be active, suspended or revoked")
			return
		}
		entry, ok := fake.ops.licenses[request.PathValue("lid")]
		if !ok {
			writeError(writer, http.StatusNotFound, redundantdns.CodeLicenseNotFound, "license not found")
			return
		}
		answer := map[string]any{}
		if entry.view.Status != input.Status {
			now := time.Now().UTC().Truncate(time.Second)
			entry.view.Status, entry.view.StatusChangedAt, entry.view.UpdatedAt, entry.view.UpdatedBy = input.Status, now, now, "usr-test"
			publishAnswer(entry.view, answer)
		}
		answer["license"] = entry.view
		writeJSON(writer, http.StatusOK, answer)
	})
	handle("GET /v1/admin/licenses/{lid}/token", func(writer http.ResponseWriter, request *http.Request) {
		entry, ok := fake.ops.licenses[request.PathValue("lid")]
		if !ok {
			writeError(writer, http.StatusNotFound, redundantdns.CodeLicenseNotFound, "license not found")
			return
		}
		writeJSON(writer, http.StatusOK, map[string]string{"lid": entry.view.LID, "token": entry.token})
	})
}

// publishAnswer adds the attestation publication of an online license.
func publishAnswer(view redundantdns.AdminLicense, answer map[string]any) {
	if view.Claims.Mode == redundantdns.LicenseModeOnline {
		answer["published"] = true
		answer["publish"] = map[string]any{"accounts": 1, "records": 1}
	}
}

// issueLicense fills the defaults the platform applies and stores the
// license.
func (fake *Fake) issueLicense(claims redundantdns.LicenseClaims) *fakeLicense {
	now := time.Now().UTC().Truncate(time.Second)
	if claims.LID == "" {
		claims.LID = fmt.Sprintf("lic-%04d", fake.nextSequence())
	}
	claims.Product = orDefault(claims.Product, "rdns-enterprise")
	claims.Edition = orDefault(claims.Edition, "enterprise")
	claims.Mode = orDefault(claims.Mode, redundantdns.LicenseModeOffline)
	claims.Term = orDefault(claims.Term, redundantdns.LicenseTermYearly)
	if claims.IssuedAt == nil {
		claims.IssuedAt = &now
	}
	if claims.NotBefore == nil {
		claims.NotBefore = &now
	}
	if claims.Expires == nil {
		expires := claims.NotBefore.AddDate(1, 0, 0)
		if claims.Term == redundantdns.LicenseTermMonthly {
			expires = claims.NotBefore.AddDate(0, 1, 0)
		}
		claims.Expires = &expires
	}
	sum := sha256.Sum256([]byte(claims.Acct + "fake-salt"))
	claims.AcctHash, claims.KID = hex.EncodeToString(sum[:]), "fake-kid"
	view := redundantdns.AdminLicense{
		LID: claims.LID, Acct: claims.Acct, AcctHash: claims.AcctHash, Status: redundantdns.LicenseActive, Claims: claims,
		CreatedAt: now, CreatedBy: "usr-test", UpdatedAt: now, StatusChangedAt: now,
	}
	if claims.Mode == redundantdns.LicenseModeOnline {
		view.AttestationName = claims.AcctHash[:32] + ".licenses.example"
	}
	entry := &fakeLicense{view: view, token: "v4.public.fake-" + claims.LID}
	fake.ops.licenses[claims.LID] = entry
	return entry
}

func orDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func (fake *Fake) sortedLicenses(acct string) []*fakeLicense {
	entries := []*fakeLicense{}
	for _, entry := range fake.ops.licenses {
		if acct == "" || entry.view.Acct == acct {
			entries = append(entries, entry)
		}
	}
	slices.SortFunc(entries, func(left, right *fakeLicense) int { return strings.Compare(left.view.LID, right.view.LID) })
	return entries
}

func customerLicense(view redundantdns.AdminLicense) redundantdns.License {
	claims := view.Claims
	license := redundantdns.License{
		LID: view.LID, OrgID: view.Acct, Status: view.Status, Product: claims.Product, Edition: claims.Edition, Mode: claims.Mode,
		Term: claims.Term, Features: claims.Features, Limits: claims.Limits, GraceDays: 30, IssuedAt: claims.IssuedAt,
		NotBefore: claims.NotBefore, StatusChangedAt: view.StatusChangedAt,
	}
	if license.Features == nil {
		license.Features = []string{}
	}
	if claims.Term == redundantdns.LicenseTermMonthly {
		license.GraceDays = 10
	}
	if claims.Grace != nil {
		license.GraceDays = *claims.Grace
	}
	if claims.Expires != nil {
		license.ExpiresAt = *claims.Expires
	}
	if claims.Mode == redundantdns.LicenseModeOnline {
		license.Attestation = &redundantdns.LicenseAttestation{State: "ok", Standing: view.Status}
	}
	return license
}

// ------------------------------------------------------------ org exports

// isExportDownload reports whether path is a one-time export download.
func isExportDownload(path string) bool {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	return len(parts) == 6 && parts[0] == "v1" && parts[1] == "orgs" && parts[3] == "exports" && parts[5] == "download"
}

func (fake *Fake) mountExports(handle func(string, handler)) {
	handle("POST /v1/orgs/{orgId}/export", func(writer http.ResponseWriter, request *http.Request) {
		if !fake.ownOrg(writer, request) {
			return
		}
		var input struct {
			Passphrase string `json:"passphrase"`
		}
		if !decode(writer, request, &input) {
			return
		}
		if len([]rune(input.Passphrase)) < redundantdns.MinExportPassphrase {
			writeError(writer, http.StatusBadRequest, redundantdns.CodePassphraseInvalid, "the passphrase needs at least 12 characters")
			return
		}
		for _, entry := range fake.ops.exports {
			if entry.export.Status == redundantdns.ExportQueued {
				writeError(writer, http.StatusConflict, redundantdns.CodeExportInProgress, "an export of this organization is already queued")
				return
			}
		}
		entry := &fakeExport{
			export: redundantdns.OrgExport{
				JobID: fmt.Sprintf("job-%04d", fake.nextSequence()), OrgID: fake.OrgID, Status: redundantdns.ExportQueued,
				RequestedAt: time.Now().UTC().Truncate(time.Second),
			},
			readsLeft: fake.ops.exportReads, fail: strings.HasPrefix(input.Passphrase, "fail"),
		}
		fake.ops.exports[entry.export.JobID] = entry
		writeJSON(writer, http.StatusAccepted, map[string]any{"export": entry.export})
	})
	handle("GET /v1/orgs/{orgId}/exports/{jobId}", func(writer http.ResponseWriter, request *http.Request) {
		if !fake.ownOrg(writer, request) {
			return
		}
		entry, ok := fake.ops.exports[request.PathValue("jobId")]
		if !ok {
			writeError(writer, http.StatusNotFound, redundantdns.CodeExportNotFound, "export not found")
			return
		}
		fake.progressExport(entry)
		view := entry.export
		if view.Status == redundantdns.ExportReady {
			entry.token = fmt.Sprintf("tok%04d", fake.nextSequence())
			view.DownloadPath = "/v1/orgs/" + url.PathEscape(fake.OrgID) + "/exports/" + url.PathEscape(view.JobID) + "/download?token=" + entry.token
			view.DownloadURL = fake.URL + view.DownloadPath
		}
		writeJSON(writer, http.StatusOK, map[string]any{"export": view})
	})
	handle("GET /v1/orgs/{orgId}/exports/{jobId}/download", func(writer http.ResponseWriter, request *http.Request) {
		entry, ok := fake.ops.exports[request.PathValue("jobId")]
		if !ok || request.PathValue("orgId") != fake.OrgID {
			writeError(writer, http.StatusNotFound, redundantdns.CodeExportNotFound, "export not found")
			return
		}
		token := request.URL.Query().Get("token")
		if entry.export.Status != redundantdns.ExportReady || token == "" || token != entry.token {
			writeError(writer, http.StatusForbidden, redundantdns.CodeDownloadTokenInvalid, "this download link was already used or replaced: get a new one from the export")
			return
		}
		now := time.Now().UTC().Truncate(time.Second)
		entry.token = ""
		entry.export.Downloads++
		entry.export.LastDownloadAt = &now
		headers := writer.Header()
		headers.Set("Content-Type", "application/x-tar")
		headers.Set("Content-Length", strconv.Itoa(len(entry.bundle)))
		headers.Set("Content-Disposition", fmt.Sprintf(`attachment; filename="rdns-%s-%s.tar"`, fake.OrgID, now.Format("20060102")))
		headers.Set("X-RDNS-SHA256", entry.export.SHA256)
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(entry.bundle)
	})
}

// ownOrg answers 404 orgNotFound for another organization in the path.
func (fake *Fake) ownOrg(writer http.ResponseWriter, request *http.Request) bool {
	if request.PathValue("orgId") != fake.OrgID {
		writeError(writer, http.StatusForbidden, redundantdns.CodeForbidden, "this token belongs to another organization")
		return false
	}
	return true
}

// progressExport counts a status read and finishes the export when due.
func (fake *Fake) progressExport(entry *fakeExport) {
	if entry.export.Status != redundantdns.ExportQueued {
		return
	}
	entry.readsLeft--
	if entry.readsLeft > 0 {
		return
	}
	now := time.Now().UTC().Truncate(time.Second)
	if entry.fail {
		entry.export.Status, entry.export.Error = redundantdns.ExportFailed, "the bundle could not be written"
		return
	}
	manifest, _ := json.Marshal(map[string]any{"format": "rdns.orgbundle.v1", "orgId": fake.OrgID, "zones": len(fake.zones)})
	entry.bundle = tarFiles(map[string][]byte{"manifest.json": manifest, "keys.json": []byte(`{"kdf":"argon2id"}`)})
	sum := sha256.Sum256(entry.bundle)
	expires := now.Add(24 * time.Hour)
	entry.export.Status, entry.export.ReadyAt, entry.export.ExpiresAt = redundantdns.ExportReady, &now, &expires
	entry.export.Size, entry.export.SHA256, entry.export.Files, entry.export.Zones = int64(len(entry.bundle)), hex.EncodeToString(sum[:]), 2, len(fake.zones)
}

// tarFiles builds a tar of the files, sorted by name.
func tarFiles(files map[string][]byte) []byte {
	var buffer bytes.Buffer
	archive := tar.NewWriter(&buffer)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		_ = archive.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(files[name])), ModTime: time.Unix(0, 0)})
		_, _ = archive.Write(files[name])
	}
	_ = archive.Close()
	return buffer.Bytes()
}

// ------------------------------------------------------------ compliance

func (fake *Fake) mountCompliance(handle func(string, handler)) {
	handle("GET /v1/compliance", func(writer http.ResponseWriter, request *http.Request) {
		if report, ok := fake.complianceReport(writer, request, request.URL.Query().Get("profile")); ok {
			writeJSON(writer, http.StatusOK, report)
		}
	})
	handle("POST /v1/compliance/run", func(writer http.ResponseWriter, request *http.Request) {
		var input struct {
			Profile string `json:"profile"`
		}
		if !decode(writer, request, &input) {
			return
		}
		report, ok := fake.complianceReport(writer, request, input.Profile)
		if !ok {
			return
		}
		fake.ops.lastCompliance[report.Scope] = report
		writeJSON(writer, http.StatusOK, report)
	})
	handle("GET /v1/compliance/last", func(writer http.ResponseWriter, request *http.Request) {
		scope, ok := complianceScope(writer, request)
		if !ok {
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{"report": fake.ops.lastCompliance[scope]})
	})
}

func complianceScope(writer http.ResponseWriter, request *http.Request) (string, bool) {
	switch scope := request.URL.Query().Get("scope"); scope {
	case "", redundantdns.ComplianceScopeOrg:
		return redundantdns.ComplianceScopeOrg, true
	case redundantdns.ComplianceScopePlatform:
		return scope, true
	}
	writeError(writer, http.StatusBadRequest, redundantdns.CodeInvalidScope, "scope must be org or platform")
	return "", false
}

// complianceReport builds the report of a profile with the configured
// status: one control per outcome up to that status.
func (fake *Fake) complianceReport(writer http.ResponseWriter, request *http.Request, profile string) (*redundantdns.ComplianceReport, bool) {
	scope, ok := complianceScope(writer, request)
	if !ok {
		return nil, false
	}
	if profile == "" {
		profile = redundantdns.ComplianceBaseline
	}
	if !slices.Contains(ComplianceProfiles, profile) {
		writeJSON(writer, http.StatusBadRequest, map[string]any{
			"error": redundantdns.CodeUnknownProfile, "message": "unknown compliance profile " + strconv.Quote(profile),
			"details": map[string]any{"profiles": ComplianceProfiles},
		})
		return nil, false
	}
	now := time.Now().UTC().Truncate(time.Second)
	controls := []redundantdns.ComplianceControl{
		{ID: "encryption.at_rest", Title: "Secrets are encrypted at rest", Status: redundantdns.CompliancePass, Required: true,
			Evidence: []redundantdns.ComplianceEvidence{{Name: "algorithm", Value: "AES-256-GCM"}},
			Mapping:  redundantdns.ComplianceMapping{ISO27001: "A.8.24", SOC2: "CC6.1"}},
		{ID: "dns.redundancy", Title: "Every zone is served by two providers", Status: redundantdns.ComplianceNotApplicable,
			Evidence: []redundantdns.ComplianceEvidence{{Name: "zones", Value: len(fake.zones)}},
			Mapping:  redundantdns.ComplianceMapping{ISO27001: "A.8.14", SOC2: "A1.2"}},
	}
	status := fake.ops.complianceStatus
	summary := redundantdns.ComplianceSummary{Pass: 1, NotApplicable: 1}
	if status == redundantdns.ComplianceWarn || status == redundantdns.ComplianceFail {
		controls = append(controls, redundantdns.ComplianceControl{
			ID: "audit.signed", Title: "The audit stream is signed", Status: redundantdns.ComplianceWarn,
			Evidence: []redundantdns.ComplianceEvidence{{Name: "signed", Value: false}}, Mapping: redundantdns.ComplianceMapping{ISO27001: "A.8.15", SOC2: "CC7.2"},
			Remediation: "Set RDNS_AUDIT_SIGNING_KEY.",
		})
		summary.Warn++
	}
	if status == redundantdns.ComplianceFail {
		controls = append(controls, redundantdns.ComplianceControl{
			ID: "access.mfa", Title: "Owners use a second factor", Status: redundantdns.ComplianceFail, Required: true,
			Evidence: []redundantdns.ComplianceEvidence{{Name: "ownersWithoutMfa", Value: 1}}, Mapping: redundantdns.ComplianceMapping{ISO27001: "A.5.17", SOC2: "CC6.1"},
			Remediation: "Turn on a second factor for every owner.",
		})
		summary.Fail++
	}
	report := &redundantdns.ComplianceReport{
		Format: "rdns.compliance.v1", Profile: profile, ProfileTitle: strings.ToUpper(profile[:1]) + profile[1:], Scope: scope,
		Status: status, CheckedAt: now, Summary: summary, Controls: controls,
	}
	if scope == redundantdns.ComplianceScopeOrg {
		report.OrgID = fake.OrgID
	}
	return report, true
}

// ------------------------------------------------------------ audit stream

func (fake *Fake) mountAuditStream(handle func(string, handler)) {
	handle("GET /v1/audit/stream/verify", func(writer http.ResponseWriter, request *http.Request) {
		from, to, ok := fake.streamPeriod(writer, request)
		if !ok {
			return
		}
		now := time.Now().UTC().Truncate(time.Second)
		report := redundantdns.AuditStreamReport{
			Org: fake.OrgID, From: from, To: to, OK: true, Segments: 2, Lines: 12, Sealed: 1, Signed: 1, Open: 1, PlatformSeals: 1,
			FirstSeq: 1, LastSeq: 12, LastSeal: &now, Keys: []string{"audit-2026"},
			Problems: []redundantdns.AuditStreamProblem{}, Warnings: []redundantdns.AuditStreamProblem{}, CheckedAt: now,
		}
		if fake.ops.auditTampered {
			seq := 1
			report.OK = false
			report.Problems = append(report.Problems, redundantdns.AuditStreamProblem{
				Org: fake.OrgID, Day: to, Seq: &seq, Line: 3, Code: "line_hash_mismatch", Message: "line 3 does not match its hash",
			})
		}
		writeJSON(writer, http.StatusOK, report)
	})
	handle("GET /v1/audit/stream/export", func(writer http.ResponseWriter, request *http.Request) {
		if fake.plan != "business" && fake.plan != "enterprise" {
			writeJSON(writer, http.StatusPaymentRequired, map[string]any{
				"error": redundantdns.CodePlanLimitReached, "message": "the audit export needs the Business plan",
				"details": map[string]any{"action": "audit.export", "plan": fake.plan, "feature": "audit-export", "upgradeTo": "business", "upgradeName": "Business"},
			})
			return
		}
		from, to, ok := fake.streamPeriod(writer, request)
		if !ok {
			return
		}
		bundle := tarFiles(map[string][]byte{"README.md": []byte("RedundantDNS audit evidence\n"), "verify.sh": []byte("#!/bin/sh\n")})
		name := "rdns-audit-" + fake.OrgID + "-" + strings.ReplaceAll(from, "-", "") + "-" + strings.ReplaceAll(to, "-", "") + ".tar"
		writer.Header().Set("Content-Type", "application/x-tar")
		writer.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(bundle)
	})
}

// streamPeriod checks the stream is on and reads from/to (inclusive
// days, default the last 30).
func (fake *Fake) streamPeriod(writer http.ResponseWriter, request *http.Request) (string, string, bool) {
	if !fake.ops.auditStream {
		writeError(writer, http.StatusServiceUnavailable, redundantdns.CodeAuditStreamUnavailable, "the audit stream is not available on this instance")
		return "", "", false
	}
	now := time.Now().UTC()
	from, to := request.URL.Query().Get("from"), request.URL.Query().Get("to")
	if to == "" {
		to = now.Format(time.DateOnly)
	}
	if from == "" {
		from = now.AddDate(0, 0, -29).Format(time.DateOnly)
	}
	start, fromErr := time.Parse(time.DateOnly, from)
	end, toErr := time.Parse(time.DateOnly, to)
	if fromErr != nil || toErr != nil || end.Before(start) || end.Sub(start) > 365*24*time.Hour {
		writeError(writer, http.StatusBadRequest, redundantdns.CodeInvalidRange, "from and to must be days (YYYY-MM-DD), from before to, at most 366 days")
		return "", "", false
	}
	return from, to, true
}

// ------------------------------------------------------------ plans

// FakePlanCatalog is the catalog GET /v1/plans answers on the fake: the
// trial, monthly and yearly intervals on sale, and the four plans.
func FakePlanCatalog() redundantdns.PlanCatalog {
	limit := func(value int) *int { return &value }
	dollars := func(value float64) *float64 { return &value }
	cents := func(value int64) *int64 { return &value }
	readOnly, detach := 7, 30
	return redundantdns.PlanCatalog{
		Source: "api", Status: redundantdns.CatalogPublished, UpdatedAt: "2026-09-24", Currency: "USD",
		Intervals: []string{redundantdns.IntervalMonthly, redundantdns.IntervalYearly}, AnnualFreeMonths: 2,
		Managed: redundantdns.PlanManaged{MarkupPercent: 20, Billing: "monthly pass-through"},
		Grace:   redundantdns.PlanGrace{ReadOnlyAfterDays: &readOnly, DetachAfterDays: &detach},
		Trial: redundantdns.PlanTrial{
			Days: 30, Limits: redundantdns.PlanLimits{Zones: limit(1), ProvidersPerZone: limit(2)},
			Modes: []string{"byo"}, Alerts: []string{"email"}, Access: []string{"dashboard", "api"},
			Channels: []string{"email"}, Features: []string{"api"},
		},
		Plans: []redundantdns.CatalogPlan{
			{ID: "starter", Name: "Starter", PriceMonthly: dollars(9), Summary: "Small teams", Limits: redundantdns.PlanLimits{Zones: limit(3), ProvidersPerZone: limit(2)},
				Modes: []string{"byo", "managed"}, Alerts: []string{"email", "webhook"}, Access: []string{"dashboard", "api", "terraform", "cli"},
				PriceMonthlyCents: 900, Purchasable: true, Available: true, Channels: []string{"email", "webhook"}, Features: []string{"api", "terraform", "cli", "managed"}},
			{ID: "pro", Name: "Pro", PriceMonthly: dollars(99), Highlight: true, Summary: "Production DNS", Limits: redundantdns.PlanLimits{Zones: limit(50), ProvidersPerZone: limit(3)},
				Modes: []string{"byo", "managed"}, Alerts: []string{"email", "webhook", "slack", "multi-region-probes"}, Access: []string{"dashboard", "api", "terraform", "cli", "mcp"},
				PriceMonthlyCents: 9900, PriceYearlyCents: cents(99000), Purchasable: true, Available: true, Channels: []string{"email", "webhook", "slack"},
				Features: []string{"api", "terraform", "cli", "managed", "mcp", "multiRegionProbes"}},
			{ID: "business", Name: "Business", PriceMonthly: dollars(299), Summary: "Compliance", Limits: redundantdns.PlanLimits{},
				Modes: []string{"byo", "managed"}, Alerts: []string{"email", "webhook", "slack", "multi-region-probes", "history-90d"},
				Access: []string{"dashboard", "api", "terraform", "cli", "mcp", "audit-export", "priority-support"}, PriceMonthlyCents: 29900, PriceYearlyCents: cents(299000),
				Purchasable: true, Available: true, Channels: []string{"email", "webhook", "slack"}, Features: []string{"api", "terraform", "cli", "managed", "mcp", "auditExport"},
				AuditRetentionDays: limit(365)},
			{ID: "enterprise", Name: "Enterprise", Custom: true, Billing: "annual", Summary: "Self-hosted", Limits: redundantdns.PlanLimits{},
				Modes: []string{"byo", "managed", "self-hosted", "byo-data-plane"}, Alerts: []string{"email", "webhook", "slack", "multi-region-probes", "history-90d"},
				Access: []string{"dashboard", "api", "terraform", "cli", "mcp", "audit-export", "priority-support", "contract"}, Available: true,
				Channels: []string{"email", "webhook", "slack"}, Features: []string{"api", "terraform", "cli", "managed", "mcp", "auditExport", "selfHosted"},
				AuditRetentionCustom: true},
		},
		ManagedCosts: map[string]redundantdns.ManagedProviderCost{"route53": {ZoneMonthUSD: 0.5, PerMillionQueryUSD: 0.4}},
	}
}
