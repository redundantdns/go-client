package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	redundantdns "github.com/redundantdns/go-client"
)

// Licenses, org export, compliance and the audit stream.

// Usage lines.
const (
	licensesDownloadUsage = "rdnsctl licenses download <lid> [--out FILE|-]"
	adminLicensesUsage    = "rdnsctl admin licenses list [--acct ORG_ID] | issue --acct ORG_ID [issue flags] [--out FILE|-] | " +
		"status <lid> active|suspended|revoked | token <lid> [--out FILE|-]"
	adminLicenseIssueFlags = "issue flags: --mode online|offline --term monthly|yearly --product P --edition E --feature F (repeatable) " +
		"--zones N --providers N --data-planes N --grace DAYS --bind SHA256 --expires YYYY-MM-DD|RFC3339 --lid ID"
	exportRequestUsage  = "rdnsctl export request --passphrase-file FILE|- [--wait]"
	exportStatusUsage   = "rdnsctl export status <jobId>"
	exportDownloadUsage = "rdnsctl export download <jobId> [--out FILE|-]"
	complianceUsage     = "rdnsctl compliance [run|last] [--profile baseline|iso27001|soc2|<extra>] [--scope org|platform] [--json]"
	auditVerifyUsage    = "rdnsctl audit verify [--from YYYY-MM-DD] [--to YYYY-MM-DD] [--json]"
	auditExportUsage    = "rdnsctl audit export [--from YYYY-MM-DD] [--to YYYY-MM-DD] [--out FILE|-]"
)

// Exit codes of rdnsctl compliance, as `rdns compliance`: the report's
// status, or complianceExitError when there is no report.
const (
	complianceExitError = 3
)

// exportPollInterval is how often export request --wait reads the status.
var exportPollInterval = 2 * time.Second

func opsGroups() map[string]group {
	return map[string]group{
		"licenses": {summary: "Licenses of your self-hosted installations", subcommands: map[string]command{
			"list":     {summary: "List the licenses of the organization", usage: "rdnsctl licenses list", run: runLicensesList},
			"download": {summary: "Save a license file (owners; 10 per hour)", usage: licensesDownloadUsage, run: runLicensesDownload},
		}},
		"export": {summary: "Export the whole organization, secrets included (owners)", subcommands: map[string]command{
			"request":  {summary: "Queue the export bundle, sealed with a passphrase", usage: exportRequestUsage, run: runExportRequest},
			"status":   {summary: "Show an export", usage: exportStatusUsage, run: runExportStatus},
			"download": {summary: "Download a ready export bundle and check its SHA-256", usage: exportDownloadUsage, run: runExportDownload},
		}},
		"audit": {summary: "Audit stream (org admins)", subcommands: map[string]command{
			"verify": {summary: "Verify the hash chain and seals of the audit stream; exit 1 when it fails", usage: auditVerifyUsage, run: runAuditVerify},
			"export": {summary: "Download the evidence bundle for an auditor (audit export plans)", usage: auditExportUsage, run: runAuditExport},
		}},
	}
}

// ------------------------------------------------------------ licenses

func runLicensesList(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	client, _, err := cli.begin(newFlagSet("licenses list", shared), shared, args, 0, "rdnsctl licenses list")
	if err != nil {
		return err
	}
	licenses, err := client.Licenses.List(ctx)
	if err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(licenses)
	}
	if len(licenses) == 0 {
		fmt.Fprintln(cli.stdout, "No licenses.")
		return nil
	}
	table := cli.table("LID", "STATUS", "PRODUCT", "EDITION", "MODE", "TERM", "EXPIRES", "ATTESTATION")
	for _, license := range licenses {
		attestation := "-"
		if license.Attestation != nil {
			attestation = license.Attestation.State
		}
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", license.LID, license.Status, license.Product, license.Edition, license.Mode,
			dash(license.Term), formatDate(&license.ExpiresAt), attestation)
	}
	return table.Flush()
}

func runLicensesDownload(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	flags := newFlagSet("licenses download", shared)
	out := flags.String("out", "", "file to write (default <lid>.license; - for stdout)")
	client, positionals, err := cli.begin(flags, shared, args, 1, licensesDownloadUsage)
	if err != nil {
		return err
	}
	file, err := client.Licenses.Download(ctx, positionals[0])
	if err != nil {
		return err
	}
	return cli.saveLicense(file, *out)
}

// saveLicense writes a license file (mode 0600; it is a secret).
func (cli *app) saveLicense(file *redundantdns.LicenseFile, out string) error {
	target := firstNonEmpty(out, safeName(file.Filename, file.LID+".license"))
	written, err := cli.writeOutput(target, strings.NewReader(file.Token+"\n"), nil)
	if err != nil {
		return err
	}
	if target != "-" {
		fmt.Fprintf(cli.stderr, "Saved license %s to %s (%d bytes). Install it on the self-hosted installation (RDNS_LICENSE_FILE).\n", file.LID, target, written)
	}
	return nil
}

func runAdminLicenses(ctx context.Context, cli *app, args []string) error {
	if len(args) == 0 {
		return usagef("usage: %s\n%s", adminLicensesUsage, adminLicenseIssueFlags)
	}
	action, rest := args[0], args[1:]
	switch action {
	case "list":
		return runAdminLicensesList(ctx, cli, rest)
	case "issue":
		return runAdminLicensesIssue(ctx, cli, rest)
	case "status":
		return runAdminLicensesStatus(ctx, cli, rest)
	case "token":
		return runAdminLicensesToken(ctx, cli, rest)
	}
	return usagef("usage: %s\n%s", adminLicensesUsage, adminLicenseIssueFlags)
}

func runAdminLicensesList(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	flags := newFlagSet("admin licenses list", shared)
	acct := flags.String("acct", "", "only the licenses of this organization")
	client, _, err := cli.begin(flags, shared, args, 0, "rdnsctl admin licenses list [--acct ORG_ID]")
	if err != nil {
		return err
	}
	licenses, err := adminClient(client).Licenses.AdminList(ctx, *acct)
	if err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(licenses)
	}
	table := cli.table("LID", "ACCT", "STATUS", "MODE", "TERM", "EXPIRES", "CREATED")
	for _, license := range licenses {
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", license.LID, license.Acct, license.Status, dash(license.Claims.Mode), dash(license.Claims.Term),
			formatDate(license.Claims.Expires), formatDate(&license.CreatedAt))
	}
	return table.Flush()
}

func runAdminLicensesIssue(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	flags := newFlagSet("admin licenses issue", shared)
	acct := flags.String("acct", "", "the customer organization id (required)")
	mode := flags.String("mode", "", "online or offline (default offline)")
	term := flags.String("term", "", "monthly or yearly (default yearly)")
	product := flags.String("product", "", "product (default rdns-enterprise)")
	edition := flags.String("edition", "", "edition (default enterprise)")
	var features multiFlag
	flags.Var(&features, "feature", "a licensed feature (repeatable)")
	zones := flags.Int("zones", 0, "zone limit (0: the edition's)")
	providers := flags.Int("providers", 0, "provider limit (0: the edition's)")
	dataPlanes := flags.Int("data-planes", 0, "data plane limit (0: the edition's)")
	grace := flags.Int("grace", -1, "grace period in days (default: the term's)")
	bind := flags.String("bind", "", "hex SHA-256 of the installation id to bind the license to")
	expires := flags.String("expires", "", "expiry, YYYY-MM-DD or RFC 3339 (default one term after now)")
	lid := flags.String("lid", "", "license id (default generated)")
	out := flags.String("out", "", "also save the license file (- for stdout)")
	usage := "rdnsctl admin licenses issue --acct ORG_ID [issue flags] [--out FILE|-]\n" + adminLicenseIssueFlags
	client, _, err := cli.begin(flags, shared, args, 0, usage)
	if err != nil {
		return err
	}
	if strings.TrimSpace(*acct) == "" {
		return usagef("name the customer organization with --acct\nusage: %s", usage)
	}
	claims := redundantdns.LicenseClaims{
		Acct: *acct, Mode: *mode, Term: *term, Product: *product, Edition: *edition, Features: features, Bind: *bind, LID: *lid,
		Limits: redundantdns.LicenseLimits{Zones: *zones, Providers: *providers, DataPlanes: *dataPlanes},
	}
	if *grace >= 0 {
		claims.Grace = grace
	}
	if *expires != "" {
		at, err := parseDateOrTime(*expires)
		if err != nil {
			return usagef("--expires: %v", err)
		}
		claims.Expires = &at
	}
	result, err := adminClient(client).Licenses.AdminIssue(ctx, claims)
	if err != nil {
		return err
	}
	if *out != "" {
		file := &redundantdns.LicenseFile{LID: result.License.LID, Token: result.Token, Filename: result.License.LID + ".license"}
		if err := cli.saveLicense(file, *out); err != nil {
			return err
		}
	}
	if shared.jsonOutput {
		return cli.printJSON(result)
	}
	license := result.License
	fmt.Fprintf(cli.stdout, "Issued license %s to %s: %s %s, %s, %s, expires %s.\n", license.LID, license.Acct, license.Claims.Product, license.Claims.Edition,
		license.Claims.Mode, license.Claims.Term, formatDate(license.Claims.Expires))
	cli.printPublish(result)
	if *out == "" {
		fmt.Fprintf(cli.stdout, "Save the license file with: rdnsctl admin licenses token %s --out %s.license\n", license.LID, license.LID)
	}
	return nil
}

// printPublish tells whether an online license's attestation was published.
func (cli *app) printPublish(result *redundantdns.AdminLicenseResult) {
	if result.Published == nil {
		return
	}
	if *result.Published {
		fmt.Fprintln(cli.stdout, "Attestation published.")
		return
	}
	fmt.Fprintf(cli.stdout, "Attestation not published yet (%s); the hourly pass will retry.\n", dash(result.PublishError))
}

func runAdminLicensesStatus(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	usage := "rdnsctl admin licenses status <lid> active|suspended|revoked"
	client, positionals, err := cli.begin(newFlagSet("admin licenses status", shared), shared, args, 2, usage)
	if err != nil {
		return err
	}
	result, err := adminClient(client).Licenses.AdminSetStatus(ctx, positionals[0], positionals[1])
	if err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(result)
	}
	fmt.Fprintf(cli.stdout, "License %s is %s.\n", result.License.LID, result.License.Status)
	cli.printPublish(result)
	return nil
}

func runAdminLicensesToken(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	flags := newFlagSet("admin licenses token", shared)
	out := flags.String("out", "", "file to write (default <lid>.license; - for stdout)")
	client, positionals, err := cli.begin(flags, shared, args, 1, "rdnsctl admin licenses token <lid> [--out FILE|-]")
	if err != nil {
		return err
	}
	file, err := adminClient(client).Licenses.AdminToken(ctx, positionals[0])
	if err != nil {
		return err
	}
	return cli.saveLicense(file, *out)
}

// parseDateOrTime reads YYYY-MM-DD (midnight UTC) or RFC 3339.
func parseDateOrTime(value string) (time.Time, error) {
	if at, err := time.Parse(time.DateOnly, value); err == nil {
		return at.UTC(), nil
	}
	at, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%q is neither YYYY-MM-DD nor RFC 3339", value)
	}
	return at.UTC(), nil
}

// ------------------------------------------------------------ org export

func runExportRequest(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	flags := newFlagSet("export request", shared)
	passphraseFile := flags.String("passphrase-file", "", "file holding the passphrase (- for stdin); at least 12 characters")
	wait := flags.Bool("wait", false, "wait until the export is ready or failed")
	client, _, err := cli.begin(flags, shared, args, 0, exportRequestUsage)
	if err != nil {
		return err
	}
	if *passphraseFile == "" {
		return usagef("pass the passphrase with --passphrase-file (never on the command line)\nusage: %s", exportRequestUsage)
	}
	passphrase, err := cli.readPassphrase(*passphraseFile)
	if err != nil {
		return err
	}
	export, err := client.Exports.Request(ctx, passphrase)
	if err != nil {
		return err
	}
	if *wait {
		if export, err = cli.waitExport(ctx, client, export.JobID); err != nil {
			return err
		}
	}
	if shared.jsonOutput {
		return cli.printJSON(export)
	}
	cli.printExport(export)
	if export.Status == redundantdns.ExportQueued {
		fmt.Fprintf(cli.stdout, "Follow it with: rdnsctl export status %s\n", export.JobID)
	}
	fmt.Fprintln(cli.stdout, "Keep the passphrase: the bundle cannot be opened without it.")
	return nil
}

// readPassphrase reads the passphrase file (or stdin for "-"), without the
// trailing line break.
func (cli *app) readPassphrase(path string) (string, error) {
	var raw []byte
	var err error
	if path == "-" {
		raw, err = io.ReadAll(cli.reader)
	} else {
		raw, err = os.ReadFile(path) //nolint:gosec // the user names the file
	}
	if err != nil {
		return "", fmt.Errorf("read the passphrase: %w", err)
	}
	passphrase := strings.TrimRight(string(raw), "\r\n")
	if len([]rune(passphrase)) < redundantdns.MinExportPassphrase {
		return "", usagef("the passphrase needs at least %d characters", redundantdns.MinExportPassphrase)
	}
	return passphrase, nil
}

// waitExport reads the export until it is no longer queued.
func (cli *app) waitExport(ctx context.Context, client *redundantdns.Client, jobID string) (*redundantdns.OrgExport, error) {
	for {
		export, err := client.Exports.Status(ctx, jobID)
		if err != nil || export.Status != redundantdns.ExportQueued {
			return export, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(exportPollInterval):
		}
	}
}

func (cli *app) printExport(export *redundantdns.OrgExport) {
	fmt.Fprintf(cli.stdout, "Export %s of %s: %s\n", export.JobID, export.OrgID, export.Status)
	switch export.Status {
	case redundantdns.ExportReady:
		fmt.Fprintf(cli.stdout, "  size %d bytes, %d zones, sha256 %s, expires %s\n", export.Size, export.Zones, export.SHA256, formatTime(export.ExpiresAt))
		fmt.Fprintf(cli.stdout, "Download it with: rdnsctl export download %s --out bundle.tar\n", export.JobID)
	case redundantdns.ExportFailed:
		fmt.Fprintf(cli.stdout, "  error: %s\n", dash(export.Error))
	}
}

func runExportStatus(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	client, positionals, err := cli.begin(newFlagSet("export status", shared), shared, args, 1, exportStatusUsage)
	if err != nil {
		return err
	}
	export, err := client.Exports.Status(ctx, positionals[0])
	if err != nil {
		return err
	}
	if shared.jsonOutput {
		// The one-time link is left out: download it with export download.
		export.DownloadPath, export.DownloadURL = "", ""
		return cli.printJSON(export)
	}
	cli.printExport(export)
	return nil
}

func runExportDownload(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	flags := newFlagSet("export download", shared)
	out := flags.String("out", "", "file to write (default the server's file name; - for stdout)")
	client, positionals, err := cli.begin(flags, shared, args, 1, exportDownloadUsage)
	if err != nil {
		return err
	}
	download, err := client.Exports.Download(ctx, positionals[0])
	if err != nil {
		return err
	}
	defer func() { _ = download.Close() }()
	target := firstNonEmpty(*out, safeName(download.Filename, "rdns-export.tar"))
	written, err := cli.writeOutput(target, download, &download.SHA256)
	if err != nil {
		return err
	}
	if target != "-" {
		fmt.Fprintf(cli.stderr, "Saved the export bundle to %s (%d bytes, sha256 %s verified). Restore it with rdns import-org.\n", target, written, download.SHA256)
	}
	return nil
}

// ------------------------------------------------------------ compliance

// runCompliance runs, records or reads a compliance report. The exit code
// is the report's: 0 pass, 1 warn, 2 fail, and 3 for a usage or API error.
func runCompliance(ctx context.Context, cli *app, args []string) error {
	action := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		action, args = args[0], args[1:]
	}
	err := cli.compliance(ctx, action, args)
	var exit exitError
	if err == nil || errors.As(err, &exit) {
		return err
	}
	return exitError{code: complianceExitError, err: err}
}

func (cli *app) compliance(ctx context.Context, action string, args []string) error {
	shared := &globals{}
	flags := newFlagSet("compliance", shared)
	profile := flags.String("profile", "", "profile: baseline (default), iso27001, soc2 or one of the operator's")
	scope := flags.String("scope", "", "org (default) or platform (platform admins, dashboard session)")
	switch action {
	case "", "run", "last":
	default:
		return usagef("unknown compliance command %q\nusage: %s", action, complianceUsage)
	}
	client, _, err := cli.begin(flags, shared, args, 0, complianceUsage)
	if err != nil {
		return err
	}
	var report *redundantdns.ComplianceReport
	switch action {
	case "run":
		report, err = client.Compliance.Run(ctx, *profile, *scope)
	case "last":
		if *profile != "" {
			return usagef("compliance last takes no --profile\nusage: %s", complianceUsage)
		}
		report, err = client.Compliance.Last(ctx, *scope)
	default:
		report, err = client.Compliance.Report(ctx, *profile, *scope)
	}
	if err != nil {
		return err
	}
	if report == nil {
		if shared.jsonOutput {
			return cli.printJSON(map[string]any{"report": nil})
		}
		fmt.Fprintln(cli.stdout, "No compliance report yet: run one with rdnsctl compliance run.")
		return nil
	}
	if shared.jsonOutput {
		if err := cli.printJSON(report); err != nil {
			return err
		}
	} else {
		cli.printCompliance(report, action == "run")
	}
	if code := report.ExitCode(); code != 0 {
		return exitError{code: code}
	}
	return nil
}

func (cli *app) printCompliance(report *redundantdns.ComplianceReport, recorded bool) {
	subject := "organization " + report.OrgID
	if report.Scope == redundantdns.ComplianceScopePlatform {
		subject = "the installation"
	}
	fmt.Fprintf(cli.stdout, "%s (%s) for %s: %s, checked %s\n", dash(report.ProfileTitle), report.Profile, subject, strings.ToUpper(report.Status),
		report.CheckedAt.UTC().Format(time.RFC3339))
	summary := report.Summary
	fmt.Fprintf(cli.stdout, "%d pass, %d warn, %d fail, %d not applicable\n\n", summary.Pass, summary.Warn, summary.Fail, summary.NotApplicable)
	table := cli.table("CONTROL", "STATUS", "REQUIRED", "ISO 27001", "SOC 2", "TITLE")
	for _, control := range report.Controls {
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\n", control.ID, control.Status, yesNo(control.Required), dash(control.Mapping.ISO27001),
			dash(control.Mapping.SOC2), control.Title)
	}
	_ = table.Flush()
	first := true
	for _, control := range report.Controls {
		if control.Remediation == "" || control.Status == redundantdns.CompliancePass || control.Status == redundantdns.ComplianceNotApplicable {
			continue
		}
		if first {
			fmt.Fprintln(cli.stdout, "\nTo fix:")
			first = false
		}
		fmt.Fprintf(cli.stdout, "  %s: %s\n", control.ID, control.Remediation)
	}
	if recorded {
		fmt.Fprintln(cli.stdout, "\nRecorded in the audit log and the audit stream.")
	}
}

// ------------------------------------------------------------ audit stream

func runAuditVerify(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	flags := newFlagSet("audit verify", shared)
	from := flags.String("from", "", "first day, YYYY-MM-DD UTC (default 30 days ago)")
	to := flags.String("to", "", "last day, YYYY-MM-DD UTC (default today)")
	client, _, err := cli.begin(flags, shared, args, 0, auditVerifyUsage)
	if err != nil {
		return err
	}
	report, err := client.Audit.Verify(ctx, *from, *to)
	if err != nil {
		return err
	}
	if shared.jsonOutput {
		if err := cli.printJSON(report); err != nil {
			return err
		}
	} else {
		cli.printAuditVerify(report)
	}
	if !report.OK {
		return exitError{code: 1}
	}
	return nil
}

func (cli *app) printAuditVerify(report *redundantdns.AuditStreamReport) {
	verdict := "OK"
	if !report.OK {
		verdict = "FAILED"
	}
	fmt.Fprintf(cli.stdout, "Audit stream of %s, %s to %s: %s\n", report.Org, report.From, report.To, verdict)
	fmt.Fprintf(cli.stdout, "  %d segments (%d sealed, %d signed, %d open), %d lines, sequence %d to %d, %d platform seals, last seal %s\n",
		report.Segments, report.Sealed, report.Signed, report.Open, report.Lines, report.FirstSeq, report.LastSeq, report.PlatformSeals, formatTime(report.LastSeal))
	for _, problem := range report.Problems {
		fmt.Fprintf(cli.stdout, "  problem %s\n", describeProblem(problem))
	}
	for _, warning := range report.Warnings {
		fmt.Fprintf(cli.stdout, "  warning %s\n", describeProblem(warning))
	}
}

func describeProblem(problem redundantdns.AuditStreamProblem) string {
	where := problem.Day
	if problem.Seq != nil {
		where += fmt.Sprintf(" segment %d", *problem.Seq)
	}
	if problem.Line > 0 {
		where += fmt.Sprintf(" line %d", problem.Line)
	}
	return fmt.Sprintf("%s (%s): %s", problem.Code, strings.TrimSpace(dash(where)), problem.Message)
}

func runAuditExport(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	flags := newFlagSet("audit export", shared)
	from := flags.String("from", "", "first day, YYYY-MM-DD UTC (default 30 days ago)")
	to := flags.String("to", "", "last day, YYYY-MM-DD UTC (default today)")
	out := flags.String("out", "", "file to write (default the server's file name; - for stdout)")
	client, _, err := cli.begin(flags, shared, args, 0, auditExportUsage)
	if err != nil {
		return err
	}
	download, err := client.Audit.Export(ctx, *from, *to)
	if err != nil {
		return err
	}
	defer func() { _ = download.Close() }()
	target := firstNonEmpty(*out, safeName(download.Filename, "rdns-audit.tar"))
	written, err := cli.writeOutput(target, download, nil)
	if err != nil {
		return err
	}
	if target != "-" {
		fmt.Fprintf(cli.stderr, "Saved the audit evidence bundle to %s (%d bytes). Check it offline with its verify.sh.\n", target, written)
	}
	return nil
}

// ------------------------------------------------------------ output files

// writeOutput copies reader to target ("-" = stdout). A file is created
// with mode 0600 next to its final name and renamed when complete, so a
// failed or corrupt download never leaves a partial file; an existing file
// is not overwritten. With wantSHA256 (a hex digest, when not empty) the
// content must match it.
func (cli *app) writeOutput(target string, reader io.Reader, wantSHA256 *string) (int64, error) {
	hash := sha256.New()
	if target == "-" {
		written, err := io.Copy(io.MultiWriter(cli.stdout, hash), reader)
		if err != nil {
			return written, err
		}
		return written, checkDigest(hash.Sum(nil), wantSHA256)
	}
	// target is the user's --out, or a base name (safeName) in the working
	// directory.
	if _, err := os.Stat(target); err == nil { //nolint:gosec // see above
		return 0, fmt.Errorf("%s already exists: remove it or choose another --out", target)
	}
	temp, err := os.CreateTemp(filepath.Dir(target), "."+filepath.Base(target)+".*")
	if err != nil {
		return 0, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = temp.Close()
			_ = os.Remove(temp.Name()) //nolint:gosec // our own temporary file
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		return 0, err
	}
	written, err := io.Copy(io.MultiWriter(temp, hash), reader)
	if err != nil {
		return written, fmt.Errorf("write %s: %w", target, err)
	}
	if err := checkDigest(hash.Sum(nil), wantSHA256); err != nil {
		return written, err
	}
	if err := temp.Close(); err != nil {
		return written, err
	}
	if err := os.Rename(temp.Name(), target); err != nil { //nolint:gosec // target: see above
		return written, err
	}
	keep = true
	return written, nil
}

// safeName keeps the base name of a file name suggested by the server (a
// download never lands outside the working directory by itself), or
// fallback when there is none.
func safeName(name, fallback string) string {
	base := filepath.Base(filepath.Clean("/" + strings.ReplaceAll(name, "\\", "/")))
	if base == "/" || base == "." || base == ".." || strings.HasPrefix(base, ".") {
		return fallback
	}
	return base
}

func checkDigest(sum []byte, want *string) error {
	if want == nil || *want == "" {
		return nil
	}
	if got := hex.EncodeToString(sum); !strings.EqualFold(got, *want) {
		return fmt.Errorf("the download does not match its SHA-256 (got %s, want %s): try again", got, *want)
	}
	return nil
}
