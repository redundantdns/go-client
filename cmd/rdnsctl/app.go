package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"

	redundantdns "github.com/redundantdns/go-client"
)

// app holds the process streams and environment, so tests can drive the
// CLI in process.
type app struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
	getenv func(string) string
	// openBrowser opens a URL for an interactive OAuth consent (nil: the
	// system browser, best effort).
	openBrowser func(target string) error

	reader *bufio.Reader
}

// globals are the flags every command accepts.
type globals struct {
	baseURL    string
	token      string
	org        string
	jsonOutput bool
	configPath string
}

// command is one leaf command.
type command struct {
	summary string
	usage   string
	run     func(ctx context.Context, cli *app, args []string) error
}

// group is a command with subcommands (zones, records...).
type group struct {
	summary     string
	subcommands map[string]command
}

// usageError marks a wrong invocation (exit code 2).
type usageError struct{ message string }

func (err usageError) Error() string { return err.message }

func usagef(format string, args ...any) error {
	return usageError{message: fmt.Sprintf(format, args...)}
}

// exitError ends the command with a specific exit code (compliance: 0
// pass, 1 warn, 2 fail, 3 error; audit verify: 1 when it fails). err, when
// set, is printed like any error.
type exitError struct {
	code int
	err  error
}

func (err exitError) Error() string {
	if err.err == nil {
		return fmt.Sprintf("exit %d", err.code)
	}
	return err.err.Error()
}

func (err exitError) Unwrap() error { return err.err }

// leafCommands are commands without subcommands.
func leafCommands() map[string]command {
	return map[string]command{
		"login":   {summary: "Sign in with an e-mail code (or store a token) and save the credentials", usage: loginUsage, run: runLogin},
		"logout":  {summary: "Forget the saved credentials", usage: "rdnsctl logout", run: runLogout},
		"whoami":  {summary: "Show the signed-in user and organization", usage: "rdnsctl whoami", run: runWhoami},
		"attach":  {summary: "Attach a provider connection to a zone", usage: "rdnsctl attach <zone> --connection <connectionId> [--provider-zone-id ID] [--adopt-existing] [--label NAME]", run: runAttach},
		"detach":  {summary: "Detach a provider from a zone", usage: "rdnsctl detach <zone> <attachmentId> [--delete-remote --yes]", run: runDetach},
		"version": {summary: "Print the version", usage: "rdnsctl version", run: runVersion},
		"billing": {summary: "Show the plan, billing status, limits with their usage and the managed pass-through", usage: billingUsage, run: runBilling},
		"compliance": {summary: "Compliance posture: run a profile now (exit 0 pass, 1 warn, 2 fail, 3 error), record a run, or read the last report",
			usage: complianceUsage, run: runCompliance},
	}
}

// groups are commands with subcommands.
func groups() map[string]group {
	all := coreGroups()
	for name, commandGroup := range opsGroups() {
		all[name] = commandGroup
	}
	return all
}

// coreGroups are the zone, provider, domain and alert commands.
func coreGroups() map[string]group {
	return map[string]group{
		"zones": {summary: "Canonical zones", subcommands: map[string]command{
			"list":   {summary: "List zones", usage: "rdnsctl zones list", run: runZonesList},
			"get":    {summary: "Show a zone with its records and attachments", usage: "rdnsctl zones get <zone>", run: runZonesGet},
			"create": {summary: "Create a zone", usage: zonesCreateUsage, run: runZonesCreate},
			"delete": {summary: "Delete a canonical zone (provider zones are kept)", usage: "rdnsctl zones delete <zone> [--yes]", run: runZonesDelete},
			"export": {summary: "Print the zone as an RFC 1035 zone file", usage: "rdnsctl zones export <zone>", run: runZonesExport},
			"status": {summary: "Show the sync state per attachment", usage: "rdnsctl zones status <zone>", run: runZonesStatus},
		}},
		"records": {summary: "Record sets", subcommands: map[string]command{
			"list":   {summary: "List the record sets of a zone", usage: "rdnsctl records list <zone>", run: runRecordsList},
			"upsert": {summary: "Create or replace a record set", usage: "rdnsctl records upsert <zone> --name NAME --type TYPE --value VALUE [--value VALUE...] [--ttl SECONDS] [--previous-name NAME --previous-type TYPE]", run: runRecordsUpsert},
			"delete": {summary: "Delete a record set", usage: "rdnsctl records delete <zone> --name NAME --type TYPE", run: runRecordsDelete},
		}},
		"connections": {summary: "Provider connections", subcommands: map[string]command{
			"list":   {summary: "List provider connections", usage: "rdnsctl connections list", run: runConnectionsList},
			"create": {summary: "Test and save a provider connection", usage: "rdnsctl connections create --provider ID [--label L] [--access-level zone_admin|zone_editor] [--mode byo|managed] [--cred KEY=VALUE...] [--cred-file KEY=PATH...] [--scope KEY=VALUE...]", run: runConnectionsCreate},
			"test":   {summary: "Re-test a stored connection", usage: "rdnsctl connections test <connectionId>", run: runConnectionsTest},
			"delete": {summary: "Delete a connection that no zone uses", usage: "rdnsctl connections delete <connectionId>", run: runConnectionsDelete},
		}},
		"providers": {summary: "DNS providers", subcommands: map[string]command{
			"list": {summary: "List the available providers and their credential fields", usage: "rdnsctl providers list", run: runProvidersList},
		}},
		"sync": {summary: "Sync jobs", subcommands: map[string]command{
			"reconcile": {summary: "Push the canonical zone to the providers now", usage: "rdnsctl sync reconcile <zone> [--attachment ID] [--wait]", run: runSyncReconcile},
			"verify":    {summary: "Compare the providers with the canonical zone now", usage: "rdnsctl sync verify <zone> [--attachment ID] [--wait]", run: runSyncVerify},
			"adopt":     {summary: "Import one provider's records into the canonical zone", usage: "rdnsctl sync adopt <zone> <attachmentId>", run: runSyncAdopt},
			"status":    {summary: "Show the sync state per attachment", usage: "rdnsctl sync status <zone>", run: runZonesStatus},
		}},
		"legal": {summary: "Legal acceptances of the organization", subcommands: map[string]command{
			"managed": {summary: "Managed Provider Terms and Acceptable Use Policy (managed providers)", usage: legalManagedUsage, run: runLegalManaged},
		}},
		"terraform": {summary: "Credentials for the Terraform provider", subcommands: map[string]command{
			"login": {summary: "Sign in with OAuth for the Terraform provider and save the credentials file", usage: terraformLoginUsage, run: runTerraformLogin},
		}},
		"delegation": {summary: "Delegation checks", subcommands: map[string]command{
			"check": {summary: "Check the parent NS set against the NS plan now", usage: "rdnsctl delegation check <zone>", run: runDelegationCheck},
		}},
		"domains": domainsGroup(),
		"admin": {summary: "Platform admin operations (dashboard session of a platform admin)", subcommands: map[string]command{
			"domains":  {summary: "Domains of the reseller account; register or renew for an organization without a payment", usage: adminDomainsUsage + "\n" + adminRegisterFlagsUsage, run: runAdminDomains},
			"licenses": {summary: "Issue and manage the licenses of self-hosted installations", usage: adminLicensesUsage + "\n" + adminLicenseIssueFlags, run: runAdminLicenses},
		}},
		"alerts": {summary: "Alerts", subcommands: map[string]command{
			"list":     {summary: "Alert history, newest first", usage: "rdnsctl alerts list [--zone ZONE] [--rule RULE] [--state firing|resolved] [--limit N]", run: runAlertsList},
			"resolve":  {summary: "Resolve a firing alert by hand", usage: "rdnsctl alerts resolve <eventId>", run: runAlertsResolve},
			"ack":      {summary: "Acknowledge a firing alert", usage: "rdnsctl alerts ack <eventId>", run: runAlertsAck},
			"rules":    {summary: "List the alert rules", usage: "rdnsctl alerts rules", run: runAlertsRules},
			"channels": {summary: "List the notification channels", usage: "rdnsctl alerts channels", run: runAlertsChannels},
		}},
	}
}

// run dispatches the command line and returns the exit code.
func (cli *app) run(ctx context.Context, args []string) int {
	cli.reader = bufio.NewReader(cli.stdin)
	args, err := hoistGlobalFlags(args)
	if err != nil {
		fmt.Fprintln(cli.stderr, "rdnsctl:", err.Error())
		return 2
	}
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		cli.printHelp(args)
		return 0
	}
	err = cli.dispatch(ctx, args)
	if err == nil {
		return 0
	}
	var exit exitError
	if errors.As(err, &exit) {
		var usage usageError
		switch {
		case exit.err == nil:
		case errors.As(exit.err, &usage):
			fmt.Fprintln(cli.stderr, "rdnsctl:", usage.message)
		case errors.Is(exit.err, flag.ErrHelp):
			return 0
		default:
			fmt.Fprintln(cli.stderr, "rdnsctl:", describeError(exit.err))
		}
		return exit.code
	}
	var usage usageError
	if errors.As(err, &usage) {
		fmt.Fprintln(cli.stderr, "rdnsctl:", usage.message)
		return 2
	}
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	fmt.Fprintln(cli.stderr, "rdnsctl:", describeError(err))
	return 1
}

// globalValueFlags are the global flags that take a value; json is the
// only boolean one.
var globalValueFlags = map[string]bool{"base-url": true, "token": true, "org": true, "config": true}

// hoistGlobalFlags lets the global flags come before the command
// (rdnsctl --json zones list): it moves the leading ones after the
// command's own arguments (before a "--" terminator), where every command
// parses them. Flags after the command are left alone. An unknown leading
// flag, or a value flag without its value, is a usage error.
func hoistGlobalFlags(args []string) ([]string, error) {
	var leading []string
	index := 0
	for index < len(args) {
		arg := args[index]
		if arg == "-h" || arg == "--help" || arg == "-help" || !strings.HasPrefix(arg, "-") || arg == "-" || arg == "--" {
			break
		}
		name, _, hasValue := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		switch {
		case name == "json":
			leading = append(leading, arg)
		case globalValueFlags[name] && hasValue:
			leading = append(leading, arg)
		case globalValueFlags[name]:
			if index+1 >= len(args) {
				return nil, usagef("flag needs an argument: %s", arg)
			}
			leading = append(leading, arg, args[index+1])
			index++
		default:
			return nil, usagef("unknown global flag %s (global flags: --base-url, --token, --org, --json, --config; see rdnsctl help)", arg)
		}
		index++
	}
	rest := args[index:]
	if len(leading) == 0 {
		return rest, nil
	}
	if len(rest) == 0 || rest[0] == "help" || rest[0] == "-h" || rest[0] == "--help" {
		// Nothing to run: the help ignores the global flags.
		return rest, nil
	}
	terminator := slices.Index(rest, "--")
	if terminator < 0 {
		terminator = len(rest)
	}
	hoisted := make([]string, 0, len(rest)+len(leading))
	hoisted = append(hoisted, rest[:terminator]...)
	hoisted = append(hoisted, leading...)
	return append(hoisted, rest[terminator:]...), nil
}

func (cli *app) dispatch(ctx context.Context, args []string) error {
	name := args[0]
	if leaf, ok := leafCommands()[name]; ok {
		if wantsHelp(args[1:]) {
			fmt.Fprintf(cli.stdout, "%s\n\nusage: %s\n%s", leaf.summary, leaf.usage, globalHelp)
			return nil
		}
		return leaf.run(ctx, cli, args[1:])
	}
	commandGroup, ok := groups()[name]
	if !ok {
		return usagef("unknown command %q (see rdnsctl help)", name)
	}
	if len(args) < 2 || args[1] == "-h" || args[1] == "--help" || args[1] == "help" {
		cli.printGroupHelp(name, commandGroup)
		return nil
	}
	sub, ok := commandGroup.subcommands[args[1]]
	if !ok {
		return usagef("unknown command %q %q (see rdnsctl %s --help)", name, args[1], name)
	}
	if wantsHelp(args[2:]) {
		fmt.Fprintf(cli.stdout, "%s\n\nusage: %s\n%s", sub.summary, sub.usage, globalHelp)
		return nil
	}
	return sub.run(ctx, cli, args[2:])
}

// wantsHelp reports whether -h or --help is among the arguments.
func wantsHelp(args []string) bool {
	for _, arg := range args {
		if arg == "--" {
			return false
		}
		if arg == "-h" || arg == "--help" || arg == "-help" {
			return true
		}
	}
	return false
}

func (cli *app) printHelp(args []string) {
	if len(args) > 1 {
		if commandGroup, ok := groups()[args[1]]; ok {
			cli.printGroupHelp(args[1], commandGroup)
			return
		}
		if leaf, ok := leafCommands()[args[1]]; ok {
			fmt.Fprintf(cli.stdout, "%s\n\nusage: %s\n", leaf.summary, leaf.usage)
			return
		}
	}
	fmt.Fprint(cli.stdout, "rdnsctl manages RedundantDNS zones from the command line.\n\nusage: rdnsctl <command> [subcommand] [flags]\n\ncommands:\n")
	table := tabwriter.NewWriter(cli.stdout, 0, 2, 2, ' ', 0)
	names := make([]string, 0)
	summaries := map[string]string{}
	for name, leaf := range leafCommands() {
		names = append(names, name)
		summaries[name] = leaf.summary
	}
	for name, commandGroup := range groups() {
		names = append(names, name)
		summaries[name] = commandGroup.summary
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(table, "  %s\t%s\n", name, summaries[name])
	}
	_ = table.Flush()
	fmt.Fprint(cli.stdout, globalHelp)
}

func (cli *app) printGroupHelp(name string, commandGroup group) {
	fmt.Fprintf(cli.stdout, "%s\n\nusage: rdnsctl %s <subcommand> [flags]\n\nsubcommands:\n", commandGroup.summary, name)
	table := tabwriter.NewWriter(cli.stdout, 0, 2, 2, ' ', 0)
	names := make([]string, 0, len(commandGroup.subcommands))
	for sub := range commandGroup.subcommands {
		names = append(names, sub)
	}
	sort.Strings(names)
	for _, sub := range names {
		fmt.Fprintf(table, "  %s\t%s\n", sub, commandGroup.subcommands[sub].usage)
	}
	_ = table.Flush()
	fmt.Fprint(cli.stdout, globalHelp)
}

const globalHelp = `
global flags (before or after the command):
  --base-url URL   API URL (env RDNS_BASE_URL, then the saved config)
  --token TOKEN    personal access or OAuth token (env RDNS_TOKEN)
  --org ORG_ID     organization (env RDNS_ORG); a token only accepts its own
  --json           print JSON instead of tables
  --config PATH    config file (default $XDG_CONFIG_HOME/rdnsctl/config.json)
`

// newFlagSet returns a flag set that registers the global flags too.
func newFlagSet(name string, shared *globals) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&shared.baseURL, "base-url", "", "API URL")
	flags.StringVar(&shared.token, "token", "", "API token")
	flags.StringVar(&shared.org, "org", "", "organization id")
	flags.BoolVar(&shared.jsonOutput, "json", false, "JSON output")
	flags.StringVar(&shared.configPath, "config", "", "config file")
	return flags
}

// parseArgs parses flags placed anywhere among the positional arguments
// (the standard flag package stops at the first positional one).
func parseArgs(flags *flag.FlagSet, args []string) ([]string, error) {
	var positionals []string
	for {
		if err := flags.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, err
			}
			return nil, usagef("%s: %v", flags.Name(), err)
		}
		args = flags.Args()
		if len(args) == 0 {
			return positionals, nil
		}
		if args[0] == "--" {
			return append(positionals, args[1:]...), nil
		}
		positionals = append(positionals, args[0])
		args = args[1:]
	}
}

// expectArgs checks the number of positional arguments.
func expectArgs(positionals []string, count int, usage string) error {
	if len(positionals) != count {
		return usagef("usage: %s", usage)
	}
	return nil
}

// multiFlag is a repeatable string flag.
type multiFlag []string

func (values *multiFlag) String() string { return strings.Join(*values, ",") }

func (values *multiFlag) Set(value string) error {
	*values = append(*values, value)
	return nil
}

// printJSON writes value as indented JSON.
func (cli *app) printJSON(value any) error {
	encoder := json.NewEncoder(cli.stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

// table starts an aligned table with a header row.
func (cli *app) table(header ...string) *tabwriter.Writer {
	writer := tabwriter.NewWriter(cli.stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(writer, strings.Join(header, "\t"))
	return writer
}

// describeError adds a hint to common API errors.
func describeError(err error) string {
	var apiError *redundantdns.APIError
	if !errors.As(err, &apiError) {
		return err.Error()
	}
	text := apiError.Code
	if apiError.Message != "" {
		text += ": " + apiError.Message
	}
	switch {
	case errors.Is(err, redundantdns.ErrUnauthorized):
		text += " (sign in again with rdnsctl login)"
	case redundantdns.HasCode(err, redundantdns.CodeInsufficientScope):
		text += " (the token lacks a scope; mint one with more scopes)"
	case errors.Is(err, redundantdns.ErrManagedTermsRequired):
		requirement, _ := redundantdns.ManagedTermsRequired(err)
		text += fmt.Sprintf(" (read %s, then accept version %s with rdnsctl legal managed accept %s)",
			dash(requirement.URL), dash(requirement.Version), dash(requirement.Version))
	case errors.Is(err, redundantdns.ErrDomainTermsRequired):
		requirement, _ := redundantdns.DomainTermsRequired(err)
		text += fmt.Sprintf(" (read %s, then accept version %s with rdnsctl domains terms accept %s, or pass --accept-terms %s to domains transfer or domains register)",
			dash(requirement.URL), dash(requirement.Version), dash(requirement.Version), dash(requirement.Version))
	case redundantdns.HasCode(err, redundantdns.CodeRegistrantProfileRequired):
		text += " (set it with rdnsctl domains registrant-profile set, or pass --contact)"
	case redundantdns.HasCode(err, redundantdns.CodeDomainRegistrationPending):
		text += " (pay its checkout, or cancel it with rdnsctl domains cancel)"
	case redundantdns.HasCode(err, redundantdns.CodeBillingUnavailable):
		text += " (this deployment has no payment gateway: domains cannot be paid for here)"
	case redundantdns.HasCode(err, redundantdns.CodeDomainUnavailable):
		text += " (see rdnsctl domains check)"
	}
	if len(apiError.Details) > 0 {
		text += "\n" + string(apiError.Details)
	}
	return text
}

// exitAborted is the exit code of a destructive command the user did not
// confirm: a wrong answer or no answer at all (stdin closed). Nothing was
// changed.
const exitAborted = 2

// errNoInput is what prompt returns when stdin is closed before a line.
var errNoInput = errors.New("no input (stdin closed)")

// confirmName asks the user to type expected to confirm a destructive
// command and returns the answer. A different answer (after normalize, when
// set) or no answer aborts with exitAborted; outcome says what did not
// happen ("nothing was deleted").
func (cli *app) confirmName(question, expected, outcome string, normalize func(string) string) (string, error) {
	answer, err := cli.prompt(question)
	if errors.Is(err, errNoInput) {
		return "", exitError{code: exitAborted, err: fmt.Errorf("aborted: no confirmation was typed (stdin closed); %s. Pass --yes to skip the prompt", outcome)}
	}
	if err != nil {
		return "", err
	}
	typed := answer
	if normalize != nil {
		typed = normalize(answer)
	}
	if typed != expected {
		return "", exitError{code: exitAborted, err: fmt.Errorf("aborted: confirmation does not match %s; %s", expected, outcome)}
	}
	return answer, nil
}

// prompt prints a question and reads one line from stdin.
func (cli *app) prompt(question string) (string, error) {
	fmt.Fprint(cli.stderr, question)
	line, err := cli.reader.ReadString('\n')
	switch {
	case err == nil, errors.Is(err, io.EOF) && line != "":
	case errors.Is(err, io.EOF):
		return "", errNoInput
	default:
		return "", err
	}
	return strings.TrimSpace(line), nil
}
