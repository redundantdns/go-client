package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
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

// leafCommands are commands without subcommands.
func leafCommands() map[string]command {
	return map[string]command{
		"login":   {summary: "Sign in with an e-mail code (or store a token) and save the credentials", usage: loginUsage, run: runLogin},
		"logout":  {summary: "Forget the saved credentials", usage: "rdnsctl logout", run: runLogout},
		"whoami":  {summary: "Show the signed-in user and organization", usage: "rdnsctl whoami", run: runWhoami},
		"attach":  {summary: "Attach a provider connection to a zone", usage: "rdnsctl attach <zone> --connection <connectionId> [--provider-zone-id ID] [--adopt-existing] [--label NAME]", run: runAttach},
		"detach":  {summary: "Detach a provider from a zone", usage: "rdnsctl detach <zone> <attachmentId> [--delete-remote --yes]", run: runDetach},
		"version": {summary: "Print the version", usage: "rdnsctl version", run: runVersion},
	}
}

// groups are commands with subcommands.
func groups() map[string]group {
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
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		cli.printHelp(args)
		return 0
	}
	err := cli.dispatch(ctx, args)
	if err == nil {
		return 0
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
global flags (any command):
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
	}
	if len(apiError.Details) > 0 {
		text += "\n" + string(apiError.Details)
	}
	return text
}

// prompt prints a question and reads one line from stdin.
func (cli *app) prompt(question string) (string, error) {
	fmt.Fprint(cli.stderr, question)
	line, err := cli.reader.ReadString('\n')
	switch {
	case err == nil, errors.Is(err, io.EOF) && line != "":
	case errors.Is(err, io.EOF):
		return "", errors.New("no input (stdin closed)")
	default:
		return "", err
	}
	return strings.TrimSpace(line), nil
}
