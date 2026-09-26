package main

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"slices"
	"strings"

	redundantdns "github.com/redundantdns/go-client"
)

func runRecordsList(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	client, positionals, err := cli.begin(newFlagSet("records list", shared), shared, args, 1, "rdnsctl records list <zone>")
	if err != nil {
		return err
	}
	zoneID, err := resolveZoneID(ctx, client, positionals[0])
	if err != nil {
		return err
	}
	recordSets, err := client.Records.List(ctx, zoneID)
	if err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(recordSets)
	}
	return cli.printRecords(recordSets)
}

func (cli *app) printRecords(recordSets []redundantdns.RecordSet) error {
	sorted := slices.Clone(recordSets)
	slices.SortFunc(sorted, func(left, right redundantdns.RecordSet) int {
		return cmp.Or(strings.Compare(left.Name, right.Name), strings.Compare(left.Type, right.Type))
	})
	table := cli.table("NAME", "TYPE", "TTL", "VALUES")
	for _, recordSet := range sorted {
		fmt.Fprintf(table, "%s\t%s\t%d\t%s\n", recordSet.Name, recordSet.Type, recordSet.TTL, strings.Join(recordSet.Values, " | "))
	}
	return table.Flush()
}

const recordsUpsertUsage = "rdnsctl records upsert <zone> --name NAME --type TYPE --value VALUE [--value VALUE...] [--ttl SECONDS] [--previous-name NAME --previous-type TYPE]"

func runRecordsUpsert(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	flags := newFlagSet("records upsert", shared)
	name := flags.String("name", "", "record name, relative (www, @) or absolute")
	recordType := flags.String("type", "", "record type (A, AAAA, CNAME, MX, TXT, SRV, CAA, NS, PTR)")
	ttl := flags.Int("ttl", 0, "TTL in seconds (default: the zone default)")
	var values multiFlag
	flags.Var(&values, "value", "a value (repeat for several)")
	previousName := flags.String("previous-name", "", "rename: the current name of the set")
	previousType := flags.String("previous-type", "", "rename: the current type of the set (default --type)")
	client, positionals, err := cli.begin(flags, shared, args, 1, recordsUpsertUsage)
	if err != nil {
		return err
	}
	if *name == "" || *recordType == "" || len(values) == 0 {
		return usagef("usage: %s", recordsUpsertUsage)
	}
	zone, err := client.Zones.Resolve(ctx, positionals[0])
	if err != nil {
		return err
	}
	zoneID := zone.ZoneID
	input := redundantdns.RecordUpsert{Name: *name, Type: strings.ToUpper(*recordType), TTL: *ttl, Values: values}
	if *previousName != "" {
		input.Previous = &redundantdns.RecordSetRef{Name: *previousName, Type: strings.ToUpper(cmp.Or(*previousType, *recordType))}
	}
	result, err := client.Records.Upsert(ctx, zoneID, input)
	if err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(result)
	}
	set := result.RecordSet
	fmt.Fprintf(cli.stdout, "Saved %s %s TTL %d: %s (serial %d)%s\n",
		set.Name, set.Type, set.TTL, strings.Join(set.Values, " | "), result.Serial, reconcileNote(zone))
	return nil
}

func runRecordsDelete(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	flags := newFlagSet("records delete", shared)
	name := flags.String("name", "", "record name")
	recordType := flags.String("type", "", "record type")
	usage := "rdnsctl records delete <zone> --name NAME --type TYPE"
	client, positionals, err := cli.begin(flags, shared, args, 1, usage)
	if err != nil {
		return err
	}
	if *name == "" || *recordType == "" {
		return usagef("usage: %s", usage)
	}
	zone, err := client.Zones.Resolve(ctx, positionals[0])
	if err != nil {
		return err
	}
	zoneID := zone.ZoneID
	serial, err := client.Records.Delete(ctx, zoneID, *name, strings.ToUpper(*recordType))
	if err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(map[string]any{"ok": true, "serial": serial})
	}
	fmt.Fprintf(cli.stdout, "Deleted %s %s (serial %d)%s\n", *name, strings.ToUpper(*recordType), serial, reconcileNote(zone))
	return nil
}

// reconcileNote ends the message of a record change: the providers are
// reconciled only when the zone has at least one attachment.
func reconcileNote(zone *redundantdns.Zone) string {
	if len(zone.Attachments) == 0 {
		return "; no providers attached yet."
	}
	return ". Providers are being reconciled."
}

// ------------------------------------------------------------ connections

func runConnectionsList(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	client, _, err := cli.begin(newFlagSet("connections list", shared), shared, args, 0, "rdnsctl connections list")
	if err != nil {
		return err
	}
	connections, err := client.Connections.List(ctx)
	if err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(connections)
	}
	table := cli.table("CONNECTION ID", "PROVIDER", "LABEL", "MODE", "ACCESS", "STATUS", "CREDENTIALS")
	for _, connection := range connections {
		hint := "-"
		if connection.CredentialsHint != "" {
			hint = "..." + connection.CredentialsHint
		}
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", connection.ConnectionID, connection.Provider, dash(connection.Label),
			connection.Mode, connection.AccessLevel, connection.Status, hint)
	}
	return table.Flush()
}

const connectionsCreateUsage = "rdnsctl connections create --provider ID [--label L] [--access-level zone_admin|zone_editor] [--mode byo|managed [--accept-managed-terms VERSION]] [--cred KEY=VALUE...] [--cred-file KEY=PATH...] [--scope KEY=VALUE...]"

func runConnectionsCreate(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	flags := newFlagSet("connections create", shared)
	provider := flags.String("provider", "", "provider id (see rdnsctl providers list)")
	label := flags.String("label", "", "label shown in the dashboard")
	accessLevel := flags.String("access-level", "", "zone_admin (creates zones, the default for byo) or zone_editor (edits existing zones)")
	mode := flags.String("mode", "", "byo (your credentials, default) or managed (platform account)")
	acceptManagedTerms := flags.String("accept-managed-terms", "", "accept this version of the Managed Provider Terms and Acceptable Use Policy (required with --mode managed)")
	var credentials, credentialFiles, scopes multiFlag
	flags.Var(&credentials, "cred", "credential field KEY=VALUE (repeat)")
	flags.Var(&credentialFiles, "cred-file", "credential field read from a file, KEY=PATH (for private keys)")
	flags.Var(&scopes, "scope", "scope hint KEY=VALUE (region, compartmentId...)")
	client, _, err := cli.begin(flags, shared, args, 0, connectionsCreateUsage)
	if err != nil {
		return err
	}
	if *provider == "" {
		return usagef("usage: %s", connectionsCreateUsage)
	}
	if *mode == redundantdns.ModeManaged && strings.TrimSpace(*acceptManagedTerms) == "" {
		return cli.refuseManagedWithoutTerms(ctx, client)
	}
	input := redundantdns.ConnectionCreate{
		Provider: *provider, Label: *label, AccessLevel: *accessLevel, Mode: *mode,
		AcceptManagedTerms: strings.TrimSpace(*acceptManagedTerms),
	}
	if input.AccessLevel == "" && input.Mode != redundantdns.ModeManaged {
		// The API requires an access level for BYO credentials.
		input.AccessLevel = redundantdns.AccessLevelZoneAdmin
	}
	if input.Credentials, err = parsePairs(credentials, "--cred"); err != nil {
		return err
	}
	files, err := parsePairs(credentialFiles, "--cred-file")
	if err != nil {
		return err
	}
	for key, path := range files {
		content, err := os.ReadFile(path) //nolint:gosec // the user names the file
		if err != nil {
			return fmt.Errorf("--cred-file %s: %w", key, err)
		}
		if input.Credentials == nil {
			input.Credentials = map[string]string{}
		}
		input.Credentials[key] = string(content)
	}
	if input.ScopeHints, err = parsePairs(scopes, "--scope"); err != nil {
		return err
	}
	result, err := client.Connections.Create(ctx, input)
	if err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(result)
	}
	connection := result.Connection
	fmt.Fprintf(cli.stdout, "Created connection %s (%s, %s, status %s).\n", connection.ConnectionID, connection.Provider, connection.AccessLevel, connection.Status)
	if result.Deferred {
		fmt.Fprintln(cli.stdout, "The credentials test is deferred: check it later with rdnsctl connections test.")
	}
	return nil
}

func runConnectionsTest(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	client, positionals, err := cli.begin(newFlagSet("connections test", shared), shared, args, 1, "rdnsctl connections test <connectionId>")
	if err != nil {
		return err
	}
	result, err := client.Connections.Test(ctx, positionals[0])
	if err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(result)
	}
	if result.Result.OK {
		fmt.Fprintf(cli.stdout, "Connection %s works (status %s).\n", positionals[0], result.Connection.Status)
		return nil
	}
	return fmt.Errorf("connection %s test failed: %s", positionals[0], dash(result.Result.Error))
}

func runConnectionsDelete(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	client, positionals, err := cli.begin(newFlagSet("connections delete", shared), shared, args, 1, "rdnsctl connections delete <connectionId>")
	if err != nil {
		return err
	}
	if err := client.Connections.Delete(ctx, positionals[0]); err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(map[string]any{"ok": true})
	}
	fmt.Fprintf(cli.stdout, "Deleted connection %s.\n", positionals[0])
	return nil
}

func runProvidersList(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	client, _, err := cli.begin(newFlagSet("providers list", shared), shared, args, 0, "rdnsctl providers list")
	if err != nil {
		return err
	}
	providers, err := client.Account.Providers(ctx)
	if err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(providers)
	}
	table := cli.table("PROVIDER", "CREDENTIAL FIELDS", "SCOPE FIELDS", "MANAGED", "APEX NS EDITABLE")
	for _, provider := range providers {
		fmt.Fprintf(table, "%s\t%s\t%s\t%t\t%t\n", provider.ID, dash(strings.Join(provider.CredentialFields, ",")),
			dash(strings.Join(provider.ScopeFields, ",")), provider.Managed, provider.Capabilities.ApexNSEditable)
	}
	return table.Flush()
}

// parsePairs turns KEY=VALUE flags into a map.
func parsePairs(pairs []string, flagName string) (map[string]string, error) {
	if len(pairs) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(pairs))
	for _, pair := range pairs {
		key, value, ok := strings.Cut(pair, "=")
		if !ok || strings.TrimSpace(key) == "" {
			return nil, usagef("%s expects KEY=VALUE, got %q", flagName, pair)
		}
		out[strings.TrimSpace(key)] = value
	}
	return out, nil
}
