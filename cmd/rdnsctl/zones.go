package main

import (
	"context"
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"

	redundantdns "github.com/redundantdns/go-client"
)

// begin parses the flags, checks the positional count and builds a client.
func (cli *app) begin(flags *flag.FlagSet, shared *globals, args []string, count int, usage string) (*redundantdns.Client, []string, error) {
	positionals, err := parseArgs(flags, args)
	if err != nil {
		return nil, nil, err
	}
	if err := expectArgs(positionals, count, usage); err != nil {
		return nil, nil, err
	}
	client, err := cli.client(shared)
	if err != nil {
		return nil, nil, err
	}
	return client, positionals, nil
}

func runZonesList(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	client, _, err := cli.begin(newFlagSet("zones list", shared), shared, args, 0, "rdnsctl zones list")
	if err != nil {
		return err
	}
	zones, err := client.Zones.List(ctx)
	if err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(zones)
	}
	table := cli.table("ZONE ID", "NAME", "SERIAL", "PROVIDERS", "STATE", "DELEGATION")
	for _, zone := range zones {
		providers := make([]string, 0, len(zone.Attachments))
		for _, attachment := range zone.Attachments {
			providers = append(providers, attachment.Provider)
		}
		fmt.Fprintf(table, "%s\t%s\t%d\t%s\t%s\t%s\n", zone.ZoneID, zone.Name, zone.Serial,
			dash(strings.Join(providers, ",")), syncSummary(zone.Status), delegationState(zone.Status))
	}
	return table.Flush()
}

func runZonesGet(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	client, positionals, err := cli.begin(newFlagSet("zones get", shared), shared, args, 1, "rdnsctl zones get <zone>")
	if err != nil {
		return err
	}
	zone, err := client.Zones.Resolve(ctx, positionals[0])
	if err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(zone)
	}
	fmt.Fprintf(cli.stdout, "Zone %s (%s)\nSerial %d, default TTL %d, created %s\n", zone.Name, zone.ZoneID, zone.Serial, zone.Settings.DefaultTTL, zone.CreatedAt.Format(time.RFC3339))
	fmt.Fprintf(cli.stdout, "NS plan: %s\n", dash(strings.Join(zone.NSPlan, " ")))
	fmt.Fprintf(cli.stdout, "Sync: %s; delegation: %s\n\n", syncSummary(zone.Status), delegationState(zone.Status))
	if len(zone.Attachments) > 0 {
		table := cli.table("ATTACHMENT ID", "PROVIDER", "LABEL", "ACCESS", "PROVIDER ZONE", "STATE")
		for _, attachment := range zone.Attachments {
			fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\n", attachment.AttachmentID, attachment.Provider, dash(attachment.Label),
				attachment.AccessLevel, attachment.ProviderZoneID, attachmentState(zone.Status, attachment.AttachmentID))
		}
		if err := table.Flush(); err != nil {
			return err
		}
		fmt.Fprintln(cli.stdout)
	}
	return cli.printRecords(zone.RecordSets)
}

func runZonesCreate(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	flags := newFlagSet("zones create", shared)
	defaultTTL := flags.Int("default-ttl", 0, "TTL of record sets created without one (default 300)")
	client, positionals, err := cli.begin(flags, shared, args, 1, "rdnsctl zones create <name> [--default-ttl SECONDS]")
	if err != nil {
		return err
	}
	zone, err := client.Zones.Create(ctx, redundantdns.ZoneCreate{Name: positionals[0], DefaultTTL: *defaultTTL})
	if err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(zone)
	}
	fmt.Fprintf(cli.stdout, "Created zone %s (%s). Attach providers with: rdnsctl attach %s --connection <connectionId>\n", zone.Name, zone.ZoneID, zone.Name)
	return nil
}

func runZonesDelete(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	flags := newFlagSet("zones delete", shared)
	yes := flags.Bool("yes", false, "do not ask for confirmation")
	client, positionals, err := cli.begin(flags, shared, args, 1, "rdnsctl zones delete <zone> [--yes]")
	if err != nil {
		return err
	}
	zone, err := client.Zones.Resolve(ctx, positionals[0])
	if err != nil {
		return err
	}
	if !*yes {
		answer, err := cli.prompt(fmt.Sprintf("Delete the canonical zone %s? Provider zones are kept. Type the zone name to confirm: ", zone.Name))
		if err != nil {
			return err
		}
		if redundantdns.NormalizeZoneName(answer) != zone.Name {
			return usagef("confirmation does not match %s; nothing was deleted", zone.Name)
		}
	}
	if err := client.Zones.Delete(ctx, zone.ZoneID); err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(map[string]any{"ok": true, "zoneId": zone.ZoneID})
	}
	fmt.Fprintf(cli.stdout, "Deleted zone %s (%s).\n", zone.Name, zone.ZoneID)
	return nil
}

func runZonesExport(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	client, positionals, err := cli.begin(newFlagSet("zones export", shared), shared, args, 1, "rdnsctl zones export <zone>")
	if err != nil {
		return err
	}
	zoneID, err := resolveZoneID(ctx, client, positionals[0])
	if err != nil {
		return err
	}
	text, err := client.Zones.Export(ctx, zoneID)
	if err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(map[string]string{"zoneId": zoneID, "zoneFile": text})
	}
	_, err = fmt.Fprint(cli.stdout, text)
	return err
}

func runZonesStatus(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	client, positionals, err := cli.begin(newFlagSet("zones status", shared), shared, args, 1, "rdnsctl zones status <zone>")
	if err != nil {
		return err
	}
	zoneID, err := resolveZoneID(ctx, client, positionals[0])
	if err != nil {
		return err
	}
	status, err := client.Zones.Status(ctx, zoneID)
	if err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(status)
	}
	return cli.printStatus(status)
}

func (cli *app) printStatus(status *redundantdns.ZoneStatus) error {
	table := cli.table("ATTACHMENT ID", "STATE", "APPLIED SERIAL", "HEALTH", "LAST SYNC", "LAST VERIFY", "ERROR")
	for _, id := range sortedKeys(status.Attachments) {
		state := status.Attachments[id]
		fmt.Fprintf(table, "%s\t%s\t%d\t%s\t%s\t%s\t%s\n", id, state.State, state.AppliedSerial, dash(state.Health),
			formatTime(state.LastSyncAt), formatTime(state.LastVerifyAt), dash(state.LastError))
	}
	if err := table.Flush(); err != nil {
		return err
	}
	if status.Delegation != nil {
		fmt.Fprintf(cli.stdout, "\nDelegation: %s (checked %s)\n", status.Delegation.State, status.Delegation.CheckedAt.Format(time.RFC3339))
	}
	return nil
}

// resolveZoneID accepts a zone id or name.
func resolveZoneID(ctx context.Context, client *redundantdns.Client, idOrName string) (string, error) {
	if strings.HasPrefix(idOrName, "zone-") {
		return idOrName, nil
	}
	zone, err := client.Zones.GetByName(ctx, idOrName)
	if err != nil {
		return "", err
	}
	return zone.ZoneID, nil
}

// syncSummary condenses the attachment states: "in_sync", "2 in_sync, 1
// drift", or "-" without attachments.
func syncSummary(status *redundantdns.ZoneStatus) string {
	if status == nil || len(status.Attachments) == 0 {
		return "-"
	}
	counts := map[string]int{}
	for _, state := range status.Attachments {
		counts[state.State]++
	}
	if len(counts) == 1 {
		for state := range counts {
			return state
		}
	}
	parts := make([]string, 0, len(counts))
	for _, state := range sortedKeys(counts) {
		parts = append(parts, strconv.Itoa(counts[state])+" "+state)
	}
	return strings.Join(parts, ", ")
}

func delegationState(status *redundantdns.ZoneStatus) string {
	if status == nil || status.Delegation == nil {
		return "-"
	}
	return status.Delegation.State
}

func attachmentState(status *redundantdns.ZoneStatus, attachmentID string) string {
	if status == nil {
		return "-"
	}
	if state, ok := status.Attachments[attachmentID]; ok {
		return state.State
	}
	return "-"
}

func formatTime(value *time.Time) string {
	if value == nil || value.IsZero() {
		return "-"
	}
	return value.UTC().Format(time.RFC3339)
}

func dash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}
