package main

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	redundantdns "github.com/redundantdns/go-client"
)

func runAttach(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	flags := newFlagSet("attach", shared)
	connectionID := flags.String("connection", "", "connection id")
	providerZoneID := flags.String("provider-zone-id", "", "existing provider zone (zone_editor connections, or with --adopt-existing)")
	adoptExisting := flags.Bool("adopt-existing", false, "attach an existing provider zone instead of creating one")
	label := flags.String("label", "", "a name for the attachment (the connection's label when omitted), e.g. the one it had before a detach")
	usage := "rdnsctl attach <zone> --connection <connectionId> [--provider-zone-id ID] [--adopt-existing] [--label NAME]"
	client, positionals, err := cli.begin(flags, shared, args, 1, usage)
	if err != nil {
		return err
	}
	if *connectionID == "" {
		return usagef("usage: %s", usage)
	}
	zoneID, err := resolveZoneID(ctx, client, positionals[0])
	if err != nil {
		return err
	}
	result, err := client.Attachments.Create(ctx, zoneID, redundantdns.AttachmentCreate{
		ConnectionID: *connectionID, ProviderZoneID: *providerZoneID, AdoptExisting: *adoptExisting, Label: *label,
	})
	if err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(result)
	}
	attachment := result.Attachment
	fmt.Fprintf(cli.stdout, "Attached %s as %s (provider zone %s).\nProvider nameservers: %s\nNS plan now: %s\n",
		attachment.Provider, attachment.AttachmentID, attachment.ProviderZoneID,
		strings.Join(attachment.NameServers, " "), strings.Join(result.NSPlan, " "))
	return nil
}

func runDetach(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	flags := newFlagSet("detach", shared)
	deleteRemote := flags.Bool("delete-remote", false, "also delete the provider zone (zone_admin connections)")
	yes := flags.Bool("yes", false, "do not ask for confirmation")
	usage := "rdnsctl detach <zone> <attachmentId> [--delete-remote --yes]"
	client, positionals, err := cli.begin(flags, shared, args, 2, usage)
	if err != nil {
		return err
	}
	zone, err := client.Zones.Resolve(ctx, positionals[0])
	if err != nil {
		return err
	}
	options := redundantdns.DetachOptions{DeleteRemote: *deleteRemote}
	if *deleteRemote {
		options.ConfirmName = zone.Name
		if !*yes {
			question := fmt.Sprintf("This deletes the provider zone of %s. Type the zone name to confirm: ", zone.Name)
			if _, err := cli.confirmName(question, zone.Name, "nothing was detached", redundantdns.NormalizeZoneName); err != nil {
				return err
			}
		}
	}
	if err := client.Attachments.Delete(ctx, zone.ZoneID, positionals[1], options); err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(map[string]any{"ok": true})
	}
	suffix := "; the provider zone was kept"
	if *deleteRemote {
		suffix = " and deleted the provider zone"
	}
	fmt.Fprintf(cli.stdout, "Detached %s from %s%s.\n", positionals[1], zone.Name, suffix)
	return nil
}

func runSyncReconcile(ctx context.Context, cli *app, args []string) error {
	return runSyncJob(ctx, cli, args, "reconcile")
}

func runSyncVerify(ctx context.Context, cli *app, args []string) error {
	return runSyncJob(ctx, cli, args, "verify")
}

func runSyncJob(ctx context.Context, cli *app, args []string, kind string) error {
	shared := &globals{}
	flags := newFlagSet("sync "+kind, shared)
	attachmentID := flags.String("attachment", "", "one attachment only")
	wait := flags.Bool("wait", false, "wait until every attachment is in sync")
	timeout := flags.Duration("timeout", 2*time.Minute, "how long --wait waits")
	client, positionals, err := cli.begin(flags, shared, args, 1, "rdnsctl sync "+kind+" <zone> [--attachment ID] [--wait]")
	if err != nil {
		return err
	}
	zoneID, err := resolveZoneID(ctx, client, positionals[0])
	if err != nil {
		return err
	}
	var jobs *redundantdns.Jobs
	if kind == "reconcile" {
		jobs, err = client.Sync.Reconcile(ctx, zoneID, *attachmentID)
	} else {
		jobs, err = client.Sync.Verify(ctx, zoneID, *attachmentID)
	}
	if err != nil {
		return err
	}
	if len(jobs.JobIDs) == 0 {
		if shared.jsonOutput {
			return cli.printJSON(jobs)
		}
		fmt.Fprintf(cli.stdout, "Nothing to %s: the zone has no attachments.\n", kind)
		return nil
	}
	if !*wait {
		if shared.jsonOutput {
			return cli.printJSON(jobs)
		}
		fmt.Fprintf(cli.stdout, "Queued %s: %s\n", kind, strings.Join(jobs.JobIDs, ", "))
		return nil
	}
	waitCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	status, err := client.Zones.WaitInSync(waitCtx, zoneID, redundantdns.WaitOptions{})
	if err != nil {
		return fmt.Errorf("wait for sync: %w", err)
	}
	if shared.jsonOutput {
		return cli.printJSON(map[string]any{"jobIds": jobs.JobIDs, "status": status})
	}
	fmt.Fprintf(cli.stdout, "Queued %s: %s. All attachments are in sync.\n", kind, strings.Join(jobs.JobIDs, ", "))
	return cli.printStatus(status)
}

func runSyncAdopt(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	client, positionals, err := cli.begin(newFlagSet("sync adopt", shared), shared, args, 2, "rdnsctl sync adopt <zone> <attachmentId>")
	if err != nil {
		return err
	}
	zoneID, err := resolveZoneID(ctx, client, positionals[0])
	if err != nil {
		return err
	}
	jobs, err := client.Sync.Adopt(ctx, zoneID, positionals[1])
	if err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(jobs)
	}
	fmt.Fprintf(cli.stdout, "Queued adopt from %s: %s. The canonical zone takes the provider's records, then every provider is reconciled.\n",
		positionals[1], strings.Join(jobs.JobIDs, ", "))
	return nil
}

func runDelegationCheck(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	client, positionals, err := cli.begin(newFlagSet("delegation check", shared), shared, args, 1, "rdnsctl delegation check <zone>")
	if err != nil {
		return err
	}
	zoneID, err := resolveZoneID(ctx, client, positionals[0])
	if err != nil {
		return err
	}
	delegation, err := client.Delegation.Check(ctx, zoneID)
	if err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(delegation)
	}
	fmt.Fprintf(cli.stdout, "Delegation: %s\nNS plan:  %s\nSeen:     %s\nMissing:  %s\nExtra:    %s\n", delegation.State,
		dash(strings.Join(delegation.NSPlan, " ")), dash(strings.Join(delegation.SeenNS, " ")),
		dash(strings.Join(delegation.Missing, " ")), dash(strings.Join(delegation.Extra, " ")))
	if delegation.Registrar != nil {
		fmt.Fprintf(cli.stdout, "Registrar: %s\n", dash(delegation.Registrar.Name))
	}
	if delegation.Hint == redundantdns.DelegationHintCloudflareRegistrar {
		fmt.Fprint(cli.stdout, cloudflareRegistrarHint)
	}
	return nil
}

// ------------------------------------------------------------------ alerts

func runAlertsList(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	flags := newFlagSet("alerts list", shared)
	zone := flags.String("zone", "", "zone id or name")
	rule := flags.String("rule", "", "drift, sync_error, delegation_broken, provider_down or zone_serial_stale")
	state := flags.String("state", "", "firing or resolved")
	limit := flags.Int("limit", 50, "maximum events (server cap 500)")
	client, _, err := cli.begin(flags, shared, args, 0, "rdnsctl alerts list [--zone ZONE] [--rule RULE] [--state STATE] [--limit N]")
	if err != nil {
		return err
	}
	filter := redundantdns.AlertEventFilter{Rule: *rule, State: *state, Limit: *limit}
	if *zone != "" {
		if filter.ZoneID, err = resolveZoneID(ctx, client, *zone); err != nil {
			return err
		}
	}
	events, err := client.Alerts.ListEvents(ctx, filter)
	if err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(events)
	}
	if len(events) == 0 {
		fmt.Fprintln(cli.stdout, "No alerts.")
		return nil
	}
	table := cli.table("EVENT ID", "STATE", "RULE", "ZONE", "SINCE", "SUMMARY")
	for _, event := range events {
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\n", event.EventID, event.State, event.Rule, event.ZoneName,
			event.FirstSeenAt.UTC().Format(time.RFC3339), event.Summary)
	}
	return table.Flush()
}

func runAlertsResolve(ctx context.Context, cli *app, args []string) error {
	return runAlertTransition(ctx, cli, args, "resolve")
}

func runAlertsAck(ctx context.Context, cli *app, args []string) error {
	return runAlertTransition(ctx, cli, args, "ack")
}

func runAlertTransition(ctx context.Context, cli *app, args []string, action string) error {
	shared := &globals{}
	client, positionals, err := cli.begin(newFlagSet("alerts "+action, shared), shared, args, 1, "rdnsctl alerts "+action+" <eventId>")
	if err != nil {
		return err
	}
	var event *redundantdns.AlertEvent
	if action == "resolve" {
		event, err = client.Alerts.Resolve(ctx, positionals[0])
	} else {
		event, err = client.Alerts.Ack(ctx, positionals[0])
	}
	if err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(event)
	}
	verb := map[string]string{"resolve": "Resolved", "ack": "Acknowledged"}[action]
	fmt.Fprintf(cli.stdout, "%s %s (%s on %s, now %s).\n", verb, event.EventID, event.Rule, event.ZoneName, event.State)
	return nil
}

func runAlertsRules(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	client, _, err := cli.begin(newFlagSet("alerts rules", shared), shared, args, 0, "rdnsctl alerts rules")
	if err != nil {
		return err
	}
	rules, err := client.Alerts.Rules(ctx)
	if err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(rules)
	}
	table := cli.table("RULE", "ENABLED", "THRESHOLD")
	for _, rule := range rules {
		threshold := "-"
		if rule.Threshold > 0 {
			threshold = fmt.Sprintf("%d (%d-%d)", rule.Threshold, rule.MinThreshold, rule.MaxThreshold)
		}
		fmt.Fprintf(table, "%s\t%t\t%s\n", rule.Kind, rule.Enabled, threshold)
	}
	return table.Flush()
}

func runAlertsChannels(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	client, _, err := cli.begin(newFlagSet("alerts channels", shared), shared, args, 0, "rdnsctl alerts channels")
	if err != nil {
		return err
	}
	channels, err := client.Alerts.Channels(ctx)
	if err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(channels)
	}
	table := cli.table("CHANNEL ID", "KIND", "LABEL", "TARGET", "ENABLED")
	for _, channel := range channels {
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%t\n", channel.ChannelID, channel.Kind, dash(channel.Label), channel.Target, channel.Enabled)
	}
	return table.Flush()
}

// sortedKeys returns the keys of a string-keyed map in order.
func sortedKeys[V any](values map[string]V) []string {
	return slices.SortedFunc(maps.Keys(values), func(left, right string) int { return cmp.Compare(left, right) })
}
