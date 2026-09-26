package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	redundantdns "github.com/redundantdns/go-client"
)

const billingUsage = "rdnsctl billing"

// runBilling prints the organization's plan, billing status, limits with
// their usage and the managed providers' pass-through (GET /v1/billing).
func runBilling(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	client, _, err := cli.begin(newFlagSet("billing", shared), shared, args, 0, billingUsage)
	if err != nil {
		return err
	}
	billing, err := client.Billing.Get(ctx)
	if err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(billing)
	}
	return cli.printBilling(billing)
}

func (cli *app) printBilling(billing *redundantdns.Billing) error {
	plan := billing.Plan
	fmt.Fprintf(cli.stdout, "Plan %s (%s), status %s", dash(plan.Name), dash(plan.ID), dash(billing.Status))
	if billing.Interval != "" {
		fmt.Fprintf(cli.stdout, ", billed %s", billing.Interval)
	}
	fmt.Fprintln(cli.stdout)
	if billing.TrialEndsAt != nil {
		fmt.Fprintf(cli.stdout, "Trial ends %s (%d-day trial)\n", formatDate(billing.TrialEndsAt), billing.TrialDays)
	}
	if billing.NextInvoiceAt != nil {
		fmt.Fprintf(cli.stdout, "Next invoice %s\n", formatDate(billing.NextInvoiceAt))
	}
	if billing.CancelAtPeriodEnd || billing.CancelAt != nil {
		fmt.Fprintf(cli.stdout, "Subscription ends %s (cancellation scheduled)\n", formatDate(billing.CancelAt))
	}
	if billing.GraceEndsAt != nil {
		fmt.Fprintf(cli.stdout, "Past due: becomes read-only on %s\n", formatDate(billing.GraceEndsAt))
	}
	if billing.ReadOnlyReason != "" {
		fmt.Fprintf(cli.stdout, "Read-only (%s) since %s", billing.ReadOnlyReason, formatDate(billing.ReadOnlySince))
		if billing.DetachAt != nil {
			fmt.Fprintf(cli.stdout, "; attachments are detached on %s", formatDate(billing.DetachAt))
		}
		fmt.Fprintln(cli.stdout)
	}
	mode := dash(billing.BillingMode)
	if billing.CompedReason != "" {
		mode += " (" + billing.CompedReason + ")"
	}
	fmt.Fprintf(cli.stdout, "Billing mode %s, payment gateway %s\n\n", mode, dash(billing.Gateway))

	table := cli.table("LIMIT", "USED", "ALLOWED")
	fmt.Fprintf(table, "zones\t%d\t%s\n", billing.Limits.Zones.Used, limitText(billing.Limits.Zones))
	fmt.Fprintf(table, "providers per zone\t%d\t%s\n", billing.Limits.ProvidersPerZone.Used, limitText(billing.Limits.ProvidersPerZone))
	fmt.Fprintf(table, "alert channels\t%d\t%s\n", billing.Limits.Channels.Used, dash(strings.Join(billing.Limits.Channels.Kinds, ", ")))
	if err := table.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(cli.stdout, "Alert history %d days; multi-region probes %s; audit export %s; priority support %s\n",
		billing.AlertHistoryDays, yesNo(billing.MultiRegionProbes), yesNo(billing.AuditExport), yesNo(billing.PrioritySupport))

	if len(billing.Detached) > 0 {
		fmt.Fprintln(cli.stdout, "\nDetached attachments (attach them again with rdnsctl attach <zone> --connection <id> --provider-zone-id <id> --adopt-existing):")
		detached := cli.table("ZONE", "PROVIDER", "CONNECTION ID", "PROVIDER ZONE", "DETACHED")
		for _, entry := range billing.Detached {
			fmt.Fprintf(detached, "%s\t%s\t%s\t%s\t%s\n", entry.ZoneName, entry.Provider, entry.ConnectionID, entry.ProviderZoneID, formatDate(&entry.DetachedAt))
		}
		if err := detached.Flush(); err != nil {
			return err
		}
	}
	return cli.printManagedUsage(billing)
}

// printManagedUsage prints the managed providers' pass-through of the
// current period.
func (cli *app) printManagedUsage(billing *redundantdns.Billing) error {
	usage := billing.Usage
	if usage == nil || len(usage.Managed) == 0 {
		fmt.Fprintln(cli.stdout, "\nManaged pass-through: none this period.")
		return nil
	}
	fmt.Fprintf(cli.stdout, "\nManaged pass-through, period %s (markup %d%%):\n", dash(usage.Period), billing.ManagedMarkupPercent)
	table := cli.table("ZONE", "PROVIDER", "QUERIES", "ZONE COST", "QUERY COST", "BILLED")
	for _, line := range usage.Managed {
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\n", line.ZoneName, line.Provider, strconv.FormatFloat(line.Queries, 'f', -1, 64),
			redundantdns.FormatPrice(line.ZoneCostCents, "USD"), redundantdns.FormatPrice(line.QueryCostCents, "USD"), redundantdns.FormatPrice(line.BilledCents, "USD"))
	}
	if err := table.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(cli.stdout, "Total: %s provider cost, %s billed\n",
		redundantdns.FormatPrice(usage.PassThroughCents, "USD"), redundantdns.FormatPrice(usage.BilledCents, "USD"))
	return nil
}

// limitText is a limit for display: "unlimited" without a cap.
func limitText(usage redundantdns.LimitUsage) string {
	if usage.Unlimited() {
		return "unlimited"
	}
	return strconv.Itoa(usage.Limit)
}
