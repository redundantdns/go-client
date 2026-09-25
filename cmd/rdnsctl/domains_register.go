package main

import (
	"context"
	"flag"
	"fmt"
	"strconv"
	"strings"

	redundantdns "github.com/redundantdns/go-client"
)

// Usage lines of the registration commands.
const (
	domainsCheckUsage    = "rdnsctl domains check <domain> [<domain>...] [--years N]"
	domainsRegisterUsage = "rdnsctl domains register <domain> [--years N] [--contact ID] [--ns a,b] [--apply-zone-ns] " +
		"[--auto-renew[=false]] [--accept-domain-terms VERSION] [--open]"
	domainsRenewUsage       = "rdnsctl domains renew <domain> [--years N] [--open]"
	adminDomainsUsage       = "rdnsctl admin domains list | assign <domain> --org ID | register <domain> --org ID [register flags] [--skip-payment] | renew <domain> --org ID [--years N] --skip-payment"
	adminRegisterFlagsUsage = "register flags: --years N --contact ID --ns a,b --apply-zone-ns --auto-renew[=false] --open"
)

// ------------------------------------------------------------ check

func runDomainsCheck(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	flags := newFlagSet("domains check", shared)
	years := flags.Int("years", 1, "years to quote (1 to 10)")
	positionals, err := parseArgs(flags, args)
	if err != nil {
		return err
	}
	if len(positionals) == 0 || len(positionals) > redundantdns.MaxCheckNames {
		return usagef("usage: %s (1 to %d names)", domainsCheckUsage, redundantdns.MaxCheckNames)
	}
	client, err := cli.client(shared)
	if err != nil {
		return err
	}
	quotes, err := client.Domains.Check(ctx, positionals, *years)
	if err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(quotes)
	}
	table := cli.table("DOMAIN", "AVAILABLE", "PRICE", "NOTE")
	for _, quote := range quotes {
		price, note := "-", quote.Reason
		if quote.Available {
			price = fmt.Sprintf("%s for %s", quote.Price(), yearsText(quote.Years))
		}
		if quote.Premium {
			note = strings.TrimSpace("premium (registered on request) " + note)
		}
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\n", quote.Name, yesNo(quote.Available), price, dash(note))
	}
	return table.Flush()
}

// ------------------------------------------------------------ register

// registerFlags are the flags shared by domains register and admin domains
// register.
type registerFlags struct {
	flags       *flag.FlagSet
	years       *int
	contactID   *string
	nameservers *string
	applyZoneNS *bool
	autoRenew   *bool
	open        *bool
}

func newRegisterFlags(flags *flag.FlagSet) registerFlags {
	registered := registerFlags{
		flags:       flags,
		years:       flags.Int("years", 1, "years to register for (1 to 10)"),
		contactID:   flags.String("contact", "", "registrant contact id (default: the registrant profile)"),
		nameservers: flags.String("ns", "", "nameservers, comma separated (default: the zone's NS plan with --apply-zone-ns, else the registrar's)"),
		applyZoneNS: flags.Bool("apply-zone-ns", false, "use the NS plan of the organization's zone with the same name"),
		autoRenew:   flags.Bool("auto-renew", true, "auto-renewal (=false to turn it off)"),
		open:        flags.Bool("open", false, "open the checkout in the browser"),
	}
	flags.StringVar(registered.nameservers, "nameservers", "", "alias of --ns")
	return registered
}

// autoRenewValue is the auto-renewal to send (nil: the server default).
func (registered registerFlags) autoRenewValue() *bool {
	if flagWasSet(registered.flags, "auto-renew") {
		return redundantdns.Bool(*registered.autoRenew)
	}
	return nil
}

func runDomainsRegister(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	flags := newFlagSet("domains register", shared)
	register := newRegisterFlags(flags)
	acceptTerms := flags.String("accept-domain-terms", "", "the Domain Registration Terms version you accept for the organization")
	flags.StringVar(acceptTerms, "accept-terms", "", "alias of --accept-domain-terms")
	client, positionals, err := cli.begin(flags, shared, args, 1, domainsRegisterUsage)
	if err != nil {
		return err
	}
	checkout, err := client.Domains.Register(ctx, redundantdns.DomainRegisterCreate{
		Name: positionals[0], Years: *register.years, ContactID: *register.contactID, Nameservers: splitList(*register.nameservers),
		ApplyZoneNS: *register.applyZoneNS, AutoRenew: register.autoRenewValue(), AcceptDomainTerms: *acceptTerms,
	})
	if err != nil {
		return err
	}
	return cli.printCheckout(shared, checkout, *register.open, "Registration")
}

// printCheckout prints the outcome of a registration or renewal: the
// checkout to pay (opened with --open), or the job already started.
func (cli *app) printCheckout(shared *globals, checkout *redundantdns.DomainCheckout, open bool, what string) error {
	if checkout.NeedsPayment() && open {
		cli.openURL(checkout.CheckoutURL)
	}
	if shared.jsonOutput {
		return cli.printJSON(checkout)
	}
	name := checkout.Domain.Name
	if checkout.NeedsPayment() {
		price := ""
		if registration := checkout.Domain.Registration; what == "Registration" && registration != nil {
			price = fmt.Sprintf(" (%s for %s)", redundantdns.FormatPrice(registration.PriceCents, registration.Currency), yearsText(registration.Years))
		} else if renewal := checkout.Domain.Renewal; renewal != nil {
			price = fmt.Sprintf(" (%s for %s)", redundantdns.FormatPrice(renewal.PriceCents, renewal.Currency), yearsText(renewal.Years))
		}
		fmt.Fprintf(cli.stdout, "%s of %s waits for its payment%s. Pay it at:\n  %s\n", what, name, price, checkout.CheckoutURL)
		fmt.Fprintf(cli.stdout, "Follow it with: rdnsctl domains get %s\n", name)
		if what == "Registration" {
			fmt.Fprintf(cli.stdout, "Changed your mind? rdnsctl domains cancel %s releases the name.\n", name)
		}
		return nil
	}
	switch {
	case checkout.Queued():
		fmt.Fprintf(cli.stdout, "%s of %s: queued, the registrar will be retried (%s).\n", what, name, dash(checkout.Job.LastError))
	case checkout.Domain.Status == redundantdns.DomainStatusRegistrationFailed:
		fmt.Fprintf(cli.stdout, "%s of %s failed: %s\n", what, name, dash(checkout.Domain.LastError))
	default:
		fmt.Fprintf(cli.stdout, "%s of %s done: %s, expires %s.\n", what, name, checkout.Domain.Status, formatDate(checkout.Domain.ExpiresAt))
	}
	return nil
}

// openURL opens a checkout in the browser, best effort.
func (cli *app) openURL(target string) {
	open := cli.openBrowser
	if open == nil {
		open = openSystemBrowser
	}
	if err := open(target); err != nil {
		fmt.Fprintln(cli.stderr, "Could not open a browser; open the checkout URL below.")
	}
}

func runDomainsRegisterRetry(ctx context.Context, cli *app, args []string) error {
	return runDomainMutation(ctx, cli, args, "domains register-retry", "rdnsctl domains register-retry <domain>",
		func(ctx context.Context, client *redundantdns.Client, domain string) (*redundantdns.DomainMutationResult, error) {
			return client.Domains.RetryRegistration(ctx, domain)
		}, "registration retried")
}

func runDomainsCancel(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	flags := newFlagSet("domains cancel", shared)
	yes := flags.Bool("yes", false, "do not ask for confirmation")
	client, positionals, err := cli.begin(flags, shared, args, 1, "rdnsctl domains cancel <domain> [--yes]")
	if err != nil {
		return err
	}
	name := redundantdns.NormalizeZoneName(positionals[0])
	if !*yes {
		answer, err := cli.prompt(fmt.Sprintf("Cancel the unpaid registration of %s (its checkout is closed and the name released)? Type the domain name to confirm: ", name))
		if err != nil {
			return err
		}
		if redundantdns.NormalizeZoneName(answer) != name {
			return usagef("confirmation does not match %s; nothing was cancelled", name)
		}
	}
	if err := client.Domains.CancelRegistration(ctx, name); err != nil {
		return err
	}
	fmt.Fprintf(cli.stdout, "Cancelled the registration of %s; the name is released.\n", name)
	return nil
}

func runDomainsRenew(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	flags := newFlagSet("domains renew", shared)
	years := flags.Int("years", 1, "years to add (1 to 10)")
	open := flags.Bool("open", false, "open the checkout in the browser (billing on)")
	client, positionals, err := cli.begin(flags, shared, args, 1, domainsRenewUsage)
	if err != nil {
		return err
	}
	checkout, err := client.Domains.Renew(ctx, positionals[0], *years)
	if err != nil {
		return err
	}
	if !checkout.NeedsPayment() && !shared.jsonOutput && !checkout.Queued() {
		fmt.Fprintf(cli.stdout, "%s: renewed for %s, expires %s.\n", checkout.Domain.Name, yearsText(*years), formatDate(checkout.Domain.ExpiresAt))
		return nil
	}
	return cli.printCheckout(shared, checkout, *open, "Renewal")
}

// ------------------------------------------------------------ admin

func runAdminDomains(ctx context.Context, cli *app, args []string) error {
	if len(args) == 0 {
		return usagef("usage: %s\n%s", adminDomainsUsage, adminRegisterFlagsUsage)
	}
	action, rest := args[0], args[1:]
	switch action {
	case "list":
		return runAdminDomainsList(ctx, cli, rest)
	case "assign":
		return runAdminDomainsAssign(ctx, cli, rest)
	case "register":
		return runAdminDomainsRegister(ctx, cli, rest)
	case "renew":
		return runAdminDomainsRenew(ctx, cli, rest)
	}
	return usagef("usage: %s\n%s", adminDomainsUsage, adminRegisterFlagsUsage)
}

// adminTarget checks that --org names the target organization: it is
// never taken from RDNS_ORG or the saved config, so an operator does not
// act on the wrong organization by accident.
func adminTarget(shared *globals, usage string) (string, error) {
	orgID := strings.TrimSpace(shared.org)
	if orgID == "" {
		return "", usagef("name the organization with --org\nusage: %s", usage)
	}
	return orgID, nil
}

// adminClient drops the organization header: the admin routes name the
// organization in their path, and a token bound to another organization
// would be refused for the header alone.
func adminClient(client *redundantdns.Client) *redundantdns.Client {
	return client.WithOrg("")
}

func runAdminDomainsList(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	client, _, err := cli.begin(newFlagSet("admin domains list", shared), shared, args, 0, "rdnsctl admin domains list")
	if err != nil {
		return err
	}
	domains, err := client.Domains.AdminList(ctx)
	if err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(domains)
	}
	table := cli.table("DOMAIN", "STATUS", "EXPIRES", "ORG", "ORG NAME")
	for _, domain := range domains {
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\n", domain.Name, domain.Status, formatDate(domain.ExpiresAt), dash(domain.OrgID), dash(domain.OrgName))
	}
	return table.Flush()
}

func runAdminDomainsAssign(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	usage := "rdnsctl admin domains assign <domain> --org ID"
	client, positionals, err := cli.begin(newFlagSet("admin domains assign", shared), shared, args, 1, usage)
	if err != nil {
		return err
	}
	orgID, err := adminTarget(shared, usage)
	if err != nil {
		return err
	}
	domain, err := adminClient(client).Domains.AdminAssign(ctx, positionals[0], orgID)
	if err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(domain)
	}
	fmt.Fprintf(cli.stdout, "Assigned %s to organization %s (%s).\n", domain.Name, orgID, domain.Status)
	return nil
}

func runAdminDomainsRegister(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	flags := newFlagSet("admin domains register", shared)
	register := newRegisterFlags(flags)
	skipPayment := flags.Bool("skip-payment", false, "register without a checkout (paid by the operator)")
	usage := "rdnsctl admin domains register <domain> --org ID [--skip-payment] [register flags]"
	client, positionals, err := cli.begin(flags, shared, args, 1, usage)
	if err != nil {
		return err
	}
	orgID, err := adminTarget(shared, usage)
	if err != nil {
		return err
	}
	checkout, err := adminClient(client).Domains.AdminRegister(ctx, orgID, redundantdns.AdminDomainRegisterCreate{
		Name: positionals[0], Years: *register.years, ContactID: *register.contactID, Nameservers: splitList(*register.nameservers),
		ApplyZoneNS: *register.applyZoneNS, AutoRenew: register.autoRenewValue(), SkipPayment: *skipPayment,
	})
	if err != nil {
		return err
	}
	return cli.printCheckout(shared, checkout, *register.open, "Registration")
}

func runAdminDomainsRenew(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	flags := newFlagSet("admin domains renew", shared)
	years := flags.Int("years", 1, "years to add (1 to 10)")
	skipPayment := flags.Bool("skip-payment", false, "renew without a payment (required: a paid renewal goes through rdnsctl domains renew)")
	usage := "rdnsctl admin domains renew <domain> --org ID [--years N] --skip-payment"
	client, positionals, err := cli.begin(flags, shared, args, 1, usage)
	if err != nil {
		return err
	}
	orgID, err := adminTarget(shared, usage)
	if err != nil {
		return err
	}
	if !*skipPayment {
		return usagef("the admin route only renews without a payment: pass --skip-payment (a paid renewal goes through rdnsctl domains renew)")
	}
	job, err := adminClient(client).Domains.AdminRenew(ctx, orgID, positionals[0], redundantdns.AdminDomainRenew{Years: *years, SkipPayment: true})
	if err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(map[string]any{"job": job})
	}
	name := redundantdns.NormalizeZoneName(positionals[0])
	if job.Status == redundantdns.JobStatusQueued || job.Status == redundantdns.JobStatusRunning {
		fmt.Fprintf(cli.stdout, "Renewal of %s for %s: queued, the registrar will be retried (%s).\n", name, yearsText(*years), dash(job.LastError))
		return nil
	}
	fmt.Fprintf(cli.stdout, "Renewed %s for %s without a payment (job %s).\n", name, yearsText(*years), dash(job.JobID))
	return nil
}

// yearsText is "1 year" or "N years".
func yearsText(years int) string {
	if years == 1 {
		return "1 year"
	}
	return strconv.Itoa(years) + " years"
}
