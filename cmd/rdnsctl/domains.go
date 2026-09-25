package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	redundantdns "github.com/redundantdns/go-client"
)

// Usage lines of the domains commands.
const (
	domainsTransferUsage = "rdnsctl domains transfer <domain> [--auth-code CODE] [--contact ID] [--nameservers a,b] " +
		"[--apply-zone-ns] [--auto-renew[=false]] [--accept-terms VERSION] [--wait [--timeout 30m]]"
	domainsNameserversUsage       = "rdnsctl domains nameservers set <domain> <nameserver> <nameserver> [<nameserver>...]"
	domainsRegistrantUsage        = "rdnsctl domains registrant set <domain> --contact ID [--yes]"
	domainsContactsUsage          = "rdnsctl domains contacts list | create [contact flags] | update <contactId> [contact flags] | delete <contactId>"
	domainsRegistrantProfileUsage = "rdnsctl domains registrant-profile get | set [contact flags]"
	domainsTermsUsage             = "rdnsctl domains terms status | accept <version>"
	contactFlagsHelp              = "contact flags: --label --company --first-name --last-name --email --phone (+CC.NUMBER) " +
		"--street --house-number --city --state --postal-code --country (ISO alpha-2) --tax-id"
)

// domainsGroup is the domains command group.
func domainsGroup() group {
	return group{summary: "Domains at the registrar: register, transfer in and manage (the organization is the registrant)", subcommands: map[string]command{
		"list":               {summary: "List the organization's domains", usage: "rdnsctl domains list", run: runDomainsList},
		"get":                {summary: "Show a domain", usage: "rdnsctl domains get <domain>", run: runDomainsGet},
		"transfer":           {summary: "Transfer a domain in with its auth code", usage: domainsTransferUsage, run: runDomainsTransfer},
		"transfer-status":    {summary: "Show the progress of a transfer", usage: "rdnsctl domains transfer-status <domain>", run: runDomainsTransferStatus},
		"sync":               {summary: "Refresh a domain from the registrar now", usage: "rdnsctl domains sync <domain>", run: runDomainsSync},
		"nameservers":        {summary: "Set a domain's nameservers", usage: domainsNameserversUsage, run: runDomainsNameservers},
		"apply-zone-ns":      {summary: "Write a zone's NS plan as the domain's nameservers", usage: "rdnsctl domains apply-zone-ns <domain> [--zone ZONE]", run: runDomainsApplyZoneNS},
		"lock":               {summary: "Turn the transfer lock on", usage: "rdnsctl domains lock <domain>", run: runDomainsLock},
		"unlock":             {summary: "Turn the transfer lock off (to transfer out)", usage: "rdnsctl domains unlock <domain>", run: runDomainsUnlock},
		"autorenew":          {summary: "Turn auto-renewal on or off", usage: "rdnsctl domains autorenew <domain> on|off", run: runDomainsAutoRenew},
		"renew":              {summary: "Renew a domain (opens a checkout when billing is on)", usage: domainsRenewUsage, run: runDomainsRenew},
		"check":              {summary: "Availability and price of names to register", usage: domainsCheckUsage, run: runDomainsCheck},
		"register":           {summary: "Register a new domain, paid through a checkout", usage: domainsRegisterUsage, run: runDomainsRegister},
		"register-retry":     {summary: "Run a paid registration that failed again", usage: "rdnsctl domains register-retry <domain>", run: runDomainsRegisterRetry},
		"cancel":             {summary: "Cancel an unpaid registration and release the name", usage: "rdnsctl domains cancel <domain> [--yes]", run: runDomainsCancel},
		"authcode":           {summary: "Print the transfer-out auth code", usage: "rdnsctl domains authcode <domain>", run: runDomainsAuthCode},
		"registrant":         {summary: "Change the registrant (trade) to another contact", usage: domainsRegistrantUsage, run: runDomainsRegistrant},
		"contacts":           {summary: "Registrant contacts", usage: domainsContactsUsage, run: runDomainsContacts},
		"registrant-profile": {summary: "The organization's registrant profile (default contact)", usage: domainsRegistrantProfileUsage, run: runDomainsRegistrantProfile},
		"export":             {summary: "Export contacts, domains and zone files as JSON", usage: "rdnsctl domains export [--out FILE]", run: runDomainsExport},
		"terms":              {summary: "Domain Registration Terms of the organization", usage: domainsTermsUsage, run: runDomainsTerms},
		"delete":             {summary: "Forget a domain whose transfer failed (or cancel an unpaid registration)", usage: "rdnsctl domains delete <domain> [--yes]", run: runDomainsDelete},
	}}
}

// ------------------------------------------------------------ reading

func runDomainsList(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	client, _, err := cli.begin(newFlagSet("domains list", shared), shared, args, 0, "rdnsctl domains list")
	if err != nil {
		return err
	}
	domains, err := client.Domains.List(ctx)
	if err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(domains)
	}
	table := cli.table("DOMAIN", "STATUS", "EXPIRES", "LOCKED", "AUTO-RENEW", "NAMESERVERS", "ZONE NS")
	for _, domain := range domains {
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", domain.Name, domain.Status, formatDate(domain.ExpiresAt),
			yesNo(domain.Locked), yesNo(domain.AutoRenew), dash(strings.Join(domain.Nameservers, ",")), zoneNSState(domain.Zone))
	}
	return table.Flush()
}

func runDomainsGet(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	client, positionals, err := cli.begin(newFlagSet("domains get", shared), shared, args, 1, "rdnsctl domains get <domain>")
	if err != nil {
		return err
	}
	domain, err := client.Domains.Get(ctx, positionals[0])
	if err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(domain)
	}
	cli.printDomain(domain)
	return nil
}

// printDomain prints the details of a domain.
func (cli *app) printDomain(domain *redundantdns.Domain) {
	fmt.Fprintf(cli.stdout, "Domain %s: %s at %s (id %s)\n", domain.Name, domain.Status, dash(domain.Registrar), dash(string(domain.RegistrarDomainID)))
	fmt.Fprintf(cli.stdout, "Expires %s, auto-renew %s, transfer lock %s\n", formatDate(domain.ExpiresAt), onOff(domain.AutoRenew), onOff(domain.Locked))
	fmt.Fprintf(cli.stdout, "Nameservers: %s\n", dash(strings.Join(domain.Nameservers, " ")))
	if registrant := domain.Registrant; registrant != nil {
		fmt.Fprintf(cli.stdout, "Registrant: %s (%s)\n", contactName(*registrant), dash(domain.OwnerContactID))
	}
	if zone := domain.Zone; zone != nil {
		fmt.Fprintf(cli.stdout, "Zone %s (%s): NS plan %s; %s, delegation %s\n", zone.Name, zone.ZoneID,
			dash(strings.Join(zone.NSPlan, " ")), zoneNSState(zone), dash(zone.DelegationState))
		if !zone.NameserversMatch && len(zone.NSPlan) > 0 {
			fmt.Fprintf(cli.stdout, "Apply the zone's NS plan with: rdnsctl domains apply-zone-ns %s\n", domain.Name)
		}
	}
	if transfer := domain.Transfer; transfer != nil {
		cli.printTransfer(domain.Name, transfer)
	}
	for _, job := range domain.PendingJobs {
		fmt.Fprintf(cli.stdout, "Job %s %s: %s (attempts %d) %s\n", dash(job.JobID), job.Op, job.Status, job.Attempts, job.LastError)
	}
	if domain.LastError != "" {
		fmt.Fprintf(cli.stdout, "Last error: %s\n", domain.LastError)
	}
}

func (cli *app) printTransfer(name string, transfer *redundantdns.DomainTransfer) {
	fmt.Fprintf(cli.stdout, "Transfer: %s (requested %s", transfer.State, formatTime(transfer.RequestedAt))
	if transfer.CompletedAt != nil {
		fmt.Fprintf(cli.stdout, ", completed %s", formatTime(transfer.CompletedAt))
	}
	fmt.Fprintln(cli.stdout, ")")
	if transfer.Detail != "" {
		fmt.Fprintf(cli.stdout, "Detail: %s\n", transfer.Detail)
	}
	if transfer.State == redundantdns.TransferStateFailed {
		fmt.Fprintf(cli.stdout, "Forget it with rdnsctl domains delete %s, then transfer it again.\n", name)
	}
}

func runDomainsTransferStatus(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	client, positionals, err := cli.begin(newFlagSet("domains transfer-status", shared), shared, args, 1, "rdnsctl domains transfer-status <domain>")
	if err != nil {
		return err
	}
	status, err := client.Domains.TransferStatus(ctx, positionals[0])
	if err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(status)
	}
	fmt.Fprintf(cli.stdout, "Domain %s: %s\n", status.Name, status.Status)
	if status.Transfer == nil {
		fmt.Fprintln(cli.stdout, "Not transferred in.")
		return nil
	}
	cli.printTransfer(status.Name, status.Transfer)
	return nil
}

// ------------------------------------------------------------ transfer

func runDomainsTransfer(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	flags := newFlagSet("domains transfer", shared)
	authCode := flags.String("auth-code", "", "transfer authorization (EPP) code; prompted when empty")
	contactID := flags.String("contact", "", "registrant contact id (default: the registrant profile)")
	nameservers := flags.String("nameservers", "", "nameservers to set in the transfer, comma separated (default: keep the current ones)")
	applyZoneNS := flags.Bool("apply-zone-ns", false, "write the NS plan of the zone with the same name when the transfer completes")
	autoRenew := flags.Bool("auto-renew", true, "auto-renewal (=false to turn it off)")
	acceptTerms := flags.String("accept-terms", "", "the Domain Registration Terms version you accept for the organization")
	wait := flags.Bool("wait", false, "wait until the transfer completes or fails")
	timeout := flags.Duration("timeout", 30*time.Minute, "maximum wait with --wait")
	interval := flags.Duration("interval", 30*time.Second, "poll interval with --wait")
	client, positionals, err := cli.begin(flags, shared, args, 1, domainsTransferUsage)
	if err != nil {
		return err
	}
	if *authCode == "" {
		if *authCode, err = cli.prompt("Auth code: "); err != nil {
			return err
		}
	}
	input := redundantdns.DomainTransferCreate{
		Name: positionals[0], AuthCode: *authCode, ContactID: *contactID, Nameservers: splitList(*nameservers),
		ApplyZoneNS: *applyZoneNS, AcceptDomainTerms: *acceptTerms,
	}
	if flagWasSet(flags, "auto-renew") {
		input.AutoRenew = redundantdns.Bool(*autoRenew)
	}
	result, err := client.Domains.TransferIn(ctx, input)
	if err != nil {
		return err
	}
	if !*wait {
		if shared.jsonOutput {
			return cli.printJSON(result)
		}
		fmt.Fprintf(cli.stdout, "Transfer of %s requested (%s). Follow it with: rdnsctl domains transfer-status %s\n",
			result.Domain.Name, result.Domain.Status, result.Domain.Name)
		return nil
	}
	waitCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	status, err := client.Domains.WaitTransfer(waitCtx, result.Domain.Name, redundantdns.WaitTransferOptions{Interval: *interval, Sync: true})
	if err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(status)
	}
	fmt.Fprintf(cli.stdout, "Transfer of %s %s; the domain is %s.\n", status.Name, status.Transfer.State, status.Status)
	return nil
}

// ------------------------------------------------------------ changes

// runDomainMutation runs a one-domain change and prints its outcome.
func runDomainMutation(ctx context.Context, cli *app, args []string, name, usage string,
	mutate func(ctx context.Context, client *redundantdns.Client, domain string) (*redundantdns.DomainMutationResult, error), done string,
) error {
	shared := &globals{}
	client, positionals, err := cli.begin(newFlagSet(name, shared), shared, args, 1, usage)
	if err != nil {
		return err
	}
	result, err := mutate(ctx, client, positionals[0])
	if err != nil {
		return err
	}
	return cli.printMutation(shared, result, done)
}

// printMutation prints a mutation result: JSON, or a line saying whether
// the registrar applied it.
func (cli *app) printMutation(shared *globals, result *redundantdns.DomainMutationResult, done string) error {
	if shared.jsonOutput {
		return cli.printJSON(result)
	}
	if result.Queued() {
		fmt.Fprintf(cli.stdout, "%s: queued, the registrar will be retried (%s).\n", result.Domain.Name, dash(result.Job.LastError))
		return nil
	}
	fmt.Fprintf(cli.stdout, "%s: %s.\n", result.Domain.Name, done)
	return nil
}

func runDomainsSync(ctx context.Context, cli *app, args []string) error {
	return runDomainMutation(ctx, cli, args, "domains sync", "rdnsctl domains sync <domain>",
		func(ctx context.Context, client *redundantdns.Client, domain string) (*redundantdns.DomainMutationResult, error) {
			return client.Domains.Sync(ctx, domain)
		}, "synced with the registrar")
}

func runDomainsLock(ctx context.Context, cli *app, args []string) error {
	return runDomainMutation(ctx, cli, args, "domains lock", "rdnsctl domains lock <domain>",
		func(ctx context.Context, client *redundantdns.Client, domain string) (*redundantdns.DomainMutationResult, error) {
			return client.Domains.SetLock(ctx, domain, true)
		}, "transfer lock on")
}

func runDomainsUnlock(ctx context.Context, cli *app, args []string) error {
	return runDomainMutation(ctx, cli, args, "domains unlock", "rdnsctl domains unlock <domain>",
		func(ctx context.Context, client *redundantdns.Client, domain string) (*redundantdns.DomainMutationResult, error) {
			return client.Domains.SetLock(ctx, domain, false)
		}, "transfer lock off")
}

func runDomainsApplyZoneNS(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	flags := newFlagSet("domains apply-zone-ns", shared)
	zone := flags.String("zone", "", "zone id or name (default: the zone with the same name)")
	client, positionals, err := cli.begin(flags, shared, args, 1, "rdnsctl domains apply-zone-ns <domain> [--zone ZONE]")
	if err != nil {
		return err
	}
	zoneID := ""
	if *zone != "" {
		if zoneID, err = resolveZoneID(ctx, client, *zone); err != nil {
			return err
		}
	}
	result, err := client.Domains.ApplyZoneNS(ctx, positionals[0], zoneID)
	if err != nil {
		return err
	}
	return cli.printMutation(shared, result, "nameservers set to the zone's NS plan ("+strings.Join(result.Domain.Nameservers, " ")+")")
}

func runDomainsNameservers(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	positionals, err := parseArgs(newFlagSet("domains nameservers", shared), args)
	if err != nil {
		return err
	}
	if len(positionals) < 4 || positionals[0] != "set" {
		return usagef("usage: %s", domainsNameserversUsage)
	}
	client, err := cli.client(shared)
	if err != nil {
		return err
	}
	result, err := client.Domains.SetNameservers(ctx, positionals[1], positionals[2:])
	if err != nil {
		return err
	}
	return cli.printMutation(shared, result, "nameservers set to "+strings.Join(result.Domain.Nameservers, " "))
}

func runDomainsAutoRenew(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	usage := "rdnsctl domains autorenew <domain> on|off"
	client, positionals, err := cli.begin(newFlagSet("domains autorenew", shared), shared, args, 2, usage)
	if err != nil {
		return err
	}
	var enable bool
	switch positionals[1] {
	case "on", "true":
		enable = true
	case "off", "false":
	default:
		return usagef("usage: %s", usage)
	}
	result, err := client.Domains.SetAutoRenew(ctx, positionals[0], enable)
	if err != nil {
		return err
	}
	return cli.printMutation(shared, result, "auto-renewal "+onOff(enable))
}

func runDomainsAuthCode(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	client, positionals, err := cli.begin(newFlagSet("domains authcode", shared), shared, args, 1, "rdnsctl domains authcode <domain>")
	if err != nil {
		return err
	}
	code, err := client.Domains.AuthCode(ctx, positionals[0])
	if err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(code)
	}
	fmt.Fprintln(cli.stdout, code.AuthCode)
	return nil
}

func runDomainsRegistrant(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	flags := newFlagSet("domains registrant", shared)
	contactID := flags.String("contact", "", "the new registrant's contact id")
	yes := flags.Bool("yes", false, "do not ask for confirmation")
	positionals, err := parseArgs(flags, args)
	if err != nil {
		return err
	}
	if len(positionals) != 2 || positionals[0] != "set" || *contactID == "" {
		return usagef("usage: %s", domainsRegistrantUsage)
	}
	client, err := cli.client(shared)
	if err != nil {
		return err
	}
	name := redundantdns.NormalizeZoneName(positionals[1])
	confirm := name
	if !*yes {
		answer, err := cli.prompt(fmt.Sprintf("Change the registrant (owner) of %s to %s? Type the domain name to confirm: ", name, *contactID))
		if err != nil {
			return err
		}
		if redundantdns.NormalizeZoneName(answer) != name {
			return usagef("confirmation does not match %s; nothing was changed", name)
		}
		confirm = answer
	}
	result, err := client.Domains.ChangeRegistrant(ctx, name, *contactID, confirm)
	if err != nil {
		return err
	}
	return cli.printMutation(shared, result, "registrant changed to "+*contactID)
}

func runDomainsDelete(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	flags := newFlagSet("domains delete", shared)
	yes := flags.Bool("yes", false, "do not ask for confirmation")
	client, positionals, err := cli.begin(flags, shared, args, 1, "rdnsctl domains delete <domain> [--yes]")
	if err != nil {
		return err
	}
	name := redundantdns.NormalizeZoneName(positionals[0])
	if !*yes {
		answer, err := cli.prompt(fmt.Sprintf("Forget %s (only a failed transfer can be forgotten; no registration is deleted)? Type the domain name to confirm: ", name))
		if err != nil {
			return err
		}
		if redundantdns.NormalizeZoneName(answer) != name {
			return usagef("confirmation does not match %s; nothing was deleted", name)
		}
	}
	if err := client.Domains.Delete(ctx, name); err != nil {
		return err
	}
	fmt.Fprintf(cli.stdout, "Forgot %s; the name is free for a new transfer.\n", name)
	return nil
}

// ------------------------------------------------------------ contacts

// contactFlags are the flags of a contact's fields.
type contactFlags struct {
	flags  *flag.FlagSet
	values map[string]*string
}

// contactFlagNames maps each flag to its field setter.
var contactFlagNames = map[string]func(fields *redundantdns.ContactFields, value string){
	"label":        func(fields *redundantdns.ContactFields, value string) { fields.Label = value },
	"company":      func(fields *redundantdns.ContactFields, value string) { fields.CompanyName = value },
	"first-name":   func(fields *redundantdns.ContactFields, value string) { fields.FirstName = value },
	"last-name":    func(fields *redundantdns.ContactFields, value string) { fields.LastName = value },
	"email":        func(fields *redundantdns.ContactFields, value string) { fields.Email = value },
	"phone":        func(fields *redundantdns.ContactFields, value string) { fields.Phone = value },
	"street":       func(fields *redundantdns.ContactFields, value string) { fields.Street = value },
	"house-number": func(fields *redundantdns.ContactFields, value string) { fields.HouseNumber = value },
	"city":         func(fields *redundantdns.ContactFields, value string) { fields.City = value },
	"state":        func(fields *redundantdns.ContactFields, value string) { fields.State = value },
	"postal-code":  func(fields *redundantdns.ContactFields, value string) { fields.PostalCode = value },
	"country":      func(fields *redundantdns.ContactFields, value string) { fields.Country = value },
	"tax-id":       func(fields *redundantdns.ContactFields, value string) { fields.TaxID = value },
}

// newContactFlags registers the contact flags on a flag set.
func newContactFlags(flags *flag.FlagSet) contactFlags {
	registered := contactFlags{flags: flags, values: map[string]*string{}}
	for name := range contactFlagNames {
		registered.values[name] = flags.String(name, "", "contact "+strings.ReplaceAll(name, "-", " "))
	}
	return registered
}

// overlay applies the flags given on the command line to base: fields
// without a flag keep their value (PUT routes replace every field).
func (registered contactFlags) overlay(base redundantdns.ContactFields) redundantdns.ContactFields {
	for name, set := range contactFlagNames {
		if flagWasSet(registered.flags, name) {
			set(&base, *registered.values[name])
		}
	}
	return base
}

func runDomainsContacts(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	flags := newFlagSet("domains contacts", shared)
	fields := newContactFlags(flags)
	yes := flags.Bool("yes", false, "do not ask for confirmation (delete)")
	positionals, err := parseArgs(flags, args)
	if err != nil {
		return err
	}
	if len(positionals) == 0 {
		return usagef("usage: %s\n%s", domainsContactsUsage, contactFlagsHelp)
	}
	action, rest := positionals[0], positionals[1:]
	wanted := map[string]int{"list": 0, "create": 0, "update": 1, "delete": 1}
	count, known := wanted[action]
	if !known || len(rest) != count {
		return usagef("usage: %s\n%s", domainsContactsUsage, contactFlagsHelp)
	}
	client, err := cli.client(shared)
	if err != nil {
		return err
	}
	switch action {
	case "list":
		return cli.listContacts(ctx, client, shared)
	case "create":
		contact, err := client.Domains.CreateContact(ctx, fields.overlay(redundantdns.ContactFields{}))
		if err != nil {
			return err
		}
		return cli.printContactResult(shared, contact, "Created contact")
	case "update":
		current, err := client.Domains.Contact(ctx, rest[0])
		if err != nil {
			return err
		}
		contact, err := client.Domains.UpdateContact(ctx, rest[0], fields.overlay(current.ContactFields))
		if err != nil {
			return err
		}
		return cli.printContactResult(shared, contact, "Updated contact")
	}
	if !*yes {
		answer, err := cli.prompt(fmt.Sprintf("Delete contact %s? Type the contact id to confirm: ", rest[0]))
		if err != nil {
			return err
		}
		if answer != rest[0] {
			return usagef("confirmation does not match %s; nothing was deleted", rest[0])
		}
	}
	if err := client.Domains.DeleteContact(ctx, rest[0]); err != nil {
		return err
	}
	fmt.Fprintf(cli.stdout, "Deleted contact %s.\n", rest[0])
	return nil
}

func (cli *app) listContacts(ctx context.Context, client *redundantdns.Client, shared *globals) error {
	contacts, err := client.Domains.Contacts(ctx)
	if err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(contacts)
	}
	table := cli.table("CONTACT ID", "LABEL", "NAME", "EMAIL", "COUNTRY", "PROFILE")
	for _, contact := range contacts {
		profile := ""
		if contact.Default {
			profile = "registrant profile"
		}
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\n", contact.ContactID, dash(contact.Label), contactName(contact),
			contact.Email, contact.Country, dash(profile))
	}
	return table.Flush()
}

func (cli *app) printContactResult(shared *globals, contact *redundantdns.Contact, verb string) error {
	if shared.jsonOutput {
		return cli.printJSON(contact)
	}
	fmt.Fprintf(cli.stdout, "%s %s (%s).\n", verb, contact.ContactID, contactName(*contact))
	return nil
}

func runDomainsRegistrantProfile(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	flags := newFlagSet("domains registrant-profile", shared)
	fields := newContactFlags(flags)
	positionals, err := parseArgs(flags, args)
	if err != nil {
		return err
	}
	if len(positionals) != 1 || (positionals[0] != "get" && positionals[0] != "set") {
		return usagef("usage: %s\n%s", domainsRegistrantProfileUsage, contactFlagsHelp)
	}
	client, err := cli.client(shared)
	if err != nil {
		return err
	}
	profile, err := client.Domains.RegistrantProfile(ctx)
	if err != nil {
		return err
	}
	if positionals[0] == "set" {
		base := redundantdns.ContactFields{}
		if profile != nil {
			base = profile.ContactFields
		}
		if profile, err = client.Domains.SetRegistrantProfile(ctx, fields.overlay(base)); err != nil {
			return err
		}
	}
	if shared.jsonOutput {
		return cli.printJSON(map[string]any{"profile": profile})
	}
	if profile == nil {
		fmt.Fprintln(cli.stdout, "No registrant profile yet: set one with rdnsctl domains registrant-profile set (see --help).")
		return nil
	}
	fmt.Fprintf(cli.stdout, "Registrant profile %s: %s\n", profile.ContactID, contactName(*profile))
	fmt.Fprintf(cli.stdout, "%s, %s\n%s %s, %s %s, %s %s\n", profile.Email, profile.Phone, profile.Street, profile.HouseNumber,
		profile.PostalCode, profile.City, profile.State, profile.Country)
	return nil
}

// ------------------------------------------------------------ export and terms

func runDomainsExport(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	flags := newFlagSet("domains export", shared)
	out := flags.String("out", "", "write the export to this file (mode 0600) instead of stdout")
	client, _, err := cli.begin(flags, shared, args, 0, "rdnsctl domains export [--out FILE]")
	if err != nil {
		return err
	}
	export, err := client.Domains.ExportJSON(ctx)
	if err != nil {
		return err
	}
	if *out == "" {
		_, err := cli.stdout.Write(export)
		return err
	}
	// The export holds personal data (contacts): keep it private.
	if err := os.WriteFile(*out, export, 0o600); err != nil {
		return fmt.Errorf("write the export: %w", err)
	}
	fmt.Fprintf(cli.stdout, "Export written to %s.\n", *out)
	return nil
}

func runDomainsTerms(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	positionals, err := parseArgs(newFlagSet("domains terms", shared), args)
	if err != nil {
		return err
	}
	if len(positionals) == 0 || (positionals[0] != "status" && positionals[0] != "accept") {
		return usagef("usage: %s", domainsTermsUsage)
	}
	client, err := cli.client(shared)
	if err != nil {
		return err
	}
	if positionals[0] == "status" {
		if len(positionals) != 1 {
			return usagef("usage: %s", domainsTermsUsage)
		}
		status, err := client.Legal.DomainStatus(ctx)
		if err != nil {
			return err
		}
		if shared.jsonOutput {
			return cli.printJSON(status)
		}
		cli.printDomainTermsStatus(status)
		return nil
	}
	if len(positionals) != 2 {
		// Acceptance must name the version the user read.
		if status, statusErr := client.Legal.DomainStatus(ctx); statusErr == nil {
			return usagef("name the version you accept: rdnsctl domains terms accept %s (text: %s)", status.Current, dash(status.URL))
		}
		return usagef("usage: %s", domainsTermsUsage)
	}
	status, err := client.Legal.AcceptDomain(ctx, positionals[1])
	if err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(status)
	}
	fmt.Fprintf(cli.stdout, "Accepted the Domain Registration Terms, version %s, for the organization.\n", status.Current)
	return nil
}

func (cli *app) printDomainTermsStatus(status *redundantdns.DomainTermsStatus) {
	fmt.Fprintf(cli.stdout, "Domain Registration Terms: version %s\nText: %s\n", status.Current, dash(status.URL))
	if status.Accepted != nil {
		fmt.Fprintf(cli.stdout, "Accepted version %s on %s by %s\n", status.Accepted.Version,
			status.Accepted.AcceptedAt.UTC().Format(time.RFC3339), dash(status.Accepted.UserID))
	}
	if status.Required {
		fmt.Fprintf(cli.stdout, "Not accepted: domain changes are refused until an admin runs rdnsctl domains terms accept %s\n"+
			"(the auth code, unlocking, sync and the export always work).\n", status.Current)
	} else {
		fmt.Fprintln(cli.stdout, "Domain changes are available.")
	}
}

// ------------------------------------------------------------ formatting

// zoneNSState says whether a domain's nameservers match its zone's NS plan.
func zoneNSState(zone *redundantdns.DomainZoneLink) string {
	switch {
	case zone == nil:
		return "-"
	case zone.NameserversMatch:
		return "match"
	default:
		return "differ"
	}
}

func contactName(contact redundantdns.Contact) string {
	name := strings.TrimSpace(contact.FirstName + " " + contact.LastName)
	if contact.CompanyName != "" {
		name += ", " + contact.CompanyName
	}
	return dash(name)
}

func formatDate(value *time.Time) string {
	if value == nil || value.IsZero() {
		return "-"
	}
	return value.UTC().Format("2006-01-02")
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func onOff(value bool) string {
	if value {
		return "on"
	}
	return "off"
}
