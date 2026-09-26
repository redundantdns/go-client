# RedundantDNS Go client and `rdnsctl`

Go client for the [RedundantDNS](https://redundantdns.com) `/v1` API, and
`rdnsctl`, the command line built on it. RedundantDNS keeps one canonical
DNS zone and replicates it to two or more providers (Route 53, OCI DNS,
Google Cloud DNS, Azure DNS, Cloudflare...), so the domain stays up when one
of them goes down.

- Module: `github.com/redundantdns/go-client` (package `redundantdns`)
- Standard library only, Go 1.27+
- License: Apache-2.0

The same client powers the
[Terraform provider](https://github.com/redundantdns/terraform-provider-redundantdns).

## Install

```sh
go get github.com/redundantdns/go-client@latest
```

While the repository is private, tell Go not to use the public proxy and
checksum database for it, and let git authenticate:

```sh
go env -w GOPRIVATE=github.com/redundantdns/*
git config --global url."https://x-access-token:${GITHUB_TOKEN}@github.com/".insteadOf "https://github.com/"
```

## Library

```go
import redundantdns "github.com/redundantdns/go-client"

client, err := redundantdns.New(
	redundantdns.WithBaseURL("https://app.redundantdns.com"),
	redundantdns.WithToken(os.Getenv("RDNS_TOKEN")), // rdns_... or an OAuth access token
)
if err != nil {
	return err
}

zone, err := client.Zones.Create(ctx, redundantdns.ZoneCreate{Name: "example.com"})
_, err = client.Attachments.Create(ctx, zone.ZoneID, redundantdns.AttachmentCreate{ConnectionID: "conn-..."})
_, err = client.Records.Upsert(ctx, zone.ZoneID, redundantdns.RecordUpsert{
	Name: "www", Type: "A", TTL: 300, Values: []string{"192.0.2.10"},
})
status, err := client.Zones.WaitInSync(ctx, zone.ZoneID, redundantdns.WaitOptions{})
```

Services on the client: `Zones`, `Records`, `Connections`, `Attachments`,
`Sync` (reconcile, verify, adopt), `Delegation`, `Alerts` (rules, channels,
events), `Audit`, `Account` (me, orgs, providers, the user's legal
acceptance), `Legal` (the organization's Managed Provider Terms and Domain
Registration Terms), `Domains` (registrar domains, contacts, registrant
profile, export), `Licenses` (self-hosted licenses; issuing for platform
admins), `Exports` (the organization export bundle), `Compliance`
(compliance profiles), `Plans` (the public plan catalog), `Billing` (the
organization's plan, status, limits with usage and managed pass-through),
`OAuth` (client
registration, authorization code with PKCE, refresh) and, for dashboard
sessions only, `Auth` (e-mail code login) and `Tokens`. `Audit` also
verifies the audit stream and downloads its evidence bundle.

### Managed providers and their terms

Managed connections use platform-owned provider accounts. The organization
must accept the current **Managed Provider Terms and Acceptable Use
Policy** first, either with `Legal.AcceptManaged(ctx, version)` or in the
connection body (`ConnectionCreate.AcceptManagedTerms`, recorded the same
way). Without it, creating or attaching a managed connection fails with
`ErrManagedTermsRequired`; `ManagedTermsRequired(err)` returns the version
to accept and the URL of the text:

```go
status, err := client.Legal.ManagedStatus(ctx) // Current, Accepted, Required, URL
_, err = client.Connections.Create(ctx, redundantdns.ConnectionCreate{
	Provider: "route53", Mode: redundantdns.ModeManaged, AcceptManagedTerms: status.Current,
})
if requirement, ok := redundantdns.ManagedTermsRequired(err); ok {
	fmt.Println("read", requirement.URL, "and accept", requirement.Version)
}
```

### Domains (registrar)

Domains held at the platform's registrar account, with the organization as
registrant. Changes run as registrar jobs: a `DomainMutationResult` carries
the domain after the change and the job (`Queued()` when the registrar
failed transiently and the platform retries it). Every change except the
exit routes (`AuthCode`, unlocking with `SetLock(ctx, name, false)`,
`Sync`, `Export`) needs the organization's acceptance of the current
**Domain Registration Terms**: `Legal.AcceptDomain(ctx, version)` or
`DomainTransferCreate.AcceptDomainTerms`; without it the API answers
`ErrDomainTermsRequired` and `DomainTermsRequired(err)` returns the version
and the URL. Tokens need the `domains:read` / `domains:write` scopes.

```go
_, err := client.Domains.SetRegistrantProfile(ctx, redundantdns.ContactFields{
	FirstName: "Ada", LastName: "Lovelace", Email: "ada@example.com", Phone: "+44.2071234567",
	Street: "Main Street", City: "London", PostalCode: "SW1A 1AA", Country: "GB",
})
result, err := client.Domains.TransferIn(ctx, redundantdns.DomainTransferCreate{
	Name: "example.com", AuthCode: authCode, ApplyZoneNS: true, AcceptDomainTerms: versions.DomainTerms,
})
status, err := client.Domains.WaitTransfer(ctx, "example.com", redundantdns.WaitTransferOptions{Sync: true})
if errors.Is(err, redundantdns.ErrTransferFailed) {
	_ = client.Domains.Delete(ctx, "example.com") // forget the failed transfer, release the name
}
_, err = client.Domains.ApplyZoneNS(ctx, "example.com", "") // NS plan of the zone with the same name
code, err := client.Domains.AuthCode(ctx, "example.com")     // transfer out, any time
```

Also: `List`/`All`, `Get`, `TransferStatus`, `SetNameservers`, `SetLock`,
`SetAutoRenew`, `ChangeRegistrant` (trade, repeat the name),
`Contacts`/`CreateContact`/`UpdateContact`/`DeleteContact`,
`RegistrantProfile`, `Export`/`ExportJSON` and, for platform admins,
`AdminList`/`AdminAssign`. The Free plan holds one domain (`402
plan_limit_reached`, `ErrPaymentRequired`).

**Registering a new domain** is paid once, through a hosted checkout:
`Check` quotes availability and the customer price (up to 20 names),
`Register` claims the name, creates the domain in `payment_pending` and
returns the `CheckoutURL` to open in a browser; the registrar job runs when
it is paid (poll `Get`: `registering`, then `active`, or
`registration_failed`, retried with `RetryRegistration` once the cause is
fixed; there is no automatic refund). `CancelRegistration` closes an unpaid
checkout and releases the name. `Renew` returns a `DomainCheckout` too:
with billing on it opens a checkout (`NeedsPayment()`), with billing off the
registrar renews at once (`Job`).

```go
quotes, err := client.Domains.Check(ctx, []string{"example.tools", "example.dev"}, 1)
for _, quote := range quotes {
	fmt.Println(quote.Name, quote.Available, quote.Price()) // example.tools true 33.00 USD
}
checkout, err := client.Domains.Register(ctx, redundantdns.DomainRegisterCreate{
	Name: "example.tools", Years: 1, ApplyZoneNS: true, AcceptDomainTerms: versions.DomainTerms,
})
fmt.Println("pay at", checkout.CheckoutURL) // the domain is payment_pending until then
```

Errors of a registration: `409 domainUnavailable`, `422 domainPremium`
(premium names are registered on request), `422 invalidYears`, `503
billing_unavailable` (no payment gateway) or `registrarUnavailable`,
`409 domainRegistrationPending` for changes before it is registered, `409
domainNotRetryable`, `409 domainRenewalInProgress`. Platform admins can
register or renew for an organization without a payment:
`AdminRegister(ctx, orgID, AdminDomainRegisterCreate{..., SkipPayment: true})`
(the organization must have accepted the terms itself; no plan limit) and
`AdminRenew(ctx, orgID, name, AdminDomainRenew{SkipPayment: true})`.

### Licenses, org export, compliance and the audit stream

```go
// Licenses of your self-hosted installations (owners download the file).
licenses, err := client.Licenses.List(ctx)
file, err := client.Licenses.Download(ctx, licenses[0].LID) // file.Token, file.Filename
// Platform admins: AdminList(acct), AdminIssue(claims), AdminSetStatus(lid, status), AdminToken(lid).

// The whole organization, secrets included, sealed under a passphrase.
export, err := client.Exports.Request(ctx, passphrase) // at least 12 characters
export, err = client.Exports.Status(ctx, export.JobID)  // until ExportReady
bundle, err := client.Exports.Download(ctx, export.JobID)
defer bundle.Close() // an io.ReadCloser; bundle.SHA256 is the digest to check

// Compliance: 0 pass, 1 warn, 2 fail with report.ExitCode().
report, err := client.Compliance.Report(ctx, redundantdns.ComplianceISO27001, "")
report, err = client.Compliance.Run(ctx, "", "")   // recorded in the audit log and stream
last, err := client.Compliance.Last(ctx, "")        // nil before the first run

// Audit stream: verification report and evidence bundle (inclusive days).
verify, err := client.Audit.Verify(ctx, "2026-09-01", "2026-09-30") // verify.OK
evidence, err := client.Audit.Export(ctx, "", "")                  // a tar, plans with audit export

// Public plan catalog: the trial and the billing intervals on sale.
catalog, err := client.Plans.Catalog(ctx)
yearly := catalog.IntervalOnSale(redundantdns.IntervalYearly) // catalog.Trial.Days: the trial

// The organization's billing page (viewer + zones:read): plan, status,
// limits with usage (Limit == redundantdns.Unlimited without a cap) and the
// managed providers' pass-through of the period.
billing, err := client.Billing.Get(ctx)
zonesLeft := billing.Limits.Zones.Limit - billing.Limits.Zones.Used
```

The export routes name the organization in their path: the client's
`WithOrg`, else the token's only organization. `Exports.Download` asks for
a fresh one-time link (every `Status` call replaces the previous one),
always follows it on the client's base URL and never retries it; it answers
`ErrExportNotReady` while the export is queued or failed. Downloads
(`*redundantdns.Download`) stream: read them to the end and close them. New
sentinels: `ErrGone` (410, `exportExpired`) and `ErrLicenseDegraded` (503
`license_degraded`, a self-hosted installation whose license is degraded).

### Subdomain redundancy

When a zone is a subdomain of another zone of the organization
(`api.example.com` under `example.com`), the platform can write its NS
delegation into the parent and keep it updated as providers are attached
(`RecordSet.ManagedBy == "delegation"` there; such sets cannot be edited).
`ZoneCreate.ParentDelegation` takes `redundantdns.Bool(true)` or `false`;
nil lets the server decide. `Zone.ParentDelegation` shows the parent. A
delegation check on a domain registered at Cloudflare Registrar has
`Hint == DelegationHintCloudflareRegistrar` and `Registrar` from RDAP.

### Token clients and OAuth software ids

The plan gates the Terraform provider, the CLI and MCP by what a token
declares. `TokenCreate.Client` is `api` (default), `terraform`, `cli` or
`mcp`; an OAuth client declares itself at registration with
`OAuthClientRegistration.SoftwareID` (`SoftwareIDCLI`,
`SoftwareIDTerraform`). `OAuthCredentials` saves an OAuth login to a file
(mode 0600) and `RefreshOAuthCredentials` refreshes it, writing the rotated
refresh token back; this is how the Terraform provider reuses
`rdnsctl terraform login`.

### Authentication and organizations

| Option | Sends | Use |
|---|---|---|
| `WithToken(t)` | `Authorization: Bearer t` | personal access token (`rdns_...`) or OAuth 2.1 access token |
| `WithSession(s)` | `Cookie: rdns_session=s` | the session from `Auth.VerifyCode`: accept the legal documents, mint tokens |
| `WithOrg(id)` | `X-RDNS-Org: id` | pick the organization of a session; a token only accepts its own |

`client.WithOrg(id)` returns a copy bound to another organization.

### Errors

API errors are `*redundantdns.APIError` with the HTTP status, the stable
code and the English message:

```go
_, err := client.Zones.Get(ctx, "zone-missing")
errors.Is(err, redundantdns.ErrNotFound)                     // by status
redundantdns.HasCode(err, redundantdns.CodeZoneNotFound)    // by code
var apiError *redundantdns.APIError
if errors.As(err, &apiError) { fmt.Println(apiError.Code, apiError.Details) }
```

Sentinels: `ErrBadRequest`, `ErrUnauthorized`, `ErrForbidden`,
`ErrNotFound`, `ErrConflict`, `ErrUnprocessable`, `ErrGone`, `ErrLicenseDegraded`,
`ErrLegalAcceptanceRequired`, `ErrManagedTermsRequired`,
`ErrDomainTermsRequired`, `ErrPaymentRequired`, `ErrRateLimited`,
`ErrServer`.

### Retries

`429` answers are always retried; `5xx` answers and network errors are
retried for idempotent methods only (GET, PUT, DELETE), because a POST that
reached the server may have taken effect. The default policy retries 4
times with exponential backoff (0.5 s, 1 s, 2 s, 4 s, with jitter), honors
`Retry-After` and caps a delay at 30 s. Change it with
`WithRetryPolicy(redundantdns.RetryPolicy{...})` or disable it with
`WithRetryPolicy(redundantdns.NoRetry())`. Every call stops when its
context is done.

### Pagination

The `/v1` lists answer the whole collection today (the alert history takes
a `limit`, capped at 500 by the server). `Zones.All` and the generic
`Paginate`/`Collect`/`Chunk` helpers give an iterator API that will not
change if the server adds cursors:

```go
for zone, err := range client.Zones.All(ctx) {
	if err != nil { return err }
	fmt.Println(zone.Name)
}
```

### Canonical values

The API stores record values in a canonical form (lowercase hostnames with
a trailing dot, compressed IPv6, quoted TXT strings, sorted values).
`NormalizeRecordValues`, `EqualRecordValues` and `NormalizeRecordName`
mirror it, so a client can compare what it sent with what it reads back.

### Testing your code

Package `rdnstest` has two test servers:

- `rdnstest.NewReplayServer(t, routes)` answers routes with responses
  recorded from a real deployment (`rdnstest/fixtures`, refreshed with
  `scripts/record-fixtures.sh`).
- `rdnstest.NewFake(t)` is a small stateful fake of `/v1` (zones, records,
  the `fake` provider, attachments, jobs, alerts, managed terms, parent
  delegation, domains, licenses, org exports, compliance, the audit stream
  and the plan catalog) and of the OAuth endpoints (it approves every
  authorization at once), with failure injection (`FailNext(429, 503)`).

The fake's domains module simulates the registrar: a transfer stays
`transfer_pending` until it has been read `SetTransferReads(n)` times
(default 2; `GET` the domain or its transfer, or `sync`), an auth code
starting with `invalid` is rejected at once (`422 registrarRejected`, the
domain stays as `transfer_failed`) and one starting with `fail` is accepted
and then fails. It enforces the Domain Registration Terms, the registrant
profile and, on the default `free` plan (`SetPlan`), one domain. Seed state
with `SeedDomain`, `SeedUnassignedDomain`, `SeedContact` and
`AcceptDomainTerms`.

Registration follows the platform's fake registrar: `GET
/v1/domains/check` quotes `DomainPriceCents` (a first label starting with
`taken-` is not available, `premium-` is a premium name). The payment
gateway is off by default (`503 billing_unavailable`, renewals apply at
once); `SetDomainBilling(true)` makes `register` and `renew` return a
checkout URL served by the fake (`GET /fake-stripe/checkout?session=...`,
no token), which pays at once, or pay it with `PayDomainCheckout(name)`.
A paid name whose first label starts with `fail-` ends as
`registration_failed`; `register/retry` then succeeds.

The fake's caller owns its organization and is a platform admin, so the
license routes of both sides answer (`SeedLicense`, `SetLicenseIssuer(false)`
for `503 license_issuer_unavailable`, `LicenseDownloadsPerHour`). An
export is ready after `SetExportReads(n)` status reads (default 1); a
passphrase starting with `fail` makes it fail. `SetCompliance("warn")` sets
the status of every compliance report; `TamperAuditStream` makes the
verification fail and `SetAuditStream(false)` answers `503
auditStreamUnavailable`. The audit evidence bundle needs `SetPlan("business")`.
`FakePlanCatalog()` is the catalog `GET /v1/plans` answers (no token).
`GET /v1/billing` follows `SetPlan` (the trial on `free`) and the fake's
zones, attachments and channels; `SetBillingUsage` sets the usage snapshot
(managed pass-through lines).

Fixtures for routes the dev lab does not serve yet (`legal_*`,
`managed_terms_required`, `zone_create_child`) follow the documented API
contract and are overwritten by the next recording run; `synthetic_*`
fixtures are states the lab cannot produce on demand.

## rdnsctl

```sh
go install github.com/redundantdns/go-client/cmd/rdnsctl@latest
# or download a release archive (built by goreleaser)
```

```text
$ rdnsctl login --base-url https://app.redundantdns.com
E-mail: you@example.com
A login code was sent to you@example.com.
Code: 123456
Signed in as you@example.com, organization Acme (org-...).
Token tok-... (zones:read, zones:write, connections:read, connections:write, domains:read, domains:write) saved to ~/.config/rdnsctl/config.json.

$ rdnsctl connections create --provider route53 --label "AWS prod" \
    --cred accessKeyId=AKIA... --cred secretAccessKey=... --scope region=us-east-1
$ rdnsctl zones create example.com
$ rdnsctl attach example.com --connection conn-... --label "Route 53 primary"
$ rdnsctl records upsert example.com --name www --type A --value 192.0.2.10 --ttl 300
$ rdnsctl sync reconcile example.com --wait
$ rdnsctl delegation check example.com
$ rdnsctl alerts list --state firing

# managed providers: read the terms, then accept them explicitly
$ rdnsctl legal managed status
$ rdnsctl connections create --provider route53 --mode managed --accept-managed-terms 2026-09-24
# subdomain redundancy: api.example.com delegated from example.com
$ rdnsctl zones create api.example.com --parent-delegation
# OAuth credentials for the Terraform provider
$ rdnsctl terraform login

# domains: registrant profile, terms, transfer in, then point it at the zone
$ rdnsctl domains registrant-profile set --first-name Ada --last-name Lovelace --email ada@example.com \
    --phone +44.2071234567 --street "Main Street" --city London --postal-code "SW1A 1AA" --country GB
$ rdnsctl domains terms status
$ rdnsctl domains transfer example.com --apply-zone-ns --accept-terms 2026-09-24 --wait
$ rdnsctl domains apply-zone-ns example.com
$ rdnsctl domains authcode example.com      # transfer out, any time
$ rdnsctl domains export --out domains-export.json
# register a new domain: check the price, then pay the checkout
$ rdnsctl domains check example.tools example.dev
DOMAIN         AVAILABLE  PRICE                 NOTE
example.tools  yes        33.00 USD for 1 year  -
example.dev    no         -                     registered by someone else
$ rdnsctl domains register example.tools --apply-zone-ns --accept-domain-terms 2026-09-24 --open
Registration of example.tools waits for its payment (33.00 USD for 1 year). Pay it at:
  https://checkout.stripe.com/c/pay/cs_live_...
Follow it with: rdnsctl domains get example.tools

# compliance posture: exit 0 pass, 1 warn, 2 fail (3 on an error)
$ rdnsctl compliance --profile iso27001
$ rdnsctl compliance run          # recorded in the audit log and stream
# audit stream: verify the chain and seals, download the evidence bundle
$ rdnsctl audit verify --from 2026-09-01 --to 2026-09-30
$ rdnsctl audit export --out evidence.tar
# export the whole organization, secrets included (owners)
$ rdnsctl export request --passphrase-file ~/.rdns-export-passphrase --wait
$ rdnsctl export download job-... --out org-bundle.tar
# plan, billing status, limits with usage, managed pass-through
$ rdnsctl billing
# self-hosted licenses
$ rdnsctl licenses list
$ rdnsctl licenses download lic-... --out acme.license
```

Commands: `login`, `logout`, `whoami`, `zones list|get|create|delete|export|status`,
`records list|upsert|delete`, `connections list|create|test|delete`,
`providers list`, `attach`, `detach`, `sync reconcile|verify|adopt|status`,
`delegation check`, `alerts list|resolve|ack|rules|channels`,
`legal managed status|accept`, `terraform login`,
`domains list|get|check|register|register-retry|cancel|transfer|transfer-status|sync|nameservers set|apply-zone-ns|lock|unlock|autorenew|renew|authcode|registrant set|contacts|registrant-profile|export|terms|delete`,
`admin domains list|assign|register|renew`,
`licenses list|download`, `admin licenses list|issue|status|token`,
`export request|status|download`, `compliance [run|last]`,
`audit verify|export`, `billing`, `version`.
Run `rdnsctl help <command>` for the flags.

- Zones are referenced by id (`zone-...`) or name.
- Global flags: `--base-url`, `--token`, `--org`, `--json`, `--config`,
  before or after the command (`rdnsctl --json zones list` and
  `rdnsctl zones list --json` are the same). Environment: `RDNS_BASE_URL`, `RDNS_TOKEN`, `RDNS_ORG`. Flags win over
  the environment, which wins over the saved config.
- `login` mints a personal access token declared as the CLI
  (`client: cli`) and stores it in `$XDG_CONFIG_HOME/rdnsctl/config.json`
  (`~/.config/rdnsctl/config.json` by default) with mode `0600`.
  `login --token rdns_...` saves an existing token instead. `logout` removes
  the file; revoke the token in the dashboard (tokens cannot revoke tokens).
- `connections create --mode managed` refuses to run without
  `--accept-managed-terms <version>` and prints where to read the terms;
  `legal managed accept <version>` records the acceptance on its own
  (organization admins).
- `zones create --parent-delegation` (or `=false`) decides whether the
  delegation of a subdomain zone is written into its parent; unset lets
  the server decide. `delegation check` explains the options when the
  domain is registered at Cloudflare Registrar.
- `domains transfer` prompts for the auth code when `--auth-code` is not
  given (keeps it out of the shell history); `--accept-terms <version>`
  accepts the Domain Registration Terms in the same call and `--wait`
  polls the registrar until the transfer completes or fails. A failed
  transfer is forgotten with `domains delete`. `domains contacts
  update` and `domains registrant-profile set` change only the fields
  given as flags. `domains authcode`, `unlock`, `sync` and `export` work
  without the terms (the exit guarantee). `domains export --out` writes
  the file with mode `0600` (it holds contact data).
- `domains register` prints the checkout URL (`--open` opens it in the
  browser); the domain stays `payment_pending` until it is paid.
  `--ns a,b` sets the nameservers, `--apply-zone-ns` uses the NS plan of the
  zone with the same name, `--accept-domain-terms <version>` (alias
  `--accept-terms`) accepts the terms in the same call. `domains cancel`
  closes an unpaid checkout and releases the name; `domains
  register-retry` runs a paid registration that failed again. `domains
  renew` prints a checkout URL too when the deployment bills renewals.
- `admin domains register <name> --org ID --skip-payment` and `admin
  domains renew <name> --org ID --skip-payment` register or renew for an
  organization without a payment (platform admins; `--org` is required
  and never taken from `RDNS_ORG` or the saved config).
- `login` asks for the `domains:*` scopes too; a deployment without the
  domains module gets a token with the other scopes.
- `terraform login` registers an OAuth client declared as
  `terraform-provider-redundantdns`, opens the consent page (the callback
  listens on `127.0.0.1:38971`, `--port` to change) and saves
  `$XDG_CONFIG_HOME/redundantdns/terraform-oauth.json` for the provider.
- `compliance` runs a profile now (`--profile`, default baseline;
  `--scope platform` for the installation, platform admins with a dashboard
  session), `compliance run` records it, `compliance last` prints the last
  recorded report. The exit code mirrors `rdns compliance`: `0` pass, `1`
  warn, `2` fail, `3` for a usage or API error.
- `audit verify` exits `1` when the verification fails; `audit export`
  needs a plan with audit export (Business and above).
- `export request` reads the passphrase from `--passphrase-file` (`-` for
  stdin), never from a flag value; `--wait` polls until the bundle is ready.
  `export download` checks the SHA-256 the server announced before keeping
  the file. `export status --json` leaves the one-time link out.
- `licenses download`, `admin licenses token` and `admin licenses issue
  --out` write the signed license. Every file the CLI downloads (licenses,
  bundles) is written with mode `0600` under a temporary name and renamed
  when complete, never over an existing file; `--out -` prints to stdout.
  Without `--out` the server's file name is used, reduced to a base name in
  the working directory.
- Destructive commands (`zones delete`, `detach --delete-remote`,
  `domains delete`, `domains cancel`, `domains registrant set`, `domains contacts delete`)
  ask you to type the name unless `--yes` is given. A wrong answer or no
  answer at all (stdin closed, as in a script without `--yes`) aborts with
  exit code `2` and changes nothing.
- `records upsert` and `records delete` say the providers are being
  reconciled only when the zone has an attachment; otherwise the change is
  saved in the canonical zone ("no providers attached yet").
- `billing` shows the plan, the billing status (trial end, next invoice,
  read-only reason), the limits with their usage and the managed
  providers' pass-through of the period; `--json` prints `GET /v1/billing`
  as is.
- Exit codes: `0` success, `1` API or runtime error, `2` wrong usage or an
  aborted confirmation (`compliance` has its own, above).

## Development

```sh
go vet ./...
go test ./...
golangci-lint run ./...

# integration tests against a deployment in e2e mode (any e-mail, code 123456):
RDNS_BASE_URL=http://localhost:8080 go test -tags integration -v ./...
# or with an existing admin token (every scope):
RDNS_BASE_URL=https://... RDNS_TOKEN=rdns_... go test -tags integration -v ./...
```

The integration test creates a connection on the `fake` provider, a zone,
an attachment, records, sync jobs, a delegation check and an alert channel,
and deletes all of it at the end, also when a step fails. The domain
registration test needs the fake registrar and payment gateway
(`RDNS_REGISTRAR=fake`, `RDNS_BILLING=fake`): it checks, registers and
cancels (the name is released); `RDNS_IT_PAY_DOMAIN=1` also pays one
registration, which stays in the organization. It skips on deployments
without the domains module, a registrar or a payment gateway. The
compliance test reads the plan catalog, runs the baseline profile on the
organization and verifies its audit stream (skipped without an audit
stream).

The managed-mode test (managed terms and parent delegation) needs the org on
a paid plan. The bootstrap moves the org to Starter through the e2e hook
`POST /e2e/billing/plan` (deployments with `RDNS_E2E=1`); on a deployment
without the hook the test skips when the org is on the Free plan, so run it
against an e2e deployment or with a token whose org is already on a paid
plan.

Releases: tag `vX.Y.Z`; the release workflow runs goreleaser to attach the
`rdnsctl` archives and checksums to the GitHub release.
