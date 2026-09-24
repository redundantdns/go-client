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
events), `Audit`, `Account` (me, orgs, providers, legal) and, for dashboard
sessions only, `Auth` (e-mail code login) and `Tokens`.

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
`ErrNotFound`, `ErrConflict`, `ErrUnprocessable`,
`ErrLegalAcceptanceRequired`, `ErrRateLimited`, `ErrServer`.

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
  the `fake` provider, attachments, jobs, alerts) with failure injection
  (`FailNext(429, 503)`).

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
Token tok-... (zones:read, zones:write, connections:read, connections:write) saved to ~/.config/rdnsctl/config.json.

$ rdnsctl connections create --provider route53 --label "AWS prod" \
    --cred accessKeyId=AKIA... --cred secretAccessKey=... --scope region=us-east-1
$ rdnsctl zones create example.com
$ rdnsctl attach example.com --connection conn-... --label "Route 53 primary"
$ rdnsctl records upsert example.com --name www --type A --value 192.0.2.10 --ttl 300
$ rdnsctl sync reconcile example.com --wait
$ rdnsctl delegation check example.com
$ rdnsctl alerts list --state firing
```

Commands: `login`, `logout`, `whoami`, `zones list|get|create|delete|export|status`,
`records list|upsert|delete`, `connections list|create|test|delete`,
`providers list`, `attach`, `detach`, `sync reconcile|verify|adopt|status`,
`delegation check`, `alerts list|resolve|ack|rules|channels`, `version`.
Run `rdnsctl help <command>` for the flags.

- Zones are referenced by id (`zone-...`) or name.
- Global flags: `--base-url`, `--token`, `--org`, `--json`, `--config`.
  Environment: `RDNS_BASE_URL`, `RDNS_TOKEN`, `RDNS_ORG`. Flags win over
  the environment, which wins over the saved config.
- `login` stores the token in `$XDG_CONFIG_HOME/rdnsctl/config.json`
  (`~/.config/rdnsctl/config.json` by default) with mode `0600`.
  `login --token rdns_...` saves an existing token instead. `logout` removes
  the file; revoke the token in the dashboard (tokens cannot revoke tokens).
- Destructive commands (`zones delete`, `detach --delete-remote`) ask you
  to type the zone name unless `--yes` is given.
- Exit codes: `0` success, `1` API or runtime error, `2` wrong usage.

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
and deletes all of it at the end, also when a step fails.

Releases: tag `vX.Y.Z`; the release workflow runs goreleaser to attach the
`rdnsctl` archives and checksums to the GitHub release.
