// Command rdnsctl is the RedundantDNS command line: sign in, manage zones,
// record sets, provider connections, attachments, sync jobs, delegation
// checks, alerts and registrar domains through the /v1 API.
//
//	rdnsctl login --base-url https://app.redundantdns.com
//	rdnsctl zones list
//	rdnsctl records upsert example.com --name www --type A --value 192.0.2.10
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// version is set at build time (-ldflags "-X main.version=...").
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cli := &app{stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr, getenv: os.Getenv}
	code := cli.run(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}
