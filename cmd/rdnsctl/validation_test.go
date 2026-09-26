package main

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	redundantdns "github.com/redundantdns/go-client"
	"github.com/redundantdns/go-client/rdnstest"
)

// Findings of the validation run against the dev deployment (D5, D6):
// global flags before the command, the billing command, the exit code of
// an aborted confirmation and the reconcile note of record changes.

func TestGlobalFlagsBeforeTheCommand(t *testing.T) {
	fake := rdnstest.NewFake(t)
	// No environment: base URL and token come from flags placed first.
	h := newHarness(t, nil)
	h.ok("--base-url", fake.URL, "--token", rdnstest.DefaultToken, "zones", "create", "example.com")
	var zones []redundantdns.Zone
	out := h.ok("--json", "--base-url="+fake.URL, "--token", rdnstest.DefaultToken, "zones", "list")
	if err := json.Unmarshal([]byte(out), &zones); err != nil || len(zones) != 1 {
		t.Fatalf("--json before the command = %v, %v\n%s", zones, err, out)
	}
	// Mixed: some globals before, some after, still one command.
	if out := h.ok("--base-url", fake.URL, "records", "list", "example.com", "--token", rdnstest.DefaultToken); !strings.Contains(out, "NAME") {
		t.Errorf("mixed positions = %s", out)
	}
	// A leading --org is applied (the fake refuses another organization).
	if out := h.run("", "--org", "org-other", "--base-url", fake.URL, "--token", rdnstest.DefaultToken, "zones", "list"); out.code != 1 || !strings.Contains(out.stderr, "forbidden") {
		t.Errorf("leading --org = %+v", out)
	}
	// A leading --config is the file login writes.
	config := t.TempDir() + "/custom.json"
	h.ok("--config", config, "login", "--base-url", fake.URL, "--token", rdnstest.DefaultToken)
	if out := h.ok("--config", config, "whoami"); !strings.Contains(out, "test@example.com") {
		t.Errorf("whoami with a leading --config = %s", out)
	}
	if out := h.run("", "--nope", "zones", "list"); out.code != 2 || !strings.Contains(out.stderr, "unknown global flag --nope") {
		t.Errorf("unknown leading flag = %+v", out)
	}
	if out := h.run("", "--config"); out.code != 2 || !strings.Contains(out.stderr, "flag needs an argument") {
		t.Errorf("--config without a value = %+v", out)
	}
	if out := h.ok("--json"); !strings.Contains(out, "commands:") {
		t.Errorf("only global flags = %s", out)
	}
	if out := h.ok("--json", "help", "zones"); !strings.Contains(out, "subcommands:") {
		t.Errorf("--json help zones = %s", out)
	}
}

func TestHoistGlobalFlags(t *testing.T) {
	cases := []struct {
		in   []string
		want []string
	}{
		{[]string{"zones", "list", "--json"}, []string{"zones", "list", "--json"}},
		{[]string{"--json", "zones", "list"}, []string{"zones", "list", "--json"}},
		{[]string{"--config", "c.json", "-org=o", "zones", "get", "z"}, []string{"zones", "get", "z", "--config", "c.json", "-org=o"}},
		// Flags go before a "--" terminator, never after it.
		{[]string{"--json", "records", "upsert", "z", "--", "-x"}, []string{"records", "upsert", "z", "--json", "--", "-x"}},
		{[]string{"--json", "--help"}, []string{"--help"}},
	}
	for _, testCase := range cases {
		got, err := hoistGlobalFlags(testCase.in)
		if err != nil || !slices.Equal(got, testCase.want) {
			t.Errorf("hoistGlobalFlags(%q) = %q, %v; want %q", testCase.in, got, err, testCase.want)
		}
	}
}

func TestBillingCommand(t *testing.T) {
	h, fake := fakeHarness(t)
	h.ok("zones", "create", "example.com")
	out := h.ok("billing")
	for _, want := range []string{"Plan Trial (trial), status trialing", "Trial ends 2026-10-24 (30-day trial)", "zones               1     1", "Managed pass-through: none this period."} {
		if !strings.Contains(out, want) {
			t.Errorf("billing lacks %q:\n%s", want, out)
		}
	}

	fake.SetPlan("business")
	fake.SetBillingUsage(&redundantdns.BillingUsage{
		Period: "2026-09",
		Managed: []redundantdns.ManagedUsageLine{{
			ZoneID: "zone-1", ZoneName: "example.com", Provider: "route53", Queries: 1500000, ZoneCostCents: 50, QueryCostCents: 60, BilledCents: 132,
		}},
		PassThroughCents: 110, BilledCents: 132,
	})
	out = h.ok("--json", "billing")
	var billing redundantdns.Billing
	if err := json.Unmarshal([]byte(out), &billing); err != nil || billing.Plan.ID != "business" || !billing.Limits.Zones.Unlimited() {
		t.Fatalf("billing --json = %+v, %v\n%s", billing, err, out)
	}
	out = h.ok("billing")
	for _, want := range []string{"Plan Business (business), status active", "unlimited", "audit export yes", "period 2026-09 (markup 20%)", "route53", "1.32 USD", "Total: 1.10 USD provider cost, 1.32 USD billed"} {
		if !strings.Contains(out, want) {
			t.Errorf("billing lacks %q:\n%s", want, out)
		}
	}
	if out := h.run("", "billing", "extra"); out.code != 2 {
		t.Errorf("billing with an argument = %+v", out)
	}
}

func TestZonesDeleteAbortedExitCode(t *testing.T) {
	h, fake := fakeHarness(t)
	h.ok("zones", "create", "example.com")
	wrong := h.run("wrong.example\n", "zones", "delete", "example.com")
	if wrong.code != exitAborted || !strings.Contains(wrong.stderr, "aborted: confirmation does not match example.com; nothing was deleted") {
		t.Errorf("wrong confirmation = %+v", wrong)
	}
	closed := h.run("", "zones", "delete", "example.com")
	if closed.code != exitAborted || !strings.Contains(closed.stderr, "aborted: no confirmation was typed (stdin closed); nothing was deleted") {
		t.Errorf("closed stdin = %+v", closed)
	}
	if fake.ZoneCount() != 1 {
		t.Fatal("an aborted delete removed the zone")
	}
	if out := h.run("example.com\n", "zones", "delete", "example.com"); out.code != 0 {
		t.Errorf("confirmed delete = %+v", out)
	}
}

func TestRecordChangesReconcileNote(t *testing.T) {
	h, _ := fakeHarness(t)
	h.ok("zones", "create", "example.com")
	out := h.ok("records", "upsert", "example.com", "--name", "www", "--type", "A", "--value", "192.0.2.10")
	if !strings.Contains(out, "(serial") || !strings.Contains(out, "; no providers attached yet.") || strings.Contains(out, "reconciled") {
		t.Errorf("upsert without attachments = %s", out)
	}
	out = h.ok("records", "delete", "example.com", "--name", "www", "--type", "A")
	if !strings.Contains(out, "; no providers attached yet.") || strings.Contains(out, "reconciled") {
		t.Errorf("delete without attachments = %s", out)
	}

	var created redundantdns.ConnectionCreateResult
	if err := json.Unmarshal([]byte(h.ok("connections", "create", "--provider", "fake", "--cred", "token=abcd1234", "--json")), &created); err != nil {
		t.Fatal(err)
	}
	h.ok("attach", "example.com", "--connection", created.Connection.ConnectionID)
	var zones []redundantdns.Zone
	if err := json.Unmarshal([]byte(h.ok("zones", "list", "--json")), &zones); err != nil || len(zones) != 1 {
		t.Fatal(err)
	}
	// By id too: the zone is read to know its attachments.
	out = h.ok("records", "upsert", zones[0].ZoneID, "--name", "www", "--type", "A", "--value", "192.0.2.10")
	if !strings.Contains(out, "Providers are being reconciled.") {
		t.Errorf("upsert with an attachment = %s", out)
	}
	if out := h.ok("records", "delete", "example.com", "--name", "www", "--type", "A"); !strings.Contains(out, "Providers are being reconciled.") {
		t.Errorf("delete with an attachment = %s", out)
	}
}
