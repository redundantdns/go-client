package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	redundantdns "github.com/redundantdns/go-client"
	"github.com/redundantdns/go-client/rdnstest"
)

func TestDomainsCheckCommand(t *testing.T) {
	h, fake := fakeHarness(t)
	fake.SeedDomain(redundantdns.Domain{Name: "held.com"})

	out := h.ok("domains", "check", "example.tools", "taken-x.com", "premium-x.com", "held.com", "--years", "2")
	for _, want := range []string{"DOMAIN", "AVAILABLE", "PRICE", "example.tools  yes", "66.00 USD for 2 years", "taken-x.com", "registered by someone else",
		"premium (registered on request)", "already in your organization"} {
		if !strings.Contains(out, want) {
			t.Errorf("check output lacks %q:\n%s", want, out)
		}
	}
	var quotes []redundantdns.DomainQuote
	if err := json.Unmarshal([]byte(h.ok("domains", "check", "example.com", "--json")), &quotes); err != nil || len(quotes) != 1 || quotes[0].PriceCents != 1300 {
		t.Errorf("check --json = %+v, %v", quotes, err)
	}
	if out := h.run("", "domains", "check"); out.code != 2 || !strings.Contains(out.stderr, "usage: rdnsctl domains check") {
		t.Errorf("check without names = %+v", out)
	}
	if out := h.run("", "domains", "check", "not a name"); out.code != 1 || !strings.Contains(out.stderr, "invalidDomainName") {
		t.Errorf("check invalid name = %+v", out)
	}
}

func TestDomainsRegisterCommands(t *testing.T) {
	h, fake := fakeHarness(t)
	var opened []string
	h.openBrowser = func(target string) error {
		opened = append(opened, target)
		return nil
	}

	if out := h.ok("domains", "--help"); !strings.Contains(out, "register-retry") || !strings.Contains(out, "rdnsctl domains cancel") {
		t.Errorf("domains help = %s", out)
	}
	if out := h.ok("domains", "register", "--help"); !strings.Contains(out, "--accept-domain-terms VERSION") || !strings.Contains(out, "--open") {
		t.Errorf("register help = %s", out)
	}
	// Billing off: the error says why.
	out := h.run("", "domains", "register", "example.tools")
	if out.code != 1 || !strings.Contains(out.stderr, "billing_unavailable") || !strings.Contains(out.stderr, "no payment gateway") {
		t.Fatalf("register without billing = %+v", out)
	}
	fake.SetDomainBilling(true)
	out = h.run("", "domains", "register", "example.tools")
	if out.code != 1 || !strings.Contains(out.stderr, "--accept-terms "+rdnstest.DomainTermsVersion+" to domains transfer or domains register") {
		t.Fatalf("register without terms = %+v", out)
	}
	h.ok(append([]string{"domains", "registrant-profile", "set"}, contactArgs...)...)
	if out := h.run("", "domains", "register", "premium-x.tools", "--accept-domain-terms", rdnstest.DomainTermsVersion); out.code != 1 || !strings.Contains(out.stderr, "domainPremium") {
		t.Errorf("register premium = %+v", out)
	}
	if out := h.run("", "domains", "register", "taken-x.tools"); out.code != 1 || !strings.Contains(out.stderr, "rdnsctl domains check") {
		t.Errorf("register taken = %+v", out)
	}

	out = h.run("", "domains", "register", "Example.tools", "--years", "2", "--ns", "ns1.example.net,ns2.example.net", "--auto-renew=false", "--open")
	if out.code != 0 || !strings.Contains(out.stdout, "Registration of example.tools waits for its payment (66.00 USD for 2 years)") ||
		!strings.Contains(out.stdout, "/fake-stripe/checkout?session=") || !strings.Contains(out.stdout, "rdnsctl domains cancel example.tools") {
		t.Fatalf("register = %+v", out)
	}
	body := lastBody(t, fake, "POST /v1/domains/register")
	if body["name"] != "example.tools" || body["years"] != float64(2) || body["autoRenew"] != false || len(body["nameservers"].([]any)) != 2 || body["acceptDomainTerms"] != nil {
		t.Errorf("register body = %v", body)
	}
	if len(opened) != 1 || !strings.Contains(opened[0], "/fake-stripe/checkout?session=") {
		t.Errorf("opened = %v", opened)
	}
	if out := h.run("", "domains", "lock", "example.tools"); out.code != 1 || !strings.Contains(out.stderr, "rdnsctl domains cancel") {
		t.Errorf("lock while unpaid = %+v", out)
	}

	// Cancel asks for the name, then releases it.
	if out := h.run("wrong.tools\n", "domains", "cancel", "example.tools"); out.code != 2 || fake.DomainCount() != 1 {
		t.Errorf("cancel with a wrong confirmation = %+v", out)
	}
	if out := h.run("example.tools\n", "domains", "cancel", "example.tools"); out.code != 0 || !strings.Contains(out.stdout, "the name is released") || fake.DomainCount() != 0 {
		t.Fatalf("cancel = %+v", out)
	}

	// A paid registration that the registrar refused is retried.
	var checkout redundantdns.DomainCheckout
	if err := json.Unmarshal([]byte(h.ok("domains", "register", "fail-x.tools", "--json")), &checkout); err != nil || checkout.CheckoutURL == "" {
		t.Fatalf("register --json = %+v, %v", checkout, err)
	}
	if !fake.PayDomainCheckout("fail-x.tools") {
		t.Fatal("no checkout to pay")
	}
	if out := h.ok("domains", "register-retry", "fail-x.tools"); !strings.Contains(out, "fail-x.tools: registration retried.") {
		t.Errorf("register-retry = %s", out)
	}
	if out := h.run("", "domains", "register-retry", "fail-x.tools"); out.code != 1 || !strings.Contains(out.stderr, "domainNotRetryable") {
		t.Errorf("retry twice = %+v", out)
	}
	if out := h.run("", "domains", "cancel", "fail-x.tools", "--yes"); out.code != 1 || !strings.Contains(out.stderr, "domainNotRemovable") {
		t.Errorf("cancel a paid registration = %+v", out)
	}

	// Renewals open a checkout while billing is on.
	opened = nil
	out = h.run("", "domains", "renew", "fail-x.tools", "--years", "3", "--open")
	if out.code != 0 || !strings.Contains(out.stdout, "Renewal of fail-x.tools waits for its payment (99.00 USD for 3 years)") || len(opened) != 1 {
		t.Fatalf("paid renew = %+v, opened %v", out, opened)
	}
	fake.SetDomainBilling(false)
	if out := h.ok("domains", "renew", "fail-x.tools"); !strings.Contains(out, "renewed for 1 year, expires") {
		t.Errorf("renew without billing = %s", out)
	}
}

func TestAdminDomainsCommands(t *testing.T) {
	h, fake := fakeHarness(t)
	fake.AcceptDomainTerms()
	fake.SeedContact(redundantdns.ContactFields{FirstName: "Ada", LastName: "Lovelace"}, true)
	fake.SeedUnassignedDomain("orphan.com")

	if out := h.ok("admin", "--help"); !strings.Contains(out, "rdnsctl admin domains list") {
		t.Errorf("admin help = %s", out)
	}
	if out := h.ok("admin", "domains", "--help"); !strings.Contains(out, "--skip-payment") {
		t.Errorf("admin domains help = %s", out)
	}
	if out := h.run("", "admin", "domains", "explode"); out.code != 2 {
		t.Errorf("unknown admin action = %+v", out)
	}
	if out := h.ok("admin", "domains", "list"); !strings.Contains(out, "orphan.com") {
		t.Errorf("admin list = %s", out)
	}
	// --org is required and names the target organization.
	if out := h.run("", "admin", "domains", "register", "gift.tools", "--skip-payment"); out.code != 2 || !strings.Contains(out.stderr, "--org") {
		t.Errorf("admin register without --org = %+v", out)
	}
	if out := h.run("", "admin", "domains", "register", "gift.tools", "--org", "org-other", "--skip-payment"); out.code != 1 || !strings.Contains(out.stderr, "orgNotFound") {
		t.Errorf("admin register other org = %+v", out)
	}
	out := h.ok("admin", "domains", "register", "Gift.tools", "--org", fake.OrgID, "--skip-payment", "--years", "2", "--apply-zone-ns")
	if !strings.Contains(out, "Registration of gift.tools done: active") {
		t.Fatalf("admin register = %s", out)
	}
	request := lastRequestOf(t, fake, "POST /v1/admin/tenants/{orgId}/domains/register")
	if request.Path != "/v1/admin/tenants/"+fake.OrgID+"/domains/register" || request.Header.Get(redundantdns.OrgHeader) != "" {
		t.Errorf("admin register request = %s %v", request.Path, request.Header)
	}
	body := lastBody(t, fake, "POST /v1/admin/tenants/{orgId}/domains/register")
	if body["skipPayment"] != true || body["years"] != float64(2) || body["applyZoneNs"] != true {
		t.Errorf("admin register body = %v", body)
	}
	if domain, _ := fake.Domain("gift.tools"); domain.Registration == nil || domain.Registration.PaidBy != redundantdns.PaidByOperator {
		t.Errorf("granted domain = %+v", domain)
	}

	// Renewals need --skip-payment.
	if out := h.run("", "admin", "domains", "renew", "gift.tools", "--org", fake.OrgID); out.code != 2 || !strings.Contains(out.stderr, "--skip-payment") {
		t.Errorf("admin renew without --skip-payment = %+v", out)
	}
	before, _ := fake.Domain("gift.tools")
	if out := h.ok("admin", "domains", "renew", "gift.tools", "--org", fake.OrgID, "--skip-payment", "--years", "3"); !strings.Contains(out, "Renewed gift.tools for 3 years without a payment") {
		t.Errorf("admin renew = %s", out)
	}
	if after, _ := fake.Domain("gift.tools"); !after.ExpiresAt.Equal(before.ExpiresAt.AddDate(3, 0, 0)) {
		t.Errorf("expiry after admin renew = %v", after.ExpiresAt)
	}
	if body := lastBody(t, fake, "POST /v1/admin/tenants/{orgId}/domains/{name}/renew"); body["skipPayment"] != true || body["years"] != float64(3) {
		t.Errorf("admin renew body = %v", body)
	}

	// Without --skip-payment the operator gets a checkout.
	fake.SetDomainBilling(true)
	if out := h.ok("admin", "domains", "register", "paid.tools", "--org", fake.OrgID); !strings.Contains(out, "waits for its payment") {
		t.Errorf("admin register with a checkout = %s", out)
	}
	if out := h.ok("admin", "domains", "assign", "orphan.com", "--org", fake.OrgID); !strings.Contains(out, "Assigned orphan.com") {
		t.Errorf("admin assign = %s", out)
	}
}

// lastRequestOf returns the last request that matched a route pattern.
func lastRequestOf(t *testing.T, fake *rdnstest.Fake, pattern string) rdnstest.Request {
	t.Helper()
	requests := fake.Requests()
	for index := len(requests) - 1; index >= 0; index-- {
		if requests[index].Pattern == pattern {
			return requests[index]
		}
	}
	t.Fatalf("no request %s", pattern)
	return rdnstest.Request{Header: http.Header{}}
}
