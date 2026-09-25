package redundantdns_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	redundantdns "github.com/redundantdns/go-client"
	"github.com/redundantdns/go-client/rdnstest"
)

func TestFakeDomainCheck(t *testing.T) {
	fake := rdnstest.NewFake(t)
	fake.SeedDomain(redundantdns.Domain{Name: "held.com"})
	fake.SeedUnassignedDomain("elsewhere.com")
	client := newClient(t, fake.URL)
	ctx := context.Background()

	quotes, err := client.Domains.Check(ctx, []string{"Example.Tools.", "taken-name.com", "premium-name.com", "held.com", "elsewhere.com"}, 2)
	if err != nil || len(quotes) != 5 {
		t.Fatalf("check = %+v, %v", quotes, err)
	}
	if request := lastRequest(t, fake, "GET /v1/domains/check"); request.Query != "names=example.tools%2Ctaken-name.com%2Cpremium-name.com%2Cheld.com%2Celsewhere.com&years=2" {
		t.Errorf("check query = %s", request.Query)
	}
	free := quotes[0]
	if free.Name != "example.tools" || !free.Available || free.Premium || free.Years != 2 || free.Currency != "USD" ||
		free.PriceCents != rdnstest.DomainPriceCents("example.tools", 2) || free.Price() != "66.00 USD" {
		t.Errorf("free quote = %+v (%s)", free, free.Price())
	}
	if taken := quotes[1]; taken.Available || taken.PriceCents != 0 || taken.Reason == "" {
		t.Errorf("taken quote = %+v", taken)
	}
	if premium := quotes[2]; !premium.Available || !premium.Premium || premium.PriceCents != 20*rdnstest.DomainPriceCents("name.com", 2) {
		t.Errorf("premium quote = %+v", premium)
	}
	if held := quotes[3]; held.Available || held.Reason != "already in your organization" {
		t.Errorf("held quote = %+v", held)
	}
	if other := quotes[4]; other.Available || other.Reason != "already managed on this platform" {
		t.Errorf("other org quote = %+v", other)
	}

	// Years 0 leaves the server default; invalid names answer 422.
	if _, err := client.Domains.Check(ctx, []string{"a.com"}, 0); err != nil || strings.Contains(lastRequest(t, fake, "GET /v1/domains/check").Query, "years") {
		t.Errorf("default years err = %v", err)
	}
	if _, err := client.Domains.Check(ctx, []string{"not a name"}, 1); !redundantdns.HasCode(err, redundantdns.CodeInvalidDomainName) || !errors.Is(err, redundantdns.ErrUnprocessable) {
		t.Errorf("invalid name err = %v", err)
	}
	if _, err := client.Domains.Check(ctx, []string{"a.com"}, 11); !redundantdns.HasCode(err, redundantdns.CodeInvalidYears) {
		t.Errorf("11 years err = %v", err)
	}
	// The limits are checked before any request.
	tooMany := make([]string, redundantdns.MaxCheckNames+1)
	for index := range tooMany {
		tooMany[index] = "a.com"
	}
	for _, names := range [][]string{nil, {" ", "."}, tooMany} {
		if _, err := client.Domains.Check(ctx, names, 1); err == nil || strings.Contains(err.Error(), "GET") {
			t.Errorf("check %d names err = %v", len(names), err)
		}
	}
}

func TestFakeDomainRegistrationLifecycle(t *testing.T) {
	fake := rdnstest.NewFake(t)
	client := newClient(t, fake.URL)
	ctx := context.Background()
	register := redundantdns.DomainRegisterCreate{Name: "Example.tools.", Years: 2, ApplyZoneNS: true, AutoRenew: redundantdns.Bool(false)}

	// Billing off: nothing can be paid.
	_, err := client.Domains.Register(ctx, register)
	if !redundantdns.HasCode(err, redundantdns.CodeBillingUnavailable) || !errors.Is(err, redundantdns.ErrServer) {
		t.Fatalf("register without billing err = %v", err)
	}
	fake.SetDomainBilling(true)

	// The terms, then the registrant profile, like a transfer.
	if _, err := client.Domains.Register(ctx, register); !errors.Is(err, redundantdns.ErrDomainTermsRequired) {
		t.Fatalf("register without terms err = %v", err)
	}
	register.AcceptDomainTerms = rdnstest.DomainTermsVersion
	if _, err := client.Domains.Register(ctx, register); !redundantdns.HasCode(err, redundantdns.CodeRegistrantProfileRequired) {
		t.Fatalf("register without profile err = %v", err)
	}
	profile, err := client.Domains.SetRegistrantProfile(ctx, validContact("Headquarters"))
	if err != nil {
		t.Fatal(err)
	}

	// Unavailable and premium names are refused.
	if _, err := client.Domains.Register(ctx, redundantdns.DomainRegisterCreate{Name: "taken-x.tools"}); !redundantdns.HasCode(err, redundantdns.CodeDomainUnavailable) || !errors.Is(err, redundantdns.ErrConflict) {
		t.Errorf("taken name err = %v", err)
	}
	if _, err := client.Domains.Register(ctx, redundantdns.DomainRegisterCreate{Name: "premium-x.tools"}); !redundantdns.HasCode(err, redundantdns.CodeDomainPremium) || !errors.Is(err, redundantdns.ErrUnprocessable) {
		t.Errorf("premium name err = %v", err)
	}
	if _, err := client.Domains.Register(ctx, redundantdns.DomainRegisterCreate{Name: "a.tools", Years: 11}); !redundantdns.HasCode(err, redundantdns.CodeInvalidYears) {
		t.Errorf("11 years err = %v", err)
	}

	// A zone with the same name gives the NS plan applied on registration.
	zone := zoneWithAttachment(t, client, "example.tools")
	checkout, err := client.Domains.Register(ctx, register)
	if err != nil {
		t.Fatal(err)
	}
	var sent map[string]any
	_ = json.Unmarshal(lastRequest(t, fake, "POST /v1/domains/register").Body, &sent)
	if sent["name"] != "example.tools" || sent["years"] != float64(2) || sent["applyZoneNs"] != true || sent["autoRenew"] != false || sent["acceptDomainTerms"] != rdnstest.DomainTermsVersion {
		t.Errorf("register body = %v", sent)
	}
	registration := checkout.Domain.Registration
	if !checkout.NeedsPayment() || checkout.Job != nil || !checkout.Domain.PaymentPending() || registration == nil ||
		registration.CheckoutURL != checkout.CheckoutURL || registration.Paid() || registration.PriceCents != rdnstest.DomainPriceCents("example.tools", 2) ||
		registration.ContactID != profile.ContactID || !registration.ApplyZoneNS || registration.AutoRenew {
		t.Fatalf("checkout = %+v, registration %+v", checkout, registration)
	}
	// The name is claimed and the domain cannot change until it is paid.
	if quotes, err := client.Domains.Check(ctx, []string{"example.tools"}, 1); err != nil || quotes[0].Available {
		t.Errorf("claimed name = %+v, %v", quotes, err)
	}
	if _, err := client.Domains.SetLock(ctx, "example.tools", true); !redundantdns.HasCode(err, redundantdns.CodeDomainRegistrationPending) {
		t.Errorf("lock while unpaid err = %v", err)
	}
	if _, err := client.Domains.Renew(ctx, "example.tools", 1); !redundantdns.HasCode(err, redundantdns.CodeDomainRegistrationPending) {
		t.Errorf("renew while unpaid err = %v", err)
	}
	if _, err := client.Domains.RetryRegistration(ctx, "example.tools"); !redundantdns.HasCode(err, redundantdns.CodeDomainNotRetryable) {
		t.Errorf("retry while unpaid err = %v", err)
	}

	// Paying the hosted checkout registers it.
	payCheckout(t, checkout.CheckoutURL, http.StatusOK)
	domain, err := client.Domains.Get(ctx, "example.tools")
	if err != nil || domain.Status != redundantdns.DomainStatusActive || !domain.Registration.Paid() || domain.Registration.PaidBy != redundantdns.PaidByStripe ||
		domain.Registration.PaymentIntentID == "" || domain.Registration.CompletedAt == nil || domain.ExpiresAt == nil ||
		domain.Zone == nil || domain.Zone.ZoneID != zone.ZoneID || !domain.Zone.NameserversMatch {
		t.Fatalf("paid domain = %+v, %v", domain, err)
	}
	payCheckout(t, checkout.CheckoutURL, http.StatusGone)
	// A paid registration is never removed.
	if err := client.Domains.CancelRegistration(ctx, "example.tools"); !redundantdns.HasCode(err, redundantdns.CodeDomainNotRemovable) {
		t.Errorf("cancel a paid registration err = %v", err)
	}

	// The Free plan holds one domain.
	_, err = client.Domains.Register(ctx, redundantdns.DomainRegisterCreate{Name: "second.tools"})
	var apiError *redundantdns.APIError
	if !errors.Is(err, redundantdns.ErrPaymentRequired) || !errors.As(err, &apiError) || !strings.Contains(string(apiError.Details), `"domain.register"`) {
		t.Fatalf("second domain on Free err = %v", err)
	}
	fake.SetPlan("starter")

	// An abandoned checkout is cancelled and the name released.
	pending, err := client.Domains.Register(ctx, redundantdns.DomainRegisterCreate{Name: "second.tools", Nameservers: []string{"NS1.example.net.", "ns2.example.net"}})
	if err != nil || pending.Domain.Registration.Nameservers[0] != "ns1.example.net" {
		t.Fatalf("second register = %+v, %v", pending, err)
	}
	if err := client.Domains.CancelRegistration(ctx, "second.tools"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Domains.Get(ctx, "second.tools"); !redundantdns.IsNotFound(err) {
		t.Errorf("cancelled domain err = %v", err)
	}
	payCheckout(t, pending.CheckoutURL, http.StatusGone)
	if fake.PayDomainCheckout("second.tools") {
		t.Error("a cancelled checkout cannot be paid")
	}

	// A registration the registrar refuses is retried by hand.
	failing, err := client.Domains.Register(ctx, redundantdns.DomainRegisterCreate{Name: "fail-name.tools", Nameservers: []string{"ns1.example.net", "ns2.example.net"}})
	if err != nil {
		t.Fatal(err)
	}
	if !fake.PayDomainCheckout("fail-name.tools") {
		t.Fatal("no open checkout for fail-name.tools")
	}
	failed, _ := fake.Domain("fail-name.tools")
	if failed.Status != redundantdns.DomainStatusRegistrationFailed || failed.Registration.Error == "" || !failed.Registration.Paid() {
		t.Fatalf("failed registration = %+v", failed)
	}
	retried, err := client.Domains.RetryRegistration(ctx, failing.Domain.Name)
	if err != nil || retried.Domain.Status != redundantdns.DomainStatusActive || retried.Job.Op != redundantdns.DomainOpRegister ||
		retried.Domain.Nameservers[0] != "ns1.example.net" {
		t.Fatalf("retry = %+v, %v", retried, err)
	}
	if _, err := client.Domains.RetryRegistration(ctx, failing.Domain.Name); !redundantdns.HasCode(err, redundantdns.CodeDomainNotRetryable) {
		t.Errorf("retry an active domain err = %v", err)
	}
}

func TestFakeDomainPaidRenewal(t *testing.T) {
	fake := rdnstest.NewFake(t)
	fake.AcceptDomainTerms()
	seeded := fake.SeedDomain(redundantdns.Domain{Name: "example.com"})
	client := newClient(t, fake.URL)
	ctx := context.Background()

	// Billing off: renewed at once.
	now, err := client.Domains.Renew(ctx, "example.com", 1)
	if err != nil || now.NeedsPayment() || now.Job == nil || now.Job.Op != redundantdns.DomainOpRenew || now.Queued() ||
		!now.Domain.ExpiresAt.Equal(seeded.ExpiresAt.AddDate(1, 0, 0)) {
		t.Fatalf("renew without billing = %+v, %v", now, err)
	}

	// Billing on: a checkout opens and the renewal runs when paid.
	fake.SetDomainBilling(true)
	first, err := client.Domains.Renew(ctx, "example.com", 2)
	if err != nil || !first.NeedsPayment() || first.Job != nil || first.Domain.Renewal == nil || first.Domain.Renewal.Years != 2 ||
		first.Domain.Renewal.PriceCents != rdnstest.DomainPriceCents("example.com", 2) {
		t.Fatalf("paid renew = %+v, %v", first, err)
	}
	// A new renewal replaces the unpaid checkout.
	second, err := client.Domains.Renew(ctx, "example.com", 3)
	if err != nil || second.CheckoutURL == first.CheckoutURL {
		t.Fatalf("second renew = %+v, %v", second, err)
	}
	payCheckout(t, first.CheckoutURL, http.StatusGone)
	payCheckout(t, second.CheckoutURL, http.StatusOK)
	domain, err := client.Domains.Get(ctx, "example.com")
	if err != nil || !domain.ExpiresAt.Equal(seeded.ExpiresAt.AddDate(4, 0, 0)) || domain.Renewal.PaidBy != redundantdns.PaidByStripe || domain.Renewal.CompletedAt == nil {
		t.Fatalf("renewed domain = %+v, %v", domain, err)
	}
}

func TestFakeDomainAdminRegistration(t *testing.T) {
	fake := rdnstest.NewFake(t)
	fake.SeedContact(validContact("Headquarters"), true)
	client := newClient(t, fake.URL)
	ctx := context.Background()
	input := redundantdns.AdminDomainRegisterCreate{Name: "premium-gift.tools", SkipPayment: true}

	// The organization must have accepted the terms itself.
	if _, err := client.Domains.AdminRegister(ctx, fake.OrgID, input); !errors.Is(err, redundantdns.ErrDomainTermsRequired) {
		t.Fatalf("admin register without terms err = %v", err)
	}
	fake.AcceptDomainTerms()
	if _, err := client.Domains.AdminRegister(ctx, "org-missing", input); !redundantdns.HasCode(err, redundantdns.CodeOrgNotFound) {
		t.Errorf("unknown org err = %v", err)
	}
	// Skipping the payment registers at once, premium names included, with
	// no plan limit (the org is on Free and already holds a domain).
	fake.SeedDomain(redundantdns.Domain{Name: "held.com"})
	granted, err := client.Domains.AdminRegister(ctx, fake.OrgID, input)
	if err != nil || granted.NeedsPayment() || granted.Job == nil || granted.Job.Status != redundantdns.JobStatusDone ||
		granted.Domain.Status != redundantdns.DomainStatusActive || granted.Domain.Registration.PaidBy != redundantdns.PaidByOperator {
		t.Fatalf("granted = %+v, %v", granted, err)
	}
	if request := lastRequest(t, fake, "POST /v1/admin/tenants/{orgId}/domains/register"); request.Path != "/v1/admin/tenants/"+fake.OrgID+"/domains/register" ||
		!strings.Contains(string(request.Body), `"skipPayment":true`) {
		t.Errorf("admin register request = %s %s", request.Path, request.Body)
	}
	// Without skipPayment the operator gets a checkout (billing on).
	if _, err := client.Domains.AdminRegister(ctx, fake.OrgID, redundantdns.AdminDomainRegisterCreate{Name: "paid.tools"}); !redundantdns.HasCode(err, redundantdns.CodeBillingUnavailable) {
		t.Errorf("admin register with billing off err = %v", err)
	}
	fake.SetDomainBilling(true)
	paid, err := client.Domains.AdminRegister(ctx, fake.OrgID, redundantdns.AdminDomainRegisterCreate{Name: "paid.tools"})
	if err != nil || !paid.NeedsPayment() || !paid.Domain.PaymentPending() {
		t.Fatalf("admin register with a checkout = %+v, %v", paid, err)
	}
	// The regular route never skips the payment.
	var forbidden struct {
		redundantdns.DomainRegisterCreate
		SkipPayment bool `json:"skipPayment"`
	}
	forbidden.Name, forbidden.SkipPayment = "gift.tools", true
	answer := rawPost(t, fake, "/v1/domains/register", forbidden)
	if answer != http.StatusForbidden {
		t.Errorf("skipPayment on the org route = %d", answer)
	}

	// Renewals by an operator skip the payment only.
	before := *granted.Domain.ExpiresAt
	if _, err := client.Domains.AdminRenew(ctx, fake.OrgID, "premium-gift.tools", redundantdns.AdminDomainRenew{Years: 2}); !redundantdns.HasCode(err, redundantdns.CodeSkipPaymentRequired) {
		t.Errorf("admin renew without skipPayment err = %v", err)
	}
	if _, err := client.Domains.AdminRenew(ctx, fake.OrgID, "paid.tools", redundantdns.AdminDomainRenew{SkipPayment: true}); !redundantdns.HasCode(err, redundantdns.CodeDomainRegistrationPending) {
		t.Errorf("admin renew of an unpaid registration err = %v", err)
	}
	job, err := client.Domains.AdminRenew(ctx, fake.OrgID, "Premium-Gift.tools.", redundantdns.AdminDomainRenew{Years: 2, SkipPayment: true})
	if err != nil || job.Op != redundantdns.DomainOpRenew || job.Status != redundantdns.JobStatusDone {
		t.Fatalf("admin renew = %+v, %v", job, err)
	}
	if domain, _ := fake.Domain("premium-gift.tools"); !domain.ExpiresAt.Equal(before.AddDate(2, 0, 0)) {
		t.Errorf("expiry after admin renew = %v", domain.ExpiresAt)
	}
}

func TestDomainRegistrationDecoding(t *testing.T) {
	// The platform's answer to POST /v1/domains/register.
	body := `{"domain":{"name":"example.tools","orgId":"org-1","registrar":"openprovider","status":"payment_pending","autoRenew":true,
"locked":false,"nameservers":null,"contacts":{},"ownerContactId":"ctc-1","createdAt":"2026-09-24T10:00:00Z","updatedAt":"2026-09-24T10:00:00Z",
"registration":{"years":1,"priceCents":3300,"currency":"USD","premium":false,"checkoutSessionId":"cs_test_1","checkoutUrl":"https://checkout.stripe.com/c/pay/cs_test_1",
"contactId":"ctc-1","nameservers":null,"applyZoneNs":false,"autoRenew":true,"requestedAt":"2026-09-24T10:00:00Z","requestedBy":"usr-1","paidAt":null,"completedAt":null,"error":""},
"renewal":null},"checkoutUrl":"https://checkout.stripe.com/c/pay/cs_test_1"}`
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusCreated)
		_, _ = writer.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	client := newClient(t, server.URL)
	checkout, err := client.Domains.Register(context.Background(), redundantdns.DomainRegisterCreate{Name: "example.tools"})
	if err != nil {
		t.Fatal(err)
	}
	registration := checkout.Domain.Registration
	if checkout.CheckoutURL != "https://checkout.stripe.com/c/pay/cs_test_1" || !checkout.Domain.PaymentPending() || checkout.Domain.Renewal != nil ||
		registration == nil || registration.PriceCents != 3300 || registration.Paid() || registration.RequestedAt.IsZero() || registration.CheckoutSessionID != "cs_test_1" {
		t.Fatalf("decoded = %+v, registration %+v", checkout, registration)
	}
	for cents, want := range map[int64]string{0: "0.00 USD", 5: "0.05 USD", 3300: "33.00 USD", -150: "-1.50 USD"} {
		if got := redundantdns.FormatPrice(cents, "usd"); got != want {
			t.Errorf("FormatPrice(%d) = %s, want %s", cents, got, want)
		}
	}
	if got := redundantdns.FormatPrice(1234, ""); got != "12.34" {
		t.Errorf("FormatPrice without currency = %s", got)
	}
}

// payCheckout opens a fake hosted checkout like a browser would.
func payCheckout(t *testing.T, checkoutURL string, wantStatus int) {
	t.Helper()
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, checkoutURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = answer.Body.Close()
	if answer.StatusCode != wantStatus {
		t.Fatalf("GET %s = %d, want %d", checkoutURL, answer.StatusCode, wantStatus)
	}
}

// rawPost sends a JSON body the typed client cannot build and returns the
// status.
func rawPost(t *testing.T, fake *rdnstest.Fake, path string, body any) int {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, fake.URL+path, strings.NewReader(string(payload)))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+fake.Token)
	request.Header.Set("Content-Type", "application/json")
	answer, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = answer.Body.Close()
	return answer.StatusCode
}
