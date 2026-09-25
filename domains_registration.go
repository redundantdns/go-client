package redundantdns

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Registration of new domains through the platform (API docs "Registering
// a domain"): Check quotes availability and the price, Register claims the
// name and opens a one-off checkout (the domain waits in payment_pending),
// and the payment starts the registrar job. When billing is on, Renew opens
// a checkout the same way. A platform admin can register or renew for an
// organization without a payment (AdminRegister, AdminRenew).

// MaxCheckNames is how many names one Check accepts.
const MaxCheckNames = 20

// DomainQuote is the availability and customer price of one name
// (Domains.Check). PriceCents is the quoted price for Years, in the
// currency's minor unit (0 when the name is not available); it is never the
// registrar's cost.
type DomainQuote struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	// Premium names are registered on request (Register answers 422
	// domainPremium).
	Premium    bool   `json:"premium,omitempty"`
	PriceCents int64  `json:"priceCents"`
	Currency   string `json:"currency"`
	Years      int    `json:"years"`
	// Reason explains why the name is not available.
	Reason string `json:"reason,omitempty"`
}

// Price formats PriceCents with the currency, for example "33.00 USD".
func (quote DomainQuote) Price() string {
	return FormatPrice(quote.PriceCents, quote.Currency)
}

// FormatPrice formats an amount in a currency's minor unit (two decimals),
// for example FormatPrice(3300, "USD") = "33.00 USD".
func FormatPrice(cents int64, currency string) string {
	sign := ""
	if cents < 0 {
		sign, cents = "-", -cents
	}
	text := fmt.Sprintf("%s%d.%02d", sign, cents/100, cents%100)
	if currency != "" {
		text += " " + strings.ToUpper(currency)
	}
	return text
}

// DomainRegistration is the registration record of a domain registered
// through the platform.
type DomainRegistration struct {
	Years int `json:"years"`
	// PriceCents is the price paid, in the currency's minor unit.
	PriceCents int64  `json:"priceCents"`
	Currency   string `json:"currency"`
	Premium    bool   `json:"premium,omitempty"`
	// CheckoutURL is the checkout that pays an open registration.
	CheckoutSessionID string     `json:"checkoutSessionId,omitempty"`
	CheckoutURL       string     `json:"checkoutUrl,omitempty"`
	ContactID         string     `json:"contactId"`
	Nameservers       []string   `json:"nameservers"`
	ApplyZoneNS       bool       `json:"applyZoneNs"`
	AutoRenew         bool       `json:"autoRenew"`
	RequestedAt       time.Time  `json:"requestedAt"`
	RequestedBy       string     `json:"requestedBy,omitempty"`
	PaidAt            *time.Time `json:"paidAt"`
	// PaidBy is PaidByStripe or PaidByOperator ("" while unpaid).
	PaidBy          string     `json:"paidBy,omitempty"`
	PaymentIntentID string     `json:"paymentIntentId,omitempty"`
	CompletedAt     *time.Time `json:"completedAt"`
	// Error is why the registrar refused the registration.
	Error string `json:"error"`
}

// Paid reports whether the registration was paid (or granted by an
// operator).
func (registration *DomainRegistration) Paid() bool {
	return registration != nil && registration.PaidAt != nil
}

// DomainRenewal is a paid renewal of a domain (billing on).
type DomainRenewal struct {
	Years             int        `json:"years"`
	PriceCents        int64      `json:"priceCents"`
	Currency          string     `json:"currency"`
	CheckoutSessionID string     `json:"checkoutSessionId,omitempty"`
	CheckoutURL       string     `json:"checkoutUrl,omitempty"`
	RequestedAt       time.Time  `json:"requestedAt"`
	RequestedBy       string     `json:"requestedBy,omitempty"`
	PaidAt            *time.Time `json:"paidAt"`
	PaidBy            string     `json:"paidBy,omitempty"`
	PaymentIntentID   string     `json:"paymentIntentId,omitempty"`
	CompletedAt       *time.Time `json:"completedAt"`
	Error             string     `json:"error"`
}

// DomainRegisterCreate is the body of Domains.Register.
type DomainRegisterCreate struct {
	// Name is the domain to register, for example "example.tools".
	Name string `json:"name"`
	// Years to register for, 1 to 10 (0 = the server default, 1).
	Years int `json:"years,omitempty"`
	// ContactID is the registrant (default: the registrant profile).
	ContactID string `json:"contactId,omitempty"`
	// Nameservers are set at registration (2 to 13 host names).
	Nameservers []string `json:"nameservers,omitempty"`
	// ApplyZoneNS uses the NS plan of the organization's zone with the same
	// name when Nameservers is empty.
	ApplyZoneNS bool `json:"applyZoneNs,omitempty"`
	// AutoRenew sets auto-renewal (nil = the server default). Use Bool.
	AutoRenew *bool `json:"autoRenew,omitempty"`
	// AcceptDomainTerms accepts the Domain Registration Terms of this
	// version for the organization in the same call (admins).
	AcceptDomainTerms string `json:"acceptDomainTerms,omitempty"`
}

// AdminDomainRegisterCreate is the body of Domains.AdminRegister.
type AdminDomainRegisterCreate struct {
	Name        string   `json:"name"`
	Years       int      `json:"years,omitempty"`
	ContactID   string   `json:"contactId,omitempty"`
	Nameservers []string `json:"nameservers,omitempty"`
	ApplyZoneNS bool     `json:"applyZoneNs,omitempty"`
	AutoRenew   *bool    `json:"autoRenew,omitempty"`
	// SkipPayment registers without a checkout (paidBy "operator"): the
	// registrar job runs at once.
	SkipPayment bool `json:"skipPayment,omitempty"`
}

// AdminDomainRenew is the body of Domains.AdminRenew. The admin route only
// renews without a payment: SkipPayment must be true (400
// skipPaymentRequired otherwise).
type AdminDomainRenew struct {
	Years       int  `json:"years,omitempty"`
	SkipPayment bool `json:"skipPayment"`
}

// DomainCheckout is the answer of Register, AdminRegister and Renew: the
// domain, and either the checkout to pay (CheckoutURL) or the registrar job
// already started (Job: an operator skipped the payment, or billing is off
// for a renewal).
type DomainCheckout struct {
	Domain      Domain     `json:"domain"`
	CheckoutURL string     `json:"checkoutUrl,omitempty"`
	Job         *DomainJob `json:"job,omitempty"`
}

// NeedsPayment reports whether the change waits for its checkout to be
// paid (open CheckoutURL in a browser).
func (checkout *DomainCheckout) NeedsPayment() bool {
	return checkout.CheckoutURL != ""
}

// Queued reports whether the registrar job was started but not applied yet.
func (checkout *DomainCheckout) Queued() bool {
	return checkout.Job != nil && (checkout.Job.Status == JobStatusQueued || checkout.Job.Status == JobStatusRunning)
}

// Check returns the availability and price of up to MaxCheckNames names
// for years (0 = the server default, 1). Names the organization or another
// one holds on the platform are not available. Errors: 422
// invalidDomainName, 503 registrarUnavailable (no registrar configured).
func (service *DomainsService) Check(ctx context.Context, names []string, years int) ([]DomainQuote, error) {
	normalized := make([]string, 0, len(names))
	for _, name := range names {
		if name = NormalizeZoneName(name); name != "" {
			normalized = append(normalized, name)
		}
	}
	if len(normalized) == 0 || len(normalized) > MaxCheckNames {
		return nil, fmt.Errorf("check: give 1 to %d names", MaxCheckNames)
	}
	query := url.Values{"names": {strings.Join(normalized, ",")}}
	if years != 0 {
		query.Set("years", strconv.Itoa(years))
	}
	var quotes []DomainQuote
	err := service.client.do(ctx, request{method: http.MethodGet, path: "/v1/domains/check", query: query}, &quotes)
	return quotes, err
}

// Register registers a new domain paid through a one-off checkout
// (admins): it claims the name, creates the domain in payment_pending and
// returns the CheckoutURL to pay; the registrar job runs on payment (poll
// Get). Errors: 402 plan_limit_reached, 428 domain_terms_required (or pass
// AcceptDomainTerms), 422 registrantProfileRequired, 409 domainUnavailable,
// 422 domainPremium, 503 billing_unavailable or registrarUnavailable.
func (service *DomainsService) Register(ctx context.Context, input DomainRegisterCreate) (*DomainCheckout, error) {
	input.Name = NormalizeZoneName(input.Name)
	return service.checkout(ctx, http.MethodPost, "/v1/domains/register", input)
}

// RetryRegistration runs the registrar job again for a paid registration
// that failed (admins; 409 domainNotRetryable otherwise).
func (service *DomainsService) RetryRegistration(ctx context.Context, name string) (*DomainMutationResult, error) {
	return service.mutate(ctx, http.MethodPost, domainPath(name, "/register/retry"), nil)
}

// CancelRegistration cancels an unpaid registration (payment_pending): its
// checkout is closed and the name released (admins). It is Delete under
// another name; a paid registration is never removed (409
// domainNotRemovable).
func (service *DomainsService) CancelRegistration(ctx context.Context, name string) error {
	return service.Delete(ctx, name)
}

// Renew renews the domain for 1 to 10 years (admins; 0 = the server
// default, 1). With billing off the registrar renews it at once (Job set);
// with billing on a one-off checkout opens (CheckoutURL) and the renewal
// runs when it is paid (409 domainRenewalInProgress while a paid one runs).
func (service *DomainsService) Renew(ctx context.Context, name string, years int) (*DomainCheckout, error) {
	body := struct {
		Years int `json:"years,omitempty"`
	}{Years: years}
	return service.checkout(ctx, http.MethodPost, domainPath(name, "/renew"), body)
}

// AdminRegister registers a domain for an organization (platform admins).
// With SkipPayment the registration is granted without a checkout
// (paidBy "operator") and the registrar job runs at once. The organization
// must have accepted the Domain Registration Terms itself (428); there is
// no plan limit.
func (service *DomainsService) AdminRegister(ctx context.Context, orgID string, input AdminDomainRegisterCreate) (*DomainCheckout, error) {
	input.Name = NormalizeZoneName(input.Name)
	return service.checkout(ctx, http.MethodPost, pathf("/v1/admin/tenants/%s/domains/register", orgID), input)
}

// AdminRenew renews an organization's domain without a payment (platform
// admins; input.SkipPayment must be true) and returns the registrar job.
func (service *DomainsService) AdminRenew(ctx context.Context, orgID, name string, input AdminDomainRenew) (*DomainJob, error) {
	var answer struct {
		Job DomainJob `json:"job"`
	}
	path := pathf("/v1/admin/tenants/%s/domains/%s/renew", orgID, NormalizeZoneName(name))
	if err := service.client.do(ctx, request{method: http.MethodPost, path: path, body: input}, &answer); err != nil {
		return nil, err
	}
	return &answer.Job, nil
}

// checkout sends a change answered by {domain, checkoutUrl?, job?}.
func (service *DomainsService) checkout(ctx context.Context, method, path string, body any) (*DomainCheckout, error) {
	answer, err := service.client.send(ctx, request{method: method, path: path, body: body})
	if err != nil {
		return nil, err
	}
	var result DomainCheckout
	if err := json.Unmarshal(answer.body, &result); err != nil {
		return nil, fmt.Errorf("%s %s: decode response: %w", method, path, err)
	}
	return &result, nil
}
