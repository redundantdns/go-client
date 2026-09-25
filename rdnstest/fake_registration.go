package rdnstest

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	redundantdns "github.com/redundantdns/go-client"
)

// Registration of new domains in the fake, like the platform with its fake
// registrar and fake payment gateway:
//
//   - GET /v1/domains/check quotes DomainPriceCents; a name is not available
//     when the organization or the reseller account holds it or its first
//     label starts with "taken-"; "premium-" marks a premium name.
//   - POST /v1/domains/register needs billing on (SetDomainBilling; 503
//     billing_unavailable otherwise), claims the name as payment_pending and
//     returns a checkout URL served by the fake itself
//     (GET /fake-stripe/checkout?session=..., no token needed), which pays
//     at once like the platform's fake gateway. PayDomainCheckout pays it
//     from a test.
//   - On payment the registration completes at once (active), except for a
//     name whose first label starts with "fail-": the registrar refuses it
//     (registration_failed). POST /v1/domains/{name}/register/retry then
//     succeeds, as if the cause had been fixed.
//   - With billing on, POST /v1/domains/{name}/renew opens a checkout too;
//     with billing off (the default) it renews at once.
//   - The admin routes (POST /v1/admin/tenants/{orgId}/domains/register and
//     .../{name}/renew) accept the fake's organization only.

// Registration name prefixes that drive the simulated registrar.
const (
	takenPrefix   = "taken-"
	premiumPrefix = "premium-"
	failPrefix    = "fail-"
)

// Registration results the fake answers.
const (
	// DomainCurrency is the currency of every fake quote.
	DomainCurrency = "USD"
	// premiumFactor multiplies the price of a premium name.
	premiumFactor = 20
	// defaultYearlyCents is the yearly price of an extension not in
	// yearlyCents.
	defaultYearlyCents = 1800
	// maxCheckNames is how many names one check accepts.
	maxCheckNames = 20
	// fakeCheckoutPath is the fake's hosted checkout page.
	fakeCheckoutPath = "/fake-stripe/checkout"
)

// defaultRegistrarNameservers are the nameservers of a registration that
// sets none (the registrar's defaults).
var defaultRegistrarNameservers = []string{"ns1.registrar.test", "ns2.registrar.test"}

// yearlyCents are the fake's yearly customer prices per extension.
var yearlyCents = map[string]int64{"com": 1300, "net": 1500, "org": 1400, "tools": 3300, "test": 1200}

// Checkout purposes.
const (
	purposeRegister = "domain_register"
	purposeRenew    = "domain_renew"
)

// fakeCheckout is an open (or closed) one-off checkout of the fake gateway.
type fakeCheckout struct {
	purpose    string
	domain     string
	years      int
	priceCents int64
	closed     bool
}

// DomainPriceCents is the fake's customer price of a name for years, in US
// cents: by extension (com 1300, net 1500, org 1400, tools 3300, test 1200,
// others 1800 per year), times 20 for a premium name.
func DomainPriceCents(name string, years int) int64 {
	name = redundantdns.NormalizeZoneName(name)
	extension := name[strings.LastIndex(name, ".")+1:]
	price, ok := yearlyCents[extension]
	if !ok {
		price = defaultYearlyCents
	}
	if strings.HasPrefix(firstLabel(name), premiumPrefix) {
		price *= premiumFactor
	}
	return price * int64(max(years, 1))
}

func firstLabel(name string) string {
	label, _, _ := strings.Cut(name, ".")
	return label
}

// ---------------------------------------------------------------- helpers for tests

// SetDomainBilling turns the fake's payment gateway on or off (off by
// default). Off: registrations answer 503 billing_unavailable and renewals
// apply at once; on: both open a checkout.
func (fake *Fake) SetDomainBilling(on bool) {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	fake.domainState.billing = on
}

// PayDomainCheckout pays the open checkout of a domain (its registration
// or its renewal) as the payment webhook would. It reports false when the
// domain has no open checkout.
func (fake *Fake) PayDomainCheckout(name string) bool {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	name = redundantdns.NormalizeZoneName(name)
	for sessionID, checkout := range fake.domainState.checkouts {
		if checkout.domain == name && !checkout.closed {
			return fake.pay(sessionID)
		}
	}
	return false
}

// ---------------------------------------------------------------- routes

func (fake *Fake) mountRegistration(handle func(string, handler)) {
	handle("GET /v1/domains/check", fake.checkDomains)
	handle("POST /v1/domains/register", fake.registerDomain)
	handle("POST /v1/domains/{name}/register/retry", fake.withDomain(fake.retryRegistration))
	handle("POST /v1/admin/tenants/{orgId}/domains/register", fake.adminRegisterDomain)
	handle("POST /v1/admin/tenants/{orgId}/domains/{name}/renew", fake.adminRenewDomain)
	handle("GET "+fakeCheckoutPath, func(writer http.ResponseWriter, request *http.Request) {
		sessionID := request.URL.Query().Get("session")
		if !fake.pay(sessionID) {
			writeError(writer, http.StatusGone, redundantdns.CodeCheckoutExpired, "this checkout expired or does not exist")
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{"paid": true, "session": sessionID})
	})
}

// checkDomains serves GET /v1/domains/check?names=a,b&years=N.
func (fake *Fake) checkDomains(writer http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	var names []string
	for part := range strings.SplitSeq(query.Get("names"), ",") {
		name := redundantdns.NormalizeZoneName(part)
		if name == "" {
			continue
		}
		if !domainLabels.MatchString(name) {
			writeJSON(writer, http.StatusUnprocessableEntity, map[string]any{
				"error": redundantdns.CodeInvalidDomainName, "message": "invalid domain name " + part, "details": map[string]string{"name": part},
			})
			return
		}
		names = append(names, name)
	}
	if len(names) == 0 || len(names) > maxCheckNames {
		writeError(writer, http.StatusUnprocessableEntity, redundantdns.CodeInvalidDomainName, fmt.Sprintf("give 1 to %d names in ?names=", maxCheckNames))
		return
	}
	years, ok := queryYears(writer, query)
	if !ok {
		return
	}
	quotes := make([]redundantdns.DomainQuote, 0, len(names))
	for _, name := range names {
		quotes = append(quotes, fake.quote(name, years))
	}
	writeJSON(writer, http.StatusOK, quotes)
}

func queryYears(writer http.ResponseWriter, query url.Values) (int, bool) {
	if query.Get("years") == "" {
		return 1, true
	}
	years, err := strconv.Atoi(query.Get("years"))
	if err != nil || years < 1 || years > 10 {
		writeError(writer, http.StatusBadRequest, redundantdns.CodeInvalidYears, "register for 1 to 10 years")
		return 0, false
	}
	return years, true
}

// quote is the availability and price of one normalized name.
func (fake *Fake) quote(name string, years int) redundantdns.DomainQuote {
	quote := redundantdns.DomainQuote{
		Name: name, Available: true, Premium: strings.HasPrefix(firstLabel(name), premiumPrefix),
		PriceCents: DomainPriceCents(name, years), Currency: DomainCurrency, Years: years,
	}
	reason := ""
	switch _, unassigned := fake.domainState.unassigned[name]; {
	case fake.domainState.domains[name] != nil:
		reason = "already in your organization"
	case unassigned:
		reason = "already managed on this platform"
	case strings.HasPrefix(firstLabel(name), takenPrefix):
		reason = "registered by someone else"
	}
	if reason != "" {
		quote.Available, quote.PriceCents, quote.Reason = false, 0, reason
	}
	return quote
}

// registerDomain serves POST /v1/domains/register.
func (fake *Fake) registerDomain(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		redundantdns.AdminDomainRegisterCreate
		AcceptDomainTerms string `json:"acceptDomainTerms"`
	}
	if !decode(writer, request, &input) {
		return
	}
	if input.SkipPayment {
		writeError(writer, http.StatusForbidden, redundantdns.CodeForbidden, "only a platform admin can register without a payment")
		return
	}
	fake.register(writer, input.AdminDomainRegisterCreate, input.AcceptDomainTerms, false)
}

// adminRegisterDomain serves POST /v1/admin/tenants/{orgId}/domains/register.
func (fake *Fake) adminRegisterDomain(writer http.ResponseWriter, request *http.Request) {
	var input redundantdns.AdminDomainRegisterCreate
	if !decode(writer, request, &input) {
		return
	}
	if request.PathValue("orgId") != fake.OrgID {
		writeError(writer, http.StatusNotFound, redundantdns.CodeOrgNotFound, "organization not found")
		return
	}
	fake.register(writer, input, "", true)
}

// register runs the checks of a registration in the platform's order, then
// claims the name and opens the checkout (or, for an operator skipping the
// payment, registers at once).
func (fake *Fake) register(writer http.ResponseWriter, input redundantdns.AdminDomainRegisterCreate, acceptTerms string, operator bool) {
	name := redundantdns.NormalizeZoneName(input.Name)
	years := input.Years
	if years == 0 {
		years = 1
	}
	nameservers, nameserversOK := normalizeNameservers(input.Nameservers)
	switch {
	case !domainLabels.MatchString(name):
		writeError(writer, http.StatusBadRequest, redundantdns.CodeInvalidDomainName, "invalid domain name")
		return
	case years < 1 || years > 10:
		writeError(writer, http.StatusBadRequest, redundantdns.CodeInvalidYears, "register or renew for 1 to 10 years")
		return
	case len(input.Nameservers) > 0 && !nameserversOK:
		writeError(writer, http.StatusBadRequest, redundantdns.CodeInvalidNameservers, "give 2 to 13 distinct host names")
		return
	}
	if len(input.Nameservers) == 0 {
		nameservers = nil
	}
	skipPayment := operator && input.SkipPayment
	if !skipPayment && !fake.domainState.billing {
		writeError(writer, http.StatusServiceUnavailable, redundantdns.CodeBillingUnavailable, "billing is not enabled on this instance: domains cannot be paid for")
		return
	}
	if !operator {
		if acceptTerms != "" {
			if acceptTerms != DomainTermsVersion {
				writeError(writer, http.StatusConflict, redundantdns.CodeLegalVersionMismatch, "the domain terms version is not the current one")
				return
			}
			fake.acceptDomainTerms()
		}
	}
	if !fake.requireDomainTerms(writer) || (!operator && !fake.domainAllowed(writer, "domain.register")) {
		return
	}
	owner, ok := fake.transferOwner(writer, input.ContactID)
	if !ok {
		return
	}
	quote := fake.quote(name, years)
	switch {
	case !quote.Available:
		writeError(writer, http.StatusConflict, redundantdns.CodeDomainUnavailable, name+" cannot be registered: "+quote.Reason)
		return
	case quote.Premium && !operator:
		writeError(writer, http.StatusUnprocessableEntity, redundantdns.CodeDomainPremium, name+" is a premium name: premium names are registered on request, contact support")
		return
	}
	entry := fake.newRegistration(name, years, input, nameservers, owner, quote)
	fake.domainState.domains[name] = entry
	if skipPayment {
		now := time.Now().UTC().Truncate(time.Second)
		entry.domain.Registration.PaidAt, entry.domain.Registration.PaidBy = &now, redundantdns.PaidByOperator
		job := fake.completeRegistration(entry)
		writeJSON(writer, http.StatusCreated, redundantdns.DomainCheckout{Domain: fake.viewDomain(entry), Job: &job})
		return
	}
	sessionID, checkoutURL := fake.openCheckout(fakeCheckout{purpose: purposeRegister, domain: name, years: years, priceCents: quote.PriceCents})
	entry.domain.Registration.CheckoutSessionID, entry.domain.Registration.CheckoutURL = sessionID, checkoutURL
	writeJSON(writer, http.StatusCreated, redundantdns.DomainCheckout{Domain: fake.viewDomain(entry), CheckoutURL: checkoutURL})
}

// newRegistration builds a domain waiting for its checkout.
func (fake *Fake) newRegistration(name string, years int, input redundantdns.AdminDomainRegisterCreate, nameservers []string,
	owner *redundantdns.Contact, quote redundantdns.DomainQuote,
) *fakeDomain {
	now := time.Now().UTC().Truncate(time.Second)
	autoRenew := input.AutoRenew == nil || *input.AutoRenew
	snapshot := *owner
	return &fakeDomain{domain: redundantdns.Domain{
		Name: name, Registrar: fakeRegistrar, Status: redundantdns.DomainStatusPaymentPending, AutoRenew: autoRenew,
		Nameservers: slices.Clone(nameservers), OwnerContactID: owner.ContactID, Registrant: &snapshot,
		Registration: &redundantdns.DomainRegistration{
			Years: years, PriceCents: quote.PriceCents, Currency: quote.Currency, Premium: quote.Premium,
			ContactID: owner.ContactID, Nameservers: slices.Clone(nameservers), ApplyZoneNS: input.ApplyZoneNS, AutoRenew: autoRenew,
			RequestedAt: now, RequestedBy: "usr-test",
		},
		CreatedAt: now, UpdatedAt: now,
	}}
}

// openCheckout records a one-off checkout and returns its session id and
// URL.
func (fake *Fake) openCheckout(checkout fakeCheckout) (sessionID, checkoutURL string) {
	sessionID = fmt.Sprintf("cs_fake_%04d", fake.nextSequence())
	fake.domainState.checkouts[sessionID] = &checkout
	query := url.Values{"session": {sessionID}}
	return sessionID, fake.URL + fakeCheckoutPath + "?" + query.Encode()
}

// closeCheckout closes the open checkouts of a domain (a cancelled
// registration, a renewal checkout replaced by a new one).
func (fake *Fake) closeCheckout(name, purpose string) {
	for _, checkout := range fake.domainState.checkouts {
		if checkout.domain == name && checkout.purpose == purpose {
			checkout.closed = true
		}
	}
}

// pay applies the payment of an open checkout; false when it is closed or
// unknown.
func (fake *Fake) pay(sessionID string) bool {
	checkout, ok := fake.domainState.checkouts[sessionID]
	if !ok || checkout.closed {
		return false
	}
	entry, ok := fake.domainState.domains[checkout.domain]
	if !ok {
		return false
	}
	checkout.closed = true
	now := time.Now().UTC().Truncate(time.Second)
	intent := "pi_" + strings.TrimPrefix(sessionID, "cs_")
	switch checkout.purpose {
	case purposeRegister:
		registration := entry.domain.Registration
		registration.PaidAt, registration.PaidBy, registration.PaymentIntentID = &now, redundantdns.PaidByStripe, intent
		fake.completeRegistration(entry)
	case purposeRenew:
		renewal := entry.domain.Renewal
		renewal.PaidAt, renewal.PaidBy, renewal.PaymentIntentID, renewal.CompletedAt = &now, redundantdns.PaidByStripe, intent, &now
		extend(entry, checkout.years)
	}
	return true
}

// completeRegistration runs the register job of a paid registration: the
// domain becomes active, or registration_failed for a "fail-" name.
func (fake *Fake) completeRegistration(entry *fakeDomain) redundantdns.DomainJob {
	now := time.Now().UTC().Truncate(time.Second)
	domain, registration := &entry.domain, entry.domain.Registration
	job := redundantdns.DomainJob{JobID: fake.nextID("job"), Op: redundantdns.DomainOpRegister, Status: redundantdns.JobStatusDone, Attempts: 1, CreatedAt: &now}
	if strings.HasPrefix(firstLabel(domain.Name), failPrefix) && !entry.retried {
		detail := "the registry refused the registration of " + domain.Name
		domain.Status, domain.LastError, registration.Error = redundantdns.DomainStatusRegistrationFailed, detail, detail
		job.Status, job.LastError = redundantdns.JobStatusFailed, detail
		return job
	}
	expires := now.AddDate(registration.Years, 0, 0)
	domain.Status, domain.ExpiresAt, domain.Locked, domain.LastError = redundantdns.DomainStatusActive, &expires, true, ""
	domain.RegistrarDomainID = redundantdns.FlexString(fmt.Sprintf("%d", 100000000+fake.nextSequence()))
	domain.Contacts = redundantdns.DomainContacts{Owner: domain.Registrant.Handles[fakeRegistrar], Admin: "ZD000001-XX", Tech: "ZD000001-XX", Billing: "ZD000001-XX"}
	switch zone := fake.zoneNamed(domain.Name); {
	case len(registration.Nameservers) > 0:
		domain.Nameservers = slices.Clone(registration.Nameservers)
	case registration.ApplyZoneNS && zone != nil && len(zone.NSPlan) > 0:
		domain.Nameservers = trimDots(zone.NSPlan)
	default:
		domain.Nameservers = slices.Clone(defaultRegistrarNameservers)
	}
	registration.CompletedAt, registration.Error = &now, ""
	domain.UpdatedAt = now
	return job
}

// retryRegistration serves POST /v1/domains/{name}/register/retry: in the
// fake the retry always succeeds.
func (fake *Fake) retryRegistration(writer http.ResponseWriter, _ *http.Request, entry *fakeDomain) {
	if entry.domain.Status != redundantdns.DomainStatusRegistrationFailed || !entry.domain.Registration.Paid() {
		writeError(writer, http.StatusConflict, redundantdns.CodeDomainNotRetryable, "only a paid registration that failed can be retried")
		return
	}
	entry.retried = true
	entry.domain.Registration.Error = ""
	job := fake.completeRegistration(entry)
	writeJSON(writer, http.StatusOK, redundantdns.DomainMutationResult{Domain: fake.viewDomain(entry), Job: job})
}

// startPaidRenewal opens a renewal checkout (billing on).
func (fake *Fake) startPaidRenewal(writer http.ResponseWriter, entry *fakeDomain, years int) {
	if renewal := entry.domain.Renewal; renewal != nil && renewal.PaidAt != nil && renewal.CompletedAt == nil {
		writeError(writer, http.StatusConflict, redundantdns.CodeDomainRenewalInProgress, "a paid renewal of this domain is still running")
		return
	}
	fake.closeCheckout(entry.domain.Name, purposeRenew)
	price := DomainPriceCents(entry.domain.Name, years)
	sessionID, checkoutURL := fake.openCheckout(fakeCheckout{purpose: purposeRenew, domain: entry.domain.Name, years: years, priceCents: price})
	entry.domain.Renewal = &redundantdns.DomainRenewal{
		Years: years, PriceCents: price, Currency: DomainCurrency, CheckoutSessionID: sessionID, CheckoutURL: checkoutURL,
		RequestedAt: time.Now().UTC().Truncate(time.Second), RequestedBy: "usr-test",
	}
	writeJSON(writer, http.StatusOK, redundantdns.DomainCheckout{Domain: fake.viewDomain(entry), CheckoutURL: checkoutURL})
}

// adminRenewDomain serves POST /v1/admin/tenants/{orgId}/domains/{name}/renew.
func (fake *Fake) adminRenewDomain(writer http.ResponseWriter, request *http.Request) {
	var input redundantdns.AdminDomainRenew
	if !decode(writer, request, &input) {
		return
	}
	if !input.SkipPayment {
		writeError(writer, http.StatusBadRequest, redundantdns.CodeSkipPaymentRequired,
			"the admin route only renews without a payment (skipPayment: true); a paid renewal goes through the organization's renew route")
		return
	}
	years := input.Years
	if years == 0 {
		years = 1
	}
	if years < 1 || years > 10 {
		writeError(writer, http.StatusBadRequest, redundantdns.CodeInvalidYears, "register or renew for 1 to 10 years")
		return
	}
	if request.PathValue("orgId") != fake.OrgID {
		writeError(writer, http.StatusNotFound, redundantdns.CodeOrgNotFound, "organization not found")
		return
	}
	entry, ok := fake.domainState.domains[redundantdns.NormalizeZoneName(request.PathValue("name"))]
	if !ok {
		writeError(writer, http.StatusNotFound, redundantdns.CodeDomainNotFound, "domain not found")
		return
	}
	if registrationOpen(entry) {
		writeError(writer, http.StatusConflict, redundantdns.CodeDomainRegistrationPending, "the domain is not in the registrar account yet")
		return
	}
	extend(entry, years)
	now := time.Now().UTC().Truncate(time.Second)
	writeJSON(writer, http.StatusOK, map[string]any{"job": redundantdns.DomainJob{
		JobID: fake.nextID("job"), Op: redundantdns.DomainOpRenew, Status: redundantdns.JobStatusDone, Attempts: 1, CreatedAt: &now,
	}})
}

// extend adds years to a domain's expiry.
func extend(entry *fakeDomain, years int) {
	expires := time.Now().UTC().Truncate(time.Second)
	if entry.domain.ExpiresAt != nil {
		expires = *entry.domain.ExpiresAt
	}
	expires = expires.AddDate(years, 0, 0)
	entry.domain.ExpiresAt = &expires
}

// registrationOpen reports whether a registration through the platform has
// not reached the registrar account yet.
func registrationOpen(entry *fakeDomain) bool {
	switch entry.domain.Status {
	case redundantdns.DomainStatusPaymentPending, redundantdns.DomainStatusRegistering, redundantdns.DomainStatusRegistrationFailed:
		return true
	}
	return false
}
