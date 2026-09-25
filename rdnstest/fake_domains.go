package rdnstest

import (
	"cmp"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	redundantdns "github.com/redundantdns/go-client"
)

// DomainTermsVersion is the Domain Registration Terms version the fake
// serves (GET /v1/legal/versions domainTerms).
const DomainTermsVersion = "2026-09-24"

// DefaultTransferReads is how many reads of a pending transfer (GET the
// domain, GET its transfer status or POST sync) it takes to complete it:
// the Nth read sees the transfer completed.
const DefaultTransferReads = 2

// domainTermsPath is where the fake says the terms can be read.
const domainTermsPath = "/legal/domain-terms"

// fakeRegistrar is the registrar id of the fake's domains.
const fakeRegistrar = "openprovider"

// Auth codes that drive the simulated registrar: a code starting with
// "invalid" is rejected at once (422 registrarRejected, the domain stays as
// transfer_failed), one starting with "fail" is accepted and the transfer
// fails when it would complete. Any other code transfers.
const (
	authCodeRejectedPrefix = "invalid"
	authCodeFailPrefix     = "fail"
)

// previousNameservers are the nameservers a transferred domain keeps from
// its previous DNS host when the transfer sets none.
var previousNameservers = []string{"ns1.previous-dns.test", "ns2.previous-dns.test"}

var (
	eppPhone     = regexp.MustCompile(`^\+[0-9]{1,3}\.[0-9]{4,14}$`)
	countryCode  = regexp.MustCompile(`^[A-Z]{2}$`)
	domainLabels = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
)

// fakeDomains is the domains module of the fake: the organization's
// domains, the reseller account's unassigned domains, contacts, the Domain
// Registration Terms acceptance and the transfer simulation settings.
type fakeDomains struct {
	domains       map[string]*fakeDomain
	unassigned    map[string]*redundantdns.Domain
	contacts      map[string]*redundantdns.Contact
	terms         *redundantdns.ManagedTermsAcceptance
	transferReads int
	// billing is the payment gateway (SetDomainBilling): registrations and
	// renewals open a checkout when on.
	billing bool
	// checkouts are the one-off checkouts by session id.
	checkouts map[string]*fakeCheckout
}

// fakeDomain is one domain of the organization and its simulated
// registrar state.
type fakeDomain struct {
	domain redundantdns.Domain
	// readsLeft counts the reads until a pending transfer completes.
	readsLeft int
	// failTransfer makes the pending transfer fail instead of completing.
	failTransfer bool
	// retried marks a failed registration retried (the retry succeeds).
	retried bool
}

func newFakeDomains() fakeDomains {
	return fakeDomains{
		domains: map[string]*fakeDomain{}, unassigned: map[string]*redundantdns.Domain{},
		contacts: map[string]*redundantdns.Contact{}, transferReads: DefaultTransferReads,
		checkouts: map[string]*fakeCheckout{},
	}
}

// ---------------------------------------------------------------- helpers for tests

// SetPlan sets the organization's plan ("free" by default): /v1/me shows
// it and, on "free", the domains module holds one domain (a second
// transfer answers 402 plan_limit_reached).
func (fake *Fake) SetPlan(plan string) {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	fake.plan = plan
}

// SetTransferReads sets how many reads of a pending transfer it takes to
// complete it (DefaultTransferReads by default; 0 or 1 completes on the
// first read). It applies to transfers requested afterwards.
func (fake *Fake) SetTransferReads(reads int) {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	fake.domainState.transferReads = reads
}

// AcceptDomainTerms records the organization's acceptance of the current
// Domain Registration Terms, as if an admin had accepted them earlier.
func (fake *Fake) AcceptDomainTerms() {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	fake.acceptDomainTerms()
}

// SeedDomain adds a domain the organization already holds (for example one
// assigned by the platform admin), filling the empty fields: registered at
// "openprovider", expiring in a year, with the previous DNS host's
// nameservers; an empty Status also means active, locked and
// auto-renewing. It returns the stored domain.
func (fake *Fake) SeedDomain(domain redundantdns.Domain) redundantdns.Domain {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	now := time.Now().UTC().Truncate(time.Second)
	domain.Name = redundantdns.NormalizeZoneName(domain.Name)
	if domain.Status == "" {
		domain.Status = redundantdns.DomainStatusActive
		domain.Locked = true
		domain.AutoRenew = true
	}
	if domain.Registrar == "" {
		domain.Registrar = fakeRegistrar
	}
	if domain.RegistrarDomainID == "" {
		domain.RegistrarDomainID = redundantdns.FlexString(fmt.Sprintf("%d", 100000000+fake.nextSequence()))
	}
	if domain.ExpiresAt == nil {
		expires := now.AddDate(1, 0, 0)
		domain.ExpiresAt = &expires
	}
	if len(domain.Nameservers) == 0 {
		domain.Nameservers = slices.Clone(previousNameservers)
	}
	if domain.CreatedAt.IsZero() {
		domain.CreatedAt, domain.UpdatedAt = now, now
	}
	fake.domainState.domains[domain.Name] = &fakeDomain{domain: domain}
	return fake.viewDomain(fake.domainState.domains[domain.Name])
}

// SeedUnassignedDomain adds a domain of the reseller account that belongs
// to no organization (listed by GET /v1/admin/domains, assignable with
// POST /v1/admin/domains/{name}/assign). Its name is taken for transfers.
func (fake *Fake) SeedUnassignedDomain(name string) {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	name = redundantdns.NormalizeZoneName(name)
	expires := time.Now().UTC().Truncate(time.Second).AddDate(1, 0, 0)
	fake.domainState.unassigned[name] = &redundantdns.Domain{
		Name: name, Registrar: fakeRegistrar, Status: redundantdns.DomainStatusActive, ExpiresAt: &expires,
		Locked: true, AutoRenew: true, Nameservers: slices.Clone(previousNameservers),
		RegistrarDomainID: redundantdns.FlexString(fmt.Sprintf("%d", 100000000+fake.nextSequence())),
	}
}

// SeedContact adds a contact; registrantProfile makes it the organization's
// registrant profile (its default contact). The fields are not validated.
func (fake *Fake) SeedContact(fields redundantdns.ContactFields, registrantProfile bool) redundantdns.Contact {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	contact := fake.newContact(fields)
	if registrantProfile {
		for _, existing := range fake.domainState.contacts {
			existing.Default = false
		}
		contact.Default = true
	}
	fake.domainState.contacts[contact.ContactID] = contact
	return *contact
}

// Domain returns a domain of the organization as the API shows it, without
// counting as a read of a pending transfer.
func (fake *Fake) Domain(name string) (redundantdns.Domain, bool) {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	entry, ok := fake.domainState.domains[redundantdns.NormalizeZoneName(name)]
	if !ok {
		return redundantdns.Domain{}, false
	}
	return fake.viewDomain(entry), true
}

// DomainCount returns how many domains the organization holds.
func (fake *Fake) DomainCount() int {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	return len(fake.domainState.domains)
}

// ContactCount returns how many contacts the organization has.
func (fake *Fake) ContactCount() int {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	return len(fake.domainState.contacts)
}

// ---------------------------------------------------------------- terms

func (fake *Fake) nextSequence() int {
	fake.sequence++
	return fake.sequence
}

func (fake *Fake) acceptDomainTerms() {
	fake.domainState.terms = &redundantdns.ManagedTermsAcceptance{
		Version: DomainTermsVersion, AcceptedAt: time.Now().UTC().Truncate(time.Second), UserID: "usr-test", IP: "198.51.100.7",
	}
}

func (fake *Fake) domainTermsAccepted() bool {
	return fake.domainState.terms != nil && fake.domainState.terms.Version == DomainTermsVersion
}

func (fake *Fake) domainTermsStatus() redundantdns.DomainTermsStatus {
	return redundantdns.DomainTermsStatus{
		Current: DomainTermsVersion, Accepted: fake.domainState.terms, Required: !fake.domainTermsAccepted(),
		URL: fake.URL + domainTermsPath,
	}
}

// requireDomainTerms answers 428 domain_terms_required (and returns false)
// until the organization accepted the current Domain Registration Terms.
func (fake *Fake) requireDomainTerms(writer http.ResponseWriter) bool {
	if fake.domainTermsAccepted() {
		return true
	}
	writeJSON(writer, http.StatusPreconditionRequired, map[string]any{
		"error":   redundantdns.CodeDomainTermsRequired,
		"message": "accept the Domain Registration Terms to change domains",
		"details": redundantdns.DomainTermsRequirement{Version: DomainTermsVersion, URL: fake.URL + domainTermsPath},
	})
	return false
}

// ---------------------------------------------------------------- routes

func (fake *Fake) mountDomains(handle func(string, handler)) {
	handle("GET /v1/legal/domains", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, fake.domainTermsStatus())
	})
	handle("POST /v1/legal/domains/accept", func(writer http.ResponseWriter, request *http.Request) {
		var input struct {
			Version string `json:"version"`
		}
		if !decode(writer, request, &input) {
			return
		}
		if input.Version != DomainTermsVersion {
			writeError(writer, http.StatusConflict, redundantdns.CodeLegalVersionMismatch, "the domain terms version is not the current one")
			return
		}
		fake.acceptDomainTerms()
		writeJSON(writer, http.StatusOK, fake.domainTermsStatus())
	})
	handle("GET /v1/domains", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, fake.domainViews())
	})
	handle("POST /v1/domains/transfer", fake.transferIn)
	handle("GET /v1/domains/export", fake.exportDomains)
	fake.mountRegistration(handle)
	fake.mountDomainRoutes(handle)
	fake.mountContacts(handle)
	fake.mountDomainAdmin(handle)
}

// mountDomainRoutes serves /v1/domains/{name}/...
func (fake *Fake) mountDomainRoutes(handle func(string, handler)) {
	handle("GET /v1/domains/{name}", fake.withDomain(func(writer http.ResponseWriter, _ *http.Request, entry *fakeDomain) {
		fake.progressTransfer(entry)
		writeJSON(writer, http.StatusOK, fake.viewDomain(entry))
	}))
	handle("DELETE /v1/domains/{name}", fake.withDomain(func(writer http.ResponseWriter, _ *http.Request, entry *fakeDomain) {
		unpaid := entry.domain.Status == redundantdns.DomainStatusPaymentPending && !entry.domain.Registration.Paid()
		if entry.domain.Status != redundantdns.DomainStatusTransferFailed && !unpaid {
			writeError(writer, http.StatusConflict, redundantdns.CodeDomainNotRemovable,
				"only a domain whose transfer failed or an unpaid registration can be removed")
			return
		}
		if unpaid {
			// Its checkout can no longer be paid.
			fake.closeCheckout(entry.domain.Name, purposeRegister)
		}
		delete(fake.domainState.domains, entry.domain.Name)
		writeJSON(writer, http.StatusOK, map[string]bool{"ok": true})
	}))
	handle("GET /v1/domains/{name}/transfer", fake.withDomain(func(writer http.ResponseWriter, _ *http.Request, entry *fakeDomain) {
		fake.progressTransfer(entry)
		view := fake.viewDomain(entry)
		writeJSON(writer, http.StatusOK, redundantdns.DomainTransferStatus{Name: view.Name, Status: view.Status, Transfer: view.Transfer})
	}))
	handle("POST /v1/domains/{name}/sync", fake.withDomain(func(writer http.ResponseWriter, _ *http.Request, entry *fakeDomain) {
		// Never gated: sync is part of the exit guarantee.
		fake.progressTransfer(entry)
		now := time.Now().UTC().Truncate(time.Second)
		entry.domain.LastSyncAt = &now
		fake.writeMutation(writer, entry, "sync")
	}))
	// One pattern for every PUT below /v1/domains/{name}/: separate patterns
	// would conflict with PUT /v1/domains/contacts/{contactId} in ServeMux.
	handle("PUT /v1/domains/{name}/{field}", fake.putDomainField)
	handle("POST /v1/domains/{name}/nameservers/apply-zone", fake.withDomain(fake.applyZoneNS))
	handle("POST /v1/domains/{name}/renew", fake.withDomain(fake.renew))
	handle("POST /v1/domains/{name}/authcode", fake.withDomain(func(writer http.ResponseWriter, _ *http.Request, entry *fakeDomain) {
		// Never gated: the auth code is part of the exit guarantee.
		if !fake.domainSettled(writer, entry) {
			return
		}
		writeJSON(writer, http.StatusOK, redundantdns.DomainAuthCode{Name: entry.domain.Name, AuthCode: fakeAuthCode(entry.domain.Name)})
	}))
	handle("POST /v1/domains/{name}/registrant", fake.withDomain(fake.changeRegistrant))
}

// putDomainField dispatches PUT /v1/domains/{name}/{field}: nameservers,
// lock, autorenew, and contacts/{contactId}.
func (fake *Fake) putDomainField(writer http.ResponseWriter, request *http.Request) {
	if request.PathValue("name") == "contacts" {
		fake.updateContact(writer, request, request.PathValue("field"))
		return
	}
	serve := map[string]func(http.ResponseWriter, *http.Request, *fakeDomain){
		"nameservers": fake.setNameservers, "lock": fake.setLock, "autorenew": fake.setAutoRenew,
	}[request.PathValue("field")]
	if serve == nil {
		writeError(writer, http.StatusNotFound, "notFound", "route not found")
		return
	}
	fake.withDomain(serve)(writer, request)
}

// withDomain loads {name} or answers domainNotFound.
func (fake *Fake) withDomain(serve func(http.ResponseWriter, *http.Request, *fakeDomain)) handler {
	return func(writer http.ResponseWriter, request *http.Request) {
		entry, ok := fake.domainState.domains[redundantdns.NormalizeZoneName(request.PathValue("name"))]
		if !ok {
			writeError(writer, http.StatusNotFound, redundantdns.CodeDomainNotFound, "domain not found")
			return
		}
		serve(writer, request, entry)
	}
}

// transferIn serves POST /v1/domains/transfer.
func (fake *Fake) transferIn(writer http.ResponseWriter, request *http.Request) {
	var input redundantdns.DomainTransferCreate
	if !decode(writer, request, &input) {
		return
	}
	name := redundantdns.NormalizeZoneName(input.Name)
	nameservers, nameserversOK := normalizeNameservers(input.Nameservers)
	switch {
	case !domainLabels.MatchString(name):
		writeError(writer, http.StatusBadRequest, redundantdns.CodeInvalidDomainName, "invalid domain name")
		return
	case strings.TrimSpace(input.AuthCode) == "":
		writeError(writer, http.StatusBadRequest, redundantdns.CodeInvalidBody, "authCode is required")
		return
	case len(input.Nameservers) > 0 && !nameserversOK:
		writeError(writer, http.StatusBadRequest, redundantdns.CodeInvalidNameservers, "give 2 to 13 distinct host names")
		return
	}
	if _, ok := fake.domainState.domains[name]; ok {
		writeError(writer, http.StatusConflict, redundantdns.CodeDomainExists, "the organization already holds this domain")
		return
	}
	if _, ok := fake.domainState.unassigned[name]; ok {
		writeError(writer, http.StatusConflict, redundantdns.CodeDomainNameTaken, "this domain belongs to another account")
		return
	}
	if !fake.domainAllowed(writer, "domain.transfer") {
		return
	}
	if input.AcceptDomainTerms != "" {
		if input.AcceptDomainTerms != DomainTermsVersion {
			writeError(writer, http.StatusConflict, redundantdns.CodeLegalVersionMismatch, "the domain terms version is not the current one")
			return
		}
		fake.acceptDomainTerms()
	}
	if !fake.requireDomainTerms(writer) {
		return
	}
	owner, ok := fake.transferOwner(writer, input.ContactID)
	if !ok {
		return
	}
	entry := fake.newTransfer(name, input, nameservers, owner)
	fake.domainState.domains[name] = entry
	if strings.HasPrefix(strings.ToLower(input.AuthCode), authCodeRejectedPrefix) {
		rejectTransfer(entry, "the registrar rejected the auth code")
		writeJSON(writer, http.StatusUnprocessableEntity, map[string]any{
			"error": redundantdns.CodeRegistrarRejected, "message": "the registrar rejected the transfer: invalid auth code",
			"details": map[string]string{"name": name, "op": redundantdns.DomainOpTransfer},
		})
		return
	}
	entry.readsLeft = fake.domainState.transferReads
	entry.failTransfer = strings.HasPrefix(strings.ToLower(input.AuthCode), authCodeFailPrefix)
	fake.writeMutationStatus(writer, http.StatusCreated, entry, redundantdns.DomainOpTransfer)
}

// domainAllowed enforces the Free plan's single domain for an action
// (domain.transfer, domain.register).
func (fake *Fake) domainAllowed(writer http.ResponseWriter, action string) bool {
	if fake.plan != "free" || len(fake.domainState.domains) < 1 {
		return true
	}
	writeJSON(writer, http.StatusPaymentRequired, map[string]any{
		"error": redundantdns.CodePlanLimitReached, "message": "the Free plan holds one domain",
		"details": map[string]any{
			"action": action, "plan": fake.plan, "limit": 1, "current": len(fake.domainState.domains),
			"feature": "domains", "upgradeTo": "starter", "upgradeName": "Starter",
		},
	})
	return false
}

// transferOwner resolves the registrant of a transfer: the given contact or
// the registrant profile.
func (fake *Fake) transferOwner(writer http.ResponseWriter, contactID string) (*redundantdns.Contact, bool) {
	if contactID != "" {
		contact, ok := fake.domainState.contacts[contactID]
		if !ok {
			writeError(writer, http.StatusNotFound, redundantdns.CodeContactNotFound, "contact not found")
		}
		return contact, ok
	}
	if profile := fake.registrantProfile(); profile != nil {
		return profile, true
	}
	writeError(writer, http.StatusUnprocessableEntity, redundantdns.CodeRegistrantProfileRequired,
		"set the organization's registrant profile (or choose a contact) before transferring or registering a domain")
	return nil, false
}

// newTransfer builds a domain whose transfer was just submitted.
func (fake *Fake) newTransfer(name string, input redundantdns.DomainTransferCreate, nameservers []string, owner *redundantdns.Contact) *fakeDomain {
	now := time.Now().UTC().Truncate(time.Second)
	autoRenew := input.AutoRenew == nil || *input.AutoRenew
	snapshot := *owner
	domain := redundantdns.Domain{
		Name: name, Registrar: fakeRegistrar, Status: redundantdns.DomainStatusTransferPending,
		RegistrarDomainID: redundantdns.FlexString(fmt.Sprintf("%d", 100000000+fake.nextSequence())),
		AutoRenew:         autoRenew, Nameservers: slices.Clone(previousNameservers),
		Contacts:       redundantdns.DomainContacts{Owner: owner.Handles[fakeRegistrar], Admin: "ZD000001-XX", Tech: "ZD000001-XX"},
		OwnerContactID: owner.ContactID, Registrant: &snapshot,
		Transfer: &redundantdns.DomainTransfer{
			State: redundantdns.TransferStatePending, RequestedAt: &now, ApplyZoneNS: input.ApplyZoneNS, Nameservers: nameservers,
		},
		CreatedAt: now, UpdatedAt: now,
	}
	return &fakeDomain{domain: domain}
}

// rejectTransfer marks a transfer the registrar refused.
func rejectTransfer(entry *fakeDomain, detail string) {
	now := time.Now().UTC().Truncate(time.Second)
	entry.domain.Status = redundantdns.DomainStatusTransferFailed
	entry.domain.Transfer.State = redundantdns.TransferStateFailed
	entry.domain.Transfer.Detail = detail
	entry.domain.LastError = detail
	entry.domain.PendingJobs = append(entry.domain.PendingJobs, redundantdns.DomainJob{
		JobID: "job-transfer-" + entry.domain.Name, Op: redundantdns.DomainOpTransfer, Status: redundantdns.JobStatusFailed,
		Attempts: 1, LastError: detail, CreatedAt: &now,
	})
}

// progressTransfer counts a read of a pending transfer and completes (or
// fails) it on the last one.
func (fake *Fake) progressTransfer(entry *fakeDomain) {
	if entry.domain.Status != redundantdns.DomainStatusTransferPending || entry.domain.Transfer == nil {
		return
	}
	entry.readsLeft--
	if entry.readsLeft > 0 {
		return
	}
	if entry.failTransfer {
		rejectTransfer(entry, "the losing registrar refused the transfer")
		return
	}
	now := time.Now().UTC().Truncate(time.Second)
	expires := now.AddDate(1, 0, 0)
	domain := &entry.domain
	domain.Status, domain.Locked, domain.ExpiresAt, domain.UpdatedAt = redundantdns.DomainStatusActive, true, &expires, now
	domain.Transfer.State, domain.Transfer.CompletedAt = redundantdns.TransferStateCompleted, &now
	switch zone := fake.zoneNamed(domain.Name); {
	case domain.Transfer.ApplyZoneNS && zone != nil && len(zone.NSPlan) > 0:
		domain.Nameservers = trimDots(zone.NSPlan)
	case len(domain.Transfer.Nameservers) > 0:
		domain.Nameservers = slices.Clone(domain.Transfer.Nameservers)
	}
}

// domainSettled answers 409 (and returns false) while a domain cannot be
// changed: its transfer is pending or failed.
func (fake *Fake) domainSettled(writer http.ResponseWriter, entry *fakeDomain) bool {
	switch entry.domain.Status {
	case redundantdns.DomainStatusTransferPending:
		writeError(writer, http.StatusConflict, redundantdns.CodeDomainTransferInProgress, "the domain's transfer is still in progress")
		return false
	case redundantdns.DomainStatusTransferFailed:
		writeError(writer, http.StatusConflict, redundantdns.CodeConflict, "the domain's transfer failed: remove it and transfer it again")
		return false
	}
	if registrationOpen(entry) {
		writeError(writer, http.StatusConflict, redundantdns.CodeDomainRegistrationPending, "the domain is not registered yet: its registration is "+entry.domain.Status)
		return false
	}
	return true
}

// changeAllowed runs the checks of a gated change: settled and terms.
func (fake *Fake) changeAllowed(writer http.ResponseWriter, entry *fakeDomain) bool {
	return fake.domainSettled(writer, entry) && fake.requireDomainTerms(writer)
}

func (fake *Fake) setNameservers(writer http.ResponseWriter, request *http.Request, entry *fakeDomain) {
	var input struct {
		Nameservers []string `json:"nameservers"`
	}
	if !decode(writer, request, &input) {
		return
	}
	nameservers, ok := normalizeNameservers(input.Nameservers)
	if !ok {
		writeError(writer, http.StatusBadRequest, redundantdns.CodeInvalidNameservers, "give 2 to 13 distinct host names")
		return
	}
	if !fake.changeAllowed(writer, entry) {
		return
	}
	entry.domain.Nameservers = nameservers
	fake.writeMutation(writer, entry, redundantdns.DomainOpNameservers)
}

func (fake *Fake) applyZoneNS(writer http.ResponseWriter, request *http.Request, entry *fakeDomain) {
	var input struct {
		ZoneID string `json:"zoneId"`
	}
	if !decode(writer, request, &input) {
		return
	}
	zone := fake.zoneNamed(entry.domain.Name)
	if input.ZoneID != "" {
		zone = fake.zones[input.ZoneID]
	}
	if zone == nil {
		writeError(writer, http.StatusNotFound, redundantdns.CodeZoneNotFound, "zone not found")
		return
	}
	if len(zone.NSPlan) == 0 {
		writeError(writer, http.StatusUnprocessableEntity, redundantdns.CodeZoneNSPlanEmpty, "the zone has no attachment: its NS plan is empty")
		return
	}
	if !fake.changeAllowed(writer, entry) {
		return
	}
	entry.domain.Nameservers = trimDots(zone.NSPlan)
	fake.writeMutation(writer, entry, redundantdns.DomainOpNameservers)
}

func (fake *Fake) setLock(writer http.ResponseWriter, request *http.Request, entry *fakeDomain) {
	var input struct {
		Locked *bool `json:"locked"`
	}
	if !decode(writer, request, &input) {
		return
	}
	if input.Locked == nil {
		writeError(writer, http.StatusBadRequest, redundantdns.CodeInvalidBody, "locked is required")
		return
	}
	// Unlocking is never gated by the terms: it is part of the exit guarantee.
	if !fake.domainSettled(writer, entry) || (*input.Locked && !fake.requireDomainTerms(writer)) {
		return
	}
	entry.domain.Locked = *input.Locked
	fake.writeMutation(writer, entry, redundantdns.DomainOpLock)
}

func (fake *Fake) setAutoRenew(writer http.ResponseWriter, request *http.Request, entry *fakeDomain) {
	var input struct {
		AutoRenew *bool `json:"autoRenew"`
	}
	if !decode(writer, request, &input) {
		return
	}
	if input.AutoRenew == nil {
		writeError(writer, http.StatusBadRequest, redundantdns.CodeInvalidBody, "autoRenew is required")
		return
	}
	if !fake.changeAllowed(writer, entry) {
		return
	}
	entry.domain.AutoRenew = *input.AutoRenew
	fake.writeMutation(writer, entry, redundantdns.DomainOpAutoRenew)
}

func (fake *Fake) renew(writer http.ResponseWriter, request *http.Request, entry *fakeDomain) {
	var input struct {
		Years int `json:"years"`
	}
	if !decode(writer, request, &input) {
		return
	}
	if input.Years == 0 {
		input.Years = 1
	}
	if input.Years < 1 || input.Years > 10 {
		writeError(writer, http.StatusBadRequest, redundantdns.CodeInvalidYears, "register or renew for 1 to 10 years")
		return
	}
	if !fake.changeAllowed(writer, entry) {
		return
	}
	if fake.domainState.billing {
		fake.startPaidRenewal(writer, entry, input.Years)
		return
	}
	extend(entry, input.Years)
	fake.writeMutation(writer, entry, redundantdns.DomainOpRenew)
}

func (fake *Fake) changeRegistrant(writer http.ResponseWriter, request *http.Request, entry *fakeDomain) {
	var input struct {
		ContactID   string `json:"contactId"`
		ConfirmName string `json:"confirmName"`
	}
	if !decode(writer, request, &input) {
		return
	}
	if redundantdns.NormalizeZoneName(input.ConfirmName) != entry.domain.Name {
		writeError(writer, http.StatusBadRequest, redundantdns.CodeConfirmNameMismatch, "type the domain name to confirm")
		return
	}
	contact, ok := fake.domainState.contacts[input.ContactID]
	if !ok {
		writeError(writer, http.StatusNotFound, redundantdns.CodeContactNotFound, "contact not found")
		return
	}
	if !fake.changeAllowed(writer, entry) {
		return
	}
	snapshot := *contact
	entry.domain.OwnerContactID, entry.domain.Registrant = contact.ContactID, &snapshot
	entry.domain.Contacts.Owner = contact.Handles[fakeRegistrar]
	fake.writeMutation(writer, entry, redundantdns.DomainOpRegistrant)
}

// writeMutation answers 200 with the domain and a done job.
func (fake *Fake) writeMutation(writer http.ResponseWriter, entry *fakeDomain, op string) {
	fake.writeMutationStatus(writer, http.StatusOK, entry, op)
}

func (fake *Fake) writeMutationStatus(writer http.ResponseWriter, status int, entry *fakeDomain, op string) {
	now := time.Now().UTC().Truncate(time.Second)
	entry.domain.UpdatedAt = now
	writeJSON(writer, status, redundantdns.DomainMutationResult{
		Domain: fake.viewDomain(entry),
		Job:    redundantdns.DomainJob{JobID: fake.nextID("job"), Op: op, Status: redundantdns.JobStatusDone, Attempts: 1, CreatedAt: &now},
	})
}

// exportDomains serves GET /v1/domains/export (never gated).
func (fake *Fake) exportDomains(writer http.ResponseWriter, _ *http.Request) {
	zones := make([]redundantdns.ExportedZone, 0, len(fake.zones))
	for _, zone := range fake.zones {
		zones = append(zones, redundantdns.ExportedZone{ZoneID: zone.ZoneID, Name: zone.Name, ZoneFile: zoneFile(zone)})
	}
	slices.SortFunc(zones, func(left, right redundantdns.ExportedZone) int { return strings.Compare(left.Name, right.Name) })
	writeJSON(writer, http.StatusOK, map[string]any{
		"exportedAt": time.Now().UTC().Truncate(time.Second),
		"org":        map[string]string{"orgId": fake.OrgID, "name": "Test org"},
		"contacts":   fake.contactViews(),
		"domains":    fake.domainViews(),
		"zones":      zones,
	})
}

// ---------------------------------------------------------------- contacts

func (fake *Fake) mountContacts(handle func(string, handler)) {
	handle("GET /v1/domains/contacts", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, fake.contactViews())
	})
	handle("POST /v1/domains/contacts", func(writer http.ResponseWriter, request *http.Request) {
		fields, ok := decodeContact(writer, request)
		if !ok {
			return
		}
		contact := fake.newContact(fields)
		fake.domainState.contacts[contact.ContactID] = contact
		writeJSON(writer, http.StatusCreated, contact)
	})
	handle("DELETE /v1/domains/contacts/{contactId}", func(writer http.ResponseWriter, request *http.Request) {
		contact, ok := fake.domainState.contacts[request.PathValue("contactId")]
		if !ok {
			writeError(writer, http.StatusNotFound, redundantdns.CodeContactNotFound, "contact not found")
			return
		}
		if contact.Default || fake.contactUsed(contact.ContactID) {
			writeError(writer, http.StatusConflict, redundantdns.CodeContactInUse, "the contact is the registrant profile or a domain's registrant")
			return
		}
		delete(fake.domainState.contacts, contact.ContactID)
		writeJSON(writer, http.StatusOK, map[string]bool{"ok": true})
	})
	handle("GET /v1/domains/registrant-profile", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, map[string]any{"profile": fake.registrantProfile()})
	})
	handle("PUT /v1/domains/registrant-profile", func(writer http.ResponseWriter, request *http.Request) {
		fields, ok := decodeContact(writer, request)
		if !ok {
			return
		}
		profile := fake.registrantProfile()
		if profile == nil {
			profile = fake.newContact(fields)
			profile.Default = true
			fake.domainState.contacts[profile.ContactID] = profile
		} else {
			profile.ContactFields, profile.UpdatedAt = fields, time.Now().UTC().Truncate(time.Second)
		}
		writeJSON(writer, http.StatusOK, map[string]any{"profile": profile})
	})
}

// updateContact serves PUT /v1/domains/contacts/{contactId} (routed by
// putDomainField).
func (fake *Fake) updateContact(writer http.ResponseWriter, request *http.Request, contactID string) {
	contact, ok := fake.domainState.contacts[contactID]
	if !ok {
		writeError(writer, http.StatusNotFound, redundantdns.CodeContactNotFound, "contact not found")
		return
	}
	fields, ok := decodeContact(writer, request)
	if !ok {
		return
	}
	contact.ContactFields, contact.UpdatedAt = fields, time.Now().UTC().Truncate(time.Second)
	writeJSON(writer, http.StatusOK, contact)
}

// decodeContact reads and validates a contact body (400 invalidContact
// with the offending fields in the details).
func decodeContact(writer http.ResponseWriter, request *http.Request) (redundantdns.ContactFields, bool) {
	var fields redundantdns.ContactFields
	if !decode(writer, request, &fields) {
		return fields, false
	}
	fields.Country = strings.ToUpper(strings.TrimSpace(fields.Country))
	if problems := contactProblems(fields); len(problems) > 0 {
		writeJSON(writer, http.StatusBadRequest, map[string]any{
			"error": redundantdns.CodeInvalidContact, "message": "missing or invalid contact fields: " + strings.Join(problems, ", "),
			"details": map[string][]string{"fields": problems},
		})
		return fields, false
	}
	return fields, true
}

// contactProblems lists the missing or invalid required fields.
func contactProblems(fields redundantdns.ContactFields) []string {
	var problems []string
	required := map[string]string{
		"firstName": fields.FirstName, "lastName": fields.LastName, "street": fields.Street,
		"city": fields.City, "postalCode": fields.PostalCode,
	}
	for name, value := range required {
		if strings.TrimSpace(value) == "" {
			problems = append(problems, name)
		}
	}
	if !strings.Contains(fields.Email, "@") {
		problems = append(problems, "email")
	}
	if !eppPhone.MatchString(fields.Phone) {
		problems = append(problems, "phone")
	}
	if !countryCode.MatchString(fields.Country) {
		problems = append(problems, "country")
	}
	slices.Sort(problems)
	return problems
}

// newContact builds a contact with a registrar handle.
func (fake *Fake) newContact(fields redundantdns.ContactFields) *redundantdns.Contact {
	now := time.Now().UTC().Truncate(time.Second)
	sequence := fake.nextSequence()
	country := cmp.Or(fields.Country, "XX")
	return &redundantdns.Contact{
		ContactID: fmt.Sprintf("ctc-%04d", sequence), ContactFields: fields,
		Handles:   map[string]string{fakeRegistrar: fmt.Sprintf("RD%06d-%s", sequence, country)},
		CreatedAt: now, UpdatedAt: now,
	}
}

func (fake *Fake) registrantProfile() *redundantdns.Contact {
	for _, contact := range fake.domainState.contacts {
		if contact.Default {
			return contact
		}
	}
	return nil
}

func (fake *Fake) contactUsed(contactID string) bool {
	for _, entry := range fake.domainState.domains {
		if entry.domain.OwnerContactID == contactID {
			return true
		}
	}
	return false
}

func (fake *Fake) contactViews() []redundantdns.Contact {
	contacts := make([]redundantdns.Contact, 0, len(fake.domainState.contacts))
	for _, contact := range fake.domainState.contacts {
		contacts = append(contacts, *contact)
	}
	slices.SortFunc(contacts, func(left, right redundantdns.Contact) int { return strings.Compare(left.ContactID, right.ContactID) })
	return contacts
}

// ---------------------------------------------------------------- admin

func (fake *Fake) mountDomainAdmin(handle func(string, handler)) {
	handle("GET /v1/admin/domains", func(writer http.ResponseWriter, _ *http.Request) {
		domains := []redundantdns.AdminDomain{}
		for _, view := range fake.domainViews() {
			domains = append(domains, adminDomain(view, fake.OrgID, "Test org"))
		}
		for _, domain := range fake.domainState.unassigned {
			domains = append(domains, adminDomain(*domain, "", ""))
		}
		slices.SortFunc(domains, func(left, right redundantdns.AdminDomain) int { return strings.Compare(left.Name, right.Name) })
		writeJSON(writer, http.StatusOK, domains)
	})
	handle("POST /v1/admin/domains/{name}/assign", func(writer http.ResponseWriter, request *http.Request) {
		var input struct {
			OrgID string `json:"orgId"`
		}
		if !decode(writer, request, &input) {
			return
		}
		if input.OrgID != fake.OrgID {
			writeError(writer, http.StatusNotFound, "orgNotFound", "organization not found")
			return
		}
		name := redundantdns.NormalizeZoneName(request.PathValue("name"))
		domain, ok := fake.domainState.unassigned[name]
		if !ok {
			writeError(writer, http.StatusNotFound, redundantdns.CodeDomainNotFound, "no unassigned domain with this name")
			return
		}
		now := time.Now().UTC().Truncate(time.Second)
		domain.CreatedAt, domain.UpdatedAt, domain.LastSyncAt = now, now, &now
		delete(fake.domainState.unassigned, name)
		entry := &fakeDomain{domain: *domain}
		fake.domainState.domains[name] = entry
		writeJSON(writer, http.StatusOK, fake.viewDomain(entry))
	})
}

func adminDomain(domain redundantdns.Domain, orgID, orgName string) redundantdns.AdminDomain {
	return redundantdns.AdminDomain{
		Name: domain.Name, Registrar: domain.Registrar, RegistrarDomainID: domain.RegistrarDomainID, Status: domain.Status,
		ExpiresAt: domain.ExpiresAt, AutoRenew: domain.AutoRenew, Locked: domain.Locked,
		Nameservers: slices.Clone(domain.Nameservers), OrgID: orgID, OrgName: orgName,
	}
}

// ---------------------------------------------------------------- views

// viewDomain renders a domain as the API does, with the link to the zone
// of the same name.
func (fake *Fake) viewDomain(entry *fakeDomain) redundantdns.Domain {
	view := entry.domain
	view.Nameservers = slices.Clone(entry.domain.Nameservers)
	view.PendingJobs = slices.Clone(entry.domain.PendingJobs)
	if entry.domain.Transfer != nil {
		transfer := *entry.domain.Transfer
		transfer.Nameservers = slices.Clone(transfer.Nameservers)
		view.Transfer = &transfer
	}
	if zone := fake.zoneNamed(view.Name); zone != nil {
		view.Zone = &redundantdns.DomainZoneLink{
			ZoneID: zone.ZoneID, Name: zone.Name, NSPlan: slices.Clone(zone.NSPlan),
			NameserversMatch: sameNameservers(view.Nameservers, zone.NSPlan), DelegationState: fake.delegation(zone).State,
		}
	}
	return view
}

func (fake *Fake) domainViews() []redundantdns.Domain {
	domains := make([]redundantdns.Domain, 0, len(fake.domainState.domains))
	for _, entry := range fake.domainState.domains {
		domains = append(domains, fake.viewDomain(entry))
	}
	slices.SortFunc(domains, func(left, right redundantdns.Domain) int { return strings.Compare(left.Name, right.Name) })
	return domains
}

// zoneNamed returns the organization's zone with this name (nil if none).
func (fake *Fake) zoneNamed(name string) *redundantdns.Zone {
	for _, zone := range fake.zones {
		if zone.Name == name {
			return zone
		}
	}
	return nil
}

// ---------------------------------------------------------------- values

// normalizeNameservers lowercases the host names and drops trailing dots;
// ok is false unless there are 2 to 13 distinct valid host names.
func normalizeNameservers(values []string) (nameservers []string, ok bool) {
	nameservers = trimDots(values)
	if len(nameservers) < 2 || len(nameservers) > 13 {
		return nameservers, false
	}
	for index, host := range nameservers {
		if !domainLabels.MatchString(host) || slices.Contains(nameservers[:index], host) {
			return nameservers, false
		}
	}
	return nameservers, true
}

// trimDots lowercases host names and drops their trailing dot.
func trimDots(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, redundantdns.NormalizeZoneName(value))
	}
	return out
}

// sameNameservers compares two nameserver lists as sets, ignoring case and
// trailing dots.
func sameNameservers(left, right []string) bool {
	normalizedLeft, normalizedRight := trimDots(left), trimDots(right)
	slices.Sort(normalizedLeft)
	slices.Sort(normalizedRight)
	return slices.Equal(slices.Compact(normalizedLeft), slices.Compact(normalizedRight))
}

// fakeAuthCode is the deterministic transfer-out code of a domain.
func fakeAuthCode(name string) string {
	return "rdns-" + strings.ReplaceAll(name, ".", "-") + "-authcode"
}
