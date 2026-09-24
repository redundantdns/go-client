package redundantdns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"net/http"
	"time"
)

// DomainsService manages the organization's domains at the platform's
// registrar (the organization is the registrant), their contacts and the
// registrant profile. Changes run as registrar jobs: most answer at once
// (DomainMutationResult.Job.Status "done"), a transient registrar failure
// leaves the job queued (Queued) and a rejection answers 422
// registrarRejected.
//
// Every change except Sync, AuthCode, unlocking and Export needs the
// organization's acceptance of the current Domain Registration Terms
// (ErrDomainTermsRequired; see Legal.AcceptDomain and DomainTermsRequired).
type DomainsService struct{ client *Client }

// ErrTransferFailed is returned by WaitTransfer when the transfer failed.
var ErrTransferFailed = errors.New("domain transfer failed")

// List returns the organization's domains.
func (service *DomainsService) List(ctx context.Context) ([]Domain, error) {
	var domains []Domain
	err := service.client.do(ctx, request{method: http.MethodGet, path: "/v1/domains"}, &domains)
	return domains, err
}

// All iterates over the domains (see Paginate).
func (service *DomainsService) All(ctx context.Context) iter.Seq2[Domain, error] {
	return Paginate(ctx, func(ctx context.Context) ([]Domain, error) { return service.List(ctx) })
}

// Get returns one domain (404 domainNotFound when the organization does not
// hold it).
func (service *DomainsService) Get(ctx context.Context, name string) (*Domain, error) {
	var domain Domain
	if err := service.client.do(ctx, request{method: http.MethodGet, path: domainPath(name, "")}, &domain); err != nil {
		return nil, err
	}
	return &domain, nil
}

// TransferIn transfers a domain into the platform's registrar account
// (admins): it claims the name, creates the domain (transfer_pending) and
// submits the transfer with the auth code. Poll TransferStatus, Sync or
// WaitTransfer for the outcome.
func (service *DomainsService) TransferIn(ctx context.Context, input DomainTransferCreate) (*DomainMutationResult, error) {
	input.Name = NormalizeZoneName(input.Name)
	return service.mutate(ctx, http.MethodPost, "/v1/domains/transfer", input)
}

// TransferStatus returns the transfer progress of a domain as last synced.
func (service *DomainsService) TransferStatus(ctx context.Context, name string) (*DomainTransferStatus, error) {
	var status DomainTransferStatus
	if err := service.client.do(ctx, request{method: http.MethodGet, path: domainPath(name, "/transfer")}, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

// Sync refreshes status, expiry, nameservers, lock and transfer progress
// from the registrar now (editors; never gated by the plan or the terms).
func (service *DomainsService) Sync(ctx context.Context, name string) (*DomainMutationResult, error) {
	return service.mutate(ctx, http.MethodPost, domainPath(name, "/sync"), nil)
}

// SetNameservers sets the domain's nameservers (2 to 13 host names).
func (service *DomainsService) SetNameservers(ctx context.Context, name string, nameservers []string) (*DomainMutationResult, error) {
	body := map[string][]string{"nameservers": nameservers}
	return service.mutate(ctx, http.MethodPut, domainPath(name, "/nameservers"), body)
}

// ApplyZoneNS writes the NS plan of a zone as the domain's nameservers.
// zoneID "" uses the organization's zone with the same name (422
// zoneNsPlanEmpty when the zone has no attachment).
func (service *DomainsService) ApplyZoneNS(ctx context.Context, name, zoneID string) (*DomainMutationResult, error) {
	body := struct {
		ZoneID string `json:"zoneId,omitempty"`
	}{ZoneID: zoneID}
	return service.mutate(ctx, http.MethodPost, domainPath(name, "/nameservers/apply-zone"), body)
}

// SetLock turns the registrar transfer lock on or off (admins). Unlocking
// is never gated.
func (service *DomainsService) SetLock(ctx context.Context, name string, locked bool) (*DomainMutationResult, error) {
	body := map[string]bool{"locked": locked}
	return service.mutate(ctx, http.MethodPut, domainPath(name, "/lock"), body)
}

// SetAutoRenew turns auto-renewal on or off (admins).
func (service *DomainsService) SetAutoRenew(ctx context.Context, name string, autoRenew bool) (*DomainMutationResult, error) {
	body := map[string]bool{"autoRenew": autoRenew}
	return service.mutate(ctx, http.MethodPut, domainPath(name, "/autorenew"), body)
}

// Renew renews the domain for 1 to 10 years (admins; 0 = the server
// default, 1).
func (service *DomainsService) Renew(ctx context.Context, name string, years int) (*DomainMutationResult, error) {
	body := struct {
		Years int `json:"years,omitempty"`
	}{Years: years}
	return service.mutate(ctx, http.MethodPost, domainPath(name, "/renew"), body)
}

// AuthCode fetches the transfer-out auth code from the registrar (admins;
// never gated, audited). The platform does not store it.
func (service *DomainsService) AuthCode(ctx context.Context, name string) (*DomainAuthCode, error) {
	var code DomainAuthCode
	if err := service.client.do(ctx, request{method: http.MethodPost, path: domainPath(name, "/authcode")}, &code); err != nil {
		return nil, err
	}
	return &code, nil
}

// ChangeRegistrant changes the registrant (a trade) to another contact of
// the organization (admins). confirmName must repeat the domain name.
func (service *DomainsService) ChangeRegistrant(ctx context.Context, name, contactID, confirmName string) (*DomainMutationResult, error) {
	body := map[string]string{"contactId": contactID, "confirmName": NormalizeZoneName(confirmName)}
	return service.mutate(ctx, http.MethodPost, domainPath(name, "/registrant"), body)
}

// Delete forgets a domain whose transfer failed and releases the name
// (admins; 409 domainNotRemovable otherwise). It never deletes a
// registration.
func (service *DomainsService) Delete(ctx context.Context, name string) error {
	return service.client.do(ctx, request{method: http.MethodDelete, path: domainPath(name, "")}, &okResponse{})
}

// Export returns everything the organization holds in the domains module
// (admins; never gated): contacts, domains and zone files.
func (service *DomainsService) Export(ctx context.Context) (*DomainExport, error) {
	raw, err := service.ExportJSON(ctx)
	if err != nil {
		return nil, err
	}
	var export DomainExport
	if err := json.Unmarshal(raw, &export); err != nil {
		return nil, fmt.Errorf("GET /v1/domains/export: decode response: %w", err)
	}
	return &export, nil
}

// ExportJSON returns the export exactly as the server sent it, for
// archiving without losing fields this client does not know.
func (service *DomainsService) ExportJSON(ctx context.Context) ([]byte, error) {
	answer, err := service.client.send(ctx, request{method: http.MethodGet, path: "/v1/domains/export"})
	if err != nil {
		return nil, err
	}
	return answer.body, nil
}

// Contacts returns the organization's contacts.
func (service *DomainsService) Contacts(ctx context.Context) ([]Contact, error) {
	var contacts []Contact
	err := service.client.do(ctx, request{method: http.MethodGet, path: "/v1/domains/contacts"}, &contacts)
	return contacts, err
}

// Contact returns one contact. The API has no single-contact route, so
// this filters Contacts; a missing id answers contactNotFound.
func (service *DomainsService) Contact(ctx context.Context, contactID string) (*Contact, error) {
	contacts, err := service.Contacts(ctx)
	if err != nil {
		return nil, err
	}
	for _, contact := range contacts {
		if contact.ContactID == contactID {
			found := contact
			return &found, nil
		}
	}
	return nil, &APIError{
		StatusCode: http.StatusNotFound, Code: CodeContactNotFound,
		Message: fmt.Sprintf("contact %q not found", contactID),
		Method:  http.MethodGet, Path: "/v1/domains/contacts",
	}
}

// CreateContact creates a contact (admins).
func (service *DomainsService) CreateContact(ctx context.Context, fields ContactFields) (*Contact, error) {
	var contact Contact
	if err := service.client.do(ctx, request{method: http.MethodPost, path: "/v1/domains/contacts", body: fields}, &contact); err != nil {
		return nil, err
	}
	return &contact, nil
}

// UpdateContact replaces a contact's fields (admins); its registrar handles
// are updated by a job.
func (service *DomainsService) UpdateContact(ctx context.Context, contactID string, fields ContactFields) (*Contact, error) {
	var contact Contact
	if err := service.client.do(ctx, request{method: http.MethodPut, path: pathf("/v1/domains/contacts/%s", contactID), body: fields}, &contact); err != nil {
		return nil, err
	}
	return &contact, nil
}

// DeleteContact deletes a contact that no domain uses and that is not the
// registrant profile (admins; 409 contactInUse otherwise).
func (service *DomainsService) DeleteContact(ctx context.Context, contactID string) error {
	return service.client.do(ctx, request{method: http.MethodDelete, path: pathf("/v1/domains/contacts/%s", contactID)}, &okResponse{})
}

// RegistrantProfile returns the organization's registrant profile (its
// default contact), nil when there is none yet.
func (service *DomainsService) RegistrantProfile(ctx context.Context) (*Contact, error) {
	answer, err := service.client.send(ctx, request{method: http.MethodGet, path: "/v1/domains/registrant-profile"})
	if err != nil {
		return nil, err
	}
	return decodeProfile(http.MethodGet, answer.body)
}

// SetRegistrantProfile creates or replaces the registrant profile (admins).
func (service *DomainsService) SetRegistrantProfile(ctx context.Context, fields ContactFields) (*Contact, error) {
	answer, err := service.client.send(ctx, request{method: http.MethodPut, path: "/v1/domains/registrant-profile", body: fields})
	if err != nil {
		return nil, err
	}
	return decodeProfile(http.MethodPut, answer.body)
}

// AdminList returns every domain of the reseller account with its owner
// organization (platform admins, dashboard session).
func (service *DomainsService) AdminList(ctx context.Context) ([]AdminDomain, error) {
	var domains []AdminDomain
	err := service.client.do(ctx, request{method: http.MethodGet, path: "/v1/admin/domains"}, &domains)
	return domains, err
}

// AdminAssign attaches an unassigned domain of the reseller account to an
// organization, then syncs it (platform admins, dashboard session).
func (service *DomainsService) AdminAssign(ctx context.Context, name, orgID string) (*Domain, error) {
	answer, err := service.client.send(ctx, request{
		method: http.MethodPost, path: pathf("/v1/admin/domains/%s/assign", NormalizeZoneName(name)),
		body: map[string]string{"orgId": orgID},
	})
	if err != nil {
		return nil, err
	}
	result, err := decodeMutation(http.MethodPost, "/v1/admin/domains/{name}/assign", answer.body)
	if err != nil {
		return nil, err
	}
	return &result.Domain, nil
}

// WaitTransferOptions controls WaitTransfer.
type WaitTransferOptions struct {
	// Interval between polls (default 1 minute; the registrar is slow and
	// the platform polls pending transfers every 15 minutes anyway).
	Interval time.Duration
	// Sync asks the registrar on every poll (Sync, editors) instead of
	// reading the last synced state (TransferStatus).
	Sync bool
}

// WaitTransfer polls a transfer until it is no longer pending. It returns
// the last status; a failed transfer returns an error wrapping
// ErrTransferFailed with the registrar's detail. Bound the wait with the
// context.
func (service *DomainsService) WaitTransfer(ctx context.Context, name string, options WaitTransferOptions) (*DomainTransferStatus, error) {
	interval := options.Interval
	if interval <= 0 {
		interval = time.Minute
	}
	for {
		status, err := service.pollTransfer(ctx, name, options.Sync)
		if err != nil {
			return nil, err
		}
		if status.Failed() {
			detail := "no detail"
			if status.Transfer != nil && status.Transfer.Detail != "" {
				detail = status.Transfer.Detail
			}
			return status, fmt.Errorf("%s: %w: %s", status.Name, ErrTransferFailed, detail)
		}
		if !status.Pending() {
			return status, nil
		}
		if err := service.client.sleep(ctx, interval); err != nil {
			return status, err
		}
	}
}

// pollTransfer reads the transfer progress, from the registrar when sync is
// set.
func (service *DomainsService) pollTransfer(ctx context.Context, name string, sync bool) (*DomainTransferStatus, error) {
	if !sync {
		return service.TransferStatus(ctx, name)
	}
	result, err := service.Sync(ctx, name)
	if err != nil {
		return nil, err
	}
	return &DomainTransferStatus{Name: result.Domain.Name, Status: result.Domain.Status, Transfer: result.Domain.Transfer}, nil
}

// mutate sends a registrar mutation and decodes its result.
func (service *DomainsService) mutate(ctx context.Context, method, path string, body any) (*DomainMutationResult, error) {
	call := request{method: method, path: path}
	if body != nil {
		call.body = body
	}
	answer, err := service.client.send(ctx, call)
	if err != nil {
		return nil, err
	}
	return decodeMutation(method, path, answer.body)
}

// decodeMutation decodes {domain, job}; a bare domain (routes that only
// return the domain) becomes a result with a done job.
func decodeMutation(method, path string, body []byte) (*DomainMutationResult, error) {
	var envelope struct {
		Domain *Domain    `json:"domain"`
		Job    *DomainJob `json:"job"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("%s %s: decode response: %w", method, path, err)
	}
	if envelope.Domain != nil {
		result := &DomainMutationResult{Domain: *envelope.Domain, Job: DomainJob{Status: JobStatusDone}}
		if envelope.Job != nil {
			result.Job = *envelope.Job
		}
		return result, nil
	}
	var domain Domain
	if err := json.Unmarshal(body, &domain); err != nil {
		return nil, fmt.Errorf("%s %s: decode response: %w", method, path, err)
	}
	return &DomainMutationResult{Domain: domain, Job: DomainJob{Status: JobStatusDone}}, nil
}

// decodeProfile decodes {profile: Contact|null}, or a bare contact.
func decodeProfile(method string, body []byte) (*Contact, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("%s /v1/domains/registrant-profile: decode response: %w", method, err)
	}
	raw, wrapped := envelope["profile"]
	if !wrapped {
		raw = body
	}
	if string(raw) == "null" {
		return nil, nil
	}
	var contact Contact
	if err := json.Unmarshal(raw, &contact); err != nil {
		return nil, fmt.Errorf("%s /v1/domains/registrant-profile: decode response: %w", method, err)
	}
	return &contact, nil
}

// domainPath builds /v1/domains/{name}{suffix} with the normalized name.
func domainPath(name, suffix string) string {
	return pathf("/v1/domains/%s", NormalizeZoneName(name)) + suffix
}
