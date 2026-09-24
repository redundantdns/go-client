package redundantdns

import (
	"encoding/json"
	"time"
)

// Domain statuses (Domain.Status).
const (
	DomainStatusActive          = "active"
	DomainStatusTransferPending = "transfer_pending"
	DomainStatusTransferFailed  = "transfer_failed"
	// DomainStatusPending: a registration or a change is in progress at the
	// registry.
	DomainStatusPending = "pending"
	DomainStatusExpired = "expired"
	DomainStatusDeleted = "deleted"
	// DomainStatusUnknown: not synced with the registrar yet.
	DomainStatusUnknown = "unknown"
)

// Transfer states (DomainTransfer.State).
const (
	TransferStatePending   = "pending"
	TransferStateCompleted = "completed"
	TransferStateFailed    = "failed"
)

// Registrar job statuses (DomainJob.Status).
const (
	JobStatusDone    = "done"
	JobStatusQueued  = "queued"
	JobStatusRunning = "running"
	JobStatusFailed  = "failed"
)

// Registrar job operations (DomainJob.Op).
const (
	DomainOpTransfer    = "transfer"
	DomainOpNameservers = "nameservers"
	DomainOpLock        = "lock"
	DomainOpAutoRenew   = "autorenew"
	DomainOpRenew       = "renew"
	DomainOpRegistrant  = "registrant"
)

// Domain is a domain held at the platform's registrar (reseller) account on
// behalf of the organization, which is its registrant.
type Domain struct {
	// Name is the domain, lowercase without a trailing dot.
	Name string `json:"name"`
	// Registrar is the registrar id, for example "openprovider".
	Registrar string `json:"registrar"`
	// RegistrarDomainID is the domain's id at the registrar.
	RegistrarDomainID FlexString `json:"registrarDomainId,omitempty"`
	// Status is one of the DomainStatus* values.
	Status    string     `json:"status"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	AutoRenew bool       `json:"autoRenew"`
	// Locked is the registrar transfer lock.
	Locked      bool     `json:"locked"`
	Nameservers []string `json:"nameservers"`
	// Contacts are the registrar contact handles per role.
	Contacts DomainContacts `json:"contacts"`
	// OwnerContactID is the organization contact used as the registrant.
	OwnerContactID string `json:"ownerContactId,omitempty"`
	// Registrant is a snapshot of the owner contact when last applied.
	Registrant *Contact `json:"registrant,omitempty"`
	// Transfer is nil for a domain that was not transferred in.
	Transfer *DomainTransfer `json:"transfer,omitempty"`
	// Zone is set when the organization has a zone with the same name.
	Zone *DomainZoneLink `json:"zone,omitempty"`
	// PendingJobs are the registrar mutations not done yet (queued, running
	// or failed).
	PendingJobs []DomainJob `json:"pendingJobs,omitempty"`
	LastSyncAt  *time.Time  `json:"lastSyncAt,omitempty"`
	LastError   string      `json:"lastError,omitempty"`
	CreatedAt   time.Time   `json:"createdAt"`
	UpdatedAt   time.Time   `json:"updatedAt"`
}

// DomainContacts are the registrar contact handles of a domain.
type DomainContacts struct {
	Owner   string `json:"owner,omitempty"`
	Admin   string `json:"admin,omitempty"`
	Tech    string `json:"tech,omitempty"`
	Billing string `json:"billing,omitempty"`
}

// DomainTransfer is the progress of a transfer in.
type DomainTransfer struct {
	// State is one of the TransferState* values.
	State       string     `json:"state"`
	RequestedAt *time.Time `json:"requestedAt,omitempty"`
	CompletedAt *time.Time `json:"completedAt,omitempty"`
	// Detail explains a failed transfer.
	Detail string `json:"detail,omitempty"`
	// ApplyZoneNS writes the NS plan of the organization's zone with the
	// same name when the transfer completes.
	ApplyZoneNS bool     `json:"applyZoneNs"`
	Nameservers []string `json:"nameservers,omitempty"`
}

// DomainZoneLink relates a domain to the organization's zone of the same
// name.
type DomainZoneLink struct {
	ZoneID string   `json:"zoneId"`
	Name   string   `json:"name"`
	NSPlan []string `json:"nsPlan"`
	// NameserversMatch compares the domain's nameservers with the zone's NS
	// plan (as sets, case-insensitive).
	NameserversMatch bool `json:"nameserversMatch"`
	// DelegationState is the zone's last delegation check.
	DelegationState string `json:"delegationState,omitempty"`
}

// DomainJob is one registrar mutation of a domain.
type DomainJob struct {
	JobID string `json:"jobId,omitempty"`
	// Op is one of the DomainOp* values.
	Op string `json:"op,omitempty"`
	// Status is one of the JobStatus* values.
	Status    string     `json:"status"`
	Attempts  int        `json:"attempts,omitempty"`
	LastError string     `json:"lastError,omitempty"`
	CreatedAt *time.Time `json:"createdAt,omitempty"`
}

// DomainMutationResult is the answer of the routes that change a domain at
// the registrar: the domain after the change and the job. Job.Status is
// JobStatusDone when the registrar applied it, JobStatusQueued when it is
// retried later (HTTP 202).
type DomainMutationResult struct {
	Domain Domain    `json:"domain"`
	Job    DomainJob `json:"job"`
}

// Queued reports whether the registrar did not apply the change yet (it is
// retried with backoff).
func (result *DomainMutationResult) Queued() bool {
	return result.Job.Status == JobStatusQueued || result.Job.Status == JobStatusRunning
}

// DomainTransferCreate is the body of Domains.TransferIn.
type DomainTransferCreate struct {
	Name string `json:"name"`
	// AuthCode is the transfer authorization (EPP) code from the losing
	// registrar.
	AuthCode string `json:"authCode"`
	// ContactID is the registrant (default: the registrant profile).
	ContactID string `json:"contactId,omitempty"`
	// Nameservers are set in the transfer (empty keeps the current ones, so
	// there is no downtime).
	Nameservers []string `json:"nameservers,omitempty"`
	// ApplyZoneNS writes the NS plan of the organization's zone with the
	// same name when the transfer completes.
	ApplyZoneNS bool `json:"applyZoneNs,omitempty"`
	// AutoRenew sets auto-renewal (nil = the server default). Use Bool.
	AutoRenew *bool `json:"autoRenew,omitempty"`
	// AcceptDomainTerms accepts the Domain Registration Terms of this
	// version for the organization before the transfer, recorded like
	// Legal.AcceptDomain.
	AcceptDomainTerms string `json:"acceptDomainTerms,omitempty"`
}

// DomainTransferStatus is the answer of Domains.TransferStatus.
type DomainTransferStatus struct {
	Name     string          `json:"name"`
	Status   string          `json:"status"`
	Transfer *DomainTransfer `json:"transfer"`
}

// Pending reports whether the transfer is still in progress.
func (status *DomainTransferStatus) Pending() bool {
	if status.Transfer != nil {
		return status.Transfer.State == TransferStatePending
	}
	return status.Status == DomainStatusTransferPending
}

// Failed reports whether the transfer failed.
func (status *DomainTransferStatus) Failed() bool {
	if status.Transfer != nil {
		return status.Transfer.State == TransferStateFailed
	}
	return status.Status == DomainStatusTransferFailed
}

// DomainAuthCode is the transfer-out authorization code of a domain. It is
// fetched from the registrar and never stored by the platform.
type DomainAuthCode struct {
	Name     string `json:"name"`
	AuthCode string `json:"authCode"`
}

// ContactFields are the editable fields of a contact. Required by the API:
// FirstName, LastName, Email, Phone (EPP style, "+<country code>.<number>"),
// Street, City, PostalCode and Country (ISO 3166-1 alpha-2).
type ContactFields struct {
	Label       string `json:"label,omitempty"`
	CompanyName string `json:"companyName,omitempty"`
	FirstName   string `json:"firstName"`
	LastName    string `json:"lastName"`
	Email       string `json:"email"`
	Phone       string `json:"phone"`
	Street      string `json:"street"`
	HouseNumber string `json:"houseNumber,omitempty"`
	City        string `json:"city"`
	State       string `json:"state,omitempty"`
	PostalCode  string `json:"postalCode"`
	Country     string `json:"country"`
	TaxID       string `json:"taxId,omitempty"`
}

// Contact is a registrant contact of the organization.
type Contact struct {
	ContactID string `json:"contactId"`
	// Default marks the registrant profile: the owner of every domain
	// transferred in unless another contact is chosen.
	Default bool `json:"default"`
	ContactFields
	// Handles are the registrar contact handles created for it (read-only),
	// by registrar id.
	Handles   map[string]string `json:"handles,omitempty"`
	CreatedAt time.Time         `json:"createdAt"`
	UpdatedAt time.Time         `json:"updatedAt"`
}

// DomainExport is everything the organization holds in the domains module:
// contacts, domains and the zone files of its zones.
type DomainExport struct {
	ExportedAt time.Time `json:"exportedAt"`
	// Org describes the organization (kept as sent by the server).
	Org      json.RawMessage `json:"org,omitempty"`
	Contacts []Contact       `json:"contacts"`
	Domains  []Domain        `json:"domains"`
	Zones    []ExportedZone  `json:"zones"`
}

// ExportedZone is one zone of an export, as an RFC 1035 zone file.
type ExportedZone struct {
	ZoneID   string `json:"zoneId"`
	Name     string `json:"name"`
	ZoneFile string `json:"zoneFile"`
}

// AdminDomain is a domain of the reseller account as the platform admin
// sees it (OrgID empty: not assigned to an organization).
type AdminDomain struct {
	Name              string     `json:"name"`
	Registrar         string     `json:"registrar"`
	RegistrarDomainID FlexString `json:"registrarDomainId,omitempty"`
	Status            string     `json:"status"`
	ExpiresAt         *time.Time `json:"expiresAt,omitempty"`
	AutoRenew         bool       `json:"autoRenew"`
	Locked            bool       `json:"locked"`
	Nameservers       []string   `json:"nameservers"`
	OrgID             string     `json:"orgId"`
	OrgName           string     `json:"orgName,omitempty"`
}
