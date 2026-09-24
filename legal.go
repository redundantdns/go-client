package redundantdns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// LegalService reads and records the organization's acceptance of the
// Managed Provider Terms and Acceptable Use Policy, required before using
// managed (platform-owned) provider accounts, and of the Domain
// Registration Terms, required before changing domains. The user-level Terms of
// Service and Privacy Policy are in AccountService (Legal, AcceptLegal).
type LegalService struct{ client *Client }

// ManagedTermsStatus is the organization's state for the Managed Provider
// Terms and Acceptable Use Policy.
type ManagedTermsStatus struct {
	// Current is the current version (YYYY-MM-DD).
	Current string `json:"current"`
	// Accepted is the organization's last acceptance (nil when never).
	Accepted *ManagedTermsAcceptance `json:"accepted"`
	// Required is true while the current version is not accepted: creating
	// or attaching a managed connection answers ErrManagedTermsRequired.
	Required bool `json:"required"`
	// URL is where the text can be read.
	URL string `json:"url,omitempty"`
}

// ManagedTermsAcceptance records who accepted which version.
type ManagedTermsAcceptance struct {
	Version    string    `json:"version"`
	AcceptedAt time.Time `json:"acceptedAt"`
	UserID     string    `json:"userId,omitempty"`
	IP         string    `json:"ip,omitempty"`
}

// ManagedStatus returns the organization's acceptance state.
func (service *LegalService) ManagedStatus(ctx context.Context) (*ManagedTermsStatus, error) {
	var status ManagedTermsStatus
	if err := service.client.do(ctx, request{method: http.MethodGet, path: "/v1/legal/managed"}, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

// AcceptManaged accepts the given version, which must be the current one
// (409 legalVersionMismatch otherwise), for the whole organization (org
// admins). The acceptance is recorded with the user, IP and time and
// written to the audit log.
func (service *LegalService) AcceptManaged(ctx context.Context, version string) (*ManagedTermsStatus, error) {
	var status ManagedTermsStatus
	body := map[string]string{"version": strings.TrimSpace(version)}
	if err := service.client.do(ctx, request{method: http.MethodPost, path: "/v1/legal/managed/accept", body: body}, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

// ManagedTermsRequirement is what a 428 managed_terms_required answer
// carries in its details: the version to accept and where to read it.
type ManagedTermsRequirement struct {
	Version string `json:"version"`
	URL     string `json:"url"`
}

// ManagedTermsRequired returns the version and URL of the terms when err is
// a managed_terms_required answer (ok is false otherwise). The URL may be
// empty when the server sent none.
func ManagedTermsRequired(err error) (requirement ManagedTermsRequirement, ok bool) {
	return termsRequirement(err, CodeManagedTermsRequired)
}

// DomainTermsStatus is the organization's state for the Domain
// Registration Terms (same shape as the managed terms status).
type DomainTermsStatus = ManagedTermsStatus

// DomainTermsRequirement is what a 428 domain_terms_required answer carries
// in its details: the version to accept and where to read it.
type DomainTermsRequirement = ManagedTermsRequirement

// DomainTermsRequired returns the version and URL of the Domain
// Registration Terms when err is a domain_terms_required answer (ok is
// false otherwise). The URL may be empty when the server sent none.
func DomainTermsRequired(err error) (requirement DomainTermsRequirement, ok bool) {
	return termsRequirement(err, CodeDomainTermsRequired)
}

// DomainStatus returns the organization's acceptance of the Domain
// Registration Terms.
func (service *LegalService) DomainStatus(ctx context.Context) (*DomainTermsStatus, error) {
	var status DomainTermsStatus
	if err := service.client.do(ctx, request{method: http.MethodGet, path: "/v1/legal/domains"}, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

// AcceptDomain accepts the given version of the Domain Registration Terms,
// which must be the current one (409 legalVersionMismatch otherwise), for
// the whole organization (org admins). The acceptance is audited.
func (service *LegalService) AcceptDomain(ctx context.Context, version string) (*DomainTermsStatus, error) {
	var status DomainTermsStatus
	body := map[string]string{"version": strings.TrimSpace(version)}
	if err := service.client.do(ctx, request{method: http.MethodPost, path: "/v1/legal/domains/accept", body: body}, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

// termsRequirement decodes the {version, url} details of a terms answer
// with the given code.
func termsRequirement(err error, code string) (requirement ManagedTermsRequirement, ok bool) {
	var apiError *APIError
	if !errors.As(err, &apiError) || apiError.Code != code {
		return ManagedTermsRequirement{}, false
	}
	if len(apiError.Details) > 0 {
		var details struct {
			ManagedTermsRequirement
			DocURL string `json:"docUrl"`
		}
		if json.Unmarshal(apiError.Details, &details) == nil {
			requirement = details.ManagedTermsRequirement
			if requirement.URL == "" {
				requirement.URL = details.DocURL
			}
		}
	}
	return requirement, true
}

// ParentDelegation describes the NS delegation the platform manages for a
// zone inside a parent zone of the same organization.
type ParentDelegation struct {
	// Enabled is true while the platform writes the delegation.
	Enabled        bool   `json:"enabled"`
	ParentZoneID   string `json:"parentZoneId,omitempty"`
	ParentZoneName string `json:"parentZoneName,omitempty"`
}

// UnmarshalJSON accepts the object form and a bare boolean.
func (delegation *ParentDelegation) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if bytes.Equal(trimmed, []byte("true")) || bytes.Equal(trimmed, []byte("false")) {
		*delegation = ParentDelegation{Enabled: bytes.Equal(trimmed, []byte("true"))}
		return nil
	}
	type plain ParentDelegation
	var decoded plain
	if err := json.Unmarshal(trimmed, &decoded); err != nil {
		return fmt.Errorf("parentDelegation: %w", err)
	}
	*delegation = ParentDelegation(decoded)
	return nil
}

// FlexString is a string that also decodes from a JSON number (identifiers
// such as the IANA registrar id come either way).
type FlexString string

// UnmarshalJSON accepts a string, a number or null.
func (value *FlexString) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if bytes.Equal(trimmed, []byte("null")) {
		*value = ""
		return nil
	}
	if len(trimmed) > 0 && trimmed[0] == '"' {
		var text string
		if err := json.Unmarshal(trimmed, &text); err != nil {
			return err
		}
		*value = FlexString(text)
		return nil
	}
	var number json.Number
	if err := json.Unmarshal(trimmed, &number); err != nil {
		return fmt.Errorf("expected a string or a number: %w", err)
	}
	*value = FlexString(number.String())
	return nil
}
