package redundantdns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// LicensesService reads the licenses of self-hosted installations: the
// caller's organizations' licenses (List, Download) and, for platform
// admins, issuing and managing them (Admin*). API docs "Licenses".
type LicensesService struct{ client *Client }

// License statuses (the operator's standing of a license).
const (
	LicenseActive    = "active"
	LicenseSuspended = "suspended"
	LicenseRevoked   = "revoked"
)

// License modes and terms.
const (
	LicenseModeOnline  = "online"
	LicenseModeOffline = "offline"
	LicenseTermMonthly = "monthly"
	LicenseTermYearly  = "yearly"
)

// LicenseLimits are the limits a license grants (0 = the edition's
// default).
type LicenseLimits struct {
	Zones      int `json:"zones"`
	Providers  int `json:"providers"`
	DataPlanes int `json:"dataPlanes"`
}

// LicenseAttestation is what the platform publishes for an online
// license. State is "ok" or why not (attestation_zone_missing,
// attestation_not_found, attestation_expired...).
type LicenseAttestation struct {
	State     string     `json:"state"`
	Standing  string     `json:"standing,omitempty"`
	IssuedAt  *time.Time `json:"issuedAt,omitempty"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
}

// License is a license of one of the caller's organizations (never the
// signed token: see Download).
type License struct {
	LID             string              `json:"lid"`
	OrgID           string              `json:"orgId"`
	Status          string              `json:"status"`
	Product         string              `json:"product"`
	Edition         string              `json:"edition"`
	Mode            string              `json:"mode"`
	Term            string              `json:"term,omitempty"`
	Features        []string            `json:"features"`
	Limits          LicenseLimits       `json:"limits"`
	GraceDays       int                 `json:"graceDays"`
	IssuedAt        *time.Time          `json:"issuedAt,omitempty"`
	NotBefore       *time.Time          `json:"notBefore,omitempty"`
	ExpiresAt       time.Time           `json:"expiresAt"`
	StatusChangedAt time.Time           `json:"statusChangedAt"`
	Attestation     *LicenseAttestation `json:"attestation,omitempty"`
}

// LicenseFile is a signed license to install on a self-hosted
// installation. Token is a secret; Filename is the suggested file name
// ("<lid>.license").
type LicenseFile struct {
	LID      string `json:"lid"`
	Token    string `json:"token"`
	Filename string `json:"filename,omitempty"`
}

// LicenseClaims are the signed contents of a license (AdminIssue input and
// AdminLicense.Claims). Only Acct is required on issue; the server fills
// the defaults (lid generated, product rdns-enterprise, edition
// enterprise, mode offline, term yearly, nbf/iat now, exp one term later).
// AcctHash and KID are always set by the server.
type LicenseClaims struct {
	LID       string        `json:"lid,omitempty"`
	Acct      string        `json:"acct"`
	AcctHash  string        `json:"acctHash,omitempty"`
	Product   string        `json:"product,omitempty"`
	Edition   string        `json:"edition,omitempty"`
	Mode      string        `json:"mode,omitempty"`
	Features  []string      `json:"features,omitempty"`
	Limits    LicenseLimits `json:"limits"`
	IssuedAt  *time.Time    `json:"iat,omitempty"`
	NotBefore *time.Time    `json:"nbf,omitempty"`
	Expires   *time.Time    `json:"exp,omitempty"`
	Term      string        `json:"term,omitempty"`
	// Grace is in days (nil: the term's default).
	Grace *int `json:"grace,omitempty"`
	// Bind is the hex SHA-256 of the installation id when the license is
	// bound to one installation.
	Bind string `json:"bind,omitempty"`
	KID  string `json:"kid,omitempty"`
}

// AdminLicense is a license as platform admins see it (without the token).
type AdminLicense struct {
	LID             string        `json:"lid"`
	Acct            string        `json:"acct"`
	AcctHash        string        `json:"acctHash"`
	Status          string        `json:"status"`
	Claims          LicenseClaims `json:"claims"`
	AttestationName string        `json:"attestationName,omitempty"`
	CreatedAt       time.Time     `json:"createdAt"`
	CreatedBy       string        `json:"createdBy,omitempty"`
	UpdatedAt       time.Time     `json:"updatedAt"`
	UpdatedBy       string        `json:"updatedBy,omitempty"`
	StatusChangedAt time.Time     `json:"statusChangedAt"`
}

// AdminLicenseResult is the answer of AdminIssue and AdminSetStatus. Token
// is set by AdminIssue only (a secret). For an online license the platform
// publishes its attestation at once: Published says whether it could
// (nil for offline licenses, or a status call that changed nothing), with
// PublishError when not (the hourly pass catches up) and Publish the data
// plane's report.
type AdminLicenseResult struct {
	License      AdminLicense    `json:"license"`
	Token        string          `json:"token,omitempty"`
	Published    *bool           `json:"published,omitempty"`
	PublishError string          `json:"publishError,omitempty"`
	Publish      json.RawMessage `json:"publish,omitempty"`
}

// List returns the licenses of the caller's organizations (a token: its
// own organization's; zones:read).
func (service *LicensesService) List(ctx context.Context) ([]License, error) {
	licenses := []License{}
	err := service.client.do(ctx, request{method: http.MethodGet, path: "/v1/me/licenses"}, &licenses)
	return licenses, err
}

// Download returns the signed license file (owners of the licensed
// organization; 10 per hour per user, 429 too_many_requests after). It is
// audited as license.token.download. 404 licenseNotFound for another
// organization's license, 403 forbidden for non-owners.
func (service *LicensesService) Download(ctx context.Context, lid string) (*LicenseFile, error) {
	var file LicenseFile
	if err := service.client.do(ctx, request{method: http.MethodGet, path: pathf("/v1/me/licenses/%s/token", strings.TrimSpace(lid))}, &file); err != nil {
		return nil, err
	}
	if file.Filename == "" {
		file.Filename = file.LID + ".license"
	}
	return &file, nil
}

// AdminList returns every license (platform admins), or one organization's
// when acct is not empty.
func (service *LicensesService) AdminList(ctx context.Context, acct string) ([]AdminLicense, error) {
	query := url.Values{}
	if acct = strings.TrimSpace(acct); acct != "" {
		query.Set("acct", acct)
	}
	licenses := []AdminLicense{}
	err := service.client.do(ctx, request{method: http.MethodGet, path: "/v1/admin/licenses", query: query}, &licenses)
	return licenses, err
}

// AdminIssue issues a license to the organization claims.Acct (platform
// admins). Errors: 404 orgNotFound, 400 invalidClaims, 409 licenseExists,
// 503 license_issuer_unavailable (no signing key on the control plane).
func (service *LicensesService) AdminIssue(ctx context.Context, claims LicenseClaims) (*AdminLicenseResult, error) {
	claims.Acct = strings.TrimSpace(claims.Acct)
	body := map[string]LicenseClaims{"claims": claims}
	var result AdminLicenseResult
	if err := service.client.do(ctx, request{method: http.MethodPost, path: "/v1/admin/licenses", body: body}, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// AdminSetStatus sets a license's status: LicenseActive, LicenseSuspended
// (the installation degrades after its grace period) or LicenseRevoked
// (degrades at once). The same status again changes nothing. Errors: 400
// invalidLicenseStatus, 404 licenseNotFound.
func (service *LicensesService) AdminSetStatus(ctx context.Context, lid, status string) (*AdminLicenseResult, error) {
	body := map[string]string{"status": strings.TrimSpace(status)}
	var result AdminLicenseResult
	path := pathf("/v1/admin/licenses/%s/status", strings.TrimSpace(lid))
	if err := service.client.do(ctx, request{method: http.MethodPost, path: path, body: body}, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// AdminToken reveals the signed license to hand to the customer (platform
// admins; audited as license.token.reveal).
func (service *LicensesService) AdminToken(ctx context.Context, lid string) (*LicenseFile, error) {
	var file LicenseFile
	if err := service.client.do(ctx, request{method: http.MethodGet, path: pathf("/v1/admin/licenses/%s/token", strings.TrimSpace(lid))}, &file); err != nil {
		return nil, err
	}
	if file.Filename == "" {
		file.Filename = file.LID + ".license"
	}
	return &file, nil
}
