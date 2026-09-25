package redundantdns

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ComplianceService answers "are we compliant right now?": a profile runs
// its controls against the live state (API docs "Compliance"). Org admins
// (zones:read for tokens) run the organization's controls
// (ComplianceScopeOrg, the default); platform admins, with a dashboard
// session, the installation's (ComplianceScopePlatform).
type ComplianceService struct{ client *Client }

// Built-in compliance profiles (an operator may load more).
const (
	ComplianceBaseline = "baseline"
	ComplianceISO27001 = "iso27001"
	ComplianceSOC2     = "soc2"
)

// Compliance scopes.
const (
	ComplianceScopeOrg      = "org"
	ComplianceScopePlatform = "platform"
)

// Control and report statuses. A report's status is its worst control;
// a warning never makes a profile fail.
const (
	CompliancePass          = "pass"
	ComplianceWarn          = "warn"
	ComplianceFail          = "fail"
	ComplianceNotApplicable = "not_applicable"
)

// ComplianceEvidence is one fact a control looked at.
type ComplianceEvidence struct {
	Name  string     `json:"name"`
	Value any        `json:"value"`
	At    *time.Time `json:"at,omitempty"`
}

// ComplianceMapping names the clauses a control evidences.
type ComplianceMapping struct {
	ISO27001 string `json:"iso27001,omitempty"`
	SOC2     string `json:"soc2,omitempty"`
}

// ComplianceControl is one control of a report.
type ComplianceControl struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status"`
	// Required controls fail the profile; the others only warn.
	Required    bool                 `json:"required,omitempty"`
	Evidence    []ComplianceEvidence `json:"evidence"`
	Mapping     ComplianceMapping    `json:"mapping"`
	Remediation string               `json:"remediation,omitempty"`
}

// ComplianceSummary counts the controls by status.
type ComplianceSummary struct {
	Pass          int `json:"pass"`
	Warn          int `json:"warn"`
	Fail          int `json:"fail"`
	NotApplicable int `json:"notApplicable"`
}

// ComplianceReport is the outcome of a profile.
type ComplianceReport struct {
	Format       string              `json:"format"`
	Profile      string              `json:"profile"`
	ProfileTitle string              `json:"profileTitle"`
	Scope        string              `json:"scope"`
	OrgID        string              `json:"orgId,omitempty"`
	Status       string              `json:"status"`
	CheckedAt    time.Time           `json:"checkedAt"`
	Summary      ComplianceSummary   `json:"summary"`
	Controls     []ComplianceControl `json:"controls"`
}

// ExitCode maps the report status to the exit code of `rdns compliance`
// and `rdnsctl compliance`: 0 pass, 1 warn, 2 fail.
func (report *ComplianceReport) ExitCode() int {
	switch report.Status {
	case ComplianceFail:
		return 2
	case ComplianceWarn:
		return 1
	}
	return 0
}

// Report runs a profile now, read only ("" = the server default,
// baseline; scope "" = the organization). Errors: 400 unknownProfile
// (details.profiles lists the loaded ones), 400 invalidScope, 503
// complianceUnavailable.
func (service *ComplianceService) Report(ctx context.Context, profile, scope string) (*ComplianceReport, error) {
	query := complianceQuery(scope)
	if profile = strings.TrimSpace(profile); profile != "" {
		query.Set("profile", profile)
	}
	var report ComplianceReport
	if err := service.client.do(ctx, request{method: http.MethodGet, path: "/v1/compliance", query: query}, &report); err != nil {
		return nil, err
	}
	return &report, nil
}

// Run runs a profile and records it: an audit entry (compliance.run), a
// line in the audit stream with each control's status and the report's
// hash, and the last report (Last). Allowed while the license is degraded.
func (service *ComplianceService) Run(ctx context.Context, profile, scope string) (*ComplianceReport, error) {
	body := map[string]string{"profile": strings.TrimSpace(profile)}
	var report ComplianceReport
	if err := service.client.do(ctx, request{method: http.MethodPost, path: "/v1/compliance/run", query: complianceQuery(scope), body: body}, &report); err != nil {
		return nil, err
	}
	return &report, nil
}

// Last returns the last recorded report (the daily check or the last Run),
// nil before the first.
func (service *ComplianceService) Last(ctx context.Context, scope string) (*ComplianceReport, error) {
	var answer struct {
		Report *ComplianceReport `json:"report"`
	}
	if err := service.client.do(ctx, request{method: http.MethodGet, path: "/v1/compliance/last", query: complianceQuery(scope)}, &answer); err != nil {
		return nil, err
	}
	return answer.Report, nil
}

func complianceQuery(scope string) url.Values {
	query := url.Values{}
	if scope = strings.TrimSpace(scope); scope != "" {
		query.Set("scope", scope)
	}
	return query
}
