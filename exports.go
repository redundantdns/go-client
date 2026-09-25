package redundantdns

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ExportsService builds and downloads the organization export bundle
// (rdns.orgbundle.v1), the exit guarantee: the whole organization, secrets
// included, sealed under a passphrase (API docs "Org export"). Owners only
// (connections:write for tokens); never refused by the plan, the billing
// state or a degraded license. Restore a bundle with `rdns import-org`.
//
// The routes name the organization in the path: the client's WithOrg, else
// the caller's only organization (a token belongs to one).
type ExportsService struct{ client *Client }

// MinExportPassphrase is the shortest passphrase the server accepts.
const MinExportPassphrase = 12

// Export states.
const (
	ExportQueued = "queued"
	ExportReady  = "ready"
	ExportFailed = "failed"
)

// ErrExportNotReady is returned by Exports.Download while the export is
// queued or failed.
var ErrExportNotReady = errors.New("the export is not ready")

// OrgExport is an org export job. A ready export carries a one-time
// download link (DownloadPath, and DownloadURL when the server knows its
// public URL), replaced on every Status call; exports expire 24 hours
// after they are ready (410 exportExpired).
type OrgExport struct {
	JobID          string     `json:"jobId"`
	OrgID          string     `json:"orgId"`
	Status         string     `json:"status"`
	RequestedAt    time.Time  `json:"requestedAt"`
	ReadyAt        *time.Time `json:"readyAt,omitempty"`
	ExpiresAt      *time.Time `json:"expiresAt,omitempty"`
	Size           int64      `json:"size,omitempty"`
	SHA256         string     `json:"sha256,omitempty"`
	Files          int        `json:"files,omitempty"`
	Zones          int        `json:"zones,omitempty"`
	Stripped       int        `json:"stripped,omitempty"`
	Error          string     `json:"error,omitempty"`
	Downloads      int        `json:"downloads"`
	LastDownloadAt *time.Time `json:"lastDownloadAt,omitempty"`
	DownloadPath   string     `json:"downloadPath,omitempty"`
	DownloadURL    string     `json:"downloadUrl,omitempty"`
}

// Request queues the export of the organization, sealed with passphrase
// (at least MinExportPassphrase characters; keep it: the bundle cannot be
// opened without it). Errors: 400 passphraseInvalid, 409 exportInProgress
// while one is queued. Poll Status until ExportReady, then Download.
func (service *ExportsService) Request(ctx context.Context, passphrase string) (*OrgExport, error) {
	if len([]rune(passphrase)) < MinExportPassphrase {
		return nil, fmt.Errorf("export: the passphrase needs at least %d characters", MinExportPassphrase)
	}
	orgID, err := service.client.resolveOrg(ctx)
	if err != nil {
		return nil, err
	}
	body := map[string]string{"passphrase": passphrase}
	return service.export(ctx, request{method: http.MethodPost, path: pathf("/v1/orgs/%s/export", orgID), body: body})
}

// Status returns an export. A ready export gets a new one-time download
// link on every call (the previous one stops working).
func (service *ExportsService) Status(ctx context.Context, jobID string) (*OrgExport, error) {
	orgID, err := service.client.resolveOrg(ctx)
	if err != nil {
		return nil, err
	}
	return service.export(ctx, request{method: http.MethodGet, path: pathf("/v1/orgs/%s/exports/%s", orgID, strings.TrimSpace(jobID))})
}

// Download fetches a fresh one-time link (Status) and streams the bundle
// (a tar; Download.SHA256 is the digest to check). It answers
// ErrExportNotReady while the export is queued or failed. The link is
// always followed on the client's base URL, and never retried: it works
// once.
func (service *ExportsService) Download(ctx context.Context, jobID string) (*Download, error) {
	export, err := service.Status(ctx, jobID)
	if err != nil {
		return nil, err
	}
	if export.Status != ExportReady || export.DownloadPath == "" {
		detail := export.Status
		if export.Error != "" {
			detail += ": " + export.Error
		}
		return nil, fmt.Errorf("export %s is %s: %w", export.JobID, detail, ErrExportNotReady)
	}
	link, err := url.Parse(export.DownloadPath)
	if err != nil || link.IsAbs() || !strings.HasPrefix(link.Path, "/") {
		return nil, fmt.Errorf("export %s: unexpected download path %q", export.JobID, export.DownloadPath)
	}
	download, err := service.client.stream(ctx, request{method: http.MethodGet, path: link.EscapedPath(), query: link.Query(), accept: "application/x-tar, application/json"}, false)
	if err != nil {
		return nil, err
	}
	if download.SHA256 == "" {
		download.SHA256 = export.SHA256
	}
	return download, nil
}

func (service *ExportsService) export(ctx context.Context, call request) (*OrgExport, error) {
	var answer struct {
		Export OrgExport `json:"export"`
	}
	if err := service.client.do(ctx, call, &answer); err != nil {
		return nil, err
	}
	return &answer.Export, nil
}

// resolveOrg returns the organization of the client: WithOrg, else the
// caller's only organization.
func (client *Client) resolveOrg(ctx context.Context) (string, error) {
	if client.orgID != "" {
		return client.orgID, nil
	}
	orgs, err := client.Account.Orgs(ctx)
	if err != nil {
		return "", err
	}
	if len(orgs) != 1 {
		return "", fmt.Errorf("the caller has %d organizations: pick one with WithOrg", len(orgs))
	}
	return orgs[0].OrgID, nil
}
