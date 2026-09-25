package redundantdns

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// The audit stream (API docs "Audit stream"): every audit entry and zone
// journal entry is also appended to the organization's hash-chained,
// sealed stream. Org admins (zones:read for tokens) verify it and download
// the evidence bundle for an auditor. Without an audit stream on the
// deployment both answer 503 auditStreamUnavailable.

// AuditStreamProblem is a verification finding.
type AuditStreamProblem struct {
	Org     string `json:"org"`
	Day     string `json:"day,omitempty"`
	Seq     *int   `json:"seq,omitempty"`
	Line    int64  `json:"line,omitempty"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// AuditStreamReport is the verification of an organization's stream over
// a period. OK is false when a line or seal was changed, removed, added or
// reordered (Problems); Warnings do not fail it.
type AuditStreamReport struct {
	Org           string `json:"org"`
	From          string `json:"from,omitempty"`
	To            string `json:"to,omitempty"`
	OK            bool   `json:"ok"`
	Segments      int    `json:"segments"`
	Lines         int    `json:"lines"`
	Sealed        int    `json:"sealed"`
	Signed        int    `json:"signed"`
	Open          int    `json:"open"`
	PlatformSeals int    `json:"platformSeals"`
	// Archived counts the sealed segments whose write-once archive copy
	// matches (compliance mode).
	Archived  int                  `json:"archived,omitempty"`
	FirstSeq  int64                `json:"firstSeq,omitempty"`
	LastSeq   int64                `json:"lastSeq,omitempty"`
	LastSeal  *time.Time           `json:"lastSeal,omitempty"`
	Keys      []string             `json:"keys"`
	Problems  []AuditStreamProblem `json:"problems"`
	Warnings  []AuditStreamProblem `json:"warnings"`
	CheckedAt time.Time            `json:"checkedAt"`
}

// Verify verifies the organization's audit stream from one day to another
// (inclusive, YYYY-MM-DD in UTC; "" = the server default, the last 30
// days; at most 366 days, 400 invalidRange otherwise).
func (service *AuditService) Verify(ctx context.Context, from, to string) (*AuditStreamReport, error) {
	var report AuditStreamReport
	if err := service.client.do(ctx, request{method: http.MethodGet, path: "/v1/audit/stream/verify", query: streamPeriod(from, to)}, &report); err != nil {
		return nil, err
	}
	return &report, nil
}

// Export streams the evidence bundle of a period (a tar: segments, seals
// with their signed messages and signatures, platform seals with the
// organization's inclusion proofs, public keys, verify.sh and a README).
// Plans with audit export only (402 plan_limit_reached otherwise); audited
// as audit.stream.export. Close the Download when done.
func (service *AuditService) Export(ctx context.Context, from, to string) (*Download, error) {
	return service.client.stream(ctx, request{method: http.MethodGet, path: "/v1/audit/stream/export", query: streamPeriod(from, to), accept: "application/x-tar, application/json"}, true)
}

func streamPeriod(from, to string) url.Values {
	query := url.Values{}
	if from = strings.TrimSpace(from); from != "" {
		query.Set("from", from)
	}
	if to = strings.TrimSpace(to); to != "" {
		query.Set("to", to)
	}
	return query
}
