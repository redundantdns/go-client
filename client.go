// Package redundantdns is a Go client for the RedundantDNS /v1 HTTP API.
//
// A Client authenticates with a personal access token (rdns_...) or an
// OAuth 2.1 access token, both sent as a bearer token. Dashboard sessions
// (the rdns_session cookie) are supported for the few routes that tokens
// cannot use, such as minting a personal access token after a login.
//
//	client, err := redundantdns.New(
//		redundantdns.WithBaseURL("https://app.redundantdns.com"),
//		redundantdns.WithToken(os.Getenv("RDNS_TOKEN")),
//	)
//	zones, err := client.Zones.List(ctx)
//
// Every call takes a context, retries 429 and 5xx answers with backoff (see
// RetryPolicy) and returns an *APIError for API errors.
package redundantdns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Version is the client version, sent in the User-Agent header.
const Version = "0.1.0"

// DefaultBaseURL is the hosted RedundantDNS API.
const DefaultBaseURL = "https://app.redundantdns.com"

// OrgHeader selects the organization for dashboard sessions. Tokens are
// bound to one organization; sending another org with a token is refused.
const OrgHeader = "X-RDNS-Org"

// SessionCookie is the name of the dashboard session cookie.
const SessionCookie = "rdns_session"

// maxErrorBody bounds how much of an error response is read.
const maxErrorBody = 1 << 20

// Client talks to one RedundantDNS deployment. It is safe for concurrent
// use. Use WithOrg to get a copy bound to another organization.
type Client struct {
	baseURL    *url.URL
	token      string
	session    string
	orgID      string
	userAgent  string
	httpClient *http.Client
	retry      RetryPolicy
	sleep      func(ctx context.Context, delay time.Duration) error

	Auth        *AuthService
	Zones       *ZonesService
	Records     *RecordsService
	Connections *ConnectionsService
	Attachments *AttachmentsService
	Sync        *SyncService
	Delegation  *DelegationService
	Alerts      *AlertsService
	Audit       *AuditService
	Account     *AccountService
	Tokens      *TokensService
	Legal       *LegalService
	OAuth       *OAuthService
	Domains     *DomainsService
	Licenses    *LicensesService
	Exports     *ExportsService
	Compliance  *ComplianceService
	Plans       *PlansService
	Billing     *BillingService
}

// Option configures a Client.
type Option func(client *Client) error

// WithBaseURL sets the deployment URL (scheme and host, optionally a path
// prefix), for example https://app.redundantdns.com.
func WithBaseURL(rawURL string) Option {
	return func(client *Client) error {
		parsed, err := url.Parse(strings.TrimRight(strings.TrimSpace(rawURL), "/"))
		if err != nil {
			return fmt.Errorf("parse base URL: %w", err)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return fmt.Errorf("base URL %q: scheme must be http or https", rawURL)
		}
		if parsed.Host == "" {
			return fmt.Errorf("base URL %q: missing host", rawURL)
		}
		client.baseURL = parsed
		return nil
	}
}

// WithToken authenticates with a personal access token or an OAuth access
// token (sent as "Authorization: Bearer <token>").
func WithToken(token string) Option {
	return func(client *Client) error {
		client.token = strings.TrimSpace(token)
		return nil
	}
}

// WithSession authenticates with a dashboard session token (the value of
// the rdns_session cookie returned by Auth.VerifyCode).
func WithSession(session string) Option {
	return func(client *Client) error {
		client.session = strings.TrimSpace(session)
		return nil
	}
}

// WithOrg sends the X-RDNS-Org header on every request. Sessions use it to
// pick the organization; a token accepts only its own organization.
func WithOrg(orgID string) Option {
	return func(client *Client) error {
		client.orgID = strings.TrimSpace(orgID)
		return nil
	}
}

// WithHTTPClient replaces the underlying *http.Client (timeouts, proxies,
// transports). The default has a 60 second timeout.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(client *Client) error {
		if httpClient == nil {
			return errors.New("http client is nil")
		}
		client.httpClient = httpClient
		return nil
	}
}

// WithUserAgent prefixes the User-Agent header, for example "rdnsctl/1.0".
func WithUserAgent(userAgent string) Option {
	return func(client *Client) error {
		if userAgent != "" {
			client.userAgent = userAgent + " " + client.userAgent
		}
		return nil
	}
}

// WithRetryPolicy replaces the retry policy (see DefaultRetryPolicy).
func WithRetryPolicy(policy RetryPolicy) Option {
	return func(client *Client) error {
		client.retry = policy
		return nil
	}
}

// New builds a Client. Without WithBaseURL it targets DefaultBaseURL.
func New(options ...Option) (*Client, error) {
	client := &Client{
		userAgent:  "redundantdns-go-client/" + Version,
		httpClient: &http.Client{Timeout: 60 * time.Second},
		retry:      DefaultRetryPolicy(),
		sleep:      sleepContext,
	}
	if err := WithBaseURL(DefaultBaseURL)(client); err != nil {
		return nil, err
	}
	for _, option := range options {
		if err := option(client); err != nil {
			return nil, err
		}
	}
	client.bindServices()
	return client, nil
}

// bindServices points every service at this client.
func (client *Client) bindServices() {
	client.Auth = &AuthService{client: client}
	client.Zones = &ZonesService{client: client}
	client.Records = &RecordsService{client: client}
	client.Connections = &ConnectionsService{client: client}
	client.Attachments = &AttachmentsService{client: client}
	client.Sync = &SyncService{client: client}
	client.Delegation = &DelegationService{client: client}
	client.Alerts = &AlertsService{client: client}
	client.Audit = &AuditService{client: client}
	client.Account = &AccountService{client: client}
	client.Tokens = &TokensService{client: client}
	client.Legal = &LegalService{client: client}
	client.OAuth = &OAuthService{client: client}
	client.Domains = &DomainsService{client: client}
	client.Licenses = &LicensesService{client: client}
	client.Exports = &ExportsService{client: client}
	client.Compliance = &ComplianceService{client: client}
	client.Plans = &PlansService{client: client}
	client.Billing = &BillingService{client: client}
}

// BaseURL returns the deployment URL.
func (client *Client) BaseURL() string { return client.baseURL.String() }

// OrgID returns the organization sent in X-RDNS-Org ("" when none).
func (client *Client) OrgID() string { return client.orgID }

// WithOrg returns a copy of the client bound to another organization.
func (client *Client) WithOrg(orgID string) *Client {
	clone := *client
	clone.orgID = strings.TrimSpace(orgID)
	clone.bindServices()
	return &clone
}

// request describes one API call.
type request struct {
	method string
	path   string
	query  url.Values
	body   any
	// form is sent as application/x-www-form-urlencoded instead of body
	// (the OAuth token endpoint).
	form url.Values
	// accept overrides the Accept header (text endpoints).
	accept string
}

// response is a raw API answer.
type response struct {
	status  int
	header  http.Header
	body    []byte
	cookies []*http.Cookie
}

// do runs a request with retries and decodes a JSON answer into out (when
// out is not nil). Non-2xx answers become *APIError.
func (client *Client) do(ctx context.Context, call request, out any) error {
	answer, err := client.send(ctx, call)
	if err != nil {
		return err
	}
	if out == nil || len(answer.body) == 0 {
		return nil
	}
	if err := json.Unmarshal(answer.body, out); err != nil {
		return fmt.Errorf("%s %s: decode response: %w", call.method, call.path, err)
	}
	return nil
}

// send runs a request with retries and returns the raw 2xx answer.
func (client *Client) send(ctx context.Context, call request) (*response, error) {
	if ctx == nil {
		return nil, errors.New("nil context")
	}
	var payload []byte
	if call.form != nil {
		payload = []byte(call.form.Encode())
	}
	if call.body != nil {
		encoded, err := json.Marshal(call.body)
		if err != nil {
			return nil, fmt.Errorf("%s %s: encode body: %w", call.method, call.path, err)
		}
		payload = encoded
	}
	target := client.resolve(call.path, call.query)
	for attempt := 0; ; attempt++ {
		answer, err := client.sendOnce(ctx, call, target, payload)
		delay, retry := client.retry.next(call.method, attempt, answer, err)
		if !retry {
			if err != nil {
				return nil, err
			}
			if answer.status < 200 || answer.status > 299 {
				return nil, newAPIError(call.method, call.path, answer)
			}
			return answer, nil
		}
		if sleepErr := client.sleep(ctx, delay); sleepErr != nil {
			if err != nil {
				return nil, fmt.Errorf("%w (retry interrupted: %w)", err, sleepErr)
			}
			return nil, sleepErr
		}
	}
}

// sendOnce performs one HTTP round trip.
func (client *Client) sendOnce(ctx context.Context, call request, target string, payload []byte) (*response, error) {
	httpRequest, err := client.newHTTPRequest(ctx, call, target, payload)
	if err != nil {
		return nil, err
	}
	httpResponse, err := client.httpClient.Do(httpRequest)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", call.method, call.path, err)
	}
	defer func() { _ = httpResponse.Body.Close() }()
	limit := int64(-1)
	if httpResponse.StatusCode >= 300 {
		limit = maxErrorBody
	}
	var reader io.Reader = httpResponse.Body
	if limit > 0 {
		reader = io.LimitReader(httpResponse.Body, limit)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("%s %s: read response: %w", call.method, call.path, err)
	}
	return &response{status: httpResponse.StatusCode, header: httpResponse.Header, body: body, cookies: httpResponse.Cookies()}, nil
}

// newHTTPRequest builds the HTTP request of a call: body, content type,
// credentials and organization header.
func (client *Client) newHTTPRequest(ctx context.Context, call request, target string, payload []byte) (*http.Request, error) {
	var bodyReader io.Reader
	if payload != nil {
		bodyReader = bytes.NewReader(payload)
	}
	httpRequest, err := http.NewRequestWithContext(ctx, call.method, target, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", call.method, call.path, err)
	}
	accept := call.accept
	if accept == "" {
		accept = "application/json"
	}
	httpRequest.Header.Set("Accept", accept)
	httpRequest.Header.Set("User-Agent", client.userAgent)
	switch {
	case call.form != nil:
		httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	case payload != nil:
		httpRequest.Header.Set("Content-Type", "application/json")
	}
	if client.token != "" {
		httpRequest.Header.Set("Authorization", "Bearer "+client.token)
	}
	if client.session != "" {
		// A request cookie only carries name and value; the Secure/HttpOnly
		// attributes belong to Set-Cookie answers.
		httpRequest.AddCookie(&http.Cookie{Name: SessionCookie, Value: client.session}) //nolint:gosec // request cookie, see above
	}
	if client.orgID != "" {
		httpRequest.Header.Set(OrgHeader, client.orgID)
	}
	return httpRequest, nil
}

// resolve joins the base URL, an API path and a query string.
func (client *Client) resolve(path string, query url.Values) string {
	target := *client.baseURL
	// path is already escaped by pathf: keep it as the raw path and derive
	// the decoded one, so URL.String does not escape it twice.
	rawPath := strings.TrimRight(client.baseURL.EscapedPath(), "/") + path
	decoded, err := url.PathUnescape(rawPath)
	if err != nil {
		decoded = rawPath
	}
	target.Path = decoded
	target.RawPath = rawPath
	if len(query) > 0 {
		target.RawQuery = query.Encode()
	}
	return target.String()
}

// pathf builds an API path, escaping every argument as one path segment.
func pathf(format string, segments ...string) string {
	escaped := make([]any, len(segments))
	for index, segment := range segments {
		escaped[index] = url.PathEscape(segment)
	}
	return fmt.Sprintf(format, escaped...)
}

// sleepContext waits for delay or until ctx is done.
func sleepContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// okResponse is the {"ok": true} answer of delete routes.
type okResponse struct {
	OK bool `json:"ok"`
}
