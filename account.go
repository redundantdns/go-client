package redundantdns

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
)

// AccountService reads the caller, organizations, providers and legal
// status.
type AccountService struct{ client *Client }

// Me returns the caller and their organizations.
func (service *AccountService) Me(ctx context.Context) (*Me, error) {
	var me Me
	if err := service.client.do(ctx, request{method: http.MethodGet, path: "/v1/me"}, &me); err != nil {
		return nil, err
	}
	return &me, nil
}

// Orgs returns the caller's organizations (a token sees only its own).
func (service *AccountService) Orgs(ctx context.Context) ([]OrgSummary, error) {
	var orgs []OrgSummary
	err := service.client.do(ctx, request{method: http.MethodGet, path: "/v1/orgs"}, &orgs)
	return orgs, err
}

// CreateOrg creates an organization; the caller becomes its owner
// (dashboard session only).
func (service *AccountService) CreateOrg(ctx context.Context, name string) (*OrgSummary, error) {
	var org OrgSummary
	body := map[string]string{"name": name}
	if err := service.client.do(ctx, request{method: http.MethodPost, path: "/v1/orgs", body: body}, &org); err != nil {
		return nil, err
	}
	return &org, nil
}

// Providers returns the available DNS providers, their credential fields
// and capabilities.
func (service *AccountService) Providers(ctx context.Context) ([]Provider, error) {
	var providers []Provider
	err := service.client.do(ctx, request{method: http.MethodGet, path: "/v1/providers"}, &providers)
	return providers, err
}

// LegalVersions returns the current Terms of Service and Privacy Policy
// versions (no authentication).
func (service *AccountService) LegalVersions(ctx context.Context) (*LegalVersions, error) {
	var versions LegalVersions
	if err := service.client.do(ctx, request{method: http.MethodGet, path: "/v1/legal/versions"}, &versions); err != nil {
		return nil, err
	}
	return &versions, nil
}

// Legal returns the caller's acceptance of the legal documents.
func (service *AccountService) Legal(ctx context.Context) (*LegalStatus, error) {
	var status LegalStatus
	if err := service.client.do(ctx, request{method: http.MethodGet, path: "/v1/me/legal"}, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

// AcceptLegal accepts the given document versions, which must be the
// current ones (dashboard session only; 409 legalVersionMismatch
// otherwise).
func (service *AccountService) AcceptLegal(ctx context.Context, versions LegalVersions) (*LegalStatus, error) {
	var status LegalStatus
	body := map[string]string{"termsVersion": versions.Terms, "privacyVersion": versions.Privacy}
	if err := service.client.do(ctx, request{method: http.MethodPost, path: "/v1/me/legal/accept", body: body}, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

// TokensService manages personal access tokens (dashboard session only:
// a token cannot manage tokens).
type TokensService struct{ client *Client }

// List returns the personal access tokens (own; admins see all).
func (service *TokensService) List(ctx context.Context) ([]Token, error) {
	var tokens []Token
	err := service.client.do(ctx, request{method: http.MethodGet, path: "/v1/tokens"}, &tokens)
	return tokens, err
}

// Create mints a personal access token, bound to the client's organization
// (X-RDNS-Org). The secret is in the result only.
func (service *TokensService) Create(ctx context.Context, input TokenCreate) (*TokenCreateResult, error) {
	var result TokenCreateResult
	if err := service.client.do(ctx, request{method: http.MethodPost, path: "/v1/tokens", body: input}, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Revoke revokes a personal access token.
func (service *TokensService) Revoke(ctx context.Context, tokenID string) error {
	return service.client.do(ctx, request{method: http.MethodDelete, path: pathf("/v1/tokens/%s", tokenID)}, &okResponse{})
}

// AuthService runs the passwordless dashboard login (e-mail code).
type AuthService struct{ client *Client }

// Session is a dashboard session obtained with VerifyCode. Use it with
// WithSession to call session-only routes (accept the legal documents,
// mint a personal access token).
type Session struct {
	// Token is the rdns_session cookie value. Treat it as a secret.
	Token     string
	ExpiresAt time.Time
	User      User
	Orgs      []OrgSummary
}

// RequestCode e-mails a one-time login code.
func (service *AuthService) RequestCode(ctx context.Context, email string) error {
	body := map[string]string{"email": strings.TrimSpace(email)}
	return service.client.do(ctx, request{method: http.MethodPost, path: "/auth/code", body: body}, &okResponse{})
}

// VerifyCode exchanges the e-mailed code for a dashboard session.
func (service *AuthService) VerifyCode(ctx context.Context, email, code string) (*Session, error) {
	body := map[string]string{"email": strings.TrimSpace(email), "code": strings.TrimSpace(code)}
	answer, err := service.client.send(ctx, request{method: http.MethodPost, path: "/auth/verify", body: body})
	if err != nil {
		return nil, err
	}
	session := &Session{}
	for _, cookie := range answer.cookies {
		if cookie.Name == SessionCookie {
			session.Token = cookie.Value
			session.ExpiresAt = cookie.Expires
		}
	}
	if session.Token == "" {
		return nil, errors.New("POST /auth/verify: no session cookie in the answer")
	}
	var me Me
	if err := decodeJSON(answer.body, &me); err != nil {
		return nil, err
	}
	session.User, session.Orgs = me.User, me.Orgs
	return session, nil
}

// Logout asks the server to clear the session cookie. Sessions are signed
// tokens: a caller that kept the token must also discard it.
func (service *AuthService) Logout(ctx context.Context) error {
	return service.client.do(ctx, request{method: http.MethodPost, path: "/auth/logout"}, &okResponse{})
}
