package redundantdns

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// Software ids a client declares at OAuth dynamic client registration
// (RFC 7591 software_id). The platform gates the plan's access channels by
// them: an id starting with "rdnsctl" is the CLI, one starting with
// "terraform" the Terraform provider.
const (
	SoftwareIDCLI       = "rdnsctl"
	SoftwareIDTerraform = "terraform-provider-redundantdns"
)

// OAuth grant types.
const (
	GrantAuthorizationCode = "authorization_code"
	GrantRefreshToken      = "refresh_token"
)

// OAuthService runs the OAuth 2.1 flows of the platform's authorization
// server: dynamic client registration, the authorization code flow with
// PKCE (S256) and refresh. Use it on a client without a token; the
// resulting access token then goes to WithToken.
type OAuthService struct{ client *Client }

// OAuthClientRegistration is an RFC 7591 registration request.
type OAuthClientRegistration struct {
	ClientName   string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
	GrantTypes   []string `json:"grant_types,omitempty"`
	// TokenEndpointAuthMethod is "none" for a public client (native apps,
	// the CLI); empty lets the server choose.
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`
	// Scope is a space separated scope list (the catalog when empty).
	Scope string `json:"scope,omitempty"`
	// SoftwareID and SoftwareVersion declare the client software
	// (SoftwareIDCLI, SoftwareIDTerraform).
	SoftwareID      string `json:"software_id,omitempty"`
	SoftwareVersion string `json:"software_version,omitempty"`
}

// OAuthClient is a registered client. ClientSecret is set only for a
// confidential client, and only in the registration answer.
type OAuthClient struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope"`
	SoftwareID              string   `json:"software_id,omitempty"`
	SoftwareVersion         string   `json:"software_version,omitempty"`
}

// Register registers a client (POST /oauth/register). A public client with
// the same redirect set gets the same client id back.
func (service *OAuthService) Register(ctx context.Context, registration OAuthClientRegistration) (*OAuthClient, error) {
	if len(registration.GrantTypes) == 0 {
		registration.GrantTypes = []string{GrantAuthorizationCode, GrantRefreshToken}
	}
	var registered OAuthClient
	if err := service.client.do(ctx, request{method: http.MethodPost, path: "/oauth/register", body: registration}, &registered); err != nil {
		return nil, err
	}
	return &registered, nil
}

// PKCE is a proof key for code exchange (RFC 7636, S256).
type PKCE struct {
	Verifier  string
	Challenge string
}

// NewPKCE returns a random verifier and its S256 challenge.
func NewPKCE() (PKCE, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return PKCE{}, fmt.Errorf("pkce: %w", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(secret)
	sum := sha256.Sum256([]byte(verifier))
	return PKCE{Verifier: verifier, Challenge: base64.RawURLEncoding.EncodeToString(sum[:])}, nil
}

// RandomState returns an opaque value for the state parameter.
func RandomState() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

// AuthorizationRequest are the parameters of the authorization URL.
type AuthorizationRequest struct {
	ClientID      string
	RedirectURI   string
	Scope         string
	State         string
	CodeChallenge string
}

// AuthorizationURL returns the URL to open in a browser (GET
// /oauth/authorize, response_type=code, S256).
func (service *OAuthService) AuthorizationURL(authorization AuthorizationRequest) string {
	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {authorization.ClientID},
		"redirect_uri":          {authorization.RedirectURI},
		"state":                 {authorization.State},
		"code_challenge":        {authorization.CodeChallenge},
		"code_challenge_method": {"S256"},
	}
	if authorization.Scope != "" {
		query.Set("scope", authorization.Scope)
	}
	return service.client.resolve("/oauth/authorize", query)
}

// OAuthToken is a token endpoint answer. Expiry is computed from
// ExpiresIn when the answer is received.
type OAuthToken struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int       `json:"expires_in"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	Scope        string    `json:"scope,omitempty"`
	Expiry       time.Time `json:"-"`
}

// ExchangeCode trades an authorization code for tokens.
func (service *OAuthService) ExchangeCode(ctx context.Context, clientID, code, redirectURI, codeVerifier string) (*OAuthToken, error) {
	return service.token(ctx, url.Values{
		"grant_type": {GrantAuthorizationCode}, "client_id": {clientID}, "code": {code},
		"redirect_uri": {redirectURI}, "code_verifier": {codeVerifier},
	})
}

// Refresh trades a refresh token for new tokens. Refresh tokens rotate:
// keep the returned RefreshToken, the old one is spent (reusing it revokes
// the whole grant).
func (service *OAuthService) Refresh(ctx context.Context, clientID, refreshToken string) (*OAuthToken, error) {
	return service.token(ctx, url.Values{
		"grant_type": {GrantRefreshToken}, "client_id": {clientID}, "refresh_token": {refreshToken},
	})
}

func (service *OAuthService) token(ctx context.Context, form url.Values) (*OAuthToken, error) {
	var token OAuthToken
	if err := service.client.do(ctx, request{method: http.MethodPost, path: "/oauth/token", form: form}, &token); err != nil {
		return nil, err
	}
	if token.AccessToken == "" {
		return nil, errors.New("POST /oauth/token: no access_token in the answer")
	}
	if token.ExpiresIn > 0 {
		token.Expiry = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	}
	return &token, nil
}

// OAuthCredentials is an OAuth login saved to a file, so a tool that
// cannot open a browser (the Terraform provider) reuses a login made by
// rdnsctl and refreshes it. The file holds secrets: it is written 0600.
type OAuthCredentials struct {
	BaseURL      string    `json:"baseUrl"`
	ClientID     string    `json:"clientId"`
	SoftwareID   string    `json:"softwareId,omitempty"`
	OrgID        string    `json:"orgId,omitempty"`
	AccessToken  string    `json:"accessToken"`
	RefreshToken string    `json:"refreshToken,omitempty"`
	Expiry       time.Time `json:"expiry"`
	Scope        string    `json:"scope,omitempty"`
}

// Apply stores a token answer, keeping the previous refresh token when the
// answer has none.
func (credentials *OAuthCredentials) Apply(token *OAuthToken) {
	credentials.AccessToken = token.AccessToken
	if token.RefreshToken != "" {
		credentials.RefreshToken = token.RefreshToken
	}
	credentials.Expiry = token.Expiry
	if token.Scope != "" {
		credentials.Scope = token.Scope
	}
}

// Expired reports whether the access token expires within margin.
func (credentials *OAuthCredentials) Expired(now time.Time, margin time.Duration) bool {
	return credentials.AccessToken == "" || (!credentials.Expiry.IsZero() && now.Add(margin).After(credentials.Expiry))
}

// LoadOAuthCredentials reads a credentials file.
func LoadOAuthCredentials(path string) (*OAuthCredentials, error) {
	content, err := os.ReadFile(path) //nolint:gosec // the caller names the file
	if err != nil {
		return nil, err
	}
	var credentials OAuthCredentials
	if err := json.Unmarshal(content, &credentials); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if credentials.ClientID == "" || credentials.BaseURL == "" {
		return nil, fmt.Errorf("%s: missing baseUrl or clientId", path)
	}
	return &credentials, nil
}

// Save writes the credentials atomically with mode 0600 (directory 0700).
func (credentials *OAuthCredentials) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	content, err := json.MarshalIndent(credentials, "", "  ") //nolint:gosec // the file is meant to hold the tokens (0600)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".oauth-*.json")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(temporary.Name()) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(append(content, '\n')); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporary.Name(), path)
}

// RefreshOAuthCredentials refreshes the access token when it expires within
// margin and saves the rotated tokens back to path. It returns whether a
// refresh happened. Two processes refreshing the same file at once can
// spend the rotated token twice (the server then revokes the grant); run
// one Terraform or rdnsctl at a time per file.
func RefreshOAuthCredentials(ctx context.Context, path string, credentials *OAuthCredentials, margin time.Duration, options ...Option) (bool, error) {
	if !credentials.Expired(time.Now(), margin) {
		return false, nil
	}
	if credentials.RefreshToken == "" {
		return false, errors.New("the OAuth access token expired and there is no refresh token: sign in again")
	}
	anonymous, err := New(append([]Option{WithBaseURL(credentials.BaseURL)}, options...)...)
	if err != nil {
		return false, err
	}
	token, err := anonymous.OAuth.Refresh(ctx, credentials.ClientID, credentials.RefreshToken)
	if err != nil {
		return false, fmt.Errorf("refresh the OAuth token: %w", err)
	}
	credentials.Apply(token)
	if err := credentials.Save(path); err != nil {
		return true, fmt.Errorf("save the refreshed OAuth token: %w", err)
	}
	return true, nil
}

// TerraformOAuthCredentialsPath is the credentials file that `rdnsctl
// terraform login` writes and the Terraform provider reads when it has no
// token, under the user's config directory (os.UserConfigDir, honoring
// XDG_CONFIG_HOME).
func TerraformOAuthCredentialsPath(configDir string) string {
	return filepath.Join(configDir, "redundantdns", "terraform-oauth.json")
}
