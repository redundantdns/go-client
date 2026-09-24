package rdnstest

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	redundantdns "github.com/redundantdns/go-client"
)

// ManagedTermsVersion is the Managed Provider Terms version the fake
// serves (GET /v1/legal/versions managedTerms).
const ManagedTermsVersion = "2026-09-24"

// managedTermsPath is where the fake says the terms can be read.
const managedTermsPath = "/legal/managed-terms"

// AcceptManagedTerms records the organization's acceptance of the current
// Managed Provider Terms, as if an admin had accepted them earlier.
func (fake *Fake) AcceptManagedTerms() {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	fake.acceptManagedTerms()
}

func (fake *Fake) acceptManagedTerms() {
	fake.managedTerms = &redundantdns.ManagedTermsAcceptance{
		Version: ManagedTermsVersion, AcceptedAt: time.Now().UTC().Truncate(time.Second), UserID: "usr-test", IP: "198.51.100.7",
	}
}

func (fake *Fake) managedTermsAccepted() bool {
	return fake.managedTerms != nil && fake.managedTerms.Version == ManagedTermsVersion
}

func (fake *Fake) managedTermsStatus() redundantdns.ManagedTermsStatus {
	return redundantdns.ManagedTermsStatus{
		Current: ManagedTermsVersion, Accepted: fake.managedTerms, Required: !fake.managedTermsAccepted(),
		URL: fake.URL + managedTermsPath,
	}
}

// writeManagedTermsRequired answers 428 managed_terms_required with the
// version and the URL of the text in the details.
func (fake *Fake) writeManagedTermsRequired(writer http.ResponseWriter) {
	writeJSON(writer, http.StatusPreconditionRequired, map[string]any{
		"error":   redundantdns.CodeManagedTermsRequired,
		"message": "accept the Managed Provider Terms and Acceptable Use Policy to use managed providers",
		"details": redundantdns.ManagedTermsRequirement{Version: ManagedTermsVersion, URL: fake.URL + managedTermsPath},
	})
}

func (fake *Fake) mountLegal(handle func(string, handler)) {
	handle("GET /v1/legal/managed", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, fake.managedTermsStatus())
	})
	handle("POST /v1/legal/managed/accept", func(writer http.ResponseWriter, request *http.Request) {
		var input struct {
			Version string `json:"version"`
		}
		if !decode(writer, request, &input) {
			return
		}
		if input.Version != ManagedTermsVersion {
			writeError(writer, http.StatusConflict, redundantdns.CodeLegalVersionMismatch, "the managed terms version is not the current one")
			return
		}
		fake.acceptManagedTerms()
		writeJSON(writer, http.StatusOK, fake.managedTermsStatus())
	})
}

// parentOf returns the closest zone of which name is a subdomain.
func (fake *Fake) parentOf(name string) *redundantdns.Zone {
	var parent *redundantdns.Zone
	for _, candidate := range fake.zones {
		if candidate.Name != name && strings.HasSuffix(name, "."+candidate.Name) &&
			(parent == nil || len(candidate.Name) > len(parent.Name)) {
			parent = candidate
		}
	}
	return parent
}

// writeDelegation writes (or refreshes) the NS set of a delegated child in
// its parent zone: the child's NS plan, marked managedBy delegation. An
// empty plan removes the set, since an NS set cannot be empty.
func (fake *Fake) writeDelegation(child *redundantdns.Zone) {
	parent, ok := fake.zones[fake.parentDelegations[child.ZoneID]]
	if !ok {
		return
	}
	label := strings.TrimSuffix(child.Name, "."+parent.Name)
	index := slices.IndexFunc(parent.RecordSets, func(set redundantdns.RecordSet) bool {
		return set.Name == label && set.Type == "NS"
	})
	if len(child.NSPlan) == 0 {
		if index >= 0 {
			parent.RecordSets = slices.Delete(parent.RecordSets, index, index+1)
			parent.Serial++
		}
		return
	}
	set := redundantdns.RecordSet{
		Name: label, Type: "NS", TTL: parent.Settings.DefaultTTL,
		Values: append([]string{}, child.NSPlan...), ManagedBy: redundantdns.ManagedByDelegation,
	}
	if index >= 0 {
		parent.RecordSets[index] = set
	} else {
		parent.RecordSets = append(parent.RecordSets, set)
	}
	parent.Serial++
}

// removeDelegation deletes a child's NS set from its parent.
func (fake *Fake) removeDelegation(child *redundantdns.Zone) {
	if _, ok := fake.parentDelegations[child.ZoneID]; !ok {
		return
	}
	plan := child.NSPlan
	child.NSPlan = nil
	fake.writeDelegation(child)
	child.NSPlan = plan
	delete(fake.parentDelegations, child.ZoneID)
}

// fakeOAuth is the fake's OAuth state: registered clients and pending
// authorization codes. Every authorization is approved at once and every
// access token is the fake's Token, so /v1 accepts it.
type fakeOAuth struct {
	clients       map[string]redundantdns.OAuthClientRegistration
	codes         map[string]fakeCode
	refreshTokens map[string]string // refresh token -> client id
}

type fakeCode struct {
	clientID, redirectURI, challenge string
}

func newFakeOAuth() fakeOAuth {
	return fakeOAuth{
		clients: map[string]redundantdns.OAuthClientRegistration{}, codes: map[string]fakeCode{},
		refreshTokens: map[string]string{},
	}
}

// OAuthRegistrations returns the registrations received, by client id.
func (fake *Fake) OAuthRegistrations() map[string]redundantdns.OAuthClientRegistration {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	registrations := map[string]redundantdns.OAuthClientRegistration{}
	for clientID, registration := range fake.oauth.clients {
		registrations[clientID] = registration
	}
	return registrations
}

func (fake *Fake) mountOAuth(handle func(string, handler)) {
	handle("POST /oauth/register", func(writer http.ResponseWriter, request *http.Request) {
		var input redundantdns.OAuthClientRegistration
		if !decode(writer, request, &input) {
			return
		}
		if len(input.RedirectURIs) == 0 {
			writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid_redirect_uri", "error_description": "redirect_uris is required"})
			return
		}
		clientID := fake.nextID("mcp")
		fake.oauth.clients[clientID] = input
		writeJSON(writer, http.StatusCreated, redundantdns.OAuthClient{
			ClientID: clientID, ClientName: input.ClientName, RedirectURIs: input.RedirectURIs, GrantTypes: input.GrantTypes,
			TokenEndpointAuthMethod: "none", Scope: strings.Join(redundantdns.AllScopes, " "),
			SoftwareID: input.SoftwareID, SoftwareVersion: input.SoftwareVersion,
		})
	})
	handle("GET /oauth/authorize", func(writer http.ResponseWriter, request *http.Request) {
		query := request.URL.Query()
		client, ok := fake.oauth.clients[query.Get("client_id")]
		redirectURI := query.Get("redirect_uri")
		if !ok || !slices.Contains(client.RedirectURIs, redirectURI) || query.Get("code_challenge_method") != "S256" {
			writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "unknown client, redirect_uri or challenge method"})
			return
		}
		code := fake.nextID("code")
		fake.oauth.codes[code] = fakeCode{clientID: query.Get("client_id"), redirectURI: redirectURI, challenge: query.Get("code_challenge")}
		target, err := url.Parse(redirectURI)
		if err != nil {
			writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "bad redirect_uri"})
			return
		}
		values := target.Query()
		values.Set("code", code)
		values.Set("state", query.Get("state"))
		target.RawQuery = values.Encode()
		// The target is a redirect URI the client registered (checked above).
		http.Redirect(writer, request, target.String(), http.StatusFound) //nolint:gosec // registered redirect URI
	})
	handle("POST /oauth/token", func(writer http.ResponseWriter, request *http.Request) {
		if err := request.ParseForm(); err != nil {
			writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "bad form"})
			return
		}
		form := request.PostForm
		clientID := form.Get("client_id")
		switch form.Get("grant_type") {
		case redundantdns.GrantAuthorizationCode:
			code, ok := fake.oauth.codes[form.Get("code")]
			delete(fake.oauth.codes, form.Get("code"))
			sum := sha256.Sum256([]byte(form.Get("code_verifier")))
			if !ok || code.clientID != clientID || code.redirectURI != form.Get("redirect_uri") ||
				base64.RawURLEncoding.EncodeToString(sum[:]) != code.challenge {
				writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "invalid code or verifier"})
				return
			}
		case redundantdns.GrantRefreshToken:
			owner, ok := fake.oauth.refreshTokens[form.Get("refresh_token")]
			delete(fake.oauth.refreshTokens, form.Get("refresh_token"))
			if !ok || owner != clientID {
				writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "invalid refresh token"})
				return
			}
		default:
			writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type", "error_description": "unsupported grant_type"})
			return
		}
		refresh := fake.nextID("rt")
		fake.oauth.refreshTokens[refresh] = clientID
		writeJSON(writer, http.StatusOK, map[string]any{
			"access_token": fake.Token, "token_type": "Bearer", "expires_in": 3600,
			"refresh_token": refresh, "scope": strings.Join(redundantdns.AllScopes, " "),
		})
	})
}
