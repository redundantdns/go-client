package redundantdns

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// ACMEService presents and cleans up ACME DNS-01 challenge values
// (_acme-challenge TXT records) and reports when every provider of the zone
// serves them. It is what the cert-manager webhook solver uses.
//
// A token with the acme:challenge scope (ScopeACMEChallenge) reaches only
// these routes, and only for the zones it was created for
// (TokenCreate.ZoneIDs). Dashboard sessions and zones:write tokens may use
// them too.
type ACMEService struct{ client *Client }

// ACME challenge propagation states (ACMEChallengeStatus.State; Present
// answers ACMEStatePending in ACMEChallenge.Propagation).
const (
	ACMEStatePending    = "pending"
	ACMEStatePropagated = "propagated"
	ACMEStateFailed     = "failed"
)

// ACME provider roles and skip reasons (ACMEProviderStatus).
const (
	ACMERoleActive  = "active"
	ACMERoleStandby = "standby"

	// ACMESkippedVerify: the attachment is in verify mode and never written.
	ACMESkippedVerify = "verify"
	// ACMESkippedNSPending: the attachment's nameservers are not known yet.
	ACMESkippedNSPending = "nsPending"
)

// ACME nameserver answers (ACMENameServerAnswer.Answer).
const (
	ACMEAnswerMatch   = "match"
	ACMEAnswerMissing = "missing"
	ACMEAnswerError   = "error"
)

// DefaultACMEChallengeTTL is the TTL the API uses when ACMEChallengeInput.TTL
// is zero.
const DefaultACMEChallengeTTL = 60

// ErrACMEChallengeFailed is returned by ACMEService.WaitPropagated when the
// challenge reached the failed state; the error message carries the reason.
var ErrACMEChallengeFailed = errors.New("acme challenge failed")

// ACMEChallengeInput is the body of ACME.Present.
type ACMEChallengeInput struct {
	// Name is the challenge owner name, relative to the zone
	// ("_acme-challenge.www") or absolute ("_acme-challenge.www.example.com.",
	// trailing dot optional). It must be _acme-challenge or start with
	// "_acme-challenge.".
	Name string `json:"name"`
	// Value is the key authorization digest (base64url, 1..255 characters;
	// 43 for a SHA-256 digest).
	Value string `json:"value"`
	// TTL in seconds; zero lets the API use DefaultACMEChallengeTTL.
	TTL int `json:"ttl,omitempty"`
}

// ACMEChallenge is the answer of ACME.Present.
type ACMEChallenge struct {
	ChallengeID string `json:"challengeId"`
	// Name is relative to the zone; FQDN is absolute with a trailing dot.
	Name string `json:"name"`
	FQDN string `json:"fqdn"`
	// Serial is the zone serial that carries the value.
	Serial int64 `json:"serial"`
	// Propagation is ACMEStatePending on a new challenge.
	Propagation string `json:"propagation"`
	// Existing is true when the same name and value were already presented
	// (Present is idempotent and returns the same ChallengeID).
	Existing bool `json:"existing"`
}

// ACMEChallengeStatus is the answer of ACME.Status: whether every provider
// that the CA may ask serves the value.
type ACMEChallengeStatus struct {
	ChallengeID string `json:"challengeId"`
	Name        string `json:"name"`
	FQDN        string `json:"fqdn"`
	Serial      int64  `json:"serial"`
	// State is ACMEStatePending, ACMEStatePropagated or ACMEStateFailed.
	State string `json:"state"`
	// Reason explains a failed state (a provider error, a verify-mode
	// attachment still in the NS plan).
	Reason    string               `json:"reason,omitempty"`
	CheckedAt time.Time            `json:"checkedAt"`
	Providers []ACMEProviderStatus `json:"providers"`
}

// Propagated reports whether the state is ACMEStatePropagated.
func (status *ACMEChallengeStatus) Propagated() bool { return status.State == ACMEStatePropagated }

// Failed reports whether the state is ACMEStateFailed.
func (status *ACMEChallengeStatus) Failed() bool { return status.State == ACMEStateFailed }

// ACMEProviderStatus is the propagation of a challenge at one attachment.
type ACMEProviderStatus struct {
	AttachmentID string `json:"attachmentId"`
	Provider     string `json:"provider"`
	Label        string `json:"label"`
	// Role is ACMERoleActive (in the NS plan, required to serve the value)
	// or ACMERoleStandby (must apply it, serving is reported only).
	Role string `json:"role"`
	// Applied: the provider holds the challenge's serial or a later one.
	Applied bool `json:"applied"`
	// Served: every nameserver answers the value (nil when not checked).
	Served *bool `json:"served"`
	// Skipped is "" or ACMESkippedVerify / ACMESkippedNSPending: the
	// attachment does not count.
	Skipped     string                 `json:"skipped"`
	Error       string                 `json:"error"`
	NameServers []ACMENameServerAnswer `json:"nameServers"`
}

// ACMENameServerAnswer is what one nameserver answered for the challenge.
type ACMENameServerAnswer struct {
	Host string `json:"host"`
	// Answer is ACMEAnswerMatch, ACMEAnswerMissing or ACMEAnswerError.
	Answer string `json:"answer"`
	Error  string `json:"error"`
}

// ACMEZone is a zone the token may present challenges in.
type ACMEZone struct {
	ZoneID string `json:"zoneId"`
	// Name is lowercase, without a trailing dot.
	Name string `json:"name"`
}

// Present adds a challenge value to the zone's TXT set at the name (other
// values at the same name are kept: apex and wildcard certificates present
// two at once) and fans it out to every provider. It is idempotent: the
// same name and value again return the same challenge with Existing true.
func (service *ACMEService) Present(ctx context.Context, zoneID string, input ACMEChallengeInput) (*ACMEChallenge, error) {
	var challenge ACMEChallenge
	if err := service.client.do(ctx, request{method: http.MethodPost, path: pathf("/v1/zones/%s/acme/challenges", zoneID), body: input}, &challenge); err != nil {
		return nil, err
	}
	return &challenge, nil
}

// Status returns the propagation of a challenge. An unknown challenge
// (already cleaned up, or expired) answers 404 acmeChallengeNotFound.
func (service *ACMEService) Status(ctx context.Context, zoneID, challengeID string) (*ACMEChallengeStatus, error) {
	var status ACMEChallengeStatus
	if err := service.client.do(ctx, request{method: http.MethodGet, path: pathf("/v1/zones/%s/acme/challenges/%s", zoneID, challengeID)}, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

// CleanUp removes a challenge value by id. It is idempotent: a challenge
// that is already gone is not an error.
func (service *ACMEService) CleanUp(ctx context.Context, zoneID, challengeID string) error {
	err := service.client.do(ctx, request{method: http.MethodDelete, path: pathf("/v1/zones/%s/acme/challenges/%s", zoneID, challengeID)}, nil)
	return ignoreChallengeGone(err)
}

// CleanUpValue removes a challenge value by name and value (what
// cert-manager's CleanUp has). It is idempotent like CleanUp.
func (service *ACMEService) CleanUpValue(ctx context.Context, zoneID, name, value string) error {
	query := url.Values{"name": {name}, "value": {value}}
	err := service.client.do(ctx, request{method: http.MethodDelete, path: pathf("/v1/zones/%s/acme/challenges", zoneID), query: query}, nil)
	return ignoreChallengeGone(err)
}

// Zones returns the zones the token may present challenges in (for a token
// restricted to zones, only those).
func (service *ACMEService) Zones(ctx context.Context) ([]ACMEZone, error) {
	var answer struct {
		Zones []ACMEZone `json:"zones"`
	}
	if err := service.client.do(ctx, request{method: http.MethodGet, path: "/v1/acme/zones"}, &answer); err != nil {
		return nil, err
	}
	if answer.Zones == nil {
		answer.Zones = []ACMEZone{}
	}
	return answer.Zones, nil
}

// ACMEWaitOptions tunes ACME.WaitPropagated.
type ACMEWaitOptions struct {
	// Interval between status polls; zero means 2 seconds (the API caches
	// the check for 2 seconds, polling faster gains nothing).
	Interval time.Duration
	// OnStatus, when set, is called with every status read (for logging).
	OnStatus func(status *ACMEChallengeStatus)
}

// DefaultACMEPollInterval is the default ACMEWaitOptions.Interval.
const DefaultACMEPollInterval = 2 * time.Second

// WaitPropagated polls Status until the challenge is propagated (it returns
// the last status and nil), failed (the status and an error wrapping
// ErrACMEChallengeFailed with the reason) or ctx is done (the last status
// read, possibly nil, and the context error). Bound the wait with a context
// deadline.
func (service *ACMEService) WaitPropagated(ctx context.Context, zoneID, challengeID string, options ACMEWaitOptions) (*ACMEChallengeStatus, error) {
	interval := options.Interval
	if interval <= 0 {
		interval = DefaultACMEPollInterval
	}
	var last *ACMEChallengeStatus
	for {
		status, err := service.Status(ctx, zoneID, challengeID)
		if err != nil {
			if ctx.Err() != nil {
				return last, fmt.Errorf("acme challenge %s: %w", challengeID, ctx.Err())
			}
			return last, err
		}
		last = status
		if options.OnStatus != nil {
			options.OnStatus(status)
		}
		switch status.State {
		case ACMEStatePropagated:
			return status, nil
		case ACMEStateFailed:
			reason := status.Reason
			if reason == "" {
				reason = "no reason given"
			}
			return status, fmt.Errorf("acme challenge %s: %w: %s", challengeID, ErrACMEChallengeFailed, reason)
		}
		if err := service.client.sleep(ctx, interval); err != nil {
			return last, fmt.Errorf("acme challenge %s still %s: %w", challengeID, status.State, err)
		}
	}
}

// ignoreChallengeGone turns a 404 acmeChallengeNotFound into success: a
// clean-up of a value that is already gone has nothing left to do.
func ignoreChallengeGone(err error) error {
	if HasCode(err, CodeACMEChallengeNotFound) {
		return nil
	}
	return err
}
