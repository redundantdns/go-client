package redundantdns

import (
	"context"
	"errors"
	"math/rand/v2"
	"net/http"
	"strconv"
	"time"
)

// RetryPolicy decides when a failed call is sent again.
//
// A 429 answer is always retried: the server did not run the request. A
// 5xx answer or a network error is retried only for idempotent methods
// (GET, HEAD, PUT, DELETE) unless RetryNonIdempotent is set, because a POST
// that failed after reaching the server (create a zone, attach a provider)
// may already have taken effect.
type RetryPolicy struct {
	// MaxRetries is the number of retries after the first attempt (0
	// disables retries).
	MaxRetries int
	// BaseDelay is the first backoff delay; each retry doubles it.
	BaseDelay time.Duration
	// MaxDelay caps a single delay, including a server Retry-After.
	MaxDelay time.Duration
	// RetryNonIdempotent also retries POST on 5xx and network errors.
	RetryNonIdempotent bool
}

// DefaultRetryPolicy retries up to 4 times: about 0.5 s, 1 s, 2 s, 4 s
// (with jitter), capped at 30 s, honoring Retry-After.
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{MaxRetries: 4, BaseDelay: 500 * time.Millisecond, MaxDelay: 30 * time.Second}
}

// NoRetry disables retries.
func NoRetry() RetryPolicy { return RetryPolicy{} }

// next reports whether attempt (0-based) should be retried and after how
// long, given its answer or transport error.
func (policy RetryPolicy) next(method string, attempt int, answer *response, err error) (time.Duration, bool) {
	if attempt >= policy.MaxRetries {
		return 0, false
	}
	idempotent := isIdempotent(method) || policy.RetryNonIdempotent
	switch {
	case err != nil:
		if !idempotent || isContextError(err) {
			return 0, false
		}
	case answer.status == http.StatusTooManyRequests:
	case answer.status >= 500 && answer.status != http.StatusNotImplemented:
		if !idempotent {
			return 0, false
		}
	default:
		return 0, false
	}
	delay := policy.backoff(attempt)
	if answer != nil {
		if retryAfter, ok := parseRetryAfter(answer.header.Get("Retry-After"), time.Now()); ok {
			delay = retryAfter
		}
	}
	if policy.MaxDelay > 0 && delay > policy.MaxDelay {
		delay = policy.MaxDelay
	}
	return delay, true
}

// backoff is BaseDelay * 2^attempt with +/-20% jitter.
func (policy RetryPolicy) backoff(attempt int) time.Duration {
	base := policy.BaseDelay
	if base <= 0 {
		base = 500 * time.Millisecond
	}
	delay := base << min(attempt, 16)
	jitter := 0.8 + rand.Float64()*0.4 //nolint:gosec // jitter does not need a CSPRNG
	return time.Duration(float64(delay) * jitter)
}

// parseRetryAfter reads a Retry-After header: seconds or an HTTP date.
func parseRetryAfter(value string, now time.Time) (time.Duration, bool) {
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second, true
	}
	if at, err := http.ParseTime(value); err == nil {
		if delay := at.Sub(now); delay > 0 {
			return delay, true
		}
		return 0, true
	}
	return 0, false
}

func isIdempotent(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPut, http.MethodDelete, http.MethodOptions:
		return true
	}
	return false
}

func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
