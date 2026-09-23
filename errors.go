package redundantdns

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// APIError is an error answer of the API: an HTTP status, a stable code
// (see the Code* constants) and an English message. OAuth endpoints answer
// with the RFC 6749 shape; its error_description lands in Message.
type APIError struct {
	// StatusCode is the HTTP status.
	StatusCode int
	// Code is the stable error code, for example "zoneNotFound".
	Code string
	// Message is the English message.
	Message string
	// Details carries optional structured details (for example the
	// capability rejections of recordSetUnsupported).
	Details json.RawMessage
	// Method and Path identify the request.
	Method string
	Path   string
}

// Error implements error.
func (apiError *APIError) Error() string {
	text := fmt.Sprintf("%s %s: %d %s", apiError.Method, apiError.Path, apiError.StatusCode, apiError.Code)
	if apiError.Message != "" {
		text += ": " + apiError.Message
	}
	return text
}

// Is matches the sentinel errors by HTTP status (and by code where one
// status carries several meanings), so callers can write
// errors.Is(err, redundantdns.ErrNotFound).
func (apiError *APIError) Is(target error) bool {
	switch target {
	case ErrBadRequest:
		return apiError.StatusCode == http.StatusBadRequest
	case ErrUnauthorized:
		return apiError.StatusCode == http.StatusUnauthorized
	case ErrForbidden:
		return apiError.StatusCode == http.StatusForbidden
	case ErrNotFound:
		return apiError.StatusCode == http.StatusNotFound
	case ErrConflict:
		return apiError.StatusCode == http.StatusConflict
	case ErrUnprocessable:
		return apiError.StatusCode == http.StatusUnprocessableEntity
	case ErrLegalAcceptanceRequired:
		return apiError.StatusCode == http.StatusPreconditionRequired || apiError.Code == CodeLegalAcceptanceRequired
	case ErrRateLimited:
		return apiError.StatusCode == http.StatusTooManyRequests
	case ErrServer:
		return apiError.StatusCode >= 500
	}
	return false
}

// Sentinel errors for errors.Is.
var (
	ErrBadRequest              = errors.New("bad request")
	ErrUnauthorized            = errors.New("unauthorized")
	ErrForbidden               = errors.New("forbidden")
	ErrNotFound                = errors.New("not found")
	ErrConflict                = errors.New("conflict")
	ErrUnprocessable           = errors.New("unprocessable")
	ErrLegalAcceptanceRequired = errors.New("legal acceptance required")
	ErrRateLimited             = errors.New("rate limited")
	ErrServer                  = errors.New("server error")
)

// Stable API error codes (the SPA maps them to errors.<code>).
const (
	CodeAlertNotFound             = "alertNotFound"
	CodeAlertRuleNotFound         = "alertRuleNotFound"
	CodeAlreadyAttached           = "alreadyAttached"
	CodeApexNsManaged             = "apexNsManaged"
	CodeAttachmentNotFound        = "attachmentNotFound"
	CodeAttachmentRequired        = "attachmentRequired"
	CodeChannelNotFound           = "channelNotFound"
	CodeCnameConflict             = "cnameConflict"
	CodeCodeExpired               = "codeExpired"
	CodeConfirmNameMismatch       = "confirmNameMismatch"
	CodeConflict                  = "conflict"
	CodeConnectionInUse           = "connectionInUse"
	CodeConnectionNotFound        = "connectionNotFound"
	CodeCredentialsIncomplete     = "credentialsIncomplete"
	CodeCredentialsNotAllowed     = "credentialsNotAllowed"
	CodeDataPlaneUnavailable      = "dataPlaneUnavailable"
	CodeDeleteRemoteNotAllowed    = "deleteRemoteNotAllowed"
	CodeForbidden                 = "forbidden"
	CodeInsufficientScope         = "insufficientScope"
	CodeInternal                  = "internal"
	CodeInvalidAccessLevel        = "invalidAccessLevel"
	CodeInvalidBody               = "invalidBody"
	CodeInvalidChannelKind        = "invalidChannelKind"
	CodeInvalidChannelURL         = "invalidChannelUrl"
	CodeInvalidCode               = "invalidCode"
	CodeInvalidEmail              = "invalidEmail"
	CodeInvalidIPAllowlist        = "invalidIpAllowlist"
	CodeInvalidMode               = "invalidMode"
	CodeInvalidScope              = "invalidScope"
	CodeInvalidState              = "invalidState"
	CodeInvalidThreshold          = "invalidThreshold"
	CodeInvalidToken              = "invalidToken"
	CodeInvalidTTL                = "invalidTtl"
	CodeInvalidWebhookSecret      = "invalidWebhookSecret"
	CodeInvalidZoneName           = "invalidZoneName"
	CodeIPNotAllowed              = "ipNotAllowed"
	CodeLabelRequired             = "labelRequired"
	CodeLegalAcceptanceRequired   = "legal_acceptance_required"
	CodeLegalVersionMismatch      = "legalVersionMismatch"
	CodeManagedExists             = "managedExists"
	CodeManagedUnavailable        = "managedUnavailable"
	CodeNameRequired              = "nameRequired"
	CodeNotFound                  = "notFound"
	CodeNotLoggedIn               = "notLoggedIn"
	CodeProviderRejected          = "providerRejected"
	CodeProviderUnavailable       = "providerUnavailable"
	CodeProviderZoneExists        = "providerZoneExists"
	CodeProviderZoneIDRequired    = "providerZoneIdRequired"
	CodeProviderZoneMismatch      = "providerZoneMismatch"
	CodeRecordSetEmpty            = "recordSetEmpty"
	CodeRecordSetExists           = "recordSetExists"
	CodeRecordSetNotFound         = "recordSetNotFound"
	CodeRecordSetUnsupported      = "recordSetUnsupported"
	CodeRecordTypeInvalid         = "recordTypeInvalid"
	CodeScopesRequired            = "scopesRequired"
	CodeSessionRequired           = "sessionRequired"
	CodeTokenNotFound             = "tokenNotFound"
	CodeTooManyChannels           = "tooManyChannels"
	CodeUnauthorized              = "unauthorized"
	CodeZoneExists                = "zoneExists"
	CodeZoneNameTaken             = "zoneNameTaken"
	CodeZoneNotFound              = "zoneNotFound"
	CodeTooManyClientRegistration = "too_many_requests"
)

// HasCode reports whether err is an *APIError with one of the codes.
func HasCode(err error, codes ...string) bool {
	var apiError *APIError
	if !errors.As(err, &apiError) {
		return false
	}
	for _, code := range codes {
		if apiError.Code == code {
			return true
		}
	}
	return false
}

// IsNotFound reports whether err is a 404 API error.
func IsNotFound(err error) bool { return errors.Is(err, ErrNotFound) }

// newAPIError decodes an error answer. Unknown bodies keep a trimmed
// excerpt as the message and get the "internal" code (5xx) or a code
// derived from the status.
func newAPIError(method, path string, answer *response) *APIError {
	apiError := &APIError{StatusCode: answer.status, Method: method, Path: path}
	var body struct {
		Error            string          `json:"error"`
		Message          string          `json:"message"`
		ErrorDescription string          `json:"error_description"`
		Details          json.RawMessage `json:"details"`
	}
	if err := json.Unmarshal(answer.body, &body); err == nil && body.Error != "" {
		apiError.Code = body.Error
		apiError.Message = body.Message
		if apiError.Message == "" {
			apiError.Message = body.ErrorDescription
		}
		if len(body.Details) > 0 && string(body.Details) != "null" {
			apiError.Details = body.Details
		}
		return apiError
	}
	apiError.Code = fallbackCode(answer.status)
	excerpt := strings.TrimSpace(string(answer.body))
	if len(excerpt) > 200 {
		excerpt = excerpt[:200] + "..."
	}
	apiError.Message = excerpt
	if apiError.Message == "" {
		apiError.Message = http.StatusText(answer.status)
	}
	return apiError
}

func fallbackCode(status int) string {
	switch {
	case status == http.StatusUnauthorized:
		return CodeUnauthorized
	case status == http.StatusForbidden:
		return CodeForbidden
	case status == http.StatusNotFound:
		return CodeNotFound
	case status == http.StatusConflict:
		return CodeConflict
	case status == http.StatusTooManyRequests:
		return "rateLimited"
	case status >= 500:
		return CodeInternal
	}
	return "httpError"
}
