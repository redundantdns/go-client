package redundantdns

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

// AlertsService manages alert rules, channels and events.
type AlertsService struct{ client *Client }

// Rules returns the alert rules with their effective thresholds.
func (service *AlertsService) Rules(ctx context.Context) ([]AlertRule, error) {
	var rules []AlertRule
	err := service.client.do(ctx, request{method: http.MethodGet, path: "/v1/alerts/rules"}, &rules)
	return rules, err
}

// UpdateRule enables or disables a rule, or changes its threshold (admins).
func (service *AlertsService) UpdateRule(ctx context.Context, rule string, input AlertRuleUpdate) (*AlertRule, error) {
	var updated AlertRule
	if err := service.client.do(ctx, request{method: http.MethodPut, path: pathf("/v1/alerts/rules/%s", rule), body: input}, &updated); err != nil {
		return nil, err
	}
	return &updated, nil
}

// Channels returns the notification channels (secrets are never returned).
func (service *AlertsService) Channels(ctx context.Context) ([]AlertChannel, error) {
	var channels []AlertChannel
	err := service.client.do(ctx, request{method: http.MethodGet, path: "/v1/alerts/channels"}, &channels)
	return channels, err
}

// Channel returns one channel (filters Channels: the API has no
// single-channel route).
func (service *AlertsService) Channel(ctx context.Context, channelID string) (*AlertChannel, error) {
	channels, err := service.Channels(ctx)
	if err != nil {
		return nil, err
	}
	for _, channel := range channels {
		if channel.ChannelID == channelID {
			found := channel
			return &found, nil
		}
	}
	return nil, &APIError{
		StatusCode: http.StatusNotFound, Code: CodeChannelNotFound,
		Message: fmt.Sprintf("channel %q not found", channelID),
		Method:  http.MethodGet, Path: "/v1/alerts/channels",
	}
}

// CreateChannel adds an e-mail, webhook or Slack channel (admins). A
// webhook's signing secret is returned once, in the result.
func (service *AlertsService) CreateChannel(ctx context.Context, input AlertChannelCreate) (*AlertChannelCreateResult, error) {
	var result AlertChannelCreateResult
	if err := service.client.do(ctx, request{method: http.MethodPost, path: "/v1/alerts/channels", body: input}, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteChannel removes a channel (admins).
func (service *AlertsService) DeleteChannel(ctx context.Context, channelID string) error {
	return service.client.do(ctx, request{method: http.MethodDelete, path: pathf("/v1/alerts/channels/%s", channelID)}, &okResponse{})
}

// TestChannel sends a test notification to a channel now (admins).
func (service *AlertsService) TestChannel(ctx context.Context, channelID string) (*AlertTestResult, error) {
	var result AlertTestResult
	if err := service.client.do(ctx, request{method: http.MethodPost, path: pathf("/v1/alerts/channels/%s/test", channelID)}, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ListEvents returns the alert history, newest first.
func (service *AlertsService) ListEvents(ctx context.Context, filter AlertEventFilter) ([]AlertEvent, error) {
	query := url.Values{}
	if filter.ZoneID != "" {
		query.Set("zoneId", filter.ZoneID)
	}
	if filter.Rule != "" {
		query.Set("rule", filter.Rule)
	}
	if filter.State != "" {
		query.Set("state", filter.State)
	}
	if filter.Limit > 0 {
		query.Set("limit", strconv.Itoa(filter.Limit))
	}
	var events []AlertEvent
	err := service.client.do(ctx, request{method: http.MethodGet, path: "/v1/alerts/events", query: query}, &events)
	return events, err
}

// Resolve resolves a firing event by hand (editors); the channels are
// notified.
func (service *AlertsService) Resolve(ctx context.Context, eventID string) (*AlertEvent, error) {
	return service.transition(ctx, pathf("/v1/alerts/events/%s/resolve", eventID))
}

// Ack acknowledges a firing event (editors): it keeps firing.
func (service *AlertsService) Ack(ctx context.Context, eventID string) (*AlertEvent, error) {
	return service.transition(ctx, pathf("/v1/alerts/events/%s/ack", eventID))
}

func (service *AlertsService) transition(ctx context.Context, path string) (*AlertEvent, error) {
	var event AlertEvent
	if err := service.client.do(ctx, request{method: http.MethodPost, path: path}, &event); err != nil {
		return nil, err
	}
	return &event, nil
}

// AuditService reads the audit log.
type AuditService struct{ client *Client }

// List returns the latest audit events of the organization, optionally for
// one zone.
func (service *AuditService) List(ctx context.Context, zoneID string) ([]AuditEntry, error) {
	query := url.Values{}
	if zoneID != "" {
		query.Set("zoneId", zoneID)
	}
	var entries []AuditEntry
	err := service.client.do(ctx, request{method: http.MethodGet, path: "/v1/audit", query: query}, &entries)
	return entries, err
}
