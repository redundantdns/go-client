package redundantdns

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// ConnectionsService manages provider connections.
type ConnectionsService struct{ client *Client }

// List returns the provider connections (credentials are never returned).
func (service *ConnectionsService) List(ctx context.Context) ([]Connection, error) {
	var connections []Connection
	err := service.client.do(ctx, request{method: http.MethodGet, path: "/v1/connections"}, &connections)
	return connections, err
}

// Get returns one connection. The API has no single-connection route, so
// this filters List; a missing id answers connectionNotFound.
func (service *ConnectionsService) Get(ctx context.Context, connectionID string) (*Connection, error) {
	connections, err := service.List(ctx)
	if err != nil {
		return nil, err
	}
	for _, connection := range connections {
		if connection.ConnectionID == connectionID {
			found := connection
			return &found, nil
		}
	}
	return nil, &APIError{
		StatusCode: http.StatusNotFound, Code: CodeConnectionNotFound,
		Message: fmt.Sprintf("connection %q not found", connectionID),
		Method:  http.MethodGet, Path: "/v1/connections",
	}
}

// Create tests and saves a provider connection (admins). Credentials are
// write-only.
func (service *ConnectionsService) Create(ctx context.Context, input ConnectionCreate) (*ConnectionCreateResult, error) {
	var result ConnectionCreateResult
	if err := service.client.do(ctx, request{method: http.MethodPost, path: "/v1/connections", body: input}, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Test re-tests a stored connection (admins).
func (service *ConnectionsService) Test(ctx context.Context, connectionID string) (*ConnectionTestResult, error) {
	var result ConnectionTestResult
	if err := service.client.do(ctx, request{method: http.MethodPost, path: pathf("/v1/connections/%s/test", connectionID)}, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Delete deletes a connection that no zone uses (admins).
func (service *ConnectionsService) Delete(ctx context.Context, connectionID string) error {
	return service.client.do(ctx, request{method: http.MethodDelete, path: pathf("/v1/connections/%s", connectionID)}, &okResponse{})
}

// AttachmentsService attaches provider connections to zones.
type AttachmentsService struct{ client *Client }

// Create attaches a connection to a zone (admins): the data plane creates
// the provider zone, or adopts an existing one. The zone's NS plan grows by
// the provider's nameservers.
func (service *AttachmentsService) Create(ctx context.Context, zoneID string, input AttachmentCreate) (*AttachResult, error) {
	var result AttachResult
	if err := service.client.do(ctx, request{method: http.MethodPost, path: pathf("/v1/zones/%s/attachments", zoneID), body: input}, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Get returns one attachment of a zone.
func (service *AttachmentsService) Get(ctx context.Context, zoneID, attachmentID string) (*Attachment, error) {
	zone, err := service.client.Zones.Get(ctx, zoneID)
	if err != nil {
		return nil, err
	}
	for _, attachment := range zone.Attachments {
		if attachment.AttachmentID == attachmentID {
			found := attachment
			return &found, nil
		}
	}
	return nil, &APIError{
		StatusCode: http.StatusNotFound, Code: CodeAttachmentNotFound,
		Message: fmt.Sprintf("attachment %q not found", attachmentID),
		Method:  http.MethodGet, Path: pathf("/v1/zones/%s", zoneID),
	}
}

// Delete detaches a provider (admins). With DeleteRemote the provider zone
// is deleted too, and ConfirmName must repeat the zone name.
func (service *AttachmentsService) Delete(ctx context.Context, zoneID, attachmentID string, options DetachOptions) error {
	query := url.Values{}
	if options.DeleteRemote {
		query.Set("deleteRemote", "true")
		query.Set("confirmName", options.ConfirmName)
	}
	return service.client.do(ctx, request{
		method: http.MethodDelete, path: pathf("/v1/zones/%s/attachments/%s", zoneID, attachmentID), query: query,
	}, &okResponse{})
}

// Adopt imports the provider's current records into the canonical zone
// ("adopt changes"), then every provider is reconciled.
func (service *AttachmentsService) Adopt(ctx context.Context, zoneID, attachmentID string) (*Jobs, error) {
	return service.client.Sync.Adopt(ctx, zoneID, attachmentID)
}
