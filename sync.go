package redundantdns

import (
	"context"
	"net/http"
)

// SyncService runs the data-plane jobs of a zone. Jobs run asynchronously:
// poll Zones.Status (or Zones.WaitInSync) for the outcome.
type SyncService struct{ client *Client }

// jobBody targets one attachment (empty = all).
type jobBody struct {
	AttachmentID string `json:"attachmentId,omitempty"`
}

// Reconcile pushes the canonical zone to the providers now (attachmentID
// "" = every attachment).
func (service *SyncService) Reconcile(ctx context.Context, zoneID, attachmentID string) (*Jobs, error) {
	return service.job(ctx, pathf("/v1/zones/%s/reconcile", zoneID), attachmentID)
}

// Verify compares the providers with the canonical zone now.
func (service *SyncService) Verify(ctx context.Context, zoneID, attachmentID string) (*Jobs, error) {
	return service.job(ctx, pathf("/v1/zones/%s/verify", zoneID), attachmentID)
}

// Adopt imports one provider's records into the canonical zone.
func (service *SyncService) Adopt(ctx context.Context, zoneID, attachmentID string) (*Jobs, error) {
	var jobs Jobs
	if err := service.client.do(ctx, request{method: http.MethodPost, path: pathf("/v1/zones/%s/attachments/%s/adopt", zoneID, attachmentID)}, &jobs); err != nil {
		return nil, err
	}
	return &jobs, nil
}

func (service *SyncService) job(ctx context.Context, path, attachmentID string) (*Jobs, error) {
	var jobs Jobs
	if err := service.client.do(ctx, request{method: http.MethodPost, path: path, body: jobBody{AttachmentID: attachmentID}}, &jobs); err != nil {
		return nil, err
	}
	return &jobs, nil
}

// DelegationService checks zone delegations.
type DelegationService struct{ client *Client }

// Check checks the delegation now: the parent zone's NS set against the NS
// plan.
func (service *DelegationService) Check(ctx context.Context, zoneID string) (*Delegation, error) {
	var delegation Delegation
	if err := service.client.do(ctx, request{method: http.MethodPost, path: pathf("/v1/zones/%s/delegation/check", zoneID)}, &delegation); err != nil {
		return nil, err
	}
	return &delegation, nil
}
