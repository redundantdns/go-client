package redundantdns

import (
	"context"
	"fmt"
	"iter"
	"net/http"
	"strings"
	"time"
)

// ZonesService manages canonical zones.
type ZonesService struct{ client *Client }

// List returns the zones of the organization (without record sets).
func (service *ZonesService) List(ctx context.Context) ([]Zone, error) {
	var zones []Zone
	err := service.client.do(ctx, request{method: http.MethodGet, path: "/v1/zones"}, &zones)
	return zones, err
}

// All iterates over the zones (see Paginate).
func (service *ZonesService) All(ctx context.Context) iter.Seq2[Zone, error] {
	return Paginate(ctx, func(ctx context.Context) ([]Zone, error) { return service.List(ctx) })
}

// Get returns one zone with record sets, attachments, capabilities and
// status.
func (service *ZonesService) Get(ctx context.Context, zoneID string) (*Zone, error) {
	var zone Zone
	if err := service.client.do(ctx, request{method: http.MethodGet, path: pathf("/v1/zones/%s", zoneID)}, &zone); err != nil {
		return nil, err
	}
	return &zone, nil
}

// GetByName returns the zone with this name (case-insensitive, trailing dot
// ignored), with its record sets. It answers an *APIError with code
// zoneNotFound when there is none.
func (service *ZonesService) GetByName(ctx context.Context, name string) (*Zone, error) {
	wanted := NormalizeZoneName(name)
	for zone, err := range service.All(ctx) {
		if err != nil {
			return nil, err
		}
		if zone.Name == wanted {
			return service.Get(ctx, zone.ZoneID)
		}
	}
	return nil, &APIError{StatusCode: http.StatusNotFound, Code: CodeZoneNotFound, Message: fmt.Sprintf("no zone named %q", wanted), Method: http.MethodGet, Path: "/v1/zones"}
}

// Resolve returns a zone given its id ("zone-...") or its name.
func (service *ZonesService) Resolve(ctx context.Context, idOrName string) (*Zone, error) {
	if strings.HasPrefix(idOrName, "zone-") {
		return service.Get(ctx, idOrName)
	}
	return service.GetByName(ctx, idOrName)
}

// Create creates a canonical zone.
func (service *ZonesService) Create(ctx context.Context, input ZoneCreate) (*Zone, error) {
	var zone Zone
	if err := service.client.do(ctx, request{method: http.MethodPost, path: "/v1/zones", body: input}, &zone); err != nil {
		return nil, err
	}
	return &zone, nil
}

// Delete deletes the canonical zone (admins). Provider zones are kept:
// detach with DeleteRemote first to remove them.
func (service *ZonesService) Delete(ctx context.Context, zoneID string) error {
	return service.client.do(ctx, request{method: http.MethodDelete, path: pathf("/v1/zones/%s", zoneID)}, &okResponse{})
}

// Export returns the zone as an RFC 1035 zone file.
func (service *ZonesService) Export(ctx context.Context, zoneID string) (string, error) {
	answer, err := service.client.send(ctx, request{method: http.MethodGet, path: pathf("/v1/zones/%s/export", zoneID), accept: "text/plain"})
	if err != nil {
		return "", err
	}
	return string(answer.body), nil
}

// Status returns the data-plane status of the zone.
func (service *ZonesService) Status(ctx context.Context, zoneID string) (*ZoneStatus, error) {
	var status ZoneStatus
	if err := service.client.do(ctx, request{method: http.MethodGet, path: pathf("/v1/zones/%s/status", zoneID)}, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

// Journal returns the latest serial changes of the zone.
func (service *ZonesService) Journal(ctx context.Context, zoneID string) ([]JournalEntry, error) {
	var entries []JournalEntry
	err := service.client.do(ctx, request{method: http.MethodGet, path: pathf("/v1/zones/%s/journal", zoneID)}, &entries)
	return entries, err
}

// WaitOptions controls WaitInSync.
type WaitOptions struct {
	// Interval between status polls (default 1 s).
	Interval time.Duration
	// MinSerial is the canonical serial every attachment must have applied
	// (0 = the zone's serial when the wait starts).
	MinSerial int64
}

// WaitInSync polls the zone status until every attachment is in_sync with
// at least the wanted serial applied. It returns the last status; an
// attachment in the error state ends the wait with an error. Bound the
// wait with the context.
func (service *ZonesService) WaitInSync(ctx context.Context, zoneID string, options WaitOptions) (*ZoneStatus, error) {
	interval := options.Interval
	if interval <= 0 {
		interval = time.Second
	}
	serial := options.MinSerial
	zone, err := service.Get(ctx, zoneID)
	if err != nil {
		return nil, err
	}
	if serial == 0 {
		serial = zone.Serial
	}
	wanted := make([]string, 0, len(zone.Attachments))
	for _, attachment := range zone.Attachments {
		wanted = append(wanted, attachment.AttachmentID)
	}
	for {
		status, err := service.Status(ctx, zoneID)
		if err != nil {
			return nil, err
		}
		done := true
		for _, attachmentID := range wanted {
			state, ok := status.Attachments[attachmentID]
			if ok && state.State == StateError && state.AppliedSerial < serial {
				return status, fmt.Errorf("attachment %s: sync error: %s", attachmentID, state.LastError)
			}
			if !ok || state.State != StateInSync || state.AppliedSerial < serial {
				done = false
			}
		}
		if done {
			return status, nil
		}
		if err := service.client.sleep(ctx, interval); err != nil {
			return status, err
		}
	}
}
