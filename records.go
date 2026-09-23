package redundantdns

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// RecordsService manages the record sets of a zone. Every change bumps the
// zone serial and asks the data plane to reconcile the providers.
type RecordsService struct{ client *Client }

// List returns the record sets of a zone.
func (service *RecordsService) List(ctx context.Context, zoneID string) ([]RecordSet, error) {
	var recordSets []RecordSet
	err := service.client.do(ctx, request{method: http.MethodGet, path: pathf("/v1/zones/%s/records", zoneID)}, &recordSets)
	return recordSets, err
}

// Get returns one record set by name and type. Name may be relative
// ("www", "@") or absolute ("www.example.com."); zoneName is used to
// relativize it (pass "" when name is already relative).
func (service *RecordsService) Get(ctx context.Context, zoneID, zoneName, name, recordType string) (*RecordSet, error) {
	recordSets, err := service.List(ctx, zoneID)
	if err != nil {
		return nil, err
	}
	wantedName := NormalizeRecordName(zoneName, name)
	wantedType := strings.ToUpper(strings.TrimSpace(recordType))
	for _, recordSet := range recordSets {
		if strings.EqualFold(recordSet.Name, wantedName) && recordSet.Type == wantedType {
			found := recordSet
			return &found, nil
		}
	}
	return nil, &APIError{
		StatusCode: http.StatusNotFound, Code: CodeRecordSetNotFound,
		Message: fmt.Sprintf("no %s record set named %q", wantedType, wantedName),
		Method:  http.MethodGet, Path: pathf("/v1/zones/%s/records", zoneID),
	}
}

// Upsert creates or replaces a record set (set Previous to rename one) and
// reconciles the providers.
func (service *RecordsService) Upsert(ctx context.Context, zoneID string, input RecordUpsert) (*RecordUpsertResult, error) {
	var result RecordUpsertResult
	if err := service.client.do(ctx, request{method: http.MethodPut, path: pathf("/v1/zones/%s/records", zoneID), body: input}, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Delete deletes a record set and reconciles the providers. It returns the
// new zone serial.
func (service *RecordsService) Delete(ctx context.Context, zoneID, name, recordType string) (int64, error) {
	var result struct {
		OK     bool  `json:"ok"`
		Serial int64 `json:"serial"`
	}
	query := url.Values{"name": {name}, "type": {recordType}}
	if err := service.client.do(ctx, request{method: http.MethodDelete, path: pathf("/v1/zones/%s/records", zoneID), query: query}, &result); err != nil {
		return 0, err
	}
	return result.Serial, nil
}
