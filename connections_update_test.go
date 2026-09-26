package redundantdns_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"

	redundantdns "github.com/redundantdns/go-client"
	"github.com/redundantdns/go-client/rdnstest"
)

func TestConnectionsUpdate(t *testing.T) {
	fake := rdnstest.NewFake(t)
	client := newClient(t, fake.URL)
	ctx := context.Background()

	created, err := client.Connections.Create(ctx, redundantdns.ConnectionCreate{
		Provider: "fake", Label: "Primary", AccessLevel: redundantdns.AccessLevelZoneAdmin,
		Credentials: map[string]string{"token": "old-1234"}, ScopeHints: map[string]string{"region": "eu"},
	})
	if err != nil {
		t.Fatal(err)
	}
	connectionID := created.Connection.ConnectionID
	zone, err := client.Zones.Create(ctx, redundantdns.ZoneCreate{Name: "rotate.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Attachments.Create(ctx, zone.ZoneID, redundantdns.AttachmentCreate{ConnectionID: connectionID}); err != nil {
		t.Fatal(err)
	}

	// Credentials only: the label and the scope hints are kept, the
	// attachment is reconciled.
	result, err := client.Connections.Update(ctx, connectionID, redundantdns.ConnectionUpdate{Credentials: map[string]string{"token": "new-5678"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Connection.ConnectionID != connectionID || result.Connection.CredentialsHint != "5678" || result.Connection.Label != "Primary" ||
		result.Connection.ScopeHints["region"] != "eu" || result.Connection.Status != "ok" || result.Deferred || len(result.JobIDs) != 1 {
		t.Fatalf("update = %+v", result)
	}
	requests := fake.Requests()
	last := requests[len(requests)-1]
	if last.Method != http.MethodPatch || last.Path != "/v1/connections/"+connectionID {
		t.Fatalf("request = %s %s", last.Method, last.Path)
	}
	var sent map[string]json.RawMessage
	if err := json.Unmarshal(last.Body, &sent); err != nil {
		t.Fatal(err)
	}
	if _, ok := sent["label"]; ok || string(sent["scopeHints"]) != "null" || sent["credentials"] == nil {
		t.Errorf("update body = %s", last.Body)
	}
	if got := fake.ConnectionCredentials(connectionID)["token"]; got != "new-5678" {
		t.Errorf("stored token = %q", got)
	}

	// Label and scope hints change together with the credentials; an empty
	// map clears the scope hints.
	label := "  Rotated  "
	result, err = client.Connections.Update(ctx, connectionID, redundantdns.ConnectionUpdate{
		Credentials: map[string]string{"token": "third-9999"}, ScopeHints: map[string]string{}, Label: &label,
	})
	if err != nil || result.Connection.Label != "Rotated" || len(result.Connection.ScopeHints) != 0 {
		t.Fatalf("update with label = %+v, %v", result, err)
	}

	// The provider refuses the credentials: nothing is saved.
	_, err = client.Connections.Update(ctx, connectionID, redundantdns.ConnectionUpdate{Credentials: map[string]string{"token": "invalid"}})
	if !errors.Is(err, redundantdns.ErrProviderRejected) || !errors.Is(err, redundantdns.ErrUnprocessable) || !redundantdns.HasCode(err, redundantdns.CodeProviderRejected) {
		t.Fatalf("rejected err = %v", err)
	}
	if got := fake.ConnectionCredentials(connectionID)["token"]; got != "third-9999" {
		t.Errorf("stored token after a refusal = %q", got)
	}
	if errors.Is(err, redundantdns.ErrConnectionManaged) || errors.Is(err, redundantdns.ErrConnectionImmutable) {
		t.Error("providerRejected matched another sentinel")
	}

	cases := []struct {
		name  string
		id    string
		input redundantdns.ConnectionUpdate
		code  string
	}{
		{"missing credentials", connectionID, redundantdns.ConnectionUpdate{}, redundantdns.CodeCredentialsIncomplete},
		{"empty label", connectionID, redundantdns.ConnectionUpdate{Credentials: map[string]string{"token": "x"}, Label: new(string)}, redundantdns.CodeLabelRequired},
		{"unknown connection", "conn-missing", redundantdns.ConnectionUpdate{Credentials: map[string]string{"token": "x"}}, redundantdns.CodeConnectionNotFound},
	}
	for _, test := range cases {
		if _, err := client.Connections.Update(ctx, test.id, test.input); !redundantdns.HasCode(err, test.code) {
			t.Errorf("%s: err = %v, want %s", test.name, err, test.code)
		}
	}

	// A managed connection has no credentials to replace.
	fake.AcceptManagedTerms()
	managed, err := client.Connections.Create(ctx, redundantdns.ConnectionCreate{Provider: "fake", Mode: redundantdns.ModeManaged})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Connections.Update(ctx, managed.Connection.ConnectionID, redundantdns.ConnectionUpdate{Credentials: map[string]string{"token": "x"}})
	if !errors.Is(err, redundantdns.ErrConnectionManaged) || !errors.Is(err, redundantdns.ErrBadRequest) {
		t.Fatalf("managed err = %v", err)
	}
}

func TestConnectionsUpdateImmutableAndDeferred(t *testing.T) {
	fake := rdnstest.NewFake(t)
	client := newClient(t, fake.URL)
	ctx := context.Background()
	created, err := client.Connections.Create(ctx, redundantdns.ConnectionCreate{
		Provider: "fake", AccessLevel: redundantdns.AccessLevelZoneEditor, Credentials: map[string]string{"token": "editor-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	connectionID := created.Connection.ConnectionID

	// The SDK never sends provider, mode or access level; a raw client that
	// sends another value is refused.
	request, err := http.NewRequestWithContext(ctx, http.MethodPatch, fake.URL+"/v1/connections/"+connectionID,
		jsonBody(t, map[string]any{"credentials": map[string]string{"token": "x"}, "accessLevel": redundantdns.AccessLevelZoneAdmin}))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+rdnstest.DefaultToken)
	answer, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(answer.Body).Decode(&body)
	_ = answer.Body.Close()
	if answer.StatusCode != http.StatusBadRequest || body.Error != redundantdns.CodeConnectionImmutable {
		t.Fatalf("immutable = %d %s", answer.StatusCode, body.Error)
	}

	// A zone_editor connection with no attachment is deferred, as on the API.
	result, err := client.Connections.Update(ctx, connectionID, redundantdns.ConnectionUpdate{Credentials: map[string]string{"token": "editor-2"}})
	if err != nil || !result.Deferred || result.Connection.Status != "pending" || len(result.JobIDs) != 0 {
		t.Fatalf("deferred update = %+v, %v", result, err)
	}
}

func TestConnectionUpdateSentinels(t *testing.T) {
	immutable := &redundantdns.APIError{StatusCode: http.StatusBadRequest, Code: redundantdns.CodeConnectionImmutable}
	if !errors.Is(immutable, redundantdns.ErrConnectionImmutable) || errors.Is(immutable, redundantdns.ErrConnectionManaged) {
		t.Error("connectionImmutable sentinel")
	}
	other := &redundantdns.APIError{StatusCode: http.StatusUnprocessableEntity, Code: redundantdns.CodeRecordSetUnsupported}
	if errors.Is(other, redundantdns.ErrProviderRejected) {
		t.Error("a 422 of another code matched ErrProviderRejected")
	}
}

// jsonBody encodes a request body.
func jsonBody(t *testing.T, value any) io.Reader {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(encoded)
}
