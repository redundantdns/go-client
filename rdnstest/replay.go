// Package rdnstest provides test servers for code built on the RedundantDNS
// Go client: a replay server that answers with responses recorded from a
// real deployment (see scripts/record-fixtures.sh) and a small stateful
// fake of the /v1 API for flows that create, read and delete resources.
package rdnstest

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

//go:embed fixtures/*.json fixtures/*.txt
var fixtureFiles embed.FS

// envelope is the on-disk shape of a recorded answer.
type envelope struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body"`
}

// Fixture returns a recorded answer: its HTTP status and JSON body. Text
// fixtures (name ending in .txt) are returned as-is with status 200.
func Fixture(name string) (int, []byte, error) {
	if len(name) > 4 && name[len(name)-4:] == ".txt" {
		body, err := fixtureFiles.ReadFile("fixtures/" + name)
		return http.StatusOK, body, err
	}
	raw, err := fixtureFiles.ReadFile("fixtures/" + name + ".json")
	if err != nil {
		return 0, nil, fmt.Errorf("fixture %q: %w", name, err)
	}
	var recorded envelope
	if err := json.Unmarshal(raw, &recorded); err != nil {
		return 0, nil, fmt.Errorf("fixture %q: %w", name, err)
	}
	return recorded.Status, recorded.Body, nil
}

// MustFixture is Fixture for tests: it fails the test on error.
func MustFixture(tb testing.TB, name string) (int, []byte) {
	tb.Helper()
	status, body, err := Fixture(name)
	if err != nil {
		tb.Fatal(err)
	}
	return status, body
}

// Request is a request received by a test server.
type Request struct {
	Method  string
	Path    string
	Query   string
	Header  http.Header
	Body    []byte
	Pattern string
}

// ReplayServer answers each route with a recorded fixture and keeps the
// requests it received.
type ReplayServer struct {
	*httptest.Server
	mutex    sync.Mutex
	requests []Request
}

// NewReplayServer starts a server whose routes (http.ServeMux patterns such
// as "GET /v1/zones/{zoneId}") answer the named fixtures. Unknown routes
// answer 404 {"error":"notFound"}. The server is closed when the test ends.
func NewReplayServer(tb testing.TB, routes map[string]string) *ReplayServer {
	tb.Helper()
	replay := &ReplayServer{}
	mux := http.NewServeMux()
	for pattern, name := range routes {
		status, body := MustFixture(tb, name)
		contentType := "application/json"
		if len(name) > 4 && name[len(name)-4:] == ".txt" {
			contentType = "text/plain; charset=utf-8"
		}
		mux.HandleFunc(pattern, func(writer http.ResponseWriter, request *http.Request) {
			replay.record(request, pattern)
			writer.Header().Set("Content-Type", contentType)
			writer.WriteHeader(status)
			_, _ = writer.Write(body)
		})
	}
	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		replay.record(request, "")
		writeError(writer, http.StatusNotFound, "notFound", "no fixture for "+request.Method+" "+request.URL.Path)
	})
	replay.Server = httptest.NewServer(mux)
	tb.Cleanup(replay.Close)
	return replay
}

func (replay *ReplayServer) record(request *http.Request, pattern string) {
	body, _ := io.ReadAll(request.Body)
	replay.mutex.Lock()
	defer replay.mutex.Unlock()
	replay.requests = append(replay.requests, Request{
		Method: request.Method, Path: request.URL.Path, Query: request.URL.RawQuery,
		Header: request.Header.Clone(), Body: body, Pattern: pattern,
	})
}

// Requests returns a copy of the requests received so far.
func (replay *ReplayServer) Requests() []Request {
	replay.mutex.Lock()
	defer replay.mutex.Unlock()
	return append([]Request(nil), replay.requests...)
}

// LastRequest returns the last request received (zero when none).
func (replay *ReplayServer) LastRequest() Request {
	requests := replay.Requests()
	if len(requests) == 0 {
		return Request{}
	}
	return requests[len(requests)-1]
}

func writeError(writer http.ResponseWriter, status int, code, message string) {
	writeJSON(writer, status, map[string]string{"error": code, "message": message})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
