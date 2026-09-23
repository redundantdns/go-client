package rdnstest

import (
	"bytes"
	"io"
	"net/http"
)

// readBody reads and returns a request body (nil when empty).
func readBody(request *http.Request) []byte {
	if request.Body == nil {
		return nil
	}
	body, _ := io.ReadAll(request.Body)
	return body
}

// newBody wraps an already read body so handlers can decode it again.
func newBody(body []byte) io.ReadCloser {
	return io.NopCloser(bytes.NewReader(body))
}
