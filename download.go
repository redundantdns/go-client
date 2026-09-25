package redundantdns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
)

// Download is a file answered by the API (an org export bundle, an audit
// evidence bundle). It streams: read it to the end and Close it. The
// metadata comes from the answer's headers.
type Download struct {
	io.ReadCloser
	// ContentType is the media type, for example "application/x-tar".
	ContentType string
	// Filename is the name suggested by Content-Disposition ("" when none).
	Filename string
	// Size is the Content-Length, -1 when unknown.
	Size int64
	// SHA256 is the hex digest the server announced in X-RDNS-SHA256 (org
	// exports; "" otherwise).
	SHA256 string
}

// stream runs a GET-like request and returns the body without reading it.
// Error answers become *APIError. With retry, 429, 5xx and network errors
// are retried as for do (only before a 2xx answer arrives).
func (client *Client) stream(ctx context.Context, call request, retry bool) (*Download, error) {
	if ctx == nil {
		return nil, errors.New("nil context")
	}
	policy := client.retry
	if !retry {
		policy = NoRetry()
	}
	target := client.resolve(call.path, call.query)
	for attempt := 0; ; attempt++ {
		download, answer, err := client.streamOnce(ctx, call, target)
		if download != nil {
			return download, nil
		}
		delay, again := policy.next(call.method, attempt, answer, err)
		if !again {
			if err != nil {
				return nil, err
			}
			return nil, newAPIError(call.method, call.path, answer)
		}
		if sleepErr := client.sleep(ctx, delay); sleepErr != nil {
			if err != nil {
				return nil, fmt.Errorf("%w (retry interrupted: %w)", err, sleepErr)
			}
			return nil, sleepErr
		}
	}
}

// streamOnce performs one round trip: a 2xx answer is returned open as a
// Download; any other answer is read (bounded) and closed.
func (client *Client) streamOnce(ctx context.Context, call request, target string) (*Download, *response, error) {
	httpRequest, err := client.newHTTPRequest(ctx, call, target, nil)
	if err != nil {
		return nil, nil, err
	}
	httpResponse, err := client.httpClient.Do(httpRequest) //nolint:bodyclose // closed below, or by the caller through Download
	if err != nil {
		return nil, nil, fmt.Errorf("%s %s: %w", call.method, call.path, err)
	}
	if httpResponse.StatusCode >= 200 && httpResponse.StatusCode <= 299 {
		return newDownload(httpResponse), nil, nil
	}
	defer func() { _ = httpResponse.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(httpResponse.Body, maxErrorBody))
	if err != nil {
		return nil, nil, fmt.Errorf("%s %s: read response: %w", call.method, call.path, err)
	}
	return nil, &response{status: httpResponse.StatusCode, header: httpResponse.Header, body: body}, nil
}

func newDownload(httpResponse *http.Response) *Download {
	download := &Download{
		ReadCloser:  httpResponse.Body,
		ContentType: httpResponse.Header.Get("Content-Type"),
		Size:        httpResponse.ContentLength,
		SHA256:      httpResponse.Header.Get("X-RDNS-SHA256"),
	}
	if mediaType, _, err := mime.ParseMediaType(download.ContentType); err == nil {
		download.ContentType = mediaType
	}
	if _, params, err := mime.ParseMediaType(httpResponse.Header.Get("Content-Disposition")); err == nil {
		download.Filename = params["filename"]
	}
	if download.Size < 0 {
		if length, err := strconv.ParseInt(httpResponse.Header.Get("Content-Length"), 10, 64); err == nil {
			download.Size = length
		}
	}
	return download
}
