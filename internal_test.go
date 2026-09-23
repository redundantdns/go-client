package redundantdns

import (
	"errors"
	"net/http"
	"slices"
	"testing"
	"time"
)

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		value string
		want  time.Duration
		ok    bool
	}{
		{"", 0, false},
		{"7", 7 * time.Second, true},
		{"-1", 0, false},
		{"soon", 0, false},
		{now.Add(90 * time.Second).Format(http.TimeFormat), 90 * time.Second, true},
		{now.Add(-time.Minute).Format(http.TimeFormat), 0, true},
	}
	for _, testCase := range cases {
		got, ok := parseRetryAfter(testCase.value, now)
		if got != testCase.want || ok != testCase.ok {
			t.Errorf("parseRetryAfter(%q) = %v, %v; want %v, %v", testCase.value, got, ok, testCase.want, testCase.ok)
		}
	}
}

func TestRetryPolicyNext(t *testing.T) {
	policy := RetryPolicy{MaxRetries: 2, BaseDelay: 100 * time.Millisecond, MaxDelay: time.Second}
	answer := func(status int, retryAfter string) *response {
		header := http.Header{}
		if retryAfter != "" {
			header.Set("Retry-After", retryAfter)
		}
		return &response{status: status, header: header}
	}
	cases := []struct {
		name    string
		method  string
		attempt int
		answer  *response
		err     error
		retry   bool
	}{
		{"429 POST", http.MethodPost, 0, answer(429, ""), nil, true},
		{"503 GET", http.MethodGet, 0, answer(503, ""), nil, true},
		{"503 POST", http.MethodPost, 0, answer(503, ""), nil, false},
		{"501 GET", http.MethodGet, 0, answer(501, ""), nil, false},
		{"404 GET", http.MethodGet, 0, answer(404, ""), nil, false},
		{"200 GET", http.MethodGet, 0, answer(200, ""), nil, false},
		{"network GET", http.MethodGet, 0, nil, errors.New("connection reset"), true},
		{"network POST", http.MethodPost, 0, nil, errors.New("connection reset"), false},
		{"exhausted", http.MethodGet, 2, answer(503, ""), nil, false},
	}
	for _, testCase := range cases {
		_, retry := policy.next(testCase.method, testCase.attempt, testCase.answer, testCase.err)
		if retry != testCase.retry {
			t.Errorf("%s: retry = %v, want %v", testCase.name, retry, testCase.retry)
		}
	}
	delay, _ := policy.next(http.MethodGet, 0, answer(429, "3"), nil)
	if delay != time.Second {
		t.Errorf("Retry-After must be capped by MaxDelay, got %v", delay)
	}
	delay, _ = policy.next(http.MethodGet, 1, answer(503, ""), nil)
	if delay < 160*time.Millisecond || delay > 240*time.Millisecond {
		t.Errorf("second backoff = %v, want about 200ms", delay)
	}
}

func TestNormalize(t *testing.T) {
	cases := []struct {
		recordType string
		in         []string
		want       []string
	}{
		{"A", []string{"192.0.2.010", " 192.0.2.1 ", "192.0.2.1", ""}, []string{"192.0.2.1", "192.0.2.10"}},
		{"AAAA", []string{"2001:DB8:0:0::1"}, []string{"2001:db8::1"}},
		{"CNAME", []string{"Target.Example.COM"}, []string{"target.example.com."}},
		{"MX", []string{"010 Mail.Example.com"}, []string{"10 mail.example.com."}},
		{"SRV", []string{"10 5 0443 sip.example.com."}, []string{"10 5 443 sip.example.com."}},
		{"CAA", []string{`0 ISSUE letsencrypt.org`}, []string{`0 issue "letsencrypt.org"`}},
		{"TXT", []string{`v=spf1 -all`, `"v=spf1" " -all"`}, []string{`"v=spf1 -all"`}},
		{"txt", []string{`say "hi"`}, []string{`"say \"hi\""`}},
	}
	for _, testCase := range cases {
		got := NormalizeRecordValues(testCase.recordType, testCase.in)
		if !slices.Equal(got, testCase.want) {
			t.Errorf("%s %q = %q, want %q", testCase.recordType, testCase.in, got, testCase.want)
		}
	}
	names := map[string]string{"": "@", "@": "@", "Example.com.": "@", "WWW.example.com.": "www", "a.b": "a.b", "api": "api"}
	for in, want := range names {
		if got := NormalizeRecordName("example.com", in); got != want {
			t.Errorf("NormalizeRecordName(%q) = %q, want %q", in, got, want)
		}
	}
	if !EqualRecordValues("CNAME", []string{"a.example.com"}, []string{"A.example.com."}) {
		t.Error("EqualRecordValues must ignore case and the trailing dot")
	}
}

func TestPathEscaping(t *testing.T) {
	client, err := New(WithBaseURL("https://example.com/prefix/"))
	if err != nil {
		t.Fatal(err)
	}
	got := client.resolve(pathf("/v1/zones/%s", "a/b c"), nil)
	if got != "https://example.com/prefix/v1/zones/a%2Fb%20c" {
		t.Errorf("resolve = %q", got)
	}
}
