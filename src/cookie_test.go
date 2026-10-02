package src

import (
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/BlackDark/test-oidc-traefik-plugin/src/config"
	"github.com/BlackDark/test-oidc-traefik-plugin/src/logging"
	"github.com/BlackDark/test-oidc-traefik-plugin/src/session"
)

func TestSetChunkedCookiesNonChunked(t *testing.T) {
	config := &config.Config{
		CookieNamePrefix: "TraefikOidcAuth",
		SessionCookie: &config.SessionCookieConfig{
			Path:     "/",
			Domain:   "",
			Secure:   true,
			HttpOnly: true,
			SameSite: "default",
			MaxAge:   0,
		},
	}

	rw := newMockResponseWriter()

	setChunkedCookies(config, rw, "TraefikOidcAuth.Session", "some-short-value")

	setCookieHeader := rw.HeaderMap.Get("Set-Cookie")

	if setCookieHeader != "TraefikOidcAuth.Session=some-short-value; Path=/; HttpOnly; Secure" {
		t.Fail()
	}
}

func TestSetChunkedCookiesChunked(t *testing.T) {
	config := &config.Config{
		CookieNamePrefix: "TraefikOidcAuth",
		SessionCookie: &config.SessionCookieConfig{
			Path:     "/",
			Domain:   "",
			Secure:   true,
			HttpOnly: true,
			SameSite: "default",
			MaxAge:   0,
		},
	}

	rw := newMockResponseWriter()

	longValue := randomFixedLengthString(4000)

	setChunkedCookies(config, rw, "TraefikOidcAuth.Session", longValue)

	setCookieHeader := rw.HeaderMap.Values("Set-Cookie")

	if len(setCookieHeader) != 3 {
		t.Fail()
	}

	if setCookieHeader[0] != "TraefikOidcAuth.Session.Chunks=2; Path=/; HttpOnly; Secure" {
		t.Fail()
	}
	if setCookieHeader[1] != fmt.Sprintf("TraefikOidcAuth.Session.1=%s; Path=/; HttpOnly; Secure", longValue[:3072]) {
		t.Fail()
	}
	if setCookieHeader[2] != fmt.Sprintf("TraefikOidcAuth.Session.2=%s; Path=/; HttpOnly; Secure", longValue[3072:]) {
		t.Fail()
	}
}

func TestReadChunkedCookieOrdered(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fail()
	}

	req.AddCookie(&http.Cookie{
		Name:  "TraefikOidcAuth.Session.Chunks",
		Value: "3",
	})
	req.AddCookie(&http.Cookie{
		Name:  "TraefikOidcAuth.Session.1",
		Value: "111",
	})
	req.AddCookie(&http.Cookie{
		Name:  "TraefikOidcAuth.Session.2",
		Value: "222",
	})
	req.AddCookie(&http.Cookie{
		Name:  "TraefikOidcAuth.Session.3",
		Value: "333",
	})

	cookieValue, err := readChunkedCookie(req, "TraefikOidcAuth.Session")
	if err != nil {
		t.Fail()
	}

	if cookieValue != "111222333" {
		t.Fail()
	}
}

func TestReadChunkedCookieUnordered(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fail()
	}

	req.AddCookie(&http.Cookie{
		Name:  "TraefikOidcAuth.Session.3",
		Value: "333",
	})
	req.AddCookie(&http.Cookie{
		Name:  "TraefikOidcAuth.Session.Chunks",
		Value: "3",
	})
	req.AddCookie(&http.Cookie{
		Name:  "TraefikOidcAuth.Session.1",
		Value: "111",
	})
	req.AddCookie(&http.Cookie{
		Name:  "TraefikOidcAuth.Session.2",
		Value: "222",
	})

	cookieValue, err := readChunkedCookie(req, "TraefikOidcAuth.Session")
	if err != nil {
		t.Fail()
	}

	if cookieValue != "111222333" {
		t.Fail()
	}
}

func TestReadChunkedCookieWithIncompleteChunks(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fail()
	}

	req.AddCookie(&http.Cookie{
		Name:  "TraefikOidcAuth.Session.Chunks",
		Value: "3",
	})
	req.AddCookie(&http.Cookie{
		Name:  "TraefikOidcAuth.Session.1",
		Value: "111",
	})
	req.AddCookie(&http.Cookie{
		Name:  "TraefikOidcAuth.Session.2",
		Value: "222",
	})

	cookieValue, err := readChunkedCookie(req, "TraefikOidcAuth.Session")

	// readChunkedCookie should fail
	if err == nil || cookieValue != "" {
		t.Fail()
	}
}

func TestReadChunkedCookieWithNoCount(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fail()
	}

	req.AddCookie(&http.Cookie{
		Name:  "TraefikOidcAuth.Session.3",
		Value: "333",
	})
	req.AddCookie(&http.Cookie{
		Name:  "TraefikOidcAuth.Session.1",
		Value: "111",
	})
	req.AddCookie(&http.Cookie{
		Name:  "TraefikOidcAuth.Session.2",
		Value: "222",
	})

	cookieValue, err := readChunkedCookie(req, "TraefikOidcAuth.Session")

	// readChunkedCookie should fail
	if err == nil || cookieValue != "" {
		t.Fail()
	}
}

type mockResponseWriter struct {
	HeaderMap http.Header
}

func newMockResponseWriter() *mockResponseWriter {
	return &mockResponseWriter{
		HeaderMap: make(http.Header),
	}
}

func (writer *mockResponseWriter) Header() http.Header {
	return writer.HeaderMap
}

func (writer *mockResponseWriter) Write([]byte) (int, error) {
	return 0, nil
}

func (writer *mockResponseWriter) WriteHeader(statusCode int) {
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randomFixedLengthString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func TestClearLegacyCodeVerifierCookies_ExpiresHostnameAndHostOnly(t *testing.T) {
	cfg := &config.Config{CookieNamePrefix: "TraefikOidcAuth"}
	callback, err := url.Parse("https://app.example.com:8443/oidc/callback")
	if err != nil {
		t.Fatal(err)
	}
	rw := newMockResponseWriter()
	req, err := http.NewRequest(http.MethodGet, "https://app.example.com:8443/oidc/callback", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: "TraefikOidcAuth.CodeVerifier", Value: "legacy"})

	clearLegacyCodeVerifierCookies(cfg, rw, req, callback)

	headers := rw.HeaderMap.Values("Set-Cookie")
	hasHostname := false
	hasHostOnly := false
	for _, raw := range headers {
		if !strings.HasPrefix(raw, "TraefikOidcAuth.CodeVerifier=") {
			continue
		}
		lower := strings.ToLower(raw)
		// Go serializes MaxAge=-1 as Max-Age=0.
		if !strings.Contains(lower, "max-age=0") && !strings.Contains(lower, "max-age=-1") {
			t.Fatalf("expected expired cookie: %s", raw)
		}
		switch {
		case strings.Contains(raw, "Domain=app.example.com"):
			hasHostname = true
		case !strings.Contains(lower, "domain="):
			hasHostOnly = true
		}
	}
	if !hasHostname || !hasHostOnly {
		t.Fatalf("missing domain variants hostname=%v hostOnly=%v headers=%v",
			hasHostname, hasHostOnly, headers)
	}
}

func TestValidateLoginCsrf(t *testing.T) {
	cfg := &config.Config{CookieNamePrefix: "TraefikOidcAuth"}
	csrf := "abc123csrfvalue"

	t.Run("ok", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://app.example.com/oidc/callback", nil)
		req.AddCookie(&http.Cookie{Name: getLoginCsrfCookieName(cfg, csrf), Value: csrf})
		if err := validateLoginCsrf(cfg, req, csrf); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("missing_cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://app.example.com/oidc/callback", nil)
		if err := validateLoginCsrf(cfg, req, csrf); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("mismatch", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://app.example.com/oidc/callback", nil)
		req.AddCookie(&http.Cookie{Name: getLoginCsrfCookieName(cfg, csrf), Value: "other"})
		if err := validateLoginCsrf(cfg, req, csrf); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("missing_state_csrf", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://app.example.com/oidc/callback", nil)
		if err := validateLoginCsrf(cfg, req, ""); err == nil {
			t.Fatal("expected error")
		}
	})
}

func testCookieConfig() *config.Config {
	return &config.Config{
		CookieNamePrefix: "TraefikOidcAuth",
		SessionCookie: &config.SessionCookieConfig{
			Path:     "/",
			Domain:   "",
			Secure:   true,
			HttpOnly: true,
			SameSite: "lax",
			MaxAge:   0,
		},
	}
}

func TestGetChunkedCookieCount(t *testing.T) {
	const name = "TraefikOidcAuth.Session"

	tests := []struct {
		name      string
		chunks    string
		wantCount int
		wantErr   bool
	}{
		{name: "no chunks cookie", chunks: "", wantCount: 0},
		{name: "zero", chunks: "0", wantCount: 0},
		{name: "one", chunks: "1", wantCount: 1},
		{name: "two", chunks: "2", wantCount: 2},
		{name: "max", chunks: strconv.Itoa(MaxSessionCookieChunks), wantCount: MaxSessionCookieChunks},
		{name: "negative", chunks: "-1", wantErr: true},
		{name: "over max", chunks: strconv.Itoa(MaxSessionCookieChunks + 1), wantErr: true},
		{name: "hostile huge", chunks: "2000000000", wantErr: true},
		{name: "not a number", chunks: "abc", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil)
			if tc.chunks != "" {
				req.AddCookie(&http.Cookie{Name: name + ".Chunks", Value: tc.chunks})
			}

			count, err := getChunkedCookieCount(req, name)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for Chunks=%q, got count=%d", tc.chunks, count)
				}
				if count != 0 {
					t.Fatalf("rejected chunk count must not be returned, got %d", count)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if count != tc.wantCount {
				t.Fatalf("count = %d, want %d", count, tc.wantCount)
			}
		})
	}
}

func TestClearChunkedCookieHostileChunkCountIsBounded(t *testing.T) {
	cfg := testCookieConfig()
	const name = "TraefikOidcAuth.Session"

	for _, hostile := range []string{"2000000000", strconv.Itoa(MaxSessionCookieChunks + 1), "-1", "abc"} {
		t.Run(hostile, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil)
			req.AddCookie(&http.Cookie{Name: name + ".Chunks", Value: hostile})

			rw := newMockResponseWriter()
			// Error may be returned, but it must never be more than the bounded pair.
			_ = clearChunkedCookie(cfg, rw, req, name)

			if got := len(rw.HeaderMap.Values("Set-Cookie")); got > 2 {
				t.Fatalf("emitted %d Set-Cookie headers for Chunks=%q, want <= 2", got, hostile)
			}
		})
	}
}

func TestClearChunkedCookieMaxChunks(t *testing.T) {
	cfg := testCookieConfig()
	const name = "TraefikOidcAuth.Session"

	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil)
	req.AddCookie(&http.Cookie{Name: name + ".Chunks", Value: strconv.Itoa(MaxSessionCookieChunks)})

	rw := newMockResponseWriter()
	if err := clearChunkedCookie(cfg, rw, req, name); err != nil {
		t.Fatal(err)
	}

	// Chunks header + one expiry per chunk.
	if got, want := len(rw.HeaderMap.Values("Set-Cookie")), MaxSessionCookieChunks+1; got != want {
		t.Fatalf("emitted %d Set-Cookie headers, want %d", got, want)
	}
	for _, raw := range rw.HeaderMap.Values("Set-Cookie") {
		if !strings.Contains(strings.ToLower(raw), "max-age=0") && !strings.Contains(strings.ToLower(raw), "max-age=-1") {
			t.Fatalf("expected expired cookie, got %s", raw)
		}
	}
}

func TestClearChunkedCookieWithoutSession(t *testing.T) {
	cfg := testCookieConfig()
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil)
	rw := newMockResponseWriter()

	if err := clearChunkedCookie(cfg, rw, req, getSessionCookieName(cfg)); err != nil {
		t.Fatal(err)
	}

	got := rw.HeaderMap.Values("Set-Cookie")
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 Set-Cookie header, got %d: %v", len(got), got)
	}
	if !strings.HasPrefix(got[0], "TraefikOidcAuth.Session=;") {
		t.Fatalf("unexpected cookie: %s", got[0])
	}
}

func TestChunkedCookieRoundTrip(t *testing.T) {
	cfg := testCookieConfig()
	name := getSessionCookieName(cfg)

	for _, size := range []int{1, 16, sessionCookieChunkSize, sessionCookieChunkSize + 1, 2 * sessionCookieChunkSize, 40000} {
		want := randomFixedLengthString(size)

		t.Run(strconv.Itoa(size), func(t *testing.T) {
			rw := newMockResponseWriter()
			setChunkedCookies(cfg, rw, name, want)

			req := httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil)
			for _, raw := range rw.HeaderMap.Values("Set-Cookie") {
				c, err := http.ParseSetCookie(raw)
				if err != nil {
					t.Fatalf("parse %q: %v", raw, err)
				}
				req.AddCookie(c)
			}

			got, err := readChunkedCookie(req, name)
			if err != nil {
				t.Fatalf("readChunkedCookie: %v", err)
			}
			if got != want {
				t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), len(want))
			}
		})
	}
}

func TestReadChunkedCookieMissingChunk(t *testing.T) {
	const name = "TraefikOidcAuth.Session"

	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil)
	req.AddCookie(&http.Cookie{Name: name + ".Chunks", Value: "3"})
	req.AddCookie(&http.Cookie{Name: name + ".1", Value: "111"})
	// .2 and .3 missing

	value, err := readChunkedCookie(req, name)
	if err == nil {
		t.Fatalf("expected error for missing chunks, got value %q", value)
	}
	if value != "" {
		t.Fatalf("expected empty value on error, got %q", value)
	}
}

func TestReadChunkedCookieRejectsHostileCount(t *testing.T) {
	const name = "TraefikOidcAuth.Session"

	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil)
	req.AddCookie(&http.Cookie{Name: name + ".Chunks", Value: "2000000000"})

	if value, err := readChunkedCookie(req, name); err == nil || value != "" {
		t.Fatalf("expected rejection of hostile chunk count, got value=%q err=%v", value, err)
	}
}

// TestSetChunkedCookiesClampsEmittedChunksToReadableBound keeps the bound on the
// number of emitted headers, but no longer treats the clamped value as usable:
// what is asserted is that whatever setChunkedCookies emits is READABLE BACK by
// readChunkedCookie for any value the caller is allowed to store (i.e. anything
// within MaxTicketSize). The clamping path is a last-resort guard, not a
// truncation strategy: session.ErrSessionTooLarge rejects an oversized ticket
// upstream, so this test's job is only to prove the clamp can never itself
// produce a cookie whose own .Chunks header disagrees with the chunks emitted.
func TestSetChunkedCookiesClampsEmittedChunksToReadableBound(t *testing.T) {
	cfg := testCookieConfig()
	name := getSessionCookieName(cfg)

	t.Run("within budget round-trips exactly", func(t *testing.T) {
		want := randomFixedLengthString(MaxSessionCookieChunks * sessionCookieChunkSize)

		rw := newMockResponseWriter()
		setChunkedCookies(cfg, rw, name, want)

		headers := rw.HeaderMap.Values("Set-Cookie")
		if got, wantN := len(headers), MaxSessionCookieChunks+1; got != wantN {
			t.Fatalf("emitted %d Set-Cookie headers, want %d", got, wantN)
		}
		if headers[0] != fmt.Sprintf("%s.Chunks=%d; Path=/; HttpOnly; Secure; SameSite=Lax", name, MaxSessionCookieChunks) {
			t.Fatalf("unexpected chunks header: %s", headers[0])
		}

		got := readBackChunkedCookie(t, headers, name)
		if got != want {
			t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), len(want))
		}
	})

	t.Run("oversized value stays internally consistent", func(t *testing.T) {
		// The caller should have rejected this already (ErrSessionTooLarge). If it
		// reaches setChunkedCookies anyway, the emitted .Chunks header and the
		// emitted chunk cookies must still agree, so readChunkedCookie returns
		// cleanly-truncated data rather than erroring.
		want := randomFixedLengthString(sessionCookieChunkSize * (MaxSessionCookieChunks + 5))

		rw := newMockResponseWriter()
		setChunkedCookies(cfg, rw, name, want)

		headers := rw.HeaderMap.Values("Set-Cookie")
		if got, wantN := len(headers), MaxSessionCookieChunks+1; got != wantN {
			t.Fatalf("emitted %d Set-Cookie headers, want %d", got, wantN)
		}

		got := readBackChunkedCookie(t, headers, name)
		if got != want[:sessionCookieChunkSize*MaxSessionCookieChunks] {
			t.Fatalf("clamped value is not a consistent prefix: got %d bytes, want %d",
				len(got), sessionCookieChunkSize*MaxSessionCookieChunks)
		}
		if len(got) > MaxSessionCookieSize {
			t.Fatalf("clamped value of %d bytes still exceeds the storeable budget %d", len(got), MaxSessionCookieSize)
		}
	})
}

// TestStoreAndEmitSessionTicket_EndToEnd is the assertion that would have caught
// the original truncation bug in the exact place it bit: an oversized session
// ticket must be rejected by storage, so no cookie is ever emitted. Before the
// fix the ticket was clamped into 32 chunks, emitted, and then failed to decrypt
// on the very next request - a permanent, silent re-login loop.
func TestStoreAndEmitSessionTicket_EndToEnd(t *testing.T) {
	cfg := testCookieConfig()
	cfg.Secret = "0123456789abcdef0123456789abcdef"
	name := getSessionCookieName(cfg)
	storage := session.CreateCookieSessionStorage()
	logger := logging.CreateLogger(logging.LevelDebug)

	// Comfortably over the cookie budget once serialized and encrypted.
	oversized := &session.SessionState{
		Id:           "e2e-session",
		AccessToken:  randomFixedLengthString(MaxSessionCookieSize + 4096),
		IdToken:      randomFixedLengthString(MaxSessionCookieSize + 4096),
		IsAuthorized: true,
	}

	rw := newMockResponseWriter()
	ticket, err := storage.StoreSession(logger, cfg, oversized.Id, oversized)
	if err == nil {
		setChunkedCookies(cfg, rw, name, ticket)

		headers := rw.HeaderMap.Values("Set-Cookie")
		req := httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil)
		for _, raw := range headers {
			c, parseErr := http.ParseSetCookie(raw)
			if parseErr != nil {
				t.Fatalf("parse %q: %v", raw, parseErr)
			}
			req.AddCookie(c)
		}

		got, readErr := readChunkedCookie(req, name)
		if readErr == nil {
			if _, decErr := storage.TryGetSession(logger, cfg, got); decErr == nil {
				t.Fatal("emitted cookie must either round-trip or be rejected at store time, never decrypt into a broken session")
			}
		}
		t.Fatal("oversized session was stored and emitted instead of being rejected with ErrSessionTooLarge")
	}
	if !errors.Is(err, session.ErrSessionTooLarge) {
		t.Fatalf("err = %v, want session.ErrSessionTooLarge", err)
	}
	if got := rw.HeaderMap.Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("nothing may be emitted for a rejected session, got %v", got)
	}

	// The same session, comfortably under budget, must still work end to end.
	ok := &session.SessionState{
		Id:           "e2e-session-ok",
		AccessToken:  randomFixedLengthString(2048),
		IdToken:      randomFixedLengthString(2048),
		IsAuthorized: true,
	}
	okTicket, err := storage.StoreSession(logger, cfg, ok.Id, ok)
	if err != nil {
		t.Fatalf("StoreSession on a normal session: %v", err)
	}
	setChunkedCookies(cfg, rw, name, okTicket)
	loaded, err := storage.TryGetSession(logger, cfg, readBackChunkedCookie(t, rw.HeaderMap.Values("Set-Cookie"), name))
	if err != nil {
		t.Fatalf("TryGetSession after cookie round-trip: %v", err)
	}
	if loaded.Id != ok.Id || loaded.AccessToken != ok.AccessToken || loaded.IdToken != ok.IdToken || !loaded.IsAuthorized {
		t.Fatalf("cookie round-trip mismatch: %+v", loaded)
	}
}

// readBackChunkedCookie replays the emitted Set-Cookie headers onto a request and
// reads them back with readChunkedCookie, failing the test if the read errors.
func readBackChunkedCookie(t *testing.T, headers []string, name string) string {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil)
	for _, raw := range headers {
		c, err := http.ParseSetCookie(raw)
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		req.AddCookie(c)
	}

	got, err := readChunkedCookie(req, name)
	if err != nil {
		t.Fatalf("readChunkedCookie after emit: %v", err)
	}
	return got
}

func TestParseCookieSameSite(t *testing.T) {
	tests := []struct {
		in      string
		want    http.SameSite
		wantErr bool
	}{
		{in: "lax", want: http.SameSiteLaxMode},
		{in: "strict", want: http.SameSiteStrictMode},
		{in: "none", want: http.SameSiteNoneMode},
		{in: "", want: http.SameSiteDefaultMode},
		{in: "default", want: http.SameSiteDefaultMode},
		{in: "Lax", wantErr: true},
		{in: "bogus", wantErr: true},
		{in: "none; secure", wantErr: true},
	}

	for _, tc := range tests {
		t.Run("in="+tc.in, func(t *testing.T) {
			mode, err := parseCookieSameSiteChecked(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tc.in)
				}
				// Must never silently degrade to SameSiteDefaultMode (no attribute).
				if mode == http.SameSiteDefaultMode {
					t.Fatalf("unknown value %q degraded to SameSiteDefaultMode", tc.in)
				}
				// The lenient wrapper must also fail closed, never to DefaultMode.
				if got := parseCookieSameSite(tc.in); got == http.SameSiteDefaultMode {
					t.Fatalf("parseCookieSameSite(%q) = SameSiteDefaultMode", tc.in)
				} else if got != http.SameSiteLaxMode {
					t.Fatalf("parseCookieSameSite(%q) = %v, want Lax", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if mode != tc.want {
				t.Fatalf("mode = %v, want %v", mode, tc.want)
			}
			if got := parseCookieSameSite(tc.in); got != tc.want {
				t.Fatalf("parseCookieSameSite(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestSetChunkedCookiesUsesNonDefaultSameSite(t *testing.T) {
	cfg := testCookieConfig()
	cfg.SessionCookie.SameSite = "bogus"
	rw := newMockResponseWriter()

	setChunkedCookies(cfg, rw, getSessionCookieName(cfg), "value")

	got := rw.HeaderMap.Get("Set-Cookie")
	if !strings.Contains(got, "SameSite=Lax") {
		t.Fatalf("invalid configured same_site must fall back to Lax, got %q", got)
	}
	if strings.Contains(got, "SameSite=Default") || strings.Contains(got, "SameSite=1") {
		t.Fatalf("invalid configured same_site leaked a default mode: %q", got)
	}
}

func TestLoginCsrfCookieAttributes(t *testing.T) {
	csrf := "csrf-token-value"
	callback, err := url.Parse("https://app.example.com:8443/oidc/callback")
	if err != nil {
		t.Fatal(err)
	}

	for _, secure := range []bool{true, false} {
		t.Run("secure="+strconv.FormatBool(secure), func(t *testing.T) {
			cfg := testCookieConfig()
			cfg.SessionCookie.Secure = secure

			rw := newMockResponseWriter()
			setLoginCsrfCookie(cfg, rw, callback, csrf)

			headers := rw.HeaderMap.Values("Set-Cookie")
			if len(headers) != 1 {
				t.Fatalf("expected 1 Set-Cookie, got %d", len(headers))
			}
			c, err := http.ParseSetCookie(headers[0])
			if err != nil {
				t.Fatal(err)
			}
			if c.Name != getLoginCsrfCookieName(cfg, csrf) {
				t.Fatalf("name = %s", c.Name)
			}
			if c.Domain != "" {
				t.Fatalf("CSRF cookie must stay host-only, got Domain=%q", c.Domain)
			}
			if !c.HttpOnly {
				t.Fatal("CSRF cookie must be HttpOnly")
			}
			if c.Secure != secure {
				t.Fatalf("Secure = %v, want %v", c.Secure, secure)
			}
			if c.SameSite != http.SameSiteLaxMode {
				t.Fatalf("SameSite = %v, want Lax", c.SameSite)
			}
			if c.Path != callback.Path {
				t.Fatalf("Path = %q, want %q", c.Path, callback.Path)
			}
			if c.MaxAge != loginCsrfMaxAge {
				t.Fatalf("MaxAge = %d, want %d", c.MaxAge, loginCsrfMaxAge)
			}

			rw2 := newMockResponseWriter()
			clearLoginCsrfCookie(cfg, rw2, callback, csrf)
			cc, err := http.ParseSetCookie(rw2.HeaderMap.Get("Set-Cookie"))
			if err != nil {
				t.Fatal(err)
			}
			if cc.Value != "" || cc.MaxAge >= 0 {
				t.Fatalf("clear must expire the CSRF cookie, got %s", rw2.HeaderMap.Get("Set-Cookie"))
			}
			if !cc.HttpOnly || cc.Domain != "" || cc.Secure != secure {
				t.Fatalf("clear must preserve cookie hardening: %s", rw2.HeaderMap.Get("Set-Cookie"))
			}
		})
	}
}

func TestClearLegacyCodeVerifierCookiesBounded(t *testing.T) {
	cfg := &config.Config{CookieNamePrefix: "TraefikOidcAuth"}
	callback, err := url.Parse("https://app.example.com:8443/oidc/callback")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com:8443/oidc/callback", nil)
	for i := 0; i < 1000; i++ {
		req.AddCookie(&http.Cookie{Name: fmt.Sprintf("TraefikOidcAuth.CodeVerifier.%d", i), Value: "x"})
	}

	rw := newMockResponseWriter()
	clearLegacyCodeVerifierCookies(cfg, rw, req, callback)

	if got := len(rw.HeaderMap.Values("Set-Cookie")); got > 2*(maxLegacyCookiesToExpire+1) {
		t.Fatalf("emitted %d Set-Cookie headers, want <= %d", got, 2*(maxLegacyCookiesToExpire+1))
	}
}
