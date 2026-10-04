package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestLoadConfig_ReadsMultiClientYAML(t *testing.T) {
	yaml := `
clients:
  - id: app
    hosts: [app.example.com]
    secret: "0123456789abcdef0123456789abcdef"
    provider:
      url: https://idp.example.com
      clientId: client
    cookieNamePrefix: app
`
	path := writeYAML(t, yaml)
	t.Setenv("CONFIG_FILE", path)

	cfg, err := parseMultiConfigFile(configFilePath())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.Clients) != 1 {
		t.Fatalf("clients=%d", len(cfg.Clients))
	}
	if cfg.Clients[0].Config.Provider.Url != "https://idp.example.com" {
		t.Fatalf("Provider.Url=%q", cfg.Clients[0].Config.Provider.Url)
	}
	if !cfg.Clients[0].Config.Provider.UsePkceBool {
		t.Fatal("UsePkceBool should default true")
	}
}

func TestLoadConfig_MissingFile(t *testing.T) {
	t.Setenv("CONFIG_FILE", filepath.Join(t.TempDir(), "missing.yaml"))

	if _, err := parseMultiConfigFile(configFilePath()); err == nil {
		t.Fatal("expected error for missing config file")
	}
}

func TestForwardedRequest_RewritesFromXForwardedHeaders(t *testing.T) {
	var gotMethod, gotPath, gotRawQuery, gotHost, gotRequestURI string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotRawQuery = r.URL.RawQuery
		gotHost = r.Host
		gotRequestURI = r.RequestURI
		w.WriteHeader(http.StatusOK)
	})

	// Simulates Traefik forwardAuth: the auth server itself is always called
	// at "/", the client's real request is described via X-Forwarded-*.
	req := httptest.NewRequest(http.MethodGet, "http://auth-server/", nil)
	req.RemoteAddr = "10.0.0.5:443"
	req.Header.Set("X-Forwarded-Method", "POST")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	req.Header.Set("X-Forwarded-Uri", "/oidc/callback?state=abc&code=xyz")

	trusted, err := parseTrustedProxies("10.0.0.0/24")
	if err != nil {
		t.Fatalf("parseTrustedProxies: %v", err)
	}

	rw := httptest.NewRecorder()
	forwardedRequest(trusted, next).ServeHTTP(rw, req)

	if gotMethod != "POST" {
		t.Fatalf("Method=%q want POST", gotMethod)
	}
	if gotPath != "/oidc/callback" {
		t.Fatalf("Path=%q want /oidc/callback", gotPath)
	}
	if gotRawQuery != "state=abc&code=xyz" {
		t.Fatalf("RawQuery=%q", gotRawQuery)
	}
	if gotHost != "app.example.com" {
		t.Fatalf("Host=%q", gotHost)
	}
	if gotRequestURI != "/oidc/callback?state=abc&code=xyz" {
		t.Fatalf("RequestURI=%q", gotRequestURI)
	}
}

func TestForwardedRequest_FallsBackWithoutHeaders(t *testing.T) {
	var gotPath string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "http://auth-server/direct-path", nil)
	req.RemoteAddr = "10.0.0.5:443"
	trusted, err := parseTrustedProxies("10.0.0.0/24")
	if err != nil {
		t.Fatalf("parseTrustedProxies: %v", err)
	}

	rw := httptest.NewRecorder()
	forwardedRequest(trusted, next).ServeHTTP(rw, req)

	if gotPath != "/direct-path" {
		t.Fatalf("Path=%q want /direct-path (fallback)", gotPath)
	}
}

func TestForwardedRequest_RejectsInvalidUri(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next must not be called for invalid X-Forwarded-Uri")
	})

	req := httptest.NewRequest(http.MethodGet, "http://auth-server/", nil)
	req.RemoteAddr = "10.0.0.5:443"
	req.Header.Set("X-Forwarded-Uri", "not a valid uri \x7f")
	trusted, err := parseTrustedProxies("10.0.0.0/24")
	if err != nil {
		t.Fatalf("parseTrustedProxies: %v", err)
	}

	rw := httptest.NewRecorder()
	forwardedRequest(trusted, next).ServeHTTP(rw, req)

	if rw.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", rw.Code)
	}
}

// TestForwardedRequest_IgnoresHeadersFromUntrustedPeer is the regression
// test for the vulnerability this gates against (same class as
// CVE-2026-40575 in oauth2-proxy): a caller that isn't in trustedProxies
// must not be able to spoof X-Forwarded-Uri to redirect request routing to
// an arbitrary path (e.g. /oidc/callback) it wasn't actually sent to.
func TestForwardedRequest_IgnoresHeadersFromUntrustedPeer(t *testing.T) {
	var gotPath string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "http://auth-server/actual-path", nil)
	req.RemoteAddr = "203.0.113.7:12345" // not in the trusted range
	req.Header.Set("X-Forwarded-Uri", "/oidc/callback?state=forged&code=forged")
	trusted, err := parseTrustedProxies("10.0.0.0/24")
	if err != nil {
		t.Fatalf("parseTrustedProxies: %v", err)
	}

	rw := httptest.NewRecorder()
	forwardedRequest(trusted, next).ServeHTTP(rw, req)

	if gotPath != "/actual-path" {
		t.Fatalf("Path=%q want /actual-path (X-Forwarded-Uri from untrusted peer must be ignored)", gotPath)
	}
}

func TestForwardedRequest_NoTrustedProxiesConfigured_NeverHonorsHeaders(t *testing.T) {
	var gotPath string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "http://auth-server/actual-path", nil)
	req.RemoteAddr = "10.0.0.5:443"
	req.Header.Set("X-Forwarded-Uri", "/oidc/callback")

	rw := httptest.NewRecorder()
	forwardedRequest(nil, next).ServeHTTP(rw, req) // trustedProxies unset

	if gotPath != "/actual-path" {
		t.Fatalf("Path=%q want /actual-path (no trusted proxies configured -> never honor headers)", gotPath)
	}
}

func TestParseTrustedProxies(t *testing.T) {
	nets, err := parseTrustedProxies("10.0.0.0/8, 192.168.1.1, ::1")
	if err != nil {
		t.Fatalf("parseTrustedProxies: %v", err)
	}
	if len(nets) != 3 {
		t.Fatalf("got %d networks, want 3", len(nets))
	}

	if !nets[0].Contains(net.ParseIP("10.1.2.3")) {
		t.Fatal("10.0.0.0/8 should contain 10.1.2.3")
	}
	if !nets[1].Contains(net.ParseIP("192.168.1.1")) {
		t.Fatal("bare IPv4 should be treated as /32")
	}
	if nets[1].Contains(net.ParseIP("192.168.1.2")) {
		t.Fatal("bare IPv4 /32 must not match a different address")
	}
	if !nets[2].Contains(net.ParseIP("::1")) {
		t.Fatal("bare IPv6 should be treated as /128")
	}
}

func TestParseTrustedProxies_Empty(t *testing.T) {
	nets, err := parseTrustedProxies("")
	if err != nil {
		t.Fatalf("parseTrustedProxies: %v", err)
	}
	if len(nets) != 0 {
		t.Fatalf("got %d networks, want 0", len(nets))
	}
}

func TestParseTrustedProxies_Invalid(t *testing.T) {
	if _, err := parseTrustedProxies("not-an-ip"); err == nil {
		t.Fatal("expected error for invalid entry")
	}
}
