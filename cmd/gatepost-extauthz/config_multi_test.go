package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/BlackDark/gatepost/src/config"
)

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"grafana.example.com", "grafana.example.com"},
		{"Grafana.Example.COM", "grafana.example.com"},
		{"grafana.example.com:443", "grafana.example.com"},
		{"GRAFANA.example.com:8443", "grafana.example.com"},
		{"  grafana.example.com  ", "grafana.example.com"},
		// Finding 6: a trailing FQDN dot is the same host (RFC 1035 5.1).
		{"grafana.example.com.", "grafana.example.com"},
		{"GRAFANA.EXAMPLE.COM.:443", "grafana.example.com"},
		{"XN--80AK6AA92E.COM.", "xn--80ak6aa92e.com"},
		{"example.com.:8443", "example.com"},
	}
	for _, tt := range tests {
		if got := normalizeHost(tt.in); got != tt.want {
			t.Fatalf("normalizeHost(%q)=%q want %q", tt.in, got, tt.want)
		}
	}
}

func TestParseMultiConfig_Valid(t *testing.T) {
	yaml := `
clients:
  - id: grafana
    hosts:
      - grafana.example.com
      - Grafana.Example.COM
    secret: "0123456789abcdef0123456789abcdef"
    provider:
      url: https://idp.example.com
      clientId: grafana
      clientSecret: secret-a
    cookieNamePrefix: grafana
  - id: argo
    hosts:
      - argo.example.com
    secret: "fedcba9876543210fedcba9876543210"
    provider:
      url: https://idp.example.com
      clientId: argo
      clientSecret: secret-b
    cookieNamePrefix: argo
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := parseMultiConfigFile(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.Clients) != 2 {
		t.Fatalf("clients=%d want 2", len(cfg.Clients))
	}
	if cfg.Clients[0].ID != "grafana" {
		t.Fatalf("id=%q", cfg.Clients[0].ID)
	}
	if cfg.Clients[0].Config.Provider.ClientId != "grafana" {
		t.Fatalf("clientId=%q", cfg.Clients[0].Config.Provider.ClientId)
	}
	if cfg.Clients[1].Config.CookieNamePrefix != "argo" {
		t.Fatalf("cookieNamePrefix=%q", cfg.Clients[1].Config.CookieNamePrefix)
	}
}

func TestParseMultiConfig_RejectsEmptyClients(t *testing.T) {
	path := writeYAML(t, "clients: []\n")
	if _, err := parseMultiConfigFile(path); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseMultiConfig_RejectsDuplicateHost(t *testing.T) {
	yaml := `
clients:
  - id: a
    hosts: [app.example.com]
    secret: "0123456789abcdef0123456789abcdef"
    provider: {url: https://idp.example.com, clientId: a}
    cookieNamePrefix: a
  - id: b
    hosts: [APP.example.com:443]
    secret: "fedcba9876543210fedcba9876543210"
    provider: {url: https://idp.example.com, clientId: b}
    cookieNamePrefix: b
`
	path := writeYAML(t, yaml)
	_, err := parseMultiConfigFile(path)
	if err == nil {
		t.Fatal("expected duplicate host error")
	}
	if !strings.Contains(err.Error(), "duplicate host") {
		t.Fatalf("err=%v", err)
	}
}

func TestParseMultiConfig_RejectsDuplicateID(t *testing.T) {
	yaml := `
clients:
  - id: same
    hosts: [a.example.com]
    secret: "0123456789abcdef0123456789abcdef"
    provider: {url: https://idp.example.com, clientId: a}
    cookieNamePrefix: a
  - id: same
    hosts: [b.example.com]
    secret: "fedcba9876543210fedcba9876543210"
    provider: {url: https://idp.example.com, clientId: b}
    cookieNamePrefix: b
`
	path := writeYAML(t, yaml)
	_, err := parseMultiConfigFile(path)
	if err == nil {
		t.Fatal("expected duplicate id error")
	}
}

func TestParseMultiConfig_RejectsDuplicateCookiePrefix(t *testing.T) {
	yaml := `
clients:
  - id: a
    hosts: [a.example.com]
    secret: "0123456789abcdef0123456789abcdef"
    provider: {url: https://idp.example.com, clientId: a}
    cookieNamePrefix: shared
  - id: b
    hosts: [b.example.com]
    secret: "fedcba9876543210fedcba9876543210"
    provider: {url: https://idp.example.com, clientId: b}
    cookieNamePrefix: shared
`
	path := writeYAML(t, yaml)
	_, err := parseMultiConfigFile(path)
	if err == nil {
		t.Fatal("expected duplicate cookieNamePrefix error")
	}
}

func TestParseMultiConfig_FileExpand(t *testing.T) {
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "client-secret")
	if err := os.WriteFile(secretPath, []byte("from-file"), 0o600); err != nil {
		t.Fatal(err)
	}
	yaml := `
clients:
  - id: a
    hosts: [a.example.com]
    secret: "0123456789abcdef0123456789abcdef"
    provider:
      url: https://idp.example.com
      clientId: a
      clientSecret: ${file:` + secretPath + `}
    cookieNamePrefix: a
`
	path := writeYAML(t, yaml)
	cfg, err := parseMultiConfigFile(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Expansion happens in src.New, not parse — raw value should still be the ${file:...} form
	if !strings.Contains(cfg.Clients[0].Config.Provider.ClientSecret, "file:") {
		t.Fatalf("expected unexpanded file ref, got %q", cfg.Clients[0].Config.Provider.ClientSecret)
	}
}

func writeYAML(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Finding 4: a bare "*" and a dotless wildcard suffix both pass validation and then match
// nothing (or match a whole TLD), so the client 403s itself. They must be rejected by name.
func TestParseMultiConfig_RejectsUnmatchableWildcardHosts(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		wantErr string
	}{
		{"bare wildcard", "*", `host "*"`},
		{"empty suffix", "*.", `host "*"`}, // normalizeHost strips the dot, so "*." lands on the bare-wildcard rejection
		{"single-label suffix", "*.ab", `host "*.ab"`},
		{"public suffix", "*.com", `host "*.com"`},
		{"wildcard not in leftmost label", "a*.example.com", `invalid wildcard host`},
		{"embedded wildcard", "graf*.example.com", `invalid wildcard host`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yaml := `
clients:
  - id: a
    hosts: ["` + tt.host + `"]
    secret: "0123456789abcdef0123456789abcdef"
    provider: {url: https://idp.example.com, clientId: a}
    cookieNamePrefix: a
`
			_, err := parseMultiConfigFile(writeYAML(t, yaml))
			if err == nil {
				t.Fatalf("host %q was accepted; it matches nothing (or a whole TLD)", tt.host)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("host %q: err=%v, want it to name the offending key (%q)", tt.host, err, tt.wantErr)
			}
		})
	}
}

// A well-formed wildcard must still be accepted, or the fix above is just a blanket refusal.
func TestParseMultiConfig_AcceptsWellFormedWildcard(t *testing.T) {
	yaml := `
clients:
  - id: a
    hosts: ["*.example.com", "tenant.example.com.", "A.Example.COM:443"]
    secret: "0123456789abcdef0123456789abcdef"
    provider: {url: https://idp.example.com, clientId: a}
    cookieNamePrefix: a
`
	cfg, err := parseMultiConfigFile(writeYAML(t, yaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.Clients) != 1 {
		t.Fatalf("clients=%d", len(cfg.Clients))
	}
	// The trailing dot on the config side must be canonicalised away, otherwise the key is
	// one no client will ever send.
	for in, want := range map[string]string{
		"*.example.com":       "*.example.com",
		"tenant.example.com.": "tenant.example.com",
		"A.Example.COM:443":   "a.example.com",
	} {
		if got := normalizeHost(in); got != want {
			t.Fatalf("normalizeHost(%q)=%q want %q", in, got, want)
		}
	}
}

// Finding 5: the secret-uniqueness invariant must not exempt "" or config.DefaultSecret.
// src.New rejects both, so this changes only which error the operator sees — but the
// invariant is documented as mandatory and must not have holes.
func TestParseMultiConfig_RejectsDuplicateEmptyAndDefaultSecret(t *testing.T) {
	tests := []struct {
		name       string
		secretLine string
		wantErr    string
	}{
		{"empty", `    secret: ""`, "duplicate secret"},
		{"default", "    secret: " + config.DefaultSecret, "duplicate secret"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yaml := `
clients:
  - id: a
    hosts: [a.example.com]
` + tt.secretLine + `
    provider: {url: https://idp.example.com, clientId: a}
    cookieNamePrefix: a
  - id: b
    hosts: [b.example.com]
` + tt.secretLine + `
    provider: {url: https://idp.example.com, clientId: b}
    cookieNamePrefix: b
`
			_, err := parseMultiConfigFile(writeYAML(t, yaml))
			if err == nil {
				t.Fatalf("two clients sharing secret %q were accepted", tt.name)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err=%v, want %q", err, tt.wantErr)
			}
		})
	}
}

// Finding 1: a YAML `null` on a pointer sub-struct that src.New dereferences used to reach
// src.New as a nil dereference and kill the whole process on reload (every tenant down).
//
// The regression slipped through because every existing buildHostMap test handed the parser a
// ready-made config object instead of a real YAML document. So this test writes a REAL YAML
// FILE for each null-able pointer field, parses it, and asserts the parse fails with an
// error naming the field. A panic here fails the test just as an error would - the point is
// that the document never reaches src.New at all.
func TestParseMultiConfig_RejectsNullPointerSubStructs(t *testing.T) {
	// Every pointer field of config.Config that a YAML document can set to null and that
	// src.New (or the request path it installs) dereferences unconditionally. Provider is
	// included: src.New nil-checks it, but naming the offending key beats surfacing a
	// generic error from deep in the plugin.
	nulls := []struct {
		name    string
		snippet string
		wantErr string
	}{
		{"sessionCookie", "    sessionCookie: null\n", "sessionCookie"},
		{"authorizationHeader", "    authorizationHeader: null\n", "authorizationHeader"},
		{"authorizationCookie", "    authorizationCookie: null\n", "authorizationCookie"},
		{"authorization", "    authorization: null\n", "authorization"},
		{"errorPages", "    errorPages: null\n", "errorPages"},
		{"errorPages.unauthenticated", "    errorPages:\n      unauthenticated: null\n", "errorPages.unauthenticated"},
		{"errorPages.unauthorized", "    errorPages:\n      unauthorized: null\n", "errorPages.unauthorized"},
		{"provider", "    provider: null\n", "provider"},
	}
	for _, tc := range nulls {
		t.Run(tc.name, func(t *testing.T) {
			providerLine := "    provider: {url: https://idp.example.com, clientId: a}\n"
			if tc.name == "provider" {
				// Omit the mapping key entirely so the document is well-formed YAML and
				// the null is what we are testing (a duplicate key would fail the parse
				// earlier, for the wrong reason).
				providerLine = ""
			}
			yaml := `
clients:
  - id: a
    hosts: [a.example.com]
    secret: "0123456789abcdef0123456789abcdef"
` + providerLine + `    cookieNamePrefix: a
` + tc.snippet
			path := writeYAML(t, yaml)

			cfg, err := parseMultiConfigFile(path)
			if err == nil {
				t.Fatalf("null %s was accepted; src.New dereferences it", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err=%v, want it to name %q", err, tc.wantErr)
			}
			if cfg != nil {
				t.Fatalf("a config was returned alongside the error")
			}

			// Belt and braces: the full reload path must not panic and must keep serving
			// the previously loaded map. This is the shape the crashing bug took in
			// production (doReload -> buildHostMap -> src.New).
			oldPath := writeYAML(t, `
clients:
  - id: a
    hosts: [a.example.com]
    secret: "0123456789abcdef0123456789abcdef"
    provider: {url: https://idp.example.com, clientId: a}
    cookieNamePrefix: a
`)
			r := newHostRouter()
			allow := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
			if err := reloadFromFile(context.Background(), r, oldPath, allow, panicOnNilFactory); err != nil {
				t.Fatalf("initial load: %v", err)
			}
			// panicOnNilFactory stands in for src.New's unconditional dereference: it panics
			// on any nil sub-struct, so a config that reached it would crash the test loudly
			// instead of silently "succeeding".
			doReload(context.Background(), &sync.Mutex{}, r, path, allow, panicOnNilFactory)

			rw := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "http://a.example.com/", nil)
			req.Host = "a.example.com"
			r.ServeHTTP(rw, req)
			if rw.Code != http.StatusOK {
				t.Fatalf("status=%d want 200: the previous map must survive a null %s", rw.Code, tc.name)
			}
		})
	}
}

// panicOnNilFactory mimics the shape of src.New's nil dereferences: it panics when handed a
// config whose pointer sub-structs were nulled. Used by the test above so the reload path is
// exercised end to end without needing a live IDP.
func panicOnNilFactory(_ context.Context, _ http.Handler, c *config.Config, _ string) (http.Handler, error) {
	if c.SessionCookie == nil || c.AuthorizationHeader == nil || c.AuthorizationCookie == nil ||
		c.Authorization == nil || c.ErrorPages == nil || c.Provider == nil {
		panic("src.New would nil-dereference this config")
	}
	if c.ErrorPages.Unauthenticated == nil || c.ErrorPages.Unauthorized == nil {
		panic("src.New would nil-dereference errorPages")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }), nil
}
