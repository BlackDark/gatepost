package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	src "github.com/BlackDark/test-oidc-traefik-plugin/src"
	"github.com/BlackDark/test-oidc-traefik-plugin/src/config"
)

func TestBuildHostMap_UsesFactoryPerClient(t *testing.T) {
	yaml := `
clients:
  - id: a
    hosts: [a.example.com, A.example.com]
    secret: "0123456789abcdef0123456789abcdef"
    provider: {url: https://idp.example.com, clientId: client-a}
    cookieNamePrefix: a
  - id: b
    hosts: [b.example.com]
    secret: "fedcba9876543210fedcba9876543210"
    provider: {url: https://idp.example.com, clientId: client-b}
    cookieNamePrefix: b
`
	path := writeYAML(t, yaml)
	cfg, err := parseMultiConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}

	seen := map[string]string{}
	factory := func(_ context.Context, _ http.Handler, c *config.Config, name string) (http.Handler, error) {
		id := c.Provider.ClientId
		seen[id] = name
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Client", id)
			w.WriteHeader(http.StatusOK)
		}), nil
	}

	allow := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	m, err := buildHostMap(context.Background(), cfg, allow, factory)
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 2 {
		t.Fatalf("hosts=%d want 2", len(m))
	}
	if seen["client-a"] == "" || seen["client-b"] == "" {
		t.Fatalf("seen=%v", seen)
	}
}

func TestReloadKeepsOldOnBadConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	good := `
clients:
  - id: a
    hosts: [a.example.com]
    secret: "0123456789abcdef0123456789abcdef"
    provider: {url: https://idp.example.com, clientId: client-a}
    cookieNamePrefix: a
`
	if err := os.WriteFile(path, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}

	factory := stubFactory()
	allow := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	r := newHostRouter()

	if err := reloadFromFile(context.Background(), r, path, allow, factory); err != nil {
		t.Fatalf("initial load: %v", err)
	}

	if err := os.WriteFile(path, []byte(`clients: []`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := reloadFromFile(context.Background(), r, path, allow, factory); err == nil {
		t.Fatal("expected reload error")
	}

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://a.example.com/", nil)
	req.Host = "a.example.com"
	r.ServeHTTP(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 from old map", rw.Code)
	}
}

func TestReloadSucceedsOnGoodUpdate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	v1 := `
clients:
  - id: a
    hosts: [a.example.com]
    secret: "0123456789abcdef0123456789abcdef"
    provider: {url: https://idp.example.com, clientId: client-a}
    cookieNamePrefix: a
`
	if err := os.WriteFile(path, []byte(v1), 0o600); err != nil {
		t.Fatal(err)
	}

	factory := stubFactory()
	allow := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	r := newHostRouter()
	if err := reloadFromFile(context.Background(), r, path, allow, factory); err != nil {
		t.Fatal(err)
	}

	v2 := `
clients:
  - id: a
    hosts: [a.example.com]
    secret: "0123456789abcdef0123456789abcdef"
    provider: {url: https://idp.example.com, clientId: client-a}
    cookieNamePrefix: a
  - id: b
    hosts: [b.example.com]
    secret: "fedcba9876543210fedcba9876543210"
    provider: {url: https://idp.example.com, clientId: client-b}
    cookieNamePrefix: b
`
	if err := os.WriteFile(path, []byte(v2), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := reloadFromFile(context.Background(), r, path, allow, factory); err != nil {
		t.Fatal(err)
	}

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://b.example.com/", nil)
	req.Host = "b.example.com"
	r.ServeHTTP(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 for new host", rw.Code)
	}
}

// Finding 7: this test used to DECLARE `secret: ${file:WILL_EXPAND_SAME}` in the YAML and then
// hand a stub factory that overwrote c.Secret by hand, so no file was ever written and no
// expansion ever happened: it would still have passed if src.New stopped expanding
// ${file:...} entirely. It now writes two REAL temp files with identical 32-byte contents and
// runs the REAL expansion through src.New (not a stub that assigns the field), so it can
// actually fail for the regression it names.
func TestBuildHostMap_RejectsDuplicateSecretAfterExpand(t *testing.T) {
	dir := t.TempDir()
	const expanded = "0123456789abcdef0123456789abcdef"
	pathA := filepath.Join(dir, "secret-a")
	pathB := filepath.Join(dir, "secret-b")
	for _, p := range []string{pathA, pathB} {
		if err := os.WriteFile(p, []byte(expanded), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	yaml := `
clients:
  - id: a
    hosts: [a.example.com]
    secret: ${file:` + pathA + `}
    provider:
      url: ` + idpURL(t) + `
      clientId: client-a
      clientSecret: client-secret-a
    cookieNamePrefix: a
  - id: b
    hosts: [b.example.com]
    secret: ${file:` + pathB + `}
    provider:
      url: ` + idpURL(t) + `
      clientId: client-b
      clientSecret: client-secret-b
    cookieNamePrefix: b
`
	cfg, err := parseMultiConfigFile(writeYAML(t, yaml))
	if err != nil {
		t.Fatal(err)
	}
	// Pre-condition: the two raw values are DIFFERENT, so only a post-expansion check can
	// catch this. Without this assertion the test would pass even with expansion disabled.
	if cfg.Clients[0].Config.Secret == cfg.Clients[1].Config.Secret {
		t.Fatal("raw secrets are already equal; the test no longer exercises expansion")
	}

	// Real factory: src.New performs the ${file:...} expansion in place.
	factory := func(ctx context.Context, next http.Handler, c *config.Config, name string) (http.Handler, error) {
		return src.New(ctx, next, c, name)
	}
	_, err = buildHostMap(context.Background(), cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), factory)
	if err == nil {
		t.Fatal("expected duplicate secret error after real ${file:} expansion")
	}
	if !strings.Contains(err.Error(), "duplicate secret after expand") {
		t.Fatalf("err=%v, want the post-expansion duplicate-secret error", err)
	}
}

// idpURL starts a throwaway OIDC discovery server and returns its issuer URL, so the real
// src.New can complete without reaching the network.
func idpURL(t *testing.T) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q,"end_session_endpoint":%q}`,
			"http://"+r.Host, "http://"+r.Host+"/auth", "http://"+r.Host+"/token", "http://"+r.Host+"/jwks", "http://"+r.Host+"/logout")
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"keys":[]}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// Finding 1b: the "bad reload keeps the previous map" promise must hold even when the reload
// PANICS rather than returning an error - doReload runs on a timer goroutine where an
// unrecovered panic takes the entire process (and therefore every tenant) down.
func TestDoReload_RecoversPanicAndKeepsPreviousMap(t *testing.T) {
	path := writeYAML(t, `
clients:
  - id: a
    hosts: [a.example.com]
    secret: "0123456789abcdef0123456789abcdef"
    provider: {url: https://idp.example.com, clientId: client-a}
    cookieNamePrefix: a
`)
	r := newHostRouter()
	allow := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {})
	if err := reloadFromFile(context.Background(), r, path, allow, stubFactory()); err != nil {
		t.Fatal(err)
	}

	// A config the factory panics on - stands in for any src.New panic, today or tomorrow.
	bad := writeYAML(t, `
clients:
  - id: a
    hosts: [a.example.com]
    secret: "0123456789abcdef0123456789abcdef"
    provider: {url: https://idp.example.com, clientId: client-a}
    cookieNamePrefix: a
  - id: b
    hosts: [b.example.com]
    secret: "fedcba9876543210fedcba9876543210"
    provider: {url: https://idp.example.com, clientId: client-b}
    cookieNamePrefix: b
`)
	panicking := func(_ context.Context, _ http.Handler, c *config.Config, _ string) (http.Handler, error) {
		if c.Provider.ClientId == "client-b" {
			panic("boom")
		}
		return stubFactory()(context.Background(), nil, c, "")
	}

	var mu sync.Mutex
	// A panic escaping here would crash the test binary: this IS the assertion.
	doReload(context.Background(), &mu, r, bad, allow, panicking)

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://a.example.com/", nil)
	req.Host = "a.example.com"
	r.ServeHTTP(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("status=%d want 200: the previous map must survive a panicking reload", rw.Code)
	}
	// And the panicking client must NOT have been added.
	rw = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "http://b.example.com/", nil)
	req.Host = "b.example.com"
	r.ServeHTTP(rw, req)
	if rw.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403: a panicking client must not be half-installed", rw.Code)
	}
}

func stubFactory() handlerFactory {
	return func(_ context.Context, _ http.Handler, c *config.Config, _ string) (http.Handler, error) {
		id := c.Provider.ClientId
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Client", id)
			w.WriteHeader(http.StatusOK)
		}), nil
	}
}
