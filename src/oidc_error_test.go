package src

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/BlackDark/test-oidc-traefik-plugin/src/config"
	"github.com/BlackDark/test-oidc-traefik-plugin/src/logging"
	"github.com/BlackDark/test-oidc-traefik-plugin/src/oidc"
)

func newErrorBodyTestAuth(t *testing.T) *TraefikOidcAuth {
	t.Helper()

	return &TraefikOidcAuth{
		logger: logging.CreateLogger(logging.LevelDebug),
		Config: &config.Config{
			Secret: "0123456789abcdef0123456789abcdef",
			Provider: &config.ProviderConfig{
				ClientId:                 "super-secret-client-id",
				ClientSecret:             "super-secret-client-secret",
				OidcTimeoutSeconds:       5,
				RevokeTokensOnLogoutBool: true,
			},
		},
	}
}

func TestCapIdcErrorBody_ScrubsClientSecretAndId(t *testing.T) {
	toa := newErrorBodyTestAuth(t)

	body := []byte(`{"error":"invalid_client","echo":"client_secret=super-secret-client-secret client_id=super-secret-client-id"}`)

	got := capIdcErrorBody(toa, body)

	if strings.Contains(got, "super-secret-client-secret") || strings.Contains(got, "super-secret-client-id") {
		t.Fatalf("credentials leaked into error body: %s", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("expected redaction marker, got %s", got)
	}
}

func TestCapIdcErrorBody_Truncates(t *testing.T) {
	toa := newErrorBodyTestAuth(t)

	got := capIdcErrorBody(toa, []byte(strings.Repeat("a", 5000)))

	if len(got) > maxIdcErrorBody+len("...(truncated)") {
		t.Fatalf("body not truncated: %d bytes", len(got))
	}
	if !strings.HasSuffix(got, "...(truncated)") {
		t.Fatal("expected truncation marker")
	}
}

func TestCapIdcErrorBody_ScrubsSecretKeyName(t *testing.T) {
	toa := newErrorBodyTestAuth(t)

	got := capIdcErrorBody(toa, []byte(`{"client_secret":"value-that-is-not-the-config-one"}`))

	if strings.Contains(got, "value-that-is-not-the-config-one") {
		t.Fatalf("unscubbed secret echo: %s", got)
	}
}

func TestIntrospectToken_InactiveReturnsFalseNilError(t *testing.T) {
	toa := newErrorBodyTestAuth(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"active":false}`))
	}))
	defer server.Close()

	toa.httpClient = server.Client()
	toa.DiscoveryDocument = &oidc.OidcDiscovery{IntrospectionEndpoint: server.URL}

	active, _, err := toa.introspectToken("some-token")
	if err != nil {
		t.Fatalf("inactive token must not be an error: %v", err)
	}
	if active {
		t.Fatal("active must be false")
	}
}

func TestIntrospectToken_MissingActiveIsError(t *testing.T) {
	toa := newErrorBodyTestAuth(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"scope":"openid"}`))
	}))
	defer server.Close()

	toa.httpClient = server.Client()
	toa.DiscoveryDocument = &oidc.OidcDiscovery{IntrospectionEndpoint: server.URL}

	active, claims, err := toa.introspectToken("some-token")
	if err == nil {
		t.Fatal("missing active must be an error")
	}
	if active || claims != nil {
		t.Fatal("no claims may be returned alongside an error")
	}
}

func TestIntrospectToken_NonOKIsError(t *testing.T) {
	toa := newErrorBodyTestAuth(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"active":true}`))
	}))
	defer server.Close()

	toa.httpClient = server.Client()
	toa.DiscoveryDocument = &oidc.OidcDiscovery{IntrospectionEndpoint: server.URL}

	active, claims, err := toa.introspectToken("some-token")
	if err == nil {
		t.Fatal("non-200 must be an error")
	}
	if active || claims != nil {
		t.Fatal("a failing introspection must never look active")
	}
}

func TestRevokeToken_PostsRefreshTokenWithClientSecret(t *testing.T) {
	toa := newErrorBodyTestAuth(t)

	var got url.Values
	var gotBasicAuth bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		got = r.PostForm
		_, _, ok := r.BasicAuth()
		gotBasicAuth = ok
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	toa.httpClient = server.Client()
	toa.DiscoveryDocument = &oidc.OidcDiscovery{RevocationEndpoint: server.URL}

	if err := toa.revokeToken(context.Background(), "refresh-token-value"); err != nil {
		t.Fatalf("revokeToken: %v", err)
	}

	if got.Get("token") != "refresh-token-value" {
		t.Fatalf("token=%q", got.Get("token"))
	}
	if got.Get("token_type_hint") != "refresh_token" {
		t.Fatalf("token_type_hint=%q", got.Get("token_type_hint"))
	}
	if got.Get("client_secret") != toa.Config.Provider.ClientSecret {
		t.Fatal("client_secret must be sent")
	}
	_ = gotBasicAuth
}

func TestRevokeToken_NoOpCases(t *testing.T) {
	toa := newErrorBodyTestAuth(t)

	// Revocation disabled.
	toa.Config.Provider.RevokeTokensOnLogoutBool = false
	toa.DiscoveryDocument = &oidc.OidcDiscovery{RevocationEndpoint: "http://127.0.0.1:1/"}
	if err := toa.revokeToken(context.Background(), "rt"); err != nil {
		t.Fatalf("disabled revocation must be a no-op, got %v", err)
	}

	// No endpoint.
	toa.Config.Provider.RevokeTokensOnLogoutBool = true
	toa.DiscoveryDocument = &oidc.OidcDiscovery{}
	if err := toa.revokeToken(context.Background(), "rt"); err != nil {
		t.Fatalf("missing endpoint must be a no-op, got %v", err)
	}

	// Empty refresh token.
	toa.DiscoveryDocument = &oidc.OidcDiscovery{RevocationEndpoint: "http://127.0.0.1:1/"}
	if err := toa.revokeToken(context.Background(), ""); err != nil {
		t.Fatalf("empty refresh token must be a no-op, got %v", err)
	}
}

func TestAuthParamsForChallenge(t *testing.T) {
	toa := newErrorBodyTestAuth(t)

	if params := toa.authParamsForChallenge(true); params != nil {
		t.Fatalf("max_age must be absent when disabled, got %v", params)
	}

	toa.Config.Provider.MaxAuthAgeSeconds = 300

	if params := toa.authParamsForChallenge(false); params != nil {
		t.Fatalf("must be nil outside a challenge, got %v", params)
	}

	params := toa.authParamsForChallenge(true)
	if params["max_age"] != "300" {
		t.Fatalf("max_age=%q", params["max_age"])
	}
}

func TestAuthTimeIsFresh(t *testing.T) {
	toa := newErrorBodyTestAuth(t)

	now := time.Now()

	// Disabled: always fresh.
	if !toa.authTimeIsFresh(nil, now) {
		t.Fatal("feature disabled must always be fresh")
	}

	toa.Config.Provider.MaxAuthAgeSeconds = 300

	if toa.authTimeIsFresh(nil, now) {
		t.Fatal("missing auth_time must not be fresh when step-up is enabled")
	}
	if toa.authTimeIsFresh(map[string]any{}, now) {
		t.Fatal("missing auth_time must not be fresh when step-up is enabled")
	}

	nowUnix := float64(now.Add(-1 * time.Minute).Unix())
	if !toa.authTimeIsFresh(map[string]any{"auth_time": nowUnix}, now) {
		t.Fatal("recent auth_time must be fresh")
	}
	if !toa.authTimeIsFresh(map[string]any{"auth_time": now.Add(-1 * time.Minute).Format(time.RFC3339)}, now) {
		t.Fatal("RFC3339 auth_time must be accepted")
	}
	if toa.authTimeIsFresh(map[string]any{"auth_time": float64(now.Add(-time.Hour).Unix())}, now) {
		t.Fatal("stale auth_time must not be fresh")
	}
	if toa.authTimeIsFresh(map[string]any{"auth_time": "not-a-time"}, now) {
		t.Fatal("unparseable auth_time must not be fresh")
	}
}

func TestAuthTimeFromClaims_JSONNumber(t *testing.T) {
	claims := map[string]any{"auth_time": float64(1700000000)}

	got, ok := authTimeFromClaims(claims)
	if !ok || got.Unix() != 1700000000 {
		t.Fatalf("auth_time=%v ok=%v", got, ok)
	}
}
