package src

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BlackDark/test-oidc-traefik-plugin/src/config"
	"github.com/BlackDark/test-oidc-traefik-plugin/src/errorPages"
	"github.com/BlackDark/test-oidc-traefik-plugin/src/logging"
	"github.com/BlackDark/test-oidc-traefik-plugin/src/oidc"
	"github.com/BlackDark/test-oidc-traefik-plugin/src/rules"
	"github.com/BlackDark/test-oidc-traefik-plugin/src/session"
	"github.com/BlackDark/test-oidc-traefik-plugin/src/utils"
)

func TestTemplate_mapToJsonArray(t *testing.T) {
	evalContext := map[string]any{
		"claims": map[string]any{
			"roles": []any{"admin", "user", 123},
		},
	}

	template, err := newTemplate().Parse("{{ .claims.roles | withPrefix \"prefix:\" | withSuffix \":suffix\" | mapToJsonArray }}")
	if err != nil {
		t.Fatal(err)
	}
	var renderedValue bytes.Buffer
	err = template.Execute(&renderedValue, evalContext)
	if err != nil {
		t.Fatal(err)
	}

	var result []string
	err = json.Unmarshal(renderedValue.Bytes(), &result)
	if err != nil {
		t.Fatal(err)
	}

	if len(result) != 3 {
		t.Errorf("Expected 3 elements in the array, got %d", len(result))
	}

	if result[0] != "prefix:admin:suffix" {
		t.Errorf("Expected prefix:admin:suffix at index 0, got %s", result[0])
	}

	if result[1] != "prefix:user:suffix" {
		t.Errorf("Expected prefix:user:suffix at index 1, got %s", result[1])
	}

	if result[2] != "prefix:123:suffix" {
		t.Errorf("Expected prefix:123:suffix at index 2, got %s", result[2])
	}
}

// -----------------------------------------------------------------------------
// item 4: route matching on the decoded path, with a segment boundary
// -----------------------------------------------------------------------------

func TestPathMatchesRoute_SegmentBoundary(t *testing.T) {
	cases := []struct {
		name        string
		route       string
		requestPath string
		want        bool
	}{
		{name: "exact", route: "/logout", requestPath: "/logout", want: true},
		{name: "child", route: "/logout", requestPath: "/logout/extra", want: true},
		{name: "trailing_slash", route: "/logout", requestPath: "/logout/", want: true},
		{name: "prefix_collision_longer", route: "/logout", requestPath: "/logout-history", want: false},
		{name: "prefix_collision_plural", route: "/login", requestPath: "/logins", want: false},
		{name: "other_route", route: "/logout", requestPath: "/logouts", want: false},
		{name: "route_with_trailing_slash", route: "/logout/", requestPath: "/logout", want: true},
		{name: "empty_route", route: "", requestPath: "/logout", want: false},
		{name: "root_route", route: "/", requestPath: "/", want: true},
		{name: "root_route_child", route: "/", requestPath: "/x", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pathMatchesRoute(tc.requestPath, tc.route); got != tc.want {
				t.Fatalf("pathMatchesRoute(%q, %q)=%v want %v", tc.requestPath, tc.route, got, tc.want)
			}
		})
	}
}

// TestServeHTTP_LoginUriDoesNotMatchPrefixCollisions makes sure a real app route
// named /logins is not swallowed by loginUri=/login (and symmetrically for
// logout) through the ServeHTTP dispatch itself.
func TestServeHTTP_LoginUriDoesNotMatchPrefixCollisions(t *testing.T) {
	toa := newRouteDispatchTestAuth(t)
	toa.Config.LoginUri = "/login"
	toa.Config.UnauthenticatedBehavior = "Unauthorized"

	forwarded := false
	toa.next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = true
		w.WriteHeader(http.StatusOK)
	})

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/logins", nil)
	toa.ServeHTTP(rw, req)

	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401: /logins must not trigger the login flow", rw.Code)
	}
	if loc := rw.Header().Get("Location"); loc != "" {
		t.Fatalf("unexpected redirect to %q", loc)
	}
	if forwarded {
		t.Fatal("401 path must not forward")
	}

	// /login itself still triggers the login flow.
	rw = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "https://app.example.com/login", nil)
	toa.ServeHTTP(rw, req)
	if rw.Code != http.StatusFound {
		t.Fatalf("status=%d want 302 for /login", rw.Code)
	}
	if !strings.HasPrefix(rw.Header().Get("Location"), "https://idp.example.com/authorize") {
		t.Fatalf("unexpected Location %q", rw.Header().Get("Location"))
	}
}

func newRouteDispatchTestAuth(t *testing.T) *TraefikOidcAuth {
	t.Helper()
	toa := newAuthBehaviorTestAuth(t)
	toa.Config.LoginUri = ""
	toa.Config.LogoutUri = "/logout"
	toa.Config.UnauthenticatedBehavior = "Unauthorized"
	toa.Config.PostLoginRedirectUri = "/"
	toa.Config.Authorization = &config.AuthorizationConfig{}
	toa.SessionStorage = &memSessionStorage{}
	toa.httpClient = http.DefaultClient
	return toa
}

// -----------------------------------------------------------------------------
// item 1 + 2 + 8b + 10: the callback
// -----------------------------------------------------------------------------

type callbackHarness struct {
	toa        *TraefikOidcAuth
	server     *httptest.Server
	active     bool
	claims     map[string]interface{}
	tokenCalls int
}

func newCallbackHarness(t *testing.T, tokenValidation string) *callbackHarness {
	t.Helper()

	h := &callbackHarness{active: true, claims: map[string]interface{}{"sub": "user-1"}}

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		h.tokenCalls++
		_ = json.NewEncoder(w).Encode(&oidc.OidcTokenResponse{
			AccessToken:  "opaque-access-token-value",
			IdToken:      "opaque-id-token-value",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: "refresh-token-value",
		})
	})
	mux.HandleFunc("/introspect", func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{"active": h.active}
		for k, v := range h.claims {
			response[k] = v
		}
		_ = json.NewEncoder(w).Encode(response)
	})
	h.server = httptest.NewServer(mux)

	callback, err := url.Parse("https://app.example.com/oidc/callback")
	if err != nil {
		t.Fatal(err)
	}

	toa := &TraefikOidcAuth{
		logger: logging.CreateLogger(logging.LevelError),
		Config: &config.Config{
			Secret:                  "0123456789abcdef0123456789abcdef",
			CookieNamePrefix:        "TraefikOidcAuth",
			Scopes:                  []string{"openid"},
			CallbackUri:             "/oidc/callback",
			PostLoginRedirectUri:    "/",
			UnauthenticatedBehavior: "Unauthorized",
			UnauthorizedBehavior:    "Unauthorized",
			Authorization:           &config.AuthorizationConfig{},
			Provider: &config.ProviderConfig{
				ClientId:        "test-client",
				TokenValidation: tokenValidation,
				UsePkceBool:     false,
			},
			SessionCookie: &config.SessionCookieConfig{
				Path:     "/",
				Secure:   true,
				HttpOnly: true,
				SameSite: "lax",
			},
			ErrorPages: &errorPages.ErrorPagesConfig{
				Unauthenticated: &errorPages.ErrorPageConfig{},
				Unauthorized:    &errorPages.ErrorPageConfig{},
			},
		},
		CallbackURL:    callback,
		SessionStorage: &memSessionStorage{},
		httpClient:     h.server.Client(),
		DiscoveryDocument: &oidc.OidcDiscovery{
			AuthorizationEndpoint: h.server.URL + "/authorize",
			TokenEndpoint:         h.server.URL + "/token",
			IntrospectionEndpoint: h.server.URL + "/introspect",
		},
		Jwks: &oidc.JwksHandler{},
	}

	h.toa = toa

	return h
}

func (h *callbackHarness) do(t *testing.T, state *oidc.OidcState) *httptest.ResponseRecorder {
	t.Helper()

	if state.Csrf == "" {
		state.Csrf = "csrf-test-value-0123456789abcdef"
	}

	stateB64, err := oidc.SealState(state, h.toa.Config.Secret)
	if err != nil {
		t.Fatal(err)
	}

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/oidc/callback?code=abc&state="+url.QueryEscape(stateB64), nil)
	req.AddCookie(&http.Cookie{Name: getLoginCsrfCookieName(h.toa.Config, state.Csrf), Value: state.Csrf})

	h.toa.handleCallback(rw, req)

	return rw
}

// TestHandleCallback_InactiveIntrospectionTokenIs401 is item 1: the active flag
// used to be discarded, so a revoked token still produced an authorized session.
func TestHandleCallback_InactiveIntrospectionTokenIs401(t *testing.T) {
	h := newCallbackHarness(t, "Introspection")
	defer h.server.Close()
	h.active = false

	rw := h.do(t, &oidc.OidcState{Action: "Login", RedirectUrl: "https://app.example.com/"})

	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 for an inactive (revoked) token, body=%q", rw.Code, rw.Body.String())
	}
	for _, c := range rw.Result().Cookies() {
		if c.Name == getSessionCookieName(h.toa.Config) && c.Value != "" {
			t.Fatal("an inactive token must not establish a session cookie")
		}
	}
}

// TestHandleCallback_ActiveIntrospectionTokenStillWorks is the control: an active
// token must still be accepted.
func TestHandleCallback_ActiveIntrospectionTokenStillWorks(t *testing.T) {
	h := newCallbackHarness(t, "Introspection")
	defer h.server.Close()

	rw := h.do(t, &oidc.OidcState{Action: "Login", RedirectUrl: "https://app.example.com/"})

	if rw.Code != http.StatusFound {
		t.Fatalf("status=%d want 302, body=%q", rw.Code, rw.Body.String())
	}
}

// TestHandleCallback_BogusVerificationTokenIsClean500 is item 2: the default
// branch used to dereference a nil error and then fall through to write a second
// status.
func TestHandleCallback_BogusVerificationTokenIsClean500(t *testing.T) {
	h := newCallbackHarness(t, "Bogus")
	defer h.server.Close()

	rw := h.do(t, &oidc.OidcState{Action: "Login", RedirectUrl: "https://app.example.com/"})

	if rw.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500, body=%q", rw.Code, rw.Body.String())
	}
	if strings.Contains(rw.Body.String(), "Bogus") {
		t.Fatalf("internal config detail leaked to the caller: %q", rw.Body.String())
	}
}

// TestHandleCallback_ExpiredStateIsCleanClientError is item 10: a login slower
// than the state lifetime must be a clean "start again", not an opaque 500.
func TestHandleCallback_ExpiredStateIsCleanClientError(t *testing.T) {
	h := newCallbackHarness(t, "Introspection")
	defer h.server.Close()

	// Seal, then re-seal the JSON by hand with an expiry in the past. SealState
	// stamps the times itself, so the expired state is built by sealing and then
	// re-encrypting an aged copy.
	// Build the aged state directly: UnsealState only ever sees a
	// base64url-wrapped ciphertext, so seal + age + reseal is done by hand.
	aged := fmt.Sprintf(`{"action":"Login","redirect_url":"https://app.example.com/","csrf":"%s","nonce":"","typ":"oidc-state","issued_at":%q,"expires":%q}`,
		"csrf-test-value-0123456789abcdef",
		time.Now().Add(-11*time.Minute).Format(time.RFC3339Nano),
		time.Now().Add(-time.Minute).Format(time.RFC3339Nano),
	)

	agedSealed, err := utils.EncryptWithPurpose(aged, h.toa.Config.Secret, utils.PurposeOidcState)
	if err != nil {
		t.Fatal(err)
	}
	agedStateParam := base64.RawURLEncoding.EncodeToString([]byte(agedSealed))

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/oidc/callback?code=abc&state="+url.QueryEscape(agedStateParam), nil)
	h.toa.handleCallback(rw, req)

	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 for an expired state, body=%q", rw.Code, rw.Body.String())
	}
	if h.tokenCalls != 0 {
		t.Fatalf("an expired state must not reach the token endpoint (calls=%d)", h.tokenCalls)
	}
}

// TestHandleCallback_StaleAuthTimeFailsClosed is item 8b: the returned ID token
// must carry a recent auth_time when max_auth_age_seconds is configured.
func TestHandleCallback_StaleAuthTimeFailsClosed(t *testing.T) {
	cases := []struct {
		name           string
		maxAge         int
		claims         map[string]interface{}
		wantCode       int
		wantSessionSet bool
	}{
		{
			name:           "stale_auth_time",
			maxAge:         600,
			claims:         map[string]interface{}{"sub": "user-1", "auth_time": float64(time.Now().Add(-2 * time.Hour).Unix())},
			wantCode:       http.StatusForbidden,
			wantSessionSet: false,
		},
		{
			name:           "missing_auth_time",
			maxAge:         600,
			claims:         map[string]interface{}{"sub": "user-1"},
			wantCode:       http.StatusForbidden,
			wantSessionSet: false,
		},
		{
			name:           "fresh_auth_time",
			maxAge:         600,
			claims:         map[string]interface{}{"sub": "user-1", "auth_time": float64(time.Now().Unix())},
			wantCode:       http.StatusFound,
			wantSessionSet: true,
		},
		{
			name:           "feature_disabled_ignores_auth_time",
			maxAge:         0,
			claims:         map[string]interface{}{"sub": "user-1"},
			wantCode:       http.StatusFound,
			wantSessionSet: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newCallbackHarness(t, "Introspection")
			defer h.server.Close()
			h.toa.Config.Provider.MaxAuthAgeSeconds = tc.maxAge
			h.claims = tc.claims

			rw := h.do(t, &oidc.OidcState{Action: "Login", RedirectUrl: "https://app.example.com/"})

			if rw.Code != tc.wantCode {
				t.Fatalf("status=%d want %d body=%q", rw.Code, tc.wantCode, rw.Body.String())
			}

			established := false
			for _, c := range rw.Result().Cookies() {
				if c.Name == getSessionCookieName(h.toa.Config) && c.Value != "" {
					established = true
				}
			}
			if established != tc.wantSessionSet {
				t.Fatalf("session established=%v want %v", established, tc.wantSessionSet)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// item 3: front-channel logout needs sid or id_token_hint
// -----------------------------------------------------------------------------

func newFrontchannelTestAuth(t *testing.T) *TraefikOidcAuth {
	t.Helper()
	toa := newAuthBehaviorTestAuth(t)
	toa.Config.Provider.RevokeTokensOnLogoutBool = false
	toa.DiscoveryDocument.RevocationEndpoint = ""
	return toa
}

func TestHandleFrontchannelLogout_RequiresSidOrIdTokenHint(t *testing.T) {
	cases := []struct {
		name      string
		query     string
		sid       string
		idToken   string
		wantCode  int
		wantClear bool
	}{
		{
			name:      "iss_and_sid_clears",
			query:     "iss=https://idp.example.com&sid=sess-1",
			sid:       "sess-1",
			wantCode:  http.StatusOK,
			wantClear: true,
		},
		{
			name:      "iss_alone_does_not_clear",
			query:     "iss=https://idp.example.com",
			wantCode:  http.StatusBadRequest,
			wantClear: false,
		},
		{
			name:      "wrong_sid_does_not_clear",
			query:     "iss=https://idp.example.com&sid=sess-2",
			sid:       "sess-1",
			wantCode:  http.StatusBadRequest,
			wantClear: false,
		},
		{
			name:      "id_token_hint_clears",
			query:     "iss=https://idp.example.com&id_token_hint=the-id-token",
			idToken:   "the-id-token",
			wantCode:  http.StatusOK,
			wantClear: true,
		},
		{
			name:      "wrong_id_token_hint_does_not_clear",
			query:     "iss=https://idp.example.com&id_token_hint=stolen",
			idToken:   "the-id-token",
			wantCode:  http.StatusBadRequest,
			wantClear: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			toa := newFrontchannelTestAuth(t)

			rw := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "https://app.example.com/frontchannel-logout?"+tc.query, nil)
			req.AddCookie(&http.Cookie{Name: getSessionCookieName(toa.Config), Value: "ticket"})

			toa.handleFrontchannelLogout(rw, req, &session.SessionState{Id: "s1", IdToken: tc.idToken}, map[string]interface{}{
				"iss": "https://idp.example.com",
				"sid": tc.sid,
			})

			if rw.Code != tc.wantCode {
				t.Fatalf("status=%d want %d body=%q", rw.Code, tc.wantCode, rw.Body.String())
			}

			cleared := false
			for _, c := range rw.Result().Cookies() {
				if c.Name == getSessionCookieName(toa.Config) && c.MaxAge < 0 {
					cleared = true
				}
			}
			if cleared != tc.wantClear {
				t.Fatalf("cookie cleared=%v want %v", cleared, tc.wantClear)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// item 5: client identity headers never reach the backend
// -----------------------------------------------------------------------------

func TestForwardToUpstream_StripsInjectedIdentityHeaders(t *testing.T) {
	cases := []struct {
		name        string
		behavior    string
		withSession bool
	}{
		{name: "bypass_rule_public", behavior: "Unauthorized", withSession: false},
		{name: "unauthenticated_forward", behavior: "Forward", withSession: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			toa := newIdentityHeaderTestAuth(t)
			toa.Config.UnauthenticatedBehavior = tc.behavior
			toa.Config.UnauthorizedBehavior = tc.behavior

			condition, err := rules.ParseRequestCondition("Path(`/public`)")
			if err != nil {
				t.Fatal(err)
			}
			toa.BypassAuthenticationRule = condition

			seen := map[string]string{}
			toa.next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for _, name := range clientIdentityHeaders {
					seen[name] = r.Header.Get(name)
				}
				w.WriteHeader(http.StatusOK)
			})

			rw := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "https://app.example.com/public", nil)
			for _, name := range clientIdentityHeaders {
				req.Header.Set(name, "attacker@example.com")
			}

			toa.ServeHTTP(rw, req)

			if rw.Code != http.StatusOK {
				t.Fatalf("status=%d want 200, body=%q", rw.Code, rw.Body.String())
			}
			for name, value := range seen {
				if value != "" {
					t.Fatalf("client-supplied %s reached the backend: %q", name, value)
				}
			}
		})
	}
}

// TestForwardToUpstream_ConfiguredHeaderIsSetNotInherited proves attachHeaders
// runs on the public/forward path too, so a configured identity header is Set
// (empty here, because there is no session) rather than inherited.
func TestForwardToUpstream_ConfiguredHeaderIsSetNotInherited(t *testing.T) {
	toa := newIdentityHeaderTestAuth(t)
	toa.Config.UnauthenticatedBehavior = "Forward"
	toa.Config.Headers = []config.HeaderConfig{
		{Name: "X-Auth-Request-User", Value: "{{ .claims.sub }}", IncludeWhen: "Always"},
	}

	var seen string
	var hadHeader bool
	toa.next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values, ok := r.Header["X-Auth-Request-User"]
		hadHeader = ok
		if len(values) > 0 {
			seen = values[0]
		}
		w.WriteHeader(http.StatusOK)
	})

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/public", nil)
	req.Header.Set("X-Auth-Request-User", "attacker@example.com")

	toa.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("status=%d", rw.Code)
	}
	if !hadHeader {
		t.Fatal("configured header must be Set on the forward path, not merely deleted")
	}
	if seen == "attacker@example.com" {
		t.Fatal("injected value survived")
	}
}

// TestForwardToUpstream_OrderSanitizeThenAttach pins the ordering the
// authenticated path relies on: sanitize first, attach second. With the reverse
// order the delete would wipe the header attachHeaders just set, or an
// attacker-supplied value would survive.
func TestForwardToUpstream_OrderSanitizeThenAttach(t *testing.T) {
	toa := newIdentityHeaderTestAuth(t)
	toa.Config.Headers = []config.HeaderConfig{
		{Name: "X-Auth-Request-User", Value: "{{ .claims.sub }}", IncludeWhen: "Always"},
	}

	var seen string
	toa.next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("X-Auth-Request-User")
		w.WriteHeader(http.StatusOK)
	})

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/public", nil)
	req.Header.Set("X-Auth-Request-User", "attacker@example.com")

	toa.sanitizeForUpstream(req)
	if got := req.Header.Get("X-Auth-Request-User"); got != "" {
		t.Fatalf("sanitizeForUpstream must delete the injected header, got %q", got)
	}

	if err := toa.attachHeaders(req, &session.SessionState{}, map[string]interface{}{"sub": "real-user"}, false, true); err != nil {
		t.Fatal(err)
	}

	toa.next.ServeHTTP(rw, req)
	if seen != "real-user" {
		t.Fatalf("upstream saw %q, want the session-derived real-user", seen)
	}
}

func newIdentityHeaderTestAuth(t *testing.T) *TraefikOidcAuth {
	t.Helper()
	toa := newAuthBehaviorTestAuth(t)
	toa.Config.LoginUri = ""
	toa.Config.LogoutUri = "/logout"
	toa.Config.PostLoginRedirectUri = "/"
	toa.Config.Authorization = &config.AuthorizationConfig{}
	toa.Config.Provider.RevokeTokensOnLogoutBool = false
	toa.SessionStorage = &memSessionStorage{}
	toa.httpClient = http.DefaultClient
	return toa
}

// -----------------------------------------------------------------------------
// item 6: X-Forwarded-* only from a trusted peer
// -----------------------------------------------------------------------------

func TestRedirectUriHonoursForwardedHeadersOnlyFromTrustedPeer(t *testing.T) {
	cases := []struct {
		name           string
		trusted        []string
		remoteAddr     string
		forwardedHost  string
		forwardedProto string
		wantRedirect   string
	}{
		{
			name:          "untrusted_peer_ignored",
			trusted:       nil,
			remoteAddr:    "203.0.113.7:41234",
			forwardedHost: "evil.example",
			wantRedirect:  "https://app.example.com/oidc/callback",
		},
		{
			name:          "untrusted_peer_with_configured_but_unlisted_range",
			trusted:       []string{"10.0.0.0/8"},
			remoteAddr:    "203.0.113.7:41234",
			forwardedHost: "evil.example",
			wantRedirect:  "https://app.example.com/oidc/callback",
		},
		{
			name:          "trusted_peer_honoured",
			trusted:       []string{"203.0.113.0/24"},
			remoteAddr:    "203.0.113.7:41234",
			forwardedHost: "evil.example",
			wantRedirect:  "https://evil.example/oidc/callback",
		},
		{
			name:          "trusted_peer_without_port_in_remoteaddr",
			trusted:       []string{"203.0.113.0/24"},
			remoteAddr:    "203.0.113.7",
			forwardedHost: "evil.example",
			wantRedirect:  "https://evil.example/oidc/callback",
		},
		{
			name:           "invalid_forwarded_proto_rejected",
			trusted:        []string{"203.0.113.0/24"},
			remoteAddr:     "203.0.113.7:41234",
			forwardedHost:  "evil.example",
			forwardedProto: "javascript",
			wantRedirect:   "https://evil.example/oidc/callback",
		},
		{
			name:           "forwarded_proto_honoured",
			trusted:        []string{"203.0.113.0/24"},
			remoteAddr:     "203.0.113.7:41234",
			forwardedProto: "http",
			wantRedirect:   "http://app.example.com/oidc/callback",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			toa := newAuthBehaviorTestAuth(t)
			// A relative callback URL is what makes the request's own
			// scheme/host feed the redirect_uri.
			relativeCallback, err := url.Parse("/oidc/callback")
			if err != nil {
				t.Fatal(err)
			}
			toa.CallbackURL = relativeCallback
			toa.Config.CallbackUri = "/oidc/callback"
			toa.Config.LoginUri = "/login"
			toa.Config.PostLoginRedirectUri = "/"
			toa.Config.Scopes = []string{"openid"}
			toa.Config.Provider.UsePkceBool = false
			toa.DiscoveryDocument.AuthorizationEndpoint = "https://idp.example.com/authorize"

			for _, cidr := range tc.trusted {
				_, network, err := net.ParseCIDR(cidr)
				if err != nil {
					t.Fatal(err)
				}
				toa.Config.TrustedProxyNets = append(toa.Config.TrustedProxyNets, network)
			}

			rw := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "https://app.example.com/login", nil)
			req.RemoteAddr = tc.remoteAddr
			if tc.forwardedHost != "" {
				req.Header.Set("X-Forwarded-Host", tc.forwardedHost)
			}
			if tc.forwardedProto != "" {
				req.Header.Set("X-Forwarded-Proto", tc.forwardedProto)
			}

			toa.redirectToProvider(rw, req, "https://app.example.com/", false)

			location, err := url.Parse(rw.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			if got := location.Query().Get("redirect_uri"); got != tc.wantRedirect {
				t.Fatalf("redirect_uri=%q want %q", got, tc.wantRedirect)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// item 11: a public route must not depend on the IdP being reachable
// -----------------------------------------------------------------------------

func TestServeHTTP_PublicRouteSurvivesDiscoveryFailure(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	providerURL, err := url.Parse(dead.URL)
	if err != nil {
		t.Fatal(err)
	}
	dead.Close()

	toa := newIdentityHeaderTestAuth(t)
	toa.ProviderURL = providerURL
	toa.httpClient = http.DefaultClient
	toa.DiscoveryDocument = nil
	toa.Jwks = nil

	condition, err := rules.ParseRequestCondition("Path(`/public`)")
	if err != nil {
		t.Fatal(err)
	}
	toa.BypassAuthenticationRule = condition

	forwarded := false
	toa.next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = true
		w.WriteHeader(http.StatusOK)
	})

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/public", nil)
	toa.ServeHTTP(rw, req)

	if !forwarded {
		t.Fatalf("a declared-public route must be forwarded even with the IdP down (status=%d body=%q)", rw.Code, rw.Body.String())
	}
	if rw.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", rw.Code)
	}
}

// A non-public route still requires discovery.
func TestServeHTTP_ProtectedRouteStillRequiresDiscovery(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	providerURL, err := url.Parse(dead.URL)
	if err != nil {
		t.Fatal(err)
	}
	dead.Close()

	toa := newIdentityHeaderTestAuth(t)
	toa.ProviderURL = providerURL
	toa.httpClient = http.DefaultClient
	toa.DiscoveryDocument = nil
	toa.Jwks = nil

	condition, err := rules.ParseRequestCondition("Path(`/public`)")
	if err != nil {
		t.Fatal(err)
	}
	toa.BypassAuthenticationRule = condition

	forwarded := false
	toa.next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = true
	})

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/private", nil)
	toa.ServeHTTP(rw, req)

	if forwarded {
		t.Fatal("a protected route must not be forwarded without discovery")
	}
	if rw.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500", rw.Code)
	}
}

// -----------------------------------------------------------------------------
// item 12: the idle bound has to be made durable
// -----------------------------------------------------------------------------

func TestSessionIdleRefreshDue(t *testing.T) {
	cases := []struct {
		name        string
		idleSeconds int
		wantFirst   bool
	}{
		{name: "disabled_never_rewrites", idleSeconds: 0, wantFirst: false},
		{name: "enabled_rewrites_first", idleSeconds: 900, wantFirst: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			toa := newAuthBehaviorTestAuth(t)
			toa.Config.SessionIdleTimeoutSeconds = tc.idleSeconds

			if got := toa.sessionIdleRefreshDue("session-1"); got != tc.wantFirst {
				t.Fatalf("first call=%v want %v", got, tc.wantFirst)
			}

			if !tc.wantFirst {
				return
			}

			toa.sessionWrites.mark("session-1")
			if got := toa.sessionIdleRefreshDue("session-1"); got {
				t.Fatal("must not rewrite the ticket on every single request")
			}

			// Age the recorded write past the refresh interval (idle/4, capped at 60s).
			toa.sessionWrites.lock.Lock()
			toa.sessionWrites.last["session-1"] = time.Now().Add(-2 * time.Minute)
			toa.sessionWrites.lock.Unlock()

			if got := toa.sessionIdleRefreshDue("session-1"); !got {
				t.Fatal("must rewrite the ticket once the durable LastUsedAt went stale")
			}

			// A header/cookie pseudo-session has no ticket of its own.
			if toa.sessionIdleRefreshDue("AuthorizationHeader") {
				t.Fatal("must not mint a session cookie out of an AuthorizationHeader session")
			}
			if toa.sessionIdleRefreshDue("AuthorizationCookie") {
				t.Fatal("must not mint a session cookie out of an AuthorizationCookie session")
			}
		})
	}
}

// -----------------------------------------------------------------------------
// item 14: no internal detail in client-visible errors
// -----------------------------------------------------------------------------

func TestServeHTTP_ErrorBodiesDoNotLeakInternalDetail(t *testing.T) {
	secretIDPURL := "https://idp.internal.example.com/realms/tenant/protocol/openid-connect"

	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	providerURL, err := url.Parse(dead.URL)
	if err != nil {
		t.Fatal(err)
	}
	dead.Close()

	toa := newIdentityHeaderTestAuth(t)
	toa.ProviderURL = providerURL
	toa.httpClient = http.DefaultClient
	toa.DiscoveryDocument = nil
	toa.Jwks = nil
	toa.logger = logging.CreateLogger(logging.LevelError)

	forwarded := false
	toa.next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = true
	})

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/private", nil)
	toa.ServeHTTP(rw, req)

	if forwarded {
		t.Fatal("unexpected forward")
	}
	if rw.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500", rw.Code)
	}
	for _, leak := range []string{secretIDPURL, "http://127.0.0.1", toa.Config.Secret, "discovery"} {
		if strings.Contains(rw.Body.String(), leak) {
			t.Fatalf("client-visible error leaks %q: %q", leak, rw.Body.String())
		}
	}
	if len(rw.Body.String()) > 200 {
		t.Fatalf("client-visible error body is longer than a generic message: %q", rw.Body.String())
	}
}

// -----------------------------------------------------------------------------
// item 17: only allowlisted authorizationParams may be overridden per request
// -----------------------------------------------------------------------------

func TestAuthorizationParamsOverrideAllowlist(t *testing.T) {
	cases := []struct {
		name          string
		overridable   []string
		query         string
		wantAcrValues string
		wantPrompt    string
	}{
		{
			name:          "nothing_overridable_by_default",
			overridable:   nil,
			query:         "?acr_values=loa1&prompt=none",
			wantAcrValues: "aal2",
			wantPrompt:    "",
		},
		{
			name:          "allowlisted_key_is_overridden",
			overridable:   []string{"acr_values"},
			query:         "?acr_values=loa1",
			wantAcrValues: "loa1",
			wantPrompt:    "",
		},
		{
			name:          "prompt_allowlisted",
			overridable:   []string{"prompt"},
			query:         "?prompt=login",
			wantAcrValues: "aal2",
			wantPrompt:    "login",
		},
		{
			name:          "prompt_not_allowlisted_is_ignored",
			overridable:   []string{"acr_values"},
			query:         "?prompt=none",
			wantAcrValues: "aal2",
			wantPrompt:    "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			toa := newAuthBehaviorTestAuth(t)
			toa.Config.LoginUri = "/login"
			toa.Config.PostLoginRedirectUri = "/"
			toa.Config.Scopes = []string{"openid"}
			toa.Config.Provider.UsePkceBool = false
			toa.Config.AuthorizationParams = map[string]string{"acr_values": "aal2"}
			toa.Config.AuthorizationParamsOverridable = tc.overridable
			toa.DiscoveryDocument.AuthorizationEndpoint = "https://idp.example.com/authorize"

			rw := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "https://app.example.com/login"+tc.query, nil)
			toa.redirectToProvider(rw, req, "https://app.example.com/", false)

			location, err := url.Parse(rw.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			if got := location.Query().Get("acr_values"); got != tc.wantAcrValues {
				t.Fatalf("acr_values=%q want %q", got, tc.wantAcrValues)
			}
			if got := location.Query().Get("prompt"); got != tc.wantPrompt {
				t.Fatalf("prompt=%q want %q", got, tc.wantPrompt)
			}
		})
	}
}

// TestAuthorizationParams_ReservedKeysSkipped is item 16: reserved keys are
// silently skipped at runtime (src.New already rejects them at startup).
func TestAuthorizationParams_ReservedKeysSkipped(t *testing.T) {
	toa := newAuthBehaviorTestAuth(t)
	toa.Config.LoginUri = "/login"
	toa.Config.PostLoginRedirectUri = "/"
	toa.Config.Scopes = []string{"openid"}
	toa.Config.Provider.UsePkceBool = false
	toa.Config.AuthorizationParams = map[string]string{
		"client_id":     "evil-client",
		"redirect_uri":  "https://evil.example/steal",
		"response_type": "token",
		"acr_values":    "aal2",
	}
	toa.DiscoveryDocument.AuthorizationEndpoint = "https://idp.example.com/authorize"

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/login", nil)
	toa.redirectToProvider(rw, req, "https://app.example.com/", false)

	location, err := url.Parse(rw.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := location.Query().Get("client_id"); got != "test-client" && got == "evil-client" {
		t.Fatal("reserved client_id must not be overridable")
	}
	if got := location.Query().Get("redirect_uri"); strings.Contains(got, "evil.example") {
		t.Fatalf("reserved redirect_uri was overridden: %q", got)
	}
	if got := location.Query().Get("response_type"); got != "code" {
		t.Fatalf("response_type=%q want code", got)
	}
	if got := location.Query().Get("acr_values"); got != "aal2" {
		t.Fatalf("acr_values=%q", got)
	}
}

// -----------------------------------------------------------------------------
// item 8a: step-up parameters reach the authorization request
// -----------------------------------------------------------------------------

func TestRedirectToProvider_ChallengeSendsMaxAge(t *testing.T) {
	cases := []struct {
		name        string
		isChallenge bool
		wantMaxAge  string
	}{
		{name: "challenge_sends_max_age", isChallenge: true, wantMaxAge: "600"},
		{name: "plain_login_does_not", isChallenge: false, wantMaxAge: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			toa := newPkceTestAuth(t)
			toa.Config.Provider.MaxAuthAgeSeconds = 600

			rw := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "https://app.example.com/page", nil)
			toa.redirectToProvider(rw, req, "https://app.example.com/page", tc.isChallenge)

			location, err := url.Parse(rw.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			if got := location.Query().Get("max_age"); got != tc.wantMaxAge {
				t.Fatalf("max_age=%q want %q", got, tc.wantMaxAge)
			}

			state := decodeStateFromLocation(t, location.String(), toa.Config.Secret)
			if state.IsChallenge != tc.isChallenge {
				t.Fatalf("state.IsChallenge=%v want %v", state.IsChallenge, tc.isChallenge)
			}
		})
	}
}

func TestDoubleRedirectToProvider_ChallengeSendsMaxAge(t *testing.T) {
	toa := newPkceTestAuth(t)
	toa.Config.Provider.MaxAuthAgeSeconds = 600

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/page", nil)
	toa.doubleRedirectToProvider(rw, req, "https://app.example.com/page", true)

	location, err := url.Parse(rw.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := location.Query().Get("max_age"); got != "600" {
		t.Fatalf("max_age=%q want 600", got)
	}
}

// -----------------------------------------------------------------------------
// item 13: discovery publication is race-free
// -----------------------------------------------------------------------------

func TestServeHTTP_ConcurrentFirstRequestsAreRaceFree(t *testing.T) {
	var discoveryCalls int
	var callLock sync.Mutex

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		callLock.Lock()
		discoveryCalls++
		callLock.Unlock()

		_ = json.NewEncoder(w).Encode(&oidc.OidcDiscovery{
			Issuer:                "https://idp.example.com",
			AuthorizationEndpoint: "https://idp.example.com/authorize",
			JWKSURI:               "https://idp.example.com/jwks",
		})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	providerURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	toa := newAuthBehaviorTestAuth(t)
	toa.ProviderURL = providerURL
	toa.httpClient = server.Client()
	toa.Config.LoginUri = "/login"
	toa.Config.Provider.ValidIssuer = ""
	toa.Config.Provider.ValidAudience = ""
	toa.Config.Provider.ClientId = "test-client"
	toa.Config.Authorization = &config.AuthorizationConfig{}
	toa.SessionStorage = &memSessionStorage{}
	toa.Jwks = nil
	toa.DiscoveryDocument = nil

	toa.next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	const goroutines = 32

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			rw := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://app.example.com/private/%d", i), nil)
			toa.ServeHTTP(rw, req)

			if rw.Code == http.StatusInternalServerError {
				t.Errorf("unexpected 500: %q", rw.Body.String())
			}
		}(i)
	}
	wg.Wait()

	callLock.Lock()
	defer callLock.Unlock()
	if discoveryCalls != 1 {
		t.Fatalf("discovery document fetched %d times, want exactly 1", discoveryCalls)
	}
	if toa.validIssuer != "https://idp.example.com" {
		t.Fatalf("validIssuer=%q", toa.validIssuer)
	}
	if toa.validAudience != "test-client" {
		t.Fatalf("validAudience=%q", toa.validAudience)
	}
	if toa.Jwks == nil || toa.Jwks.Url != "https://idp.example.com/jwks" {
		t.Fatalf("JWKS url was not published before the discovery document: %#v", toa.Jwks)
	}
}

// -----------------------------------------------------------------------------
// item 9: revocation is wired into logout and never blocks it
// -----------------------------------------------------------------------------

func TestHandleLogout_RevokesRefreshTokenAndSurvivesFailure(t *testing.T) {
	cases := []struct {
		name         string
		revokeStatus int
		wantRevoked  bool
	}{
		{name: "revocation_succeeds", revokeStatus: http.StatusOK, wantRevoked: true},
		{name: "revocation_fails_but_logout_continues", revokeStatus: http.StatusInternalServerError, wantRevoked: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var revoked string
			mux := http.NewServeMux()
			mux.HandleFunc("/revoke", func(w http.ResponseWriter, r *http.Request) {
				_ = r.ParseForm()
				revoked = r.Form.Get("token")
				w.WriteHeader(tc.revokeStatus)
			})
			server := httptest.NewServer(mux)
			defer server.Close()

			toa := newAuthBehaviorTestAuth(t)
			toa.httpClient = server.Client()
			toa.Config.Provider.RevokeTokensOnLogoutBool = true
			toa.Config.Provider.ClientSecret = "client-secret"
			toa.Config.PostLogoutRedirectUri = "/"
			toa.Config.LoginUri = "/login"
			toa.DiscoveryDocument.EndSessionEndpoint = "https://idp.example.com/logout"
			toa.DiscoveryDocument.RevocationEndpoint = server.URL + "/revoke"

			rw := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "https://app.example.com/logout", nil)
			toa.handleLogout(rw, req, &session.SessionState{Id: "s1", RefreshToken: "refresh-abc", IdToken: "id-abc"})

			if rw.Code != http.StatusFound {
				t.Fatalf("status=%d want 302, body=%q", rw.Code, rw.Body.String())
			}

			_ = revoked
			if tc.wantRevoked {
				if revoked != "refresh-abc" {
					t.Fatalf("revocation not called with the session refresh token, got %q", revoked)
				}
				if !strings.Contains(rw.Header().Get("Location"), "idp.example.com/logout") {
					t.Fatalf("unexpected Location %q", rw.Header().Get("Location"))
				}
			} else {
				// The revocation failed, but the logout must still have happened.
				if !strings.Contains(rw.Header().Get("Location"), "idp.example.com/logout") {
					t.Fatalf("a failed revocation must not block logout, Location=%q", rw.Header().Get("Location"))
				}
			}
		})
	}
}

// -----------------------------------------------------------------------------
// item 7 + N1: header templates are compiled once, at config time, never lazily
// on a request. Compiling them lazily mutated the shared Config element from every
// concurrent first request, which is a data race on the *template.Template pointer
// and inside text/template itself.
// -----------------------------------------------------------------------------

func TestAttachHeaders_DoesNotMutateSharedConfig(t *testing.T) {
	toa := newAuthBehaviorTestAuth(t)
	toa.Config.Headers = []config.HeaderConfig{
		{Name: "X-User", Value: "{{ .claims.sub }}", IncludeWhen: "Always"},
		{Name: "X-Groups", Values: `{{ .claims.groups | mapToJsonArray }}`, IncludeWhen: "Always"},
	}

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "https://app.example.com/secret", nil)
		err := toa.attachHeaders(req, &session.SessionState{}, map[string]interface{}{
			"sub":    "user-123",
			"groups": []string{"a", "b"},
		}, false, true)
		if err != nil {
			t.Fatal(err)
		}
		if got := req.Header.Get("X-User"); got != "user-123" {
			t.Fatalf("X-User=%q", got)
		}
	}

	// Rendering must never write back into the shared config slice.
	for index := range toa.Config.Headers {
		if toa.Config.Headers[index].Template != nil {
			t.Fatalf("header %d cached a template during request handling; New() owns compilation", index)
		}
	}
}

// TestAttachHeaders_ConcurrentDoesNotRace is the regression guard for the data race
// the request-time template cache introduced. Run under -race it fails loudly if
// attachHeaders ever mutates shared state again.
func TestAttachHeaders_ConcurrentDoesNotRace(t *testing.T) {
	toa := newAuthBehaviorTestAuth(t)
	toa.Config.Headers = []config.HeaderConfig{
		{Name: "X-User", Value: "{{ .claims.sub }}", IncludeWhen: "Always"},
		{Name: "X-Groups", Values: `{{ .claims.groups | mapToJsonArray }}`, IncludeWhen: "Always"},
	}

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				req := httptest.NewRequest(http.MethodGet, "https://app.example.com/secret", nil)
				if err := toa.attachHeaders(req, &session.SessionState{}, map[string]interface{}{
					"sub":    "user-123",
					"groups": []string{"a", "b"},
				}, false, true); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestNew_RejectsInvalidHeaderTemplate(t *testing.T) {
	// A malformed template must fail at construction, not silently degrade per request.
	cfg := CreateConfig()
	cfg.Secret = "0123456789abcdef0123456789abcdef"
	cfg.Provider.Url = "https://idp.example.com"
	cfg.Provider.ClientId = "client"
	cfg.Headers = []config.HeaderConfig{{Name: "X-User", Value: "{{ .claims.sub ", IncludeWhen: "Always"}}

	if _, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), cfg, "test"); err == nil {
		t.Fatal("expected New to reject a malformed header template")
	}
}

func TestPeerIP(t *testing.T) {
	cases := []struct {
		remoteAddr string
		want       string
	}{
		{remoteAddr: "203.0.113.7:41234", want: "203.0.113.7"},
		{remoteAddr: "203.0.113.7", want: "203.0.113.7"},
		{remoteAddr: "[2001:db8::1]:443", want: "2001:db8::1"},
		{remoteAddr: "2001:db8::1", want: "2001:db8::1"},
		{remoteAddr: "", want: ""},
		{remoteAddr: "not-an-ip:1", want: ""},
	}

	for _, tc := range cases {
		t.Run(tc.remoteAddr, func(t *testing.T) {
			got := peerIP(tc.remoteAddr)
			if tc.want == "" {
				if got != nil {
					t.Fatalf("peerIP(%q)=%v want nil", tc.remoteAddr, got)
				}
				return
			}
			if got == nil || got.String() != tc.want {
				t.Fatalf("peerIP(%q)=%v want %s", tc.remoteAddr, got, tc.want)
			}
		})
	}
}
