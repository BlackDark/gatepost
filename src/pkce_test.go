package src

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/BlackDark/gatepost/src/config"
	"github.com/BlackDark/gatepost/src/logging"
	"github.com/BlackDark/gatepost/src/oidc"
	"github.com/BlackDark/gatepost/src/session"
	"github.com/BlackDark/gatepost/src/utils"
)

func newPkceTestAuth(t *testing.T) *Gatepost {
	t.Helper()
	callback, err := url.Parse("https://app.example.com/oidc/callback")
	if err != nil {
		t.Fatal(err)
	}
	return &Gatepost{
		logger: logging.CreateLogger(logging.LevelError),
		Config: &config.Config{
			Secret:           "0123456789abcdef0123456789abcdef",
			CookieNamePrefix: "Gatepost",
			Scopes:           []string{"openid"},
			Provider: &config.ProviderConfig{
				ClientId:    "test-client",
				UsePkceBool: true,
			},
		},
		CallbackURL: callback,
		DiscoveryDocument: &oidc.OidcDiscovery{
			AuthorizationEndpoint: "https://idp.example.com/authorize",
			TokenEndpoint:         "https://idp.example.com/token",
		},
	}
}

func decodeStateFromLocation(t *testing.T, location string, secret string) *oidc.OidcState {
	t.Helper()
	u, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	st, err := oidc.UnsealState(u.Query().Get("state"), secret)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func s256Challenge(verifier string) string {
	sha2 := sha256.New()
	_, _ = io.WriteString(sha2, verifier)
	return base64.RawURLEncoding.EncodeToString(sha2.Sum(nil))
}

func TestRedirectToProvider_PkcePutsEncryptedVerifierInState(t *testing.T) {
	toa := newPkceTestAuth(t)
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/page", nil)

	toa.redirectToProvider(rw, req, "https://app.example.com/page", false)

	if rw.Code != http.StatusFound {
		t.Fatalf("status=%d", rw.Code)
	}
	for _, c := range rw.Result().Cookies() {
		if strings.Contains(c.Name, "CodeVerifier") && c.MaxAge >= 0 && c.Value != "" {
			t.Fatalf("unexpected CodeVerifier cookie %q value set", c.Name)
		}
	}

	loc, err := url.Parse(rw.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	st := decodeStateFromLocation(t, loc.String(), toa.Config.Secret)
	if st.CodeVerifierEnc == "" {
		t.Fatal("expected CodeVerifierEnc in state")
	}
	plain, err := utils.Decrypt(st.CodeVerifierEnc, toa.Config.Secret)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if len(plain) < 32 {
		t.Fatalf("verifier too short: %q", plain)
	}
	challenge := loc.Query().Get("code_challenge")
	if challenge == "" {
		t.Fatal("missing code_challenge")
	}
	if got := s256Challenge(plain); got != challenge {
		t.Fatalf("code_challenge mismatch: got %q want %q", challenge, got)
	}
	if loc.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("unexpected method %q", loc.Query().Get("code_challenge_method"))
	}
}

func TestRedirectToProvider_ParallelFlowsHaveDistinctVerifiers(t *testing.T) {
	toa := newPkceTestAuth(t)
	verifiers := map[string]struct{}{}
	for i := 0; i < 5; i++ {
		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://app.example.com/page", nil)
		toa.redirectToProvider(rw, req, "https://app.example.com/page", false)
		st := decodeStateFromLocation(t, rw.Header().Get("Location"), toa.Config.Secret)
		plain, err := utils.Decrypt(st.CodeVerifierEnc, toa.Config.Secret)
		if err != nil {
			t.Fatal(err)
		}
		if _, dup := verifiers[plain]; dup {
			t.Fatalf("duplicate verifier across parallel redirects")
		}
		verifiers[plain] = struct{}{}
	}
}

func TestRedirectToProvider_ClearsLegacyCodeVerifierCookies(t *testing.T) {
	toa := newPkceTestAuth(t)
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/page", nil)
	req.AddCookie(&http.Cookie{Name: "Gatepost.CodeVerifier", Value: "old"})
	req.AddCookie(&http.Cookie{Name: "Gatepost.CodeVerifier.abc", Value: "old2"})

	toa.redirectToProvider(rw, req, "https://app.example.com/page", false)

	expired := map[string]bool{}
	for _, c := range rw.Result().Cookies() {
		if strings.Contains(c.Name, "CodeVerifier") && c.MaxAge < 0 {
			expired[c.Name] = true
		}
	}
	if !expired["Gatepost.CodeVerifier"] || !expired["Gatepost.CodeVerifier.abc"] {
		t.Fatalf("expected legacy CodeVerifier cookies expired, got %#v", expired)
	}
}

func TestRedirectToProvider_NoLegacyClearWhenPkceDisabled(t *testing.T) {
	toa := newPkceTestAuth(t)
	toa.Config.Provider.UsePkceBool = false
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/page", nil)
	req.AddCookie(&http.Cookie{Name: "Gatepost.CodeVerifier", Value: "old"})

	toa.redirectToProvider(rw, req, "https://app.example.com/page", false)

	for _, c := range rw.Result().Cookies() {
		if strings.Contains(c.Name, "CodeVerifier") {
			t.Fatalf("PKCE disabled must not clear CodeVerifier cookies, got %q", c.Name)
		}
	}
}

type memSessionStorage struct{}

func (m *memSessionStorage) StoreSession(logger *logging.Logger, cfg *config.Config, sessionId string, state *session.SessionState) (string, error) {
	return "ticket", nil
}

func (m *memSessionStorage) TryGetSession(logger *logging.Logger, cfg *config.Config, sessionTicket string) (*session.SessionState, error) {
	return nil, nil
}

func newCallbackTestAuth(t *testing.T, usePkce bool, tokenURL, introspectURL string) *Gatepost {
	t.Helper()
	toa := newPkceTestAuth(t)
	toa.Config.Provider.UsePkceBool = usePkce
	toa.Config.Provider.TokenValidation = "Introspection"
	toa.Config.Authorization = &config.AuthorizationConfig{}
	toa.Config.SessionCookie = &config.SessionCookieConfig{
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: "lax",
	}
	toa.Config.PostLoginRedirectUri = "/"
	toa.SessionStorage = &memSessionStorage{}
	toa.httpClient = http.DefaultClient
	toa.DiscoveryDocument.TokenEndpoint = tokenURL
	toa.DiscoveryDocument.IntrospectionEndpoint = introspectURL
	return toa
}

func TestHandleCallback_ClearsLegacyCookiesOnlyWhenPkceEnabled(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(&oidc.OidcTokenResponse{
			AccessToken: "access-token",
			IdToken:     "id-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	})
	mux.HandleFunc("/introspect", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"active": true,
			"sub":    "user-1",
		})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	cases := []struct {
		name       string
		usePkce    bool
		wantClears bool
	}{
		{name: "pkce_off", usePkce: false, wantClears: false},
		{name: "pkce_on", usePkce: true, wantClears: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			toa := newCallbackTestAuth(t, tc.usePkce, server.URL+"/token", server.URL+"/introspect")

			state := &oidc.OidcState{
				Action:      "Login",
				RedirectUrl: "https://app.example.com/",
				Csrf:        "csrf-test-value-0123456789abcdef",
			}
			if tc.usePkce {
				enc, err := utils.Encrypt("pkce-verifier-value-for-callback-test-01234567", toa.Config.Secret)
				if err != nil {
					t.Fatal(err)
				}
				state.CodeVerifierEnc = enc
			}
			stateB64, err := oidc.SealState(state, toa.Config.Secret)
			if err != nil {
				t.Fatal(err)
			}

			rw := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "https://app.example.com/oidc/callback?code=abc&state="+url.QueryEscape(stateB64), nil)
			req.AddCookie(&http.Cookie{Name: "Gatepost.CodeVerifier", Value: "legacy"})
			req.AddCookie(&http.Cookie{Name: getLoginCsrfCookieName(toa.Config, state.Csrf), Value: state.Csrf})

			toa.handleCallback(rw, req)

			if rw.Code >= 400 {
				t.Fatalf("callback status=%d body=%s", rw.Code, rw.Body.String())
			}

			cleared := false
			for _, c := range rw.Result().Cookies() {
				if strings.Contains(c.Name, "CodeVerifier") && c.MaxAge < 0 {
					cleared = true
					break
				}
			}
			if cleared != tc.wantClears {
				t.Fatalf("cleared=%v wantClears=%v cookies=%v", cleared, tc.wantClears, rw.Result().Cookies())
			}
		})
	}
}

func TestRedirectToProvider_StateSizeReasonable(t *testing.T) {
	toa := newPkceTestAuth(t)
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/page", nil)
	longRedirect := "https://app.example.com/" + strings.Repeat("a", 2000)
	toa.redirectToProvider(rw, req, longRedirect, false)

	loc, err := url.Parse(rw.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	state := loc.Query().Get("state")
	if len(state) > 5000 {
		t.Fatalf("state too large: %d bytes", len(state))
	}
}

func TestExchangeAuthCode_UsesStateVerifier(t *testing.T) {
	const wantVerifier = "pkce-verifier-value-for-test-0123456789abcdef"
	posted := make(chan string, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		posted <- r.Form.Get("code_verifier")
		_ = json.NewEncoder(w).Encode(&oidc.OidcTokenResponse{
			AccessToken: "access",
			IdToken:     "id",
			TokenType:   "Bearer",
		})
	}))
	defer server.Close()

	toa := newPkceTestAuth(t)
	toa.httpClient = server.Client()
	toa.DiscoveryDocument.TokenEndpoint = server.URL

	enc, err := utils.Encrypt(wantVerifier, toa.Config.Secret)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/oidc/callback", nil)
	// Cookie present must be ignored — verifier comes from state.
	req.AddCookie(&http.Cookie{Name: "Gatepost.CodeVerifier", Value: "wrong"})

	_, err = exchangeAuthCode(toa, req, "auth-code", enc)
	if err != nil {
		t.Fatalf("exchangeAuthCode: %v", err)
	}
	got := <-posted
	if got != wantVerifier {
		t.Fatalf("code_verifier=%q want %q", got, wantVerifier)
	}
}

func TestExchangeAuthCode_MissingVerifierFailsBeforePost(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	toa := newPkceTestAuth(t)
	toa.httpClient = server.Client()
	toa.DiscoveryDocument.TokenEndpoint = server.URL

	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/oidc/callback", nil)
	_, err := exchangeAuthCode(toa, req, "auth-code", "")
	if err == nil {
		t.Fatal("expected error")
	}
	if called {
		t.Fatal("token endpoint must not be called without verifier")
	}
}

func TestExchangeAuthCode_GarbageVerifierFailsBeforePost(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	toa := newPkceTestAuth(t)
	toa.httpClient = server.Client()
	toa.DiscoveryDocument.TokenEndpoint = server.URL

	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/oidc/callback", nil)
	_, err := exchangeAuthCode(toa, req, "auth-code", "not-valid-ciphertext")
	if err == nil {
		t.Fatal("expected error")
	}
	if called {
		t.Fatal("token endpoint must not be called with garbage verifier")
	}
}

func TestDoubleRedirect_DoesNotSetPkceCookieOrChallenge(t *testing.T) {
	toa := newPkceTestAuth(t)
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/page", nil)

	toa.doubleRedirectToProvider(rw, req, "https://app.example.com/page", false)

	if rw.Code != http.StatusFound {
		t.Fatalf("status=%d", rw.Code)
	}
	for _, c := range rw.Result().Cookies() {
		if strings.Contains(c.Name, "CodeVerifier") && c.Value != "" && c.MaxAge >= 0 {
			t.Fatalf("double redirect must not set PKCE cookie: %q", c.Name)
		}
	}
	loc, err := url.Parse(rw.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Query().Get("code_challenge") != "" {
		t.Fatal("double redirect must not send code_challenge to IdP")
	}
	st, err := oidc.UnsealState(loc.Query().Get("state"), toa.Config.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if st.Action != "RedirectThenLogin" {
		t.Fatalf("action=%q", st.Action)
	}
	if st.CodeVerifierEnc != "" {
		t.Fatal("verifier must be created only on IdP redirect hop")
	}
	if st.Csrf != "" {
		t.Fatal("csrf must be created only on IdP redirect hop")
	}
	for _, c := range rw.Result().Cookies() {
		if strings.Contains(c.Name, "LoginCsrf") && c.MaxAge >= 0 && c.Value != "" {
			t.Fatalf("double redirect must not set LoginCsrf cookie: %q", c.Name)
		}
	}
}

func TestRedirectToProvider_SetsNonce(t *testing.T) {
	toa := newPkceTestAuth(t)
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/page", nil)
	toa.redirectToProvider(rw, req, "https://app.example.com/page", false)

	loc, err := url.Parse(rw.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	st := decodeStateFromLocation(t, loc.String(), toa.Config.Secret)
	if st.Nonce == "" {
		t.Fatal("expected nonce in state")
	}
	if loc.Query().Get("nonce") != st.Nonce {
		t.Fatalf("authorize nonce=%q state=%q", loc.Query().Get("nonce"), st.Nonce)
	}
}

func TestOidcNonceMatches(t *testing.T) {
	if !oidcNonceMatches("abc", "abc") {
		t.Fatal("expected match")
	}
	if oidcNonceMatches("abc", "xyz") {
		t.Fatal("expected mismatch")
	}
}

func TestRedirectToProvider_SetsLoginCsrfCookie(t *testing.T) {
	toa := newPkceTestAuth(t)
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/page", nil)
	toa.redirectToProvider(rw, req, "https://app.example.com/page", false)

	st := decodeStateFromLocation(t, rw.Header().Get("Location"), toa.Config.Secret)
	if st.Csrf == "" {
		t.Fatal("expected csrf in state")
	}
	found := false
	for _, c := range rw.Result().Cookies() {
		if c.Name == getLoginCsrfCookieName(toa.Config, st.Csrf) && c.Value == st.Csrf {
			found = true
			if c.SameSite != http.SameSiteLaxMode {
				t.Fatalf("SameSite=%v", c.SameSite)
			}
		}
	}
	if !found {
		t.Fatal("expected LoginCsrf cookie matching state")
	}
}

func httpsRequest(rawURL string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, rawURL, nil)
	req.TLS = &tls.ConnectionState{}
	return req
}

func TestNeedsDoubleRedirect(t *testing.T) {
	cases := []struct {
		name       string
		callback   string
		requestURL string
		usePkce    bool
		want       bool
	}{
		{name: "relative_callback", callback: "/oidc/callback", requestURL: "https://app.example.com/page", usePkce: true},
		{name: "relative_callback_no_pkce", callback: "/oidc/callback", requestURL: "https://app.example.com/page"},
		{name: "same_host", callback: "https://app.example.com/oidc/callback", requestURL: "https://app.example.com/page", usePkce: true},
		{name: "same_host_no_pkce", callback: "https://app.example.com/oidc/callback", requestURL: "https://app.example.com/page"},
		{name: "other_host_pkce", callback: "https://auth.example.com/oidc/callback", requestURL: "https://app.example.com/page", usePkce: true, want: true},
		{name: "other_host_no_pkce", callback: "https://auth.example.com/oidc/callback", requestURL: "https://app.example.com/page", want: true},
		{name: "other_port", callback: "https://app.example.com:8443/oidc/callback", requestURL: "https://app.example.com/page", want: true},
		{name: "default_https_port", callback: "https://app.example.com/oidc/callback", requestURL: "https://app.example.com:443/page"},
		{name: "default_https_port_on_callback", callback: "https://app.example.com:443/oidc/callback", requestURL: "https://app.example.com/page"},
		{name: "other_scheme", callback: "http://app.example.com/oidc/callback", requestURL: "https://app.example.com/page", want: true},
		{name: "host_is_prefix_of_callback_host", callback: "https://app.example.com.evil.test/oidc/callback", requestURL: "https://app.example.com/page", want: true},
		{name: "host_case_insensitive", callback: "https://APP.EXAMPLE.COM/oidc/callback", requestURL: "https://app.example.com/page"},
		{name: "ipv6", callback: "https://[2001:db8::1]/oidc/callback", requestURL: "https://[2001:db8::1]/page"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			toa := newPkceTestAuth(t)
			toa.Config.Provider.UsePkceBool = tc.usePkce

			callback, err := url.Parse(tc.callback)
			if err != nil {
				t.Fatal(err)
			}
			toa.CallbackURL = callback

			if got := toa.needsDoubleRedirect(httpsRequest(tc.requestURL)); got != tc.want {
				t.Fatalf("needsDoubleRedirect=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestNeedsDoubleRedirect_DoesNotLoopOnCallbackPath(t *testing.T) {
	toa := newPkceTestAuth(t)
	callback, err := url.Parse("https://app.example.com/oidc/callback")
	if err != nil {
		t.Fatal(err)
	}
	toa.CallbackURL = callback

	state, err := oidc.SealState(&oidc.OidcState{Action: "RedirectThenLogin", RedirectUrl: "https://app.example.com/page"}, toa.Config.Secret)
	if err != nil {
		t.Fatal(err)
	}
	onCallback := httptest.NewRequest(http.MethodGet, "http://app.example.com/oidc/callback?state="+url.QueryEscape(state), nil)
	if toa.needsDoubleRedirect(onCallback) {
		t.Fatal("must not bounce the callback path again when the bounce state came back")
	}

	onPage := httptest.NewRequest(http.MethodGet, "http://app.example.com/page", nil)
	if !toa.needsDoubleRedirect(onPage) {
		t.Fatal("a different path should still bounce to the https callback")
	}
}

func TestNeedsDoubleRedirect_BareIPv6Host(t *testing.T) {
	toa := newPkceTestAuth(t)
	callback, err := url.Parse("https://[2001:db8::1]/oidc/callback")
	if err != nil {
		t.Fatal(err)
	}
	toa.CallbackURL = callback

	req := httpsRequest("https://[2001:db8::1]/page")
	req.Host = "2001:db8::1"
	if toa.needsDoubleRedirect(req) {
		t.Fatal("bare IPv6 host must match the bracketed callback host")
	}
	if !toa.isCallbackRequest(httpsRequest("https://[2001:db8::1]/oidc/callback")) {
		t.Fatal("bracketed IPv6 callback must be recognized")
	}
}

func TestNeedsDoubleRedirect_StopsForRewrittenCallbackHost(t *testing.T) {
	toa := newPkceTestAuth(t)
	callback, err := url.Parse("https://app.example.com/oidc/callback")
	if err != nil {
		t.Fatal(err)
	}
	toa.CallbackURL = callback

	state, err := oidc.SealState(&oidc.OidcState{Action: "RedirectThenLogin", RedirectUrl: "https://app.example.com/page"}, toa.Config.Secret)
	if err != nil {
		t.Fatal(err)
	}

	// A proxy in front of an HTTP entrypoint can present the https callback as
	// http with an explicit :443, which is not the default port for http.
	withPort := httptest.NewRequest(http.MethodGet, "http://app.example.com/oidc/callback?state="+url.QueryEscape(state), nil)
	withPort.Host = "app.example.com:443"
	if toa.needsDoubleRedirect(withPort) {
		t.Fatal("bounce state must stop a :443 rewrite from looping")
	}

	otherHost := httptest.NewRequest(http.MethodGet, "https://service1.example.com/oidc/callback?state="+url.QueryEscape(state), nil)
	otherHost.Host = "service1.example.com"
	otherHost.TLS = &tls.ConnectionState{}
	if !toa.needsDoubleRedirect(otherHost) {
		t.Fatal("a bounce state on a different host must still be sent to the callback host")
	}
}

func TestRedirectToProvider_PreservesCallbackQuery(t *testing.T) {
	toa := newPkceTestAuth(t)
	callback, err := url.Parse("https://app.example.com/oidc/callback?client=web")
	if err != nil {
		t.Fatal(err)
	}
	toa.CallbackURL = callback

	rw := httptest.NewRecorder()
	toa.redirectToProvider(rw, httpsRequest("https://app.example.com/page"), "https://app.example.com/page", false)

	loc, err := url.Parse(rw.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := loc.Query().Get("redirect_uri"); got != "https://app.example.com/oidc/callback?client=web" {
		t.Fatalf("redirect_uri=%q", got)
	}
	if toa.CallbackURL.RawQuery != "client=web" {
		t.Fatalf("CallbackURL query=%q", toa.CallbackURL.RawQuery)
	}
}

func TestIsCallbackRequest_DefaultPort(t *testing.T) {
	toa := newPkceTestAuth(t)
	callback, err := url.Parse("https://app.example.com/oidc/callback")
	if err != nil {
		t.Fatal(err)
	}
	toa.CallbackURL = callback

	req := httpsRequest("https://app.example.com:443/oidc/callback")
	if !toa.isCallbackRequest(req) {
		t.Fatal("https default port must still be the callback")
	}

	req = httpsRequest("https://app.example.com.evil.test/oidc/callback")
	if toa.isCallbackRequest(req) {
		t.Fatal("a longer host must not be the callback")
	}
}

func TestNeedsDoubleRedirect_UsesTrustedForwardedOrigin(t *testing.T) {
	toa := newPkceTestAuth(t)
	toa.Config.Provider.UsePkceBool = false
	callback, err := url.Parse("https://auth.example.com/oidc/callback")
	if err != nil {
		t.Fatal(err)
	}
	toa.CallbackURL = callback

	_, network, err := net.ParseCIDR("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	toa.Config.TrustedProxyNets = []*net.IPNet{network}

	req := httptest.NewRequest(http.MethodGet, "http://internal/page", nil)
	req.RemoteAddr = "192.0.2.10:1234"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "auth.example.com")
	if toa.needsDoubleRedirect(req) {
		t.Fatal("trusted forwarded origin matches the callback; must not double-redirect")
	}

	req.RemoteAddr = "203.0.113.7:1234"
	if !toa.needsDoubleRedirect(req) {
		t.Fatal("untrusted X-Forwarded-Host must not skip the callback hop")
	}
}

func TestHandleLogin_CrossOriginCallbackSetsCsrfOnCallbackHost(t *testing.T) {
	toa := newPkceTestAuth(t)
	toa.Config.Provider.UsePkceBool = false
	toa.Config.ValidPostLoginRedirectUris = []string{"https://app.example.com/page"}
	callback, err := url.Parse("https://auth.example.com/oidc/callback")
	if err != nil {
		t.Fatal(err)
	}
	toa.CallbackURL = callback

	rw := httptest.NewRecorder()
	toa.handleLogin(rw, httpsRequest("https://app.example.com/page"), false, "https://app.example.com/page")

	if rw.Code != http.StatusFound {
		t.Fatalf("status=%d", rw.Code)
	}
	loc, err := url.Parse(rw.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Scheme != "https" || loc.Host != "auth.example.com" || loc.Path != "/oidc/callback" {
		t.Fatalf("Location=%q, want the callback origin", rw.Header().Get("Location"))
	}
	st, err := oidc.UnsealState(loc.Query().Get("state"), toa.Config.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if st.Action != "RedirectThenLogin" {
		t.Fatalf("action=%q", st.Action)
	}
	if st.Csrf != "" {
		t.Fatal("csrf must be created on the callback host, not the app host")
	}
	for _, c := range rw.Result().Cookies() {
		if strings.Contains(c.Name, "LoginCsrf") && c.MaxAge >= 0 && c.Value != "" {
			t.Fatalf("app host must not set LoginCsrf: %q", c.Name)
		}
	}
	if toa.CallbackURL.RawQuery != "" || toa.CallbackURL.Fragment != "" {
		t.Fatalf("double redirect mutated CallbackURL: %s", toa.CallbackURL)
	}

	// The callback host now starts the real IdP redirect. redirect_uri must be
	// the registered callback, not the bounce URL with its state query.
	rw2 := httptest.NewRecorder()
	arrived := httpsRequest(rw.Header().Get("Location"))
	toa.handleCallback(rw2, arrived)
	if rw2.Code != http.StatusFound {
		t.Fatalf("callback status=%d body=%s", rw2.Code, rw2.Body.String())
	}
	idp, err := url.Parse(rw2.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if idp.Query().Get("redirect_uri") != "https://auth.example.com/oidc/callback" {
		t.Fatalf("redirect_uri=%q", idp.Query().Get("redirect_uri"))
	}
	if toa.CallbackURL.RawQuery != "" {
		t.Fatalf("CallbackURL query still set: %q", toa.CallbackURL.RawQuery)
	}
}

func TestHandleCallback_RejectsMissingCsrfCookie(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		t.Error("token endpoint must not be called")
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	toa := newCallbackTestAuth(t, false, server.URL+"/token", server.URL+"/introspect")
	state := &oidc.OidcState{
		Action:      "Login",
		RedirectUrl: "https://app.example.com/",
		Csrf:        "csrf-missing-cookie-test",
	}
	stateB64, err := oidc.SealState(state, toa.Config.Secret)
	if err != nil {
		t.Fatal(err)
	}
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/oidc/callback?code=abc&state="+url.QueryEscape(stateB64), nil)
	toa.handleCallback(rw, req)
	if rw.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403", rw.Code)
	}
}
