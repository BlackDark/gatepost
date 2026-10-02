package src

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/BlackDark/test-oidc-traefik-plugin/src/config"
	"github.com/BlackDark/test-oidc-traefik-plugin/src/errorPages"
	"github.com/BlackDark/test-oidc-traefik-plugin/src/rules"

	"github.com/BlackDark/test-oidc-traefik-plugin/src/logging"
	"github.com/BlackDark/test-oidc-traefik-plugin/src/oidc"
	"github.com/BlackDark/test-oidc-traefik-plugin/src/session"
	"github.com/BlackDark/test-oidc-traefik-plugin/src/utils"
)

// clientIdentityHeaders are the well-known headers a backend or a sibling
// authenticating proxy treats as proof of authentication. A client can set any
// header it likes, so leaving them in place lets a caller claim to be any user on
// every path that reaches the backend without this middleware having verified
// them: the bypass-rule path, unauthenticatedBehavior: Forward and
// unauthorizedBehavior: Forward. They are removed unconditionally and then
// re-set from the session by attachHeaders.
var clientIdentityHeaders = []string{
	"X-Forwarded-User",
	"X-Forwarded-Groups",
	"X-Forwarded-Email",
	"X-Auth-Request-User",
	"X-Auth-Request-Email",
	"X-Auth-Request-Groups",
	"X-Auth-Request-Preferred-Username",
	"Remote-User",
	"Remote-Groups",
}

type TraefikOidcAuth struct {
	logger                      *logging.Logger
	next                        http.Handler
	httpClient                  *http.Client
	ProviderURL                 *url.URL
	ClientJwtPrivateKey         *rsa.PrivateKey
	CallbackURL                 *url.URL
	Config                      *config.Config
	SessionStorage              session.SessionStorage
	DiscoveryDocument           *oidc.OidcDiscovery
	Jwks                        *oidc.JwksHandler
	Lock                        sync.RWMutex
	BypassAuthenticationRule    *rules.RequestCondition
	RedirectUriWildcardsEnabled bool

	// validIssuer / validAudience are the middleware-owned copies of the
	// discovery defaults. They are filled in once, under Lock, at the moment
	// discovery initialises - the config copy is only mutated because
	// validateTokenLocally (src/oidc.go) reads it directly.
	validIssuer   string
	validAudience string

	// sessionWrites tracks when this process last emitted a session ticket per
	// session, so the idle bound can be made durable without writing a
	// Set-Cookie on literally every request. See sessionIdleRefreshDue.
	sessionWrites sessionWriteTracker
}

// EnsureOidcDiscovery fetches the OIDC discovery document exactly once and
// publishes it in a safe order: Jwks and the issuer/audience defaults are fully
// initialised before DiscoveryDocument becomes visible, so a reader that sees a
// non-nil document also sees everything that depends on it.
//
// A failed attempt is not cached, so a temporarily unreachable IdP recovers on
// the next request.
func (toa *TraefikOidcAuth) EnsureOidcDiscovery() error {
	// Fast path under the read lock: unsynchronised reads of DiscoveryDocument
	// are a data race against the initialisation below.
	toa.Lock.RLock()
	ready := toa.DiscoveryDocument != nil
	toa.Lock.RUnlock()

	if ready {
		return nil
	}

	toa.Lock.Lock()
	defer toa.Lock.Unlock()

	// check again after lock
	if toa.DiscoveryDocument != nil {
		return nil
	}

	parsedURL := toa.ProviderURL

	jwks := &oidc.JwksHandler{}
	toa.Jwks = jwks
	toa.logger.Log(logging.LevelInfo, "Getting OIDC discovery document...")

	oidcDiscoveryDocument, err := GetOidcDiscovery(toa.logger, toa.httpClient, parsedURL)
	if err != nil {
		toa.logger.Log(logging.LevelError, "Error while retrieving discovery document: %s", err.Error())
		return err
	}

	// Apply defaults
	validIssuer := toa.Config.Provider.ValidIssuer
	if validIssuer == "" {
		validIssuer = oidcDiscoveryDocument.Issuer
	}
	validAudience := toa.Config.Provider.ValidAudience
	if validAudience == "" {
		validAudience = toa.Config.Provider.ClientId
	}

	toa.logger.Log(logging.LevelInfo, "OIDC Discovery successful. AuthEndPoint: %s", oidcDiscoveryDocument.AuthorizationEndpoint)

	// Everything that DiscoveryDocument consumers depend on is set before the
	// document itself is published.
	jwks.Url = oidcDiscoveryDocument.JWKSURI
	toa.validIssuer = validIssuer
	toa.validAudience = validAudience

	// src/oidc.go validates tokens against the config values directly, so they
	// have to be filled in too - but only here, under the write lock, before
	// publication. Nothing mutates the shared config after this point.
	toa.Config.Provider.ValidIssuer = validIssuer
	toa.Config.Provider.ValidAudience = validAudience

	toa.DiscoveryDocument = oidcDiscoveryDocument

	return nil
}

// validIssuerOrConfig returns the effective issuer: the middleware-owned copy
// when discovery initialised, else the configured value (which is what a
// hand-constructed middleware - tests, the Traefik catalog hack - carries).
func (toa *TraefikOidcAuth) effectiveValidIssuer() string {
	toa.Lock.RLock()
	value := toa.validIssuer
	toa.Lock.RUnlock()

	if value != "" {
		return value
	}

	if toa.Config == nil || toa.Config.Provider == nil {
		return ""
	}

	return toa.Config.Provider.ValidIssuer
}

// requestScheme resolves the scheme to use for absolute URLs. X-Forwarded-Proto
// is attacker-controlled, so it is only read from a peer listed in
// trusted_proxies, and only when it names a scheme we are willing to build a URL
// from.
func (toa *TraefikOidcAuth) requestScheme(req *http.Request) string {
	if toa.requestFromTrustedProxy(req) {
		if proto := firstForwardedValue(req.Header.Get("X-Forwarded-Proto")); proto != "" {
			if validForwardedProto(proto) {
				return proto
			}

			toa.logger.Log(logging.LevelWarn, "Ignoring X-Forwarded-Proto %q from a trusted proxy: not one of http, https, ws, wss", proto)
		}
	}

	if req.TLS != nil {
		return "https"
	}

	return "http"
}

// requestHost resolves the host to use for absolute URLs, under the same
// trusted-proxy gating as requestScheme.
func (toa *TraefikOidcAuth) requestHost(req *http.Request) string {
	if toa.requestFromTrustedProxy(req) {
		if host := firstForwardedValue(req.Header.Get("X-Forwarded-Host")); host != "" {
			return host
		}
	}

	return req.Host
}

func (toa *TraefikOidcAuth) fullHost(req *http.Request) string {
	return toa.requestScheme(req) + "://" + toa.requestHost(req)
}

// ensureAbsoluteUrl is the trusted-proxy aware replacement for
// utils.EnsureAbsoluteUrl.
func (toa *TraefikOidcAuth) ensureAbsoluteUrl(req *http.Request, rawUrl string) string {
	if strings.HasPrefix(rawUrl, "http://") || strings.HasPrefix(rawUrl, "https://") {
		return rawUrl
	}

	if !strings.HasPrefix(rawUrl, "/") {
		rawUrl = "/" + rawUrl
	}

	return toa.fullHost(req) + rawUrl
}

// requestFromTrustedProxy reports whether the request arrived from a proxy the
// operator declared in trusted_proxies. An empty list trusts nothing, which is
// the same fail-closed default cmd/extauth-server uses.
func (toa *TraefikOidcAuth) requestFromTrustedProxy(req *http.Request) bool {
	if toa.Config == nil || len(toa.Config.TrustedProxyNets) == 0 {
		return false
	}

	ip := peerIP(req.RemoteAddr)
	if ip == nil {
		return false
	}

	for _, network := range toa.Config.TrustedProxyNets {
		if network != nil && network.Contains(ip) {
			return true
		}
	}

	return false
}

// peerIP extracts the IP from an http.Request.RemoteAddr, which carries a port
// in the server case and may be a bare IP (or a bracketed IPv6 literal with a
// zone) in other cases.
func peerIP(remoteAddr string) net.IP {
	if remoteAddr == "" {
		return nil
	}

	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		remoteAddr = host
	}

	remoteAddr = strings.TrimSuffix(strings.TrimPrefix(remoteAddr, "["), "]")

	if zone := strings.LastIndex(remoteAddr, "%"); zone > 0 {
		remoteAddr = remoteAddr[:zone]
	}

	return net.ParseIP(remoteAddr)
}

func validForwardedProto(proto string) bool {
	switch proto {
	case "http", "https", "ws", "wss":
		return true
	}

	return false
}

// firstForwardedValue returns the first entry of a possibly comma-separated
// forwarding header, which is the hop closest to the client.
func firstForwardedValue(value string) string {
	value = strings.TrimSpace(value)
	if index := strings.Index(value, ","); index >= 0 {
		value = strings.TrimSpace(value[:index])
	}

	return value
}

func (toa *TraefikOidcAuth) GetAbsoluteCallbackURL(req *http.Request) *url.URL {
	if utils.UrlIsAbsolute(toa.CallbackURL) {
		return toa.CallbackURL
	}

	abs := *toa.CallbackURL
	abs.Scheme = toa.requestScheme(req)
	abs.Host = toa.requestHost(req)
	return &abs
}

func (toa *TraefikOidcAuth) isCallbackRequest(req *http.Request) bool {
	// Compare against the decoded path, like every other route match below, and
	// never mutate req.URL.
	if !pathMatchesRoute(req.URL.Path, toa.CallbackURL.Path) {
		return false
	}

	if utils.UrlIsAbsolute(toa.CallbackURL) {
		if toa.requestScheme(req) != toa.CallbackURL.Scheme || toa.requestHost(req) != toa.CallbackURL.Host {
			return false
		}
	}

	return true
}

// pathMatchesRoute matches a decoded request path against a configured route:
// either exactly, or below it with a trailing slash. Never a bare prefix, so
// /logout does not swallow /logout-history and /logins is not a login.
func pathMatchesRoute(requestPath, route string) bool {
	if route == "" {
		return false
	}

	// Normalise the route so a configured trailing slash is not a difference.
	trimmed := strings.TrimSuffix(route, "/")
	if trimmed == "" {
		trimmed = "/"
	}

	if requestPath == route || requestPath == trimmed {
		return true
	}

	if trimmed == "/" {
		return false
	}

	return strings.HasPrefix(requestPath, trimmed+"/")
}

// pathMatchesConfiguredRoute matches the request's decoded path against a
// configured route. The raw RequestURI (query string and percent-encoding
// included) is deliberately not used.
func (toa *TraefikOidcAuth) pathMatchesConfiguredRoute(req *http.Request, route string) bool {
	return pathMatchesRoute(req.URL.Path, route)
}

func (toa *TraefikOidcAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	isPublic := false
	if toa.BypassAuthenticationRule != nil {
		if toa.BypassAuthenticationRule.Match(toa.logger, req) {
			toa.logger.Log(logging.LevelDebug, "BypassAuthenticationRule matched. Forwarding request without authentication.")
			isPublic = true
		} else {
			toa.logger.Log(logging.LevelDebug, "BypassAuthenticationRule not matched. Requiring authentication.")
		}
	}

	if toa.isCallbackRequest(req) {
		if err := toa.EnsureOidcDiscovery(); err != nil {
			toa.internalError(rw, "Authentication is temporarily unavailable", "getting oidc discovery", err)
			return
		}

		toa.handleCallback(rw, req)
		return
	}

	// A route the operator explicitly declared public must not depend on the
	// IdP being reachable: an IdP outage used to turn a public route into a 500.
	// Only short-circuit when there is no session material that would have to be
	// validated (and would therefore need discovery).
	if isPublic && !toa.hasSessionMaterial(req) {
		toa.forwardToUpstream(rw, req, nil, nil, true, false)
		return
	}

	err := toa.EnsureOidcDiscovery()
	if err != nil {
		toa.internalError(rw, "Authentication is temporarily unavailable", "getting oidc discovery", err)
		return
	}

	if toa.pathMatchesConfiguredRoute(req, toa.Config.LoginUri) {
		toa.handleLogin(rw, req, false, "")
		return
	}

	sess, updateSession, claims, err := toa.getSessionForRequest(req)

	if err == nil && sess != nil {
		// Handle logout
		if toa.pathMatchesConfiguredRoute(req, toa.Config.LogoutUri) {
			toa.handleLogout(rw, req, sess)
			return
		}

		if toa.pathMatchesConfiguredRoute(req, toa.Config.FrontChannelLogoutUri) {
			toa.handleFrontchannelLogout(rw, req, sess, claims)
			return
		}

		// If this request is using external authentication by using a header or custom cookie,
		// we need to validate the authorization on every request.
		// Ensure the session is authorized
		if sess.Id == "AuthorizationHeader" || sess.Id == "AuthorizationCookie" || toa.Config.Authorization.CheckOnEveryRequest {
			sess.IsAuthorized = isAuthorized(toa.logger, toa.Config.Authorization, claims)
		}

		if !sess.IsAuthorized && toa.Config.UnauthorizedBehavior != "Forward" {
			toa.handleUnauthorized(rw, req, sess, "")
			return
		}

		// Strip the internal cookies and any client-supplied identity headers
		// FIRST, then attach the configured headers, so a configured identity
		// header is Set from the session rather than deleted again (or inherited).
		toa.sanitizeForUpstream(req)

		// Attach upstream headers
		err = toa.attachHeaders(req, sess, claims, isPublic, sess.IsAuthorized)
		if err != nil {
			toa.internalError(rw, "Authentication is temporarily unavailable", "attaching headers", err)
			return
		}

		if updateSession || toa.sessionIdleRefreshDue(sess.Id) {
			toa.storeSessionAndAttachCookie(sess, rw)
			toa.sessionWrites.mark(sess.Id)
		}

		// Forward the request
		toa.next.ServeHTTP(rw, req)
		return
	}

	if isPublic {
		toa.forwardToUpstream(rw, req, nil, nil, true, false)
		return
	}

	if toa.pathMatchesConfiguredRoute(req, toa.Config.FrontChannelLogoutUri) {
		// Idempotent: already logged out / no session. Do not clear cookies or require auth.
		toa.writeSuccessfulLogout(rw, req)
		return
	}

	toa.logger.Log(logging.LevelDebug, "No usable session for this request: %v", err)

	// Clear the session cookie
	_ = clearChunkedCookie(toa.Config, rw, req, getSessionCookieName(toa.Config))

	toa.handleUnauthenticated(rw, req)
}

// hasSessionMaterial reports whether the request carries anything that would
// have to be validated before it can be forwarded: a session cookie (including
// its chunks) or a configured external Authorization header/cookie.
func (toa *TraefikOidcAuth) hasSessionMaterial(req *http.Request) bool {
	if ticket, err := readChunkedCookie(req, getSessionCookieName(toa.Config)); err == nil && ticket != "" {
		return true
	}

	if toa.Config.AuthorizationHeader != nil && toa.Config.AuthorizationHeader.Name != "" {
		if req.Header.Get(toa.Config.AuthorizationHeader.Name) != "" {
			return true
		}
	}

	if toa.Config.AuthorizationCookie != nil && toa.Config.AuthorizationCookie.Name != "" {
		if cookie, err := req.Cookie(toa.Config.AuthorizationCookie.Name); err == nil && cookie.Value != "" {
			return true
		}
	}

	return false
}

// forwardToUpstream strips the internal cookies and every client-supplied
// identity header, then re-applies the configured headers, so a configured
// header is Set from the session instead of being inherited from the caller.
func (toa *TraefikOidcAuth) forwardToUpstream(rw http.ResponseWriter, req *http.Request, sess *session.SessionState, claims map[string]interface{}, isPublicRoute bool, isAuthorized bool) {
	toa.sanitizeForUpstream(req)

	if sess == nil {
		sess = &session.SessionState{}
	}

	if err := toa.attachHeaders(req, sess, claims, isPublicRoute, isAuthorized); err != nil {
		// Nothing useful can be done about a bad header template at this point and
		// it must not turn into a 500 on a path the operator declared public.
		toa.logger.Log(logging.LevelError, "Error while attaching headers: %s", err.Error())
	}

	toa.next.ServeHTTP(rw, req)
}

func (toa *TraefikOidcAuth) sanitizeForUpstream(req *http.Request) {
	// Remove all internal cookies from the request before forwarding
	keepCookies := make([]*http.Cookie, 0)

	for _, c := range req.Cookies() {
		if !strings.HasPrefix(c.Name, toa.Config.CookieNamePrefix) {
			keepCookies = append(keepCookies, c)
		}
	}

	req.Header.Del("Cookie")

	for _, c := range keepCookies {
		req.AddCookie(c)
	}

	// Remove client-supplied identity headers. They are attacker-controlled and
	// must never reach a backend that trusts them, on any path.
	for _, header := range clientIdentityHeaders {
		req.Header.Del(header)
	}
}

// sessionWriteTracker remembers, per session id, when this process last emitted
// a session ticket.
type sessionWriteTracker struct {
	lock  sync.Mutex
	last  map[string]time.Time
	count int
}

// maxTrackedSessions bounds the tracker. Sessions are stateless, so this map
// grows with the number of sessions seen by this process; dropping it wholesale
// is safe because a missing entry only means "write a ticket again sooner".
const maxTrackedSessions = 20000

func (t *sessionWriteTracker) lastWrite(sessionId string) (time.Time, bool) {
	t.lock.Lock()
	defer t.lock.Unlock()

	seen, ok := t.last[sessionId]
	return seen, ok
}

func (t *sessionWriteTracker) mark(sessionId string) {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.last == nil {
		t.last = make(map[string]time.Time)
	}

	if t.count >= maxTrackedSessions {
		t.last = make(map[string]time.Time)
		t.count = 0
	}

	t.last[sessionId] = time.Now()
	t.count++
}

// sessionIdleRefreshDue reports whether the durable LastUsedAt of this session
// has aged enough that session_idle_timeout_seconds would not actually be
// enforced.
//
// LastUsedAt only survives when the ticket is rewritten, so a session that is
// accepted but never renewed keeps a stale timestamp in the browser. Rewriting
// the ticket on every request would emit a Set-Cookie per request; instead the
// ticket is rewritten when the last write is older than a quarter of the idle
// bound, capped at 60s. That keeps the durable timestamp at most that much older
// than reality, so a session can outlive the idle bound by at most one refresh
// interval instead of indefinitely.
func (toa *TraefikOidcAuth) sessionIdleRefreshDue(sessionId string) bool {
	// AuthorizationHeader / AuthorizationCookie are per-request pseudo-sessions
	// with no cookie of their own; re-storing them would mint a session cookie
	// out of a header value.
	if sessionId == "" || sessionId == "AuthorizationHeader" || sessionId == "AuthorizationCookie" {
		return false
	}

	idle := 0
	if toa.Config != nil {
		idle = toa.Config.SessionIdleTimeoutSeconds
	}

	if idle <= 0 || sessionId == "" {
		return false
	}

	interval := idle / 4
	if interval > 60 {
		interval = 60
	}
	if interval <= 0 {
		interval = 1
	}

	lastWrite, ok := toa.sessionWrites.lastWrite(sessionId)
	if !ok {
		// First time this process serves this session: write the ticket once so a
		// real LastUsedAt exists.
		return true
	}

	return time.Since(lastWrite) >= time.Duration(interval)*time.Second
}

func withSuffixPrefix(suffixPrefix string, values any, format string) any {
	var result []string
	valueOf := reflect.ValueOf(values)
	if valueOf.Kind() == reflect.Array || valueOf.Kind() == reflect.Slice {
		for i := 0; i < valueOf.Len(); i++ {
			result = append(result, fmt.Sprintf(format, fmt.Sprint(valueOf.Index(i)), suffixPrefix))
		}
		return result
	}
	return fmt.Sprintf(format, fmt.Sprint(valueOf), suffixPrefix)
}

// headerTemplateFuncs is built once at package level: rebuilding the FuncMap per
// header per request was pure overhead on the hot path.
var headerTemplateFuncs = template.FuncMap{
	"withPrefix": func(prefix string, values any) any {
		return withSuffixPrefix(prefix, values, "%[2]s%[1]s")
	},
	"withSuffix": func(suffix string, values any) any {
		return withSuffixPrefix(suffix, values, "%[1]s%[2]s")
	},
	"mapToJsonArray": func(values any) string {
		valueOf := reflect.ValueOf(values)
		var builder strings.Builder
		builder.WriteRune('[')
		if valueOf.Kind() == reflect.Array || valueOf.Kind() == reflect.Slice {
			for i := 0; i < valueOf.Len(); i++ {
				if i > 0 {
					builder.WriteRune(',')
				}
				builder.WriteRune('"')
				template.JSEscape(&builder, []byte(fmt.Sprint(valueOf.Index(i))))
				builder.WriteRune('"')
			}
		} else {
			builder.WriteRune('"')
			template.JSEscape(&builder, []byte(fmt.Sprint(valueOf)))
			builder.WriteRune('"')
		}
		builder.WriteRune(']')
		return builder.String()
	},
}

func newTemplate() *template.Template {
	return template.New("").Funcs(headerTemplateFuncs)
}

func (toa *TraefikOidcAuth) attachHeaders(req *http.Request, session *session.SessionState, claims map[string]interface{}, isPublicRoute bool, isAuthorized bool) error {
	if toa.Config.Headers != nil {
		evalContext := make(map[string]interface{})

		evalContext["claims"] = claims
		evalContext["accessToken"] = session.AccessToken
		evalContext["idToken"] = session.IdToken
		evalContext["refreshToken"] = session.RefreshToken

		// Iterate by index: ranging over Config.Headers copies the HeaderConfig
		// values, so the parsed template was written to a copy and thrown away,
		// re-parsing every template through reflection on every request.
		for index := range toa.Config.Headers {
			header := &toa.Config.Headers[index]

			if isPublicRoute && header.IncludeWhen != "Always" && header.IncludeWhen != "Public" {
				continue
			}

			if !isAuthorized && header.IncludeWhen != "Always" && header.IncludeWhen != "Forward" {
				continue
			}

			if header.Value != "" {
				if header.Template == nil {
					tpl, err := newTemplate().Parse(header.Value)
					if err != nil {
						return err
					}

					header.Template = tpl
				}

				var renderedValue bytes.Buffer
				err := header.Template.Execute(&renderedValue, evalContext)

				if err == nil {
					req.Header.Set(header.Name, renderedValue.String())
				} else {
					req.Header.Set(header.Name, err.Error())
				}
			} else if header.Values != "" {
				if header.Template == nil {
					tpl, err := newTemplate().Parse(header.Values)
					if err != nil {
						return err
					}

					header.Template = tpl
				}

				var renderedValue bytes.Buffer
				err := header.Template.Execute(&renderedValue, evalContext)
				if err != nil {
					req.Header.Set(header.Name, err.Error())
				}

				var values []string
				err = json.Unmarshal(renderedValue.Bytes(), &values)
				if err != nil {
					req.Header.Set(header.Name, err.Error())
				}

				if len(values) > 0 {
					for i, value := range values {
						if i == 0 {
							req.Header.Set(header.Name, value)
						} else {
							req.Header.Add(header.Name, value)
						}
					}
				} else {
					req.Header.Del(header.Name)
				}
			} else {
				req.Header.Set(header.Name, "")
			}
		}
	}

	return nil
}

// internalError logs the real reason server-side and returns a short generic
// message. Internal error text carries IDP endpoints, config detail and
// upstream URLs that must not reach an unauthenticated caller.
func (toa *TraefikOidcAuth) internalError(rw http.ResponseWriter, publicMessage string, context string, err error) {
	if err != nil {
		toa.logger.Log(logging.LevelError, "%s: %s", context, err.Error())
	} else {
		toa.logger.Log(logging.LevelError, "%s", context)
	}

	http.Error(rw, publicMessage, http.StatusInternalServerError)
}

func (toa *TraefikOidcAuth) handleCallback(rw http.ResponseWriter, req *http.Request) {
	base64State := req.URL.Query().Get("state")
	if base64State == "" {
		toa.logger.Log(logging.LevelWarn, "State on callback request is missing.")
		http.Error(rw, "State is missing", http.StatusBadRequest)
		return
	}

	state, err := oidc.UnsealState(base64State, toa.Config.Secret)
	if err != nil {
		if errors.Is(err, oidc.ErrStateExpired) {
			// A login that took longer than the state lifetime is not an internal
			// error: tell the user to start again instead of showing an opaque 500.
			toa.logger.Log(logging.LevelInfo, "OIDC login state expired (%v), the user has to start the login again", err.Error())
			http.Error(rw, "Your login request expired. Please start again.", http.StatusUnauthorized)
			return
		}

		toa.logger.Log(logging.LevelWarn, "State on callback request is invalid: %s", err.Error())
		http.Error(rw, "State is invalid", http.StatusBadRequest)
		return
	}

	redirectUrl := state.RedirectUrl

	switch state.Action {
	case "Login":
		if err := validateLoginCsrf(toa.Config, req, state.Csrf); err != nil {
			toa.logger.Log(logging.LevelWarn, "Login CSRF validation failed: %s", err.Error())
			clearLoginCsrfCookie(toa.Config, rw, toa.CallbackURL, state.Csrf)
			http.Error(rw, "Invalid login state", http.StatusForbidden)
			return
		}
		clearLoginCsrfCookie(toa.Config, rw, toa.CallbackURL, state.Csrf)

		authCode := req.URL.Query().Get("code")
		if authCode == "" {
			toa.logger.Log(logging.LevelWarn, "The identity provider didn't return a code.")
			http.Error(rw, "Code is missing", http.StatusBadRequest)
			return
		}

		token, err := exchangeAuthCode(toa, req, authCode, state.CodeVerifierEnc)
		if err != nil {
			toa.logger.Log(logging.LevelError, "Exchange Auth Code: %s", err.Error())
			http.Error(rw, "Failed to exchange auth code", http.StatusInternalServerError)
			return
		}

		claims, err := toa.validateCallbackToken(rw, req, token, state)
		if err != nil {
			// validateCallbackToken has already answered the request.
			return
		}

		if !toa.authTimeIsFresh(claims, time.Now()) {
			// Step-up requested (provider.max_auth_age_seconds): the IdP handed back
			// an authentication that is too old. Fail closed instead of accepting a
			// stale session.
			toa.logger.Log(logging.LevelWarn, "Rejecting login: the IDP authentication is older than provider.max_auth_age_seconds")
			toa.writeUnauthorizedError(rw, req)
			return
		}

		sess := toa.establishSession(rw, token, claims, state)

		if toa.Config.Provider.UsePkceBool {
			clearLegacyCodeVerifierCookies(toa.Config, rw, req, toa.CallbackURL)
		}

		if redirectUrl != "" {
			// Only enforce allowlist when configured (same as /login?redirect_uri=...).
			if len(toa.Config.ValidPostLoginRedirectUris) > 0 {
				validated, err := utils.ValidateRedirectUri(redirectUrl, toa.Config.ValidPostLoginRedirectUris, toa.RedirectUriWildcardsEnabled)
				if err != nil {
					toa.logger.Log(logging.LevelWarn, "Post-login redirect rejected: %s", err.Error())
					http.Error(rw, "Invalid redirect", http.StatusBadRequest)
					return
				}
				redirectUrl = validated
			}
			redirectUrl = toa.ensureAbsoluteUrl(req, redirectUrl)
		} else {
			redirectUrl = toa.ensureAbsoluteUrl(req, toa.Config.PostLoginRedirectUri)
		}

		if !sess.IsAuthorized {
			// req is the callback URL — pass original destination for Challenge re-login.
			toa.handleUnauthorized(rw, req, sess, redirectUrl)
			return
		}
	case "Logout":
		toa.logger.Log(logging.LevelDebug, "Post logout. Clearing cookie.")

		// Clear the cookie
		_ = clearChunkedCookie(toa.Config, rw, req, getSessionCookieName(toa.Config))
	case "RedirectThenLogin":
		toa.redirectToProvider(rw, req, redirectUrl, state.IsChallenge)
		return
	}

	toa.logger.Log(logging.LevelInfo, "Redirecting to %s", redirectUrl)

	http.Redirect(rw, req, redirectUrl, http.StatusFound)
}

// validateCallbackToken runs the configured token validation for the callback
// and returns the resulting claims.
//
// It writes the error response itself and returns a non-nil error in that case;
// a nil error means claims are usable. The bool returned by introspectToken is
// honoured here: a revoked or expired token must not produce a session.
func (toa *TraefikOidcAuth) validateCallbackToken(rw http.ResponseWriter, req *http.Request, token *oidc.OidcTokenResponse, state *oidc.OidcState) (map[string]interface{}, error) {
	tokenValidation := toa.Config.Provider.TokenValidation

	var usedToken string

	switch tokenValidation {
	case "AccessToken":
		usedToken = token.AccessToken
	case "IdToken":
		usedToken = token.IdToken
	case "Introspection":
		usedToken = token.AccessToken
	default:
		// src.New rejects an unusable verification_token at startup; this branch is
		// defence in depth for a config that bypasses New.
		toa.logger.Log(logging.LevelError, "Invalid value '%s' for verification_token", tokenValidation)
		http.Error(rw, "Authentication is temporarily unavailable", http.StatusInternalServerError)
		return nil, errors.New("invalid verification_token")
	}

	var (
		claims map[string]interface{}
		err    error
		active bool
	)

	if tokenValidation == "Introspection" {
		active, claims, err = toa.introspectToken(usedToken)
		if err != nil {
			toa.logger.Log(logging.LevelError, "Introspection failed: %s", err.Error())
			http.Error(rw, "Returned token is not valid", http.StatusUnauthorized)
			return nil, err
		}

		if !active {
			toa.logger.Log(logging.LevelError, "Introspection reported the access token as inactive (revoked or expired)")
			http.Error(rw, "Returned token is not valid", http.StatusUnauthorized)
			return nil, errors.New("introspection reported an inactive token")
		}
	} else {
		active, claims, err = toa.validateTokenLocally(usedToken, state.Nonce)
		if err != nil || !active {
			if err == nil {
				err = errors.New("token is not valid")
			}
			toa.logger.Log(logging.LevelError, "Returned token is not valid: %s", err.Error())
			http.Error(rw, "Returned token is not valid", http.StatusUnauthorized)
			return nil, err
		}
	}

	if toa.Config.Provider.UseClaimsFromUserInfoBool {
		subClaim, ok := claims["sub"].(string)
		if !ok {
			toa.logger.Log(logging.LevelError, "failed to fetch UserInfo: 'sub' claim is not a string or missing")
			http.Error(rw, "Failed to fetch UserInfo", http.StatusInternalServerError)
			return nil, errors.New("userinfo 'sub' claim missing")
		}

		userInfoClaims, err := toa.getUserInfo(token.AccessToken, subClaim)
		if err != nil {
			toa.logger.Log(logging.LevelError, "failed to fetch UserInfo: %s", err.Error())
			http.Error(rw, "Failed to fetch UserInfo", http.StatusInternalServerError)
			return nil, err
		}

		claims = mergeClaims(claims, userInfoClaims)
	}

	// Never log any part of the token: even a truncated opaque token is a
	// meaningful, replayable prefix.
	toa.logger.Log(logging.LevelInfo, "Exchange Auth Code completed, validated a %s", tokenValidation)

	return claims, nil
}

// establishSession creates the session for a validated callback and attaches it
// to the response.
func (toa *TraefikOidcAuth) establishSession(rw http.ResponseWriter, token *oidc.OidcTokenResponse, claims map[string]interface{}, state *oidc.OidcState) *session.SessionState {
	isAuthorized := isAuthorized(toa.logger, toa.Config.Authorization, claims)

	sess := &session.SessionState{
		Id:                 session.GenerateSessionId(),
		RefreshedAt:        time.Now(),
		AccessToken:        token.AccessToken,
		IdToken:            token.IdToken,
		RefreshToken:       token.RefreshToken,
		IsAuthorized:       isAuthorized,
		TokenExpiresIn:     token.ExpiresIn,
		ChallengeAttempted: state.IsChallenge,
	}

	toa.storeSessionAndAttachCookie(sess, rw)
	toa.sessionWrites.mark(sess.Id)

	return sess
}

func (toa *TraefikOidcAuth) handleLogout(rw http.ResponseWriter, req *http.Request, session *session.SessionState) {
	toa.logger.Log(logging.LevelInfo, "Logging out...")

	// https://openid.net/specs/openid-connect-rpinitiated-1_0.html

	endSessionURL, err := url.Parse(toa.DiscoveryDocument.EndSessionEndpoint)
	if err != nil {
		toa.logger.Log(logging.LevelError, "Error while parsing the end_session_endpoint: %s", err.Error())
		toa.internalError(rw, "Logout is temporarily unavailable", "parsing the end_session_endpoint", err)
		return
	}

	// Revoke first: a failure here must never keep the user in a session they
	// asked to end, so it is logged at WARN and logout continues either way.
	if err := toa.revokeToken(req.Context(), session.RefreshToken); err != nil {
		toa.logger.Log(logging.LevelWarn, "Token revocation failed, continuing with logout: %s", err.Error())
	}

	callbackUri := toa.GetAbsoluteCallbackURL(req).String()
	redirectUri := toa.ensureAbsoluteUrl(req, toa.Config.PostLogoutRedirectUri)

	redirectUriFromQuery := req.URL.Query().Get("redirect_uri")
	if redirectUriFromQuery == "" {
		redirectUriFromQuery = req.URL.Query().Get("post_logout_redirect_uri")
	}

	if redirectUriFromQuery != "" {
		redirectUriFromQuery, err = utils.ValidateRedirectUri(redirectUriFromQuery, toa.Config.ValidPostLogoutRedirectUris, toa.RedirectUriWildcardsEnabled)
		if err != nil {
			toa.logger.Log(logging.LevelError, "Post-logout redirect rejected: %s", err.Error())
			http.Error(rw, "Invalid redirect", http.StatusBadRequest)
			return
		}

		if redirectUriFromQuery != "" {
			redirectUri = toa.ensureAbsoluteUrl(req, redirectUriFromQuery)
		}
	}

	state := &oidc.OidcState{
		Action:      "Logout",
		RedirectUrl: redirectUri,
	}

	base64State, err := oidc.SealState(state, toa.Config.Secret)
	if err != nil {
		toa.logger.Log(logging.LevelError, "Failed to serialize state: %s", err.Error())
		toa.internalError(rw, "Logout is temporarily unavailable", "serializing the logout state", err)
		return
	}

	endSessionURL.RawQuery = url.Values{
		"client_id":                {toa.Config.Provider.ClientId},
		"post_logout_redirect_uri": {callbackUri},
		"state":                    {base64State},
		"id_token_hint":            {session.IdToken},
	}.Encode()

	http.Redirect(rw, req, endSessionURL.String(), http.StatusFound)
}

func secureStringEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// handleFrontchannelLogout implements OpenID Connect Front-Channel Logout 1.0 with hardened checks.
//
// Per the spec a logout notification MUST carry either sid or id_token_hint.
// iss alone is identical for every user of the provider, so accepting it would
// let a single unauthenticated GET (an <img> tag, an iframe) log any visitor
// out. Both are therefore required and compared against the session in constant
// time; a rejected notification never clears the cookie.
func (toa *TraefikOidcAuth) handleFrontchannelLogout(rw http.ResponseWriter, req *http.Request, sess *session.SessionState, claims map[string]interface{}) {
	toa.logger.Log(logging.LevelInfo, "Handling frontchannel logout...")

	iss := req.URL.Query().Get("iss")
	if iss == "" {
		toa.logger.Log(logging.LevelWarn, "Frontchannel logout rejected: iss is missing")
		http.Error(rw, "iss is missing", http.StatusBadRequest)
		return
	}

	claimIss, ok := claims["iss"].(string)
	if !ok || !secureStringEqual(iss, claimIss) {
		toa.logger.Log(logging.LevelWarn, "Frontchannel logout rejected: iss does not match")
		http.Error(rw, "iss does not match", http.StatusBadRequest)
		return
	}

	validIssuer := toa.effectiveValidIssuer()
	if toa.Config.Provider.ValidateIssuerBool && validIssuer != "" {
		if !secureStringEqual(iss, validIssuer) {
			toa.logger.Log(logging.LevelWarn, "Frontchannel logout rejected: iss does not match the expected issuer")
			http.Error(rw, "iss does not match", http.StatusBadRequest)
			return
		}
	}

	sid := req.URL.Query().Get("sid")
	idTokenHint := req.URL.Query().Get("id_token_hint")

	if sid == "" && idTokenHint == "" {
		toa.logger.Log(logging.LevelWarn, "Frontchannel logout rejected: neither sid nor id_token_hint was supplied")
		http.Error(rw, "sid or id_token_hint is required", http.StatusBadRequest)
		return
	}

	if sid != "" {
		claimSid, ok := claims["sid"].(string)
		if !ok {
			toa.logger.Log(logging.LevelWarn, "Frontchannel logout rejected: sid provided but claims lack sid")
			http.Error(rw, "sid does not match", http.StatusBadRequest)
			return
		}
		if !secureStringEqual(sid, claimSid) {
			toa.logger.Log(logging.LevelWarn, "Frontchannel logout rejected: sid does not match")
			http.Error(rw, "sid does not match", http.StatusBadRequest)
			return
		}
	} else if !secureStringEqual(idTokenHint, sess.IdToken) || sess.IdToken == "" {
		toa.logger.Log(logging.LevelWarn, "Frontchannel logout rejected: id_token_hint does not match the session id token")
		http.Error(rw, "id_token_hint does not match", http.StatusBadRequest)
		return
	}

	// Best effort: revoking this session's refresh token must never block the
	// logout, so failures are logged and the cookie is cleared regardless.
	if err := toa.revokeToken(req.Context(), sess.RefreshToken); err != nil {
		toa.logger.Log(logging.LevelWarn, "Token revocation failed, continuing with frontchannel logout: %s", err.Error())
	}

	_ = clearChunkedCookie(toa.Config, rw, req, getSessionCookieName(toa.Config))
	toa.writeSuccessfulLogout(rw, req)
}

func (toa *TraefikOidcAuth) writeSuccessfulLogout(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	data := make(map[string]interface{})
	data["statusType"] = "about:blank"
	data["statusCode"] = http.StatusOK
	data["statusName"] = "Logged out"
	data["description"] = "You have been logged out successfully."

	if toa.Config.LoginUri != "" {
		data["primaryButtonText"] = "Log back in"
		data["primaryButtonUrl"] = toa.ensureAbsoluteUrl(req, toa.Config.LoginUri)
	}

	errorPages.WriteError(toa.logger, &errorPages.ErrorPageConfig{}, rw, req, data)
}

func (toa *TraefikOidcAuth) handleUnauthenticated(rw http.ResponseWriter, req *http.Request) {
	switch toa.Config.UnauthenticatedBehavior {
	case "Challenge":
		// Handle login
		toa.handleLogin(rw, req, false, "")
	case "Unauthorized":
		// Respond with 401 Unauthorized
		toa.writeUnauthenticatedError(rw, req)
	case "Forward":
		// Forward request
		toa.forwardToUpstream(rw, req, nil, nil, false, false)
	case "Auto":
		if utils.IsHtmlRequest(req) {
			// Handle login for HTML requests
			toa.handleLogin(rw, req, false, "")
		} else {
			// Respond with 401 Unauthorized for non-HTML requests
			toa.writeUnauthenticatedError(rw, req)
		}
	default:
		// Respond with 401 Unauthorized as a fallback
		toa.writeUnauthenticatedError(rw, req)
	}
}

func (toa *TraefikOidcAuth) writeUnauthenticatedError(rw http.ResponseWriter, req *http.Request) {
	data := make(map[string]interface{})

	data["statusType"] = "https://tools.ietf.org/html/rfc9110#section-15.5.2"
	data["statusCode"] = http.StatusUnauthorized
	data["statusName"] = "Unauthorized"
	data["description"] = "You're not authorized to access this resource. Please log in to continue."

	if toa.Config.LoginUri != "" {
		data["primaryButtonText"] = "Login"
		data["primaryButtonUrl"] = toa.ensureAbsoluteUrl(req, toa.Config.LoginUri)
	}

	errorPages.WriteError(toa.logger, toa.Config.ErrorPages.Unauthenticated, rw, req, data)
}

// handleUnauthorized handles a valid session that fails Authorization rules.
// redirectUrlOverride is empty on normal requests; from handleCallback it is the original destination.
func (toa *TraefikOidcAuth) handleUnauthorized(rw http.ResponseWriter, req *http.Request, session *session.SessionState, redirectUrlOverride string) {
	switch toa.Config.UnauthorizedBehavior {
	case "Challenge":
		if !session.ChallengeAttempted && utils.IsHtmlRequest(req) {
			toa.handleLogin(rw, req, true, redirectUrlOverride)
		} else {
			toa.writeUnauthorizedError(rw, req)
		}
	case "Unauthorized":
		toa.writeUnauthorizedError(rw, req)
	case "Forward":
		// Never forward the OAuth callback URL (code/state leak). Redirect to app instead.
		if redirectUrlOverride != "" {
			http.Redirect(rw, req, redirectUrlOverride, http.StatusFound)
			return
		}
		toa.forwardToUpstream(rw, req, session, nil, false, false)
	default:
		toa.writeUnauthorizedError(rw, req)
	}
}

func (toa *TraefikOidcAuth) writeUnauthorizedError(rw http.ResponseWriter, req *http.Request) {
	data := make(map[string]interface{})

	data["statusType"] = "https://tools.ietf.org/html/rfc9110#section-15.5.4"
	data["statusCode"] = http.StatusForbidden
	data["statusName"] = "Forbidden"
	data["description"] = "It seems like your account is not allowed to access this resource.\nTry to log in using a different account or log out by using one of the options below."

	if toa.Config.LoginUri != "" {
		data["primaryButtonText"] = "Login with a different account"
		data["primaryButtonUrl"] = toa.ensureAbsoluteUrl(req, toa.Config.LoginUri) + "?prompt=login"
	}

	data["secondaryButtonText"] = "Logout"
	data["secondaryButtonUrl"] = toa.ensureAbsoluteUrl(req, toa.Config.LogoutUri)

	errorPages.WriteError(toa.logger, toa.Config.ErrorPages.Unauthorized, rw, req, data)
}

// handleLogin starts the OIDC login flow. Non-empty redirectUrlOverride wins over request-derived targets
// (used when re-challenging from handleCallback where req is the callback URL).
func (toa *TraefikOidcAuth) handleLogin(rw http.ResponseWriter, req *http.Request, isChallenge bool, redirectUrlOverride string) {
	toa.logger.Log(logging.LevelInfo, "Logging in...")
	var redirectUrl string

	if redirectUrlOverride != "" {
		redirectUrl = redirectUrlOverride
	} else {
		// If the user specified one on the /login request, use this one
		redirectUriFromQuery, err := utils.ValidateRedirectUri(req.URL.Query().Get("redirect_uri"), toa.Config.ValidPostLoginRedirectUris, toa.RedirectUriWildcardsEnabled)
		if err != nil {
			toa.logger.Log(logging.LevelError, "Login redirect rejected: %s", err.Error())
			http.Error(rw, "Invalid redirect", http.StatusBadRequest)
			return
		}

		isLoginRequest := toa.pathMatchesConfiguredRoute(req, toa.Config.LoginUri)

		if isLoginRequest && redirectUriFromQuery != "" {
			redirectUrl = redirectUriFromQuery
		} else if toa.Config.PostLoginRedirectUri != "" {
			redirectUrl = toa.ensureAbsoluteUrl(req, toa.Config.PostLoginRedirectUri)
		} else {
			host := toa.fullHost(req)
			redirectUrl = fmt.Sprintf("%s%s", host, req.URL.RequestURI())

			// Special case: If someone just calls /login but doesn't provide a redirect_uri, we go to / instead of /login again.
			if isLoginRequest {
				redirectUrl = host
			}
		}
	}

	if toa.needsDoubleRedirect(req) {
		toa.doubleRedirectToProvider(rw, req, redirectUrl, isChallenge)
	} else {
		toa.redirectToProvider(rw, req, redirectUrl, isChallenge)
	}
}

func (toa *TraefikOidcAuth) needsDoubleRedirect(req *http.Request) bool {
	if toa.Config.Provider.UsePkceBool {
		host := toa.fullHost(req)
		callbackUrl := toa.GetAbsoluteCallbackURL(req).String()
		if !strings.HasPrefix(callbackUrl, host) {
			return true
		}
	}

	return false
}

// Protocol-critical parameters that AuthorizationParams must not be allowed to override.
var reservedAuthorizationParams = map[string]bool{
	"response_type":         true,
	"client_id":             true,
	"redirect_uri":          true,
	"state":                 true,
	"scope":                 true,
	"resource":              true,
	"code_challenge":        true,
	"code_challenge_method": true,
	"nonce":                 true,
}

// isOverridableParam reports whether an incoming request may replace the
// configured value of this authorizationParams key. The default - an empty
// allowlist - means nothing is overridable.
func (toa *TraefikOidcAuth) isOverridableParam(key string) bool {
	for _, allowed := range toa.Config.AuthorizationParamsOverridable {
		if allowed == key {
			return true
		}
	}

	return false
}

// applyAuthorizationParamOverrides writes the configured authorizationParams into
// urlValues, letting an incoming request override a key only when that key is
// listed in authorization_params_overridable.
func (toa *TraefikOidcAuth) applyAuthorizationParamOverrides(urlValues url.Values, req *http.Request) {
	set := urlValues.Set
	for key, value := range toa.Config.AuthorizationParams {
		// src.New rejects reserved keys at startup. Skipping them here is
		// defence in depth for a config that bypasses New.
		if reservedAuthorizationParams[key] {
			continue
		}

		override := req.URL.Query().Get(key)
		if override != "" {
			if toa.isOverridableParam(key) {
				value = override
			} else {
				toa.logger.Log(logging.LevelDebug, "Ignoring request-supplied authorization parameter %q: it is not in authorization_params_overridable", key)
			}
		}

		set(key, value)
	}

	// prompt is only honoured per-request when explicitly allowlisted, because
	// ?prompt=none satisfies a login without any user interaction.
	if toa.isOverridableParam("prompt") {
		if prompt := req.URL.Query().Get("prompt"); prompt != "" {
			set("prompt", prompt)
		}
	}
}

func (toa *TraefikOidcAuth) redirectToProvider(rw http.ResponseWriter, req *http.Request, redirectUrl string, isChallenge bool) {
	toa.logger.Log(logging.LevelInfo, "Redirecting to OIDC provider...")

	callbackUrl := toa.GetAbsoluteCallbackURL(req).String()

	state := oidc.OidcState{
		Action:      "Login",
		RedirectUrl: redirectUrl,
		IsChallenge: isChallenge,
	}

	csrf, err := randomBytesInHex(16)
	if err != nil {
		toa.internalError(rw, "Authentication is temporarily unavailable", "generating the login CSRF token", err)
		return
	}
	state.Csrf = csrf
	setLoginCsrfCookie(toa.Config, rw, toa.CallbackURL, csrf)

	nonce, err := randomBytesInHex(16)
	if err != nil {
		toa.internalError(rw, "Authentication is temporarily unavailable", "generating the login nonce", err)
		return
	}
	state.Nonce = nonce

	toa.logger.Log(logging.LevelDebug, "AuthorizationEndPoint: %s", toa.DiscoveryDocument.AuthorizationEndpoint)

	authorizationEndpointUrl, err := url.Parse(toa.DiscoveryDocument.AuthorizationEndpoint)
	if err != nil {
		toa.internalError(rw, "Authentication is temporarily unavailable", "parsing the authorization endpoint", err)
		return
	}

	urlValues := url.Values{
		"response_type": {"code"},
		"scope":         {strings.Join(toa.Config.Scopes, " ")},
		"client_id":     {toa.Config.Provider.ClientId},
		"redirect_uri":  {callbackUrl},
		"resource":      toa.Config.RequestedResources,
	}

	toa.applyAuthorizationParamOverrides(urlValues, req)

	// Step-up: max_age is what makes the IdP re-authenticate instead of
	// silently reusing its own session.
	for k, v := range toa.authParamsForChallenge(isChallenge) {
		urlValues.Set(k, v)
	}

	urlValues.Set("nonce", state.Nonce)

	if toa.Config.Provider.UsePkceBool {
		codeVerifier, err := randomBytesInHex(32)
		if err != nil {
			toa.internalError(rw, "Authentication is temporarily unavailable", "generating the PKCE code verifier", err)
			return
		}

		sha2 := sha256.New()
		if _, writeErr := io.WriteString(sha2, codeVerifier); writeErr != nil {
			toa.internalError(rw, "Authentication is temporarily unavailable", "hashing the PKCE code verifier", writeErr)
			return
		}
		codeChallenge := base64.RawURLEncoding.EncodeToString(sha2.Sum(nil))

		urlValues.Set("code_challenge_method", "S256")
		urlValues.Set("code_challenge", codeChallenge)

		encryptedCodeVerifier, err := utils.Encrypt(codeVerifier, toa.Config.Secret)
		if err != nil {
			toa.internalError(rw, "Authentication is temporarily unavailable", "encrypting the PKCE code verifier", err)
			return
		}
		state.CodeVerifierEnc = encryptedCodeVerifier

		clearLegacyCodeVerifierCookies(toa.Config, rw, req, toa.CallbackURL)
	}

	stateBase64, err := oidc.SealState(&state, toa.Config.Secret)
	if err != nil {
		toa.internalError(rw, "Authentication is temporarily unavailable", "serializing the login state", err)
		return
	}
	urlValues.Set("state", stateBase64)

	authorizationEndpointUrl.RawQuery = urlValues.Encode()

	http.Redirect(rw, req, authorizationEndpointUrl.String(), http.StatusFound)
}

func (toa *TraefikOidcAuth) doubleRedirectToProvider(rw http.ResponseWriter, req *http.Request, redirectUrl string, isChallenge bool) {
	toa.logger.Log(logging.LevelInfo, "Redirecting to OIDC provider via callback URL...")

	callbackUrl := toa.GetAbsoluteCallbackURL(req)

	state := oidc.OidcState{
		Action:      "RedirectThenLogin",
		RedirectUrl: redirectUrl,
		IsChallenge: isChallenge,
	}

	stateBase64, err := oidc.SealState(&state, toa.Config.Secret)
	if err != nil {
		toa.internalError(rw, "Authentication is temporarily unavailable", "serializing the login state", err)
		return
	}

	urlValues := url.Values{
		"state": {stateBase64},
	}

	// Only the overrides travel here; the configured parameters are applied when
	// the callback runs redirectToProvider for the sealed state.
	for key := range toa.Config.AuthorizationParams {
		if reservedAuthorizationParams[key] {
			continue
		}
		if !toa.isOverridableParam(key) {
			if req.URL.Query().Get(key) != "" {
				toa.logger.Log(logging.LevelDebug, "Ignoring request-supplied authorization parameter %q: it is not in authorization_params_overridable", key)
			}
			continue
		}
		if override := req.URL.Query().Get(key); override != "" {
			urlValues.Add(key, override)
		}
	}

	if toa.isOverridableParam("prompt") {
		if prompt := req.URL.Query().Get("prompt"); prompt != "" {
			urlValues.Add("prompt", prompt)
		}
	}

	for k, v := range toa.authParamsForChallenge(isChallenge) {
		urlValues.Add(k, v)
	}

	callbackUrl.RawQuery = urlValues.Encode()

	http.Redirect(rw, req, callbackUrl.String(), http.StatusFound)
}
