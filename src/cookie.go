package src

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/BlackDark/test-oidc-traefik-plugin/src/config"
	"github.com/BlackDark/test-oidc-traefik-plugin/src/utils"
)

const (
	// sessionCookieChunkSize is the payload size of a single chunk cookie.
	sessionCookieChunkSize = 3072
	// maxSessionCookieChunks bounds how many chunk cookies the middleware will ever
	// read or emit. Without it, a single unauthenticated request carrying an
	// attacker-chosen "<name>.Chunks=2000000000" cookie made us emit (or iterate)
	// billions of Set-Cookie headers, exhausting memory in the proxy. 16 chunks of
	// 3072 bytes covers ~48 KB of session state, far beyond any real session.
	maxSessionCookieChunks = 16
)

func setChunkedCookies(config *config.Config, rw http.ResponseWriter, cookieName string, cookieValue string) {
	cookieChunks := utils.ChunkString(cookieValue, sessionCookieChunkSize)

	// Defensive: never emit more headers than a reader will accept back, otherwise
	// the session becomes unreadable and the response is an amplification vector.
	if len(cookieChunks) > maxSessionCookieChunks {
		cookieChunks = cookieChunks[:maxSessionCookieChunks]
	}

	baseCookie := createSessionCookie(config)
	baseCookie.Name = cookieName

	// Set the cookie
	if len(cookieChunks) == 1 {
		c := baseCookie
		c.Value = cookieValue
		http.SetCookie(rw, c)
	} else {
		c := baseCookie
		c.Name = cookieName + ".Chunks"
		c.Value = strconv.Itoa(len(cookieChunks))
		http.SetCookie(rw, c)

		for index, chunk := range cookieChunks {
			c.Name = fmt.Sprintf("%s.%d", cookieName, index+1)
			c.Value = chunk
			http.SetCookie(rw, c)
		}
	}
}

func readChunkedCookie(req *http.Request, cookieName string) (string, error) {
	chunkCount, err := getChunkedCookieCount(req, cookieName)
	if err != nil {
		// Fail closed: a chunk count we refuse to trust is never turned into a loop.
		return "", err
	}

	if chunkCount == 0 {
		cookie, err := req.Cookie(cookieName)
		if err != nil {
			return "", err
		}

		return cookie.Value, nil
	}

	value := ""

	var valueSb58 strings.Builder
	for i := 0; i < chunkCount; i++ {
		cookie, err := req.Cookie(fmt.Sprintf("%s.%d", cookieName, i+1))
		if err != nil {
			return "", err
		}

		valueSb58.WriteString(cookie.Value)
	}
	value += valueSb58.String()

	return value, nil
}

func getChunkedCookieCount(req *http.Request, cookieName string) (int, error) {
	chunksCookie, err := req.Cookie(cookieName + ".Chunks")
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return 0, nil
		}
		return 0, err
	}

	chunkCount, err := strconv.Atoi(chunksCookie.Value)
	if err != nil {
		return 0, fmt.Errorf("invalid chunk count cookie %s: %w", chunksCookie.Name, err)
	}

	// The count comes straight off the wire, so it is untrusted input: bounds-check
	// it before any caller uses it as a loop bound or header multiplier.
	if chunkCount < 0 || chunkCount > maxSessionCookieChunks {
		return 0, fmt.Errorf("chunk count cookie %s out of range: %d (allowed 0-%d)",
			chunksCookie.Name, chunkCount, maxSessionCookieChunks)
	}

	return chunkCount, nil
}

func clearChunkedCookie(config *config.Config, rw http.ResponseWriter, req *http.Request, cookieName string) error {
	chunkCount, err := getChunkedCookieCount(req, cookieName)

	baseCookie := createSessionCookie(config)
	baseCookie.Name = cookieName
	baseCookie.Value = ""
	makeCookieExpireImmediately(baseCookie)

	// An unreadable or hostile chunk count is treated as "no chunks": we still expire
	// the base cookie and the count cookie (a bounded two headers) so a rejected
	// session does not linger, and never widen the loop below with untrusted input.
	if chunkCount == 0 {
		http.SetCookie(rw, baseCookie)
	} else {
		c := baseCookie
		c.Name = cookieName + ".Chunks"
		http.SetCookie(rw, c)

		for i := 0; i < chunkCount; i++ {
			c.Name = fmt.Sprintf("%s.%d", cookieName, i+1)
			http.SetCookie(rw, c)
		}
	}

	return err
}

// parseCookieSameSite maps a configured value to a SameSite mode. Unrecognised
// values fall back to Lax: never to SameSiteDefaultMode, which serialises to no
// SameSite attribute at all and silently relies on the browser default.
func parseCookieSameSite(sameSite string) http.SameSite {
	mode, err := parseCookieSameSiteChecked(sameSite)
	if err != nil {
		return http.SameSiteLaxMode
	}
	return mode
}

// parseCookieSameSiteChecked is parseCookieSameSite plus a descriptive error for
// unknown values, so callers that can log can surface the misconfiguration.
func parseCookieSameSiteChecked(sameSite string) (http.SameSite, error) {
	switch sameSite {
	case "none":
		return http.SameSiteNoneMode, nil
	case "lax":
		return http.SameSiteLaxMode, nil
	case "strict":
		return http.SameSiteStrictMode, nil
	case "", "default":
		// Historically accepted: empty config means "let Go decide".
		return http.SameSiteDefaultMode, nil
	default:
		return http.SameSiteLaxMode, fmt.Errorf("unknown session cookie same_site value %q, expected one of none, lax, strict", sameSite)
	}
}

func makeCookieExpireImmediately(cookie *http.Cookie) *http.Cookie {
	cookie.Expires = time.Now().Add(-24 * time.Hour)
	cookie.MaxAge = -1
	return cookie
}

func getCodeVerifierCookieName(config *config.Config) string {
	return makeCookieName(config, "CodeVerifier")
}

func getLoginCsrfCookieName(config *config.Config, csrf string) string {
	return makeCookieName(config, "LoginCsrf."+csrf)
}

func getSessionCookieName(config *config.Config) string {
	return makeCookieName(config, "Session")
}

func makeCookieName(config *config.Config, name string) string {
	return fmt.Sprintf("%s.%s", config.CookieNamePrefix, name)
}

// clearLegacyCodeVerifierCookies expires shared and per-request PKCE cookies from older implementations.
// Emits expire Set-Cookie for Hostname() and host-only (empty Domain).
// Note: net/http rejects Domain values that include a port, so old builds that passed url.Host with a port
// never actually persisted that Domain — those cookies were host-only and are covered by Domain="".
// maxLegacyCookiesToExpire bounds how many request-supplied legacy PKCE cookie
// names we will echo back as expired Set-Cookie headers, so an oversized Cookie
// header cannot be amplified into a large response.
const maxLegacyCookiesToExpire = 32

func clearLegacyCodeVerifierCookies(config *config.Config, rw http.ResponseWriter, req *http.Request, callbackURL *url.URL) {
	if callbackURL == nil {
		return
	}

	prefix := getCodeVerifierCookieName(config)
	seen := map[string]struct{}{}

	expire := func(name string, cookieDomain string) {
		key := name + "\x00" + cookieDomain
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		http.SetCookie(rw, makeCookieExpireImmediately(&http.Cookie{
			Name:     name,
			Value:    "",
			Secure:   true,
			HttpOnly: true,
			Path:     callbackURL.Path,
			Domain:   cookieDomain,
			SameSite: http.SameSiteLaxMode,
		}))
	}

	expireVariants := func(name string) {
		if host := callbackURL.Hostname(); host != "" {
			expire(name, host)
		}
		expire(name, "")
	}

	expireVariants(prefix)
	expired := 0
	for _, c := range req.Cookies() {
		if expired >= maxLegacyCookiesToExpire {
			break
		}
		if c.Name == prefix || strings.HasPrefix(c.Name, prefix+".") {
			expireVariants(c.Name)
			expired++
		}
	}
}

const loginCsrfMaxAge = 600

// csrfCookieSecure mirrors the session cookie's Secure flag. Fails closed (true)
// when the session cookie config is absent, so a misconfigured deployment never
// downgrades the CSRF cookie to plaintext.
func csrfCookieSecure(config *config.Config) bool {
	if config == nil || config.SessionCookie == nil {
		return true
	}
	return config.SessionCookie.Secure
}

func setLoginCsrfCookie(config *config.Config, rw http.ResponseWriter, callbackURL *url.URL, csrf string) {
	if callbackURL == nil || csrf == "" {
		return
	}
	http.SetCookie(rw, &http.Cookie{
		Name:     getLoginCsrfCookieName(config, csrf),
		Value:    csrf,
		MaxAge:   loginCsrfMaxAge,
		Secure:   csrfCookieSecure(config),
		HttpOnly: true,
		Path:     callbackURL.Path,
		Domain:   "", // host-only, same as session cookie default
		SameSite: http.SameSiteLaxMode,
	})
}

func clearLoginCsrfCookie(config *config.Config, rw http.ResponseWriter, callbackURL *url.URL, csrf string) {
	if callbackURL == nil || csrf == "" {
		return
	}
	http.SetCookie(rw, makeCookieExpireImmediately(&http.Cookie{
		Name:     getLoginCsrfCookieName(config, csrf),
		Value:    "",
		Secure:   csrfCookieSecure(config),
		HttpOnly: true,
		Path:     callbackURL.Path,
		Domain:   "",
		SameSite: http.SameSiteLaxMode,
	}))
}

// validateLoginCsrf checks the LoginCsrf cookie against sealed state. Returns nil on success.
func validateLoginCsrf(config *config.Config, req *http.Request, csrf string) error {
	if csrf == "" {
		return errors.New("missing CSRF in state")
	}
	c, err := req.Cookie(getLoginCsrfCookieName(config, csrf))
	if err != nil {
		return errors.New("missing CSRF cookie")
	}
	if subtle.ConstantTimeCompare([]byte(c.Value), []byte(csrf)) != 1 {
		return errors.New("CSRF cookie mismatch")
	}
	return nil
}
