package src

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/BlackDark/test-oidc-traefik-plugin/src/logging"
	"github.com/BlackDark/test-oidc-traefik-plugin/src/oidc"
	"github.com/BlackDark/test-oidc-traefik-plugin/src/utils"
)

const (
	// defaultOidcTimeout bounds outbound IDP calls when the config value is missing
	// or non-positive. An unbounded call pins the request goroutine forever.
	defaultOidcTimeout = 30 * time.Second

	// maxOidcResponseBody caps how much of an IDP response we are willing to read.
	// Token/introspection/userinfo responses are small; anything larger is a
	// misconfigured or hostile endpoint and must not be buffered or logged.
	maxOidcResponseBody = 1 << 20

	// maxIdcErrorBody bounds the IDP error body echoed into logs. Error bodies from
	// a token endpoint can echo the request (including client_secret) back.
	maxIdcErrorBody = 512
)

// oidcTimeout returns the per-call deadline for outbound IDP requests.
func (toa *TraefikOidcAuth) oidcTimeout() time.Duration {
	if toa.Config == nil || toa.Config.Provider == nil || toa.Config.Provider.OidcTimeoutSeconds <= 0 {
		return defaultOidcTimeout
	}

	return time.Duration(toa.Config.Provider.OidcTimeoutSeconds) * time.Second
}

// oidcContext derives a bounded context for IDP calls that have no request
// context of their own (session refresh, background introspection).
func (toa *TraefikOidcAuth) oidcContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), toa.oidcTimeout())
}

// secretValuePattern matches the JSON shape `client_secret": "value"` (and the
// assertion equivalent). Providers commonly echo the whole request back in their
// error body, so the configured secret is scrubbed by value and any other value
// under these keys is scrubbed by key.
var secretValuePattern = regexp.MustCompile(`(?i)("?(?:client_secret|client_assertion|client_assertion_type)"?\s*[:=]\s*"?)([^"&,\s}]+)`)

// capIdcErrorBody truncates and scrubs an IDP error body so it can be logged
// safely. Providers routinely echo the request parameters back in the error,
// which would put the client secret into the log file.
func capIdcErrorBody(toa *TraefikOidcAuth, body []byte) string {
	if toa != nil && toa.Config != nil && toa.Config.Provider != nil {
		body = []byte(scrubSecret(body, toa.Config.Provider.ClientSecret))
		body = []byte(scrubSecret(body, toa.Config.Provider.ClientId))
	}

	body = secretValuePattern.ReplaceAll(body, []byte("${1}[REDACTED]"))

	if len(body) > maxIdcErrorBody {
		return string(body[:maxIdcErrorBody]) + "...(truncated)"
	}

	return string(body)
}

// scrubSecret replaces every occurrence of secret with a placeholder.
func scrubSecret(body []byte, secret string) string {
	if secret == "" {
		return string(body)
	}

	return strings.ReplaceAll(string(body), secret, "[REDACTED]")
}

// logIdcErrorBody logs a truncated, scrubbed IDP error body at WARN. The body is
// attacker-influenced and may contain credentials, so it never goes to INFO.
func logIdcErrorBody(toa *TraefikOidcAuth, operation string, resp *http.Response) {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxOidcResponseBody))
	toa.logger.Log(logging.LevelWarn, "%s: Provider returned status %d: %s", operation, resp.StatusCode, capIdcErrorBody(toa, body))
}

func GetOidcDiscovery(logger *logging.Logger, httpClient *http.Client, providerUrl *url.URL) (*oidc.OidcDiscovery, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultOidcTimeout)
	defer cancel()

	return GetOidcDiscoveryContext(ctx, logger, httpClient, providerUrl)
}

// GetOidcDiscoveryContext fetches the provider's discovery document. Discovery runs
// under the middleware's load lock, so it must not be able to hang.
func GetOidcDiscoveryContext(ctx context.Context, logger *logging.Logger, httpClient *http.Client, providerUrl *url.URL) (*oidc.OidcDiscovery, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	wellKnownUrl := *providerUrl

	wellKnownUrl.Path = path.Join(wellKnownUrl.Path, ".well-known/openid-configuration")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnownUrl.String(), nil)
	if err != nil {
		logger.Log(logging.LevelError, "http-get discovery endpoints - Err: %v", err)
		return nil, errors.New("HTTP GET error")
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		logger.Log(logging.LevelError, "http-get discovery endpoints - Err: %v", err)
		return nil, errors.New("HTTP GET error")
	}

	defer resp.Body.Close()

	// Check if the response status code is successful
	if resp.StatusCode >= 300 {
		logger.Log(logging.LevelError, "http-get OIDC discovery endpoints - http status code: %s", resp.Status)
		return nil, errors.New("HTTP error - Status code: " + resp.Status)
	}

	document := oidc.OidcDiscovery{}
	err = json.NewDecoder(io.LimitReader(resp.Body, maxOidcResponseBody)).Decode(&document)
	if err != nil {
		logger.Log(logging.LevelError, "Failed to decode OIDC discovery document: %v", err)
		return &document, fmt.Errorf("failed to decode OIDC discovery document: %w", err)
	}

	return &document, nil
}

func randomBytesInHex(count int) (string, error) {
	buf := make([]byte, count)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		return "", fmt.Errorf("could not generate %d random bytes: %w", count, err)
	}

	return hex.EncodeToString(buf), nil
}

func exchangeAuthCode(oidcAuth *TraefikOidcAuth, req *http.Request, authCode string, codeVerifierEnc string) (*oidc.OidcTokenResponse, error) {
	ctx, cancel := oidcAuth.oidcContext()
	defer cancel()

	return exchangeAuthCodeContext(ctx, oidcAuth, req, authCode, codeVerifierEnc)
}

func exchangeAuthCodeContext(ctx context.Context, oidcAuth *TraefikOidcAuth, req *http.Request, authCode string, codeVerifierEnc string) (*oidc.OidcTokenResponse, error) {
	redirectUrl := oidcAuth.GetAbsoluteCallbackURL(req).String()

	urlValues := url.Values{
		"grant_type":   {"authorization_code"},
		"client_id":    {oidcAuth.Config.Provider.ClientId},
		"code":         {authCode},
		"redirect_uri": {redirectUrl},
		"resource":     oidcAuth.Config.RequestedResources,
	}

	if oidcAuth.Config.Provider.ClientSecret != "" {
		urlValues.Add("client_secret", oidcAuth.Config.Provider.ClientSecret)
	}

	if oidcAuth.ClientJwtPrivateKey != nil {
		clientAssertionToken, err := oidcAuth.getClientAssertionJwtToken()
		if err != nil {
			return nil, err
		}

		urlValues.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		urlValues.Add("client_assertion", clientAssertionToken)
	}

	if oidcAuth.Config.Provider.UsePkceBool {
		if codeVerifierEnc == "" {
			return nil, errors.New("missing PKCE code verifier in state")
		}

		codeVerifier, err := utils.Decrypt(codeVerifierEnc, oidcAuth.Config.Secret)
		if err != nil {
			return nil, err
		}

		urlValues.Add("code_verifier", codeVerifier)
	}

	return oidcAuth.postFormToTokenEndpoint(ctx, "exchangeAuthCode", urlValues)
}

// renewToken exchanges a refresh token for a new access token.
func (toa *TraefikOidcAuth) renewToken(refreshToken string) (*oidc.OidcTokenResponse, error) {
	ctx, cancel := toa.oidcContext()
	defer cancel()

	return toa.renewTokenContext(ctx, refreshToken)
}

func (toa *TraefikOidcAuth) renewTokenContext(ctx context.Context, refreshToken string) (*oidc.OidcTokenResponse, error) {
	urlValues := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {toa.Config.Provider.ClientId},
		"scope":         {strings.Join(toa.Config.Scopes, " ")},
		"refresh_token": {refreshToken},
		"resources":     toa.Config.RequestedResources,
	}

	if toa.Config.Provider.ClientSecret != "" {
		urlValues.Add("client_secret", toa.Config.Provider.ClientSecret)
	}

	if toa.ClientJwtPrivateKey != nil {
		clientAssertionToken, err := toa.getClientAssertionJwtToken()
		if err != nil {
			return nil, err
		}

		urlValues.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		urlValues.Add("client_assertion", clientAssertionToken)
	}

	return toa.postFormToTokenEndpoint(ctx, "renewToken", urlValues)
}

// postFormToTokenEndpoint performs the shared form-POST to the token endpoint used
// by both the authorization_code and refresh_token grants.
func (toa *TraefikOidcAuth) postFormToTokenEndpoint(ctx context.Context, operation string, urlValues url.Values) (*oidc.OidcTokenResponse, error) {
	if toa.DiscoveryDocument == nil || toa.DiscoveryDocument.TokenEndpoint == "" {
		return nil, errors.New("token_endpoint is not set")
	}

	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPost, toa.DiscoveryDocument.TokenEndpoint, strings.NewReader(urlValues.Encode()))
	if err != nil {
		toa.logger.Log(logging.LevelError, "%s: couldn't create token request: %v", operation, err)
		return nil, err
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := toa.httpClient.Do(tokenReq)
	if err != nil {
		toa.logger.Log(logging.LevelError, "%s: couldn't POST to Provider: %v", operation, err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logIdcErrorBody(toa, operation, resp)
		return nil, errors.New("invalid status code")
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOidcResponseBody+1))
	if err != nil {
		toa.logger.Log(logging.LevelError, "%s: couldn't read token response: %v", operation, err)
		return nil, err
	}

	if len(body) > maxOidcResponseBody {
		toa.logger.Log(logging.LevelError, "%s: token response exceeds %d bytes", operation, maxOidcResponseBody)
		return nil, errors.New("token response too large")
	}

	tokenResponse := &oidc.OidcTokenResponse{}
	if err := json.Unmarshal(body, tokenResponse); err != nil {
		toa.logger.Log(logging.LevelError, "%s: couldn't decode OidcTokenResponse: %v", operation, err)
		return nil, err
	}

	return tokenResponse, nil
}

// parseJwtWithJwksRetry parses a locally-validated JWT, force-reloading the JWKS once
// on a non-expiry failure (unknown kid after a key rotation). Centralised so both
// local parsers - id/access token and the signed userinfo response - share the retry
// and cannot drift apart.
func (toa *TraefikOidcAuth) parseJwtWithJwksRetry(ctx context.Context, tokenString string, options []jwt.ParserOption, operation string) (jwt.MapClaims, error) {
	// Bounded: a hanging JWKS endpoint must not pin the request that needs the key.
	if err := toa.Jwks.EnsureLoadedContext(ctx, toa.logger, toa.httpClient, false); err != nil {
		return nil, err
	}

	parser := jwt.NewParser(options...)

	claims := jwt.MapClaims{}

	_, err := parser.ParseWithClaims(tokenString, claims, toa.Jwks.Keyfunc)
	if err == nil {
		return claims, nil
	}

	// If the token is expired, reloading JWKS won't help — skip the retry.
	if isTokenExpiredError(err) {
		toa.logger.Log(logging.LevelDebug, "token expired")
		return nil, err
	}

	if err := toa.Jwks.EnsureLoadedContext(ctx, toa.logger, toa.httpClient, true); err != nil {
		return nil, err
	}

	claims = jwt.MapClaims{}

	if _, err := parser.ParseWithClaims(tokenString, claims, toa.Jwks.Keyfunc); err != nil {
		if isTokenExpiredError(err) {
			toa.logger.Log(logging.LevelDebug, "token expired")
		} else {
			toa.logger.Log(logging.LevelError, "Failed to parse %s token: %v", operation, err)
		}

		return nil, err
	}

	return claims, nil
}

func (toa *TraefikOidcAuth) validateTokenLocally(tokenString string, expectedNonce string) (bool, map[string]interface{}, error) {
	ctx, cancel := toa.oidcContext()
	defer cancel()

	return toa.validateTokenLocallyContext(ctx, tokenString, expectedNonce)
}

func (toa *TraefikOidcAuth) validateTokenLocallyContext(ctx context.Context, tokenString string, expectedNonce string) (bool, map[string]interface{}, error) {
	leeway := time.Duration(toa.Config.Provider.TokenClockSkewSeconds) * time.Second

	options := []jwt.ParserOption{
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(leeway),
		// Defence in depth: the key lookup already rejects unknown algorithms,
		// but the parser must not accept a method the allowlist does not name.
		jwt.WithValidMethods(oidc.AllowedAlgorithms()),
	}

	if toa.Config.Provider.ValidateIssuerBool {
		options = append(options, jwt.WithIssuer(toa.Config.Provider.ValidIssuer))
	}
	if toa.Config.Provider.ValidateAudienceBool {
		options = append(options, jwt.WithAudience(toa.Config.Provider.ValidAudience))
	}

	parsed, err := toa.parseJwtWithJwksRetry(ctx, tokenString, options, "id/access")
	if err != nil {
		return false, nil, err
	}

	if expectedNonce != "" && toa.Config.Provider.ValidateNonceBool {
		claimNonce, _ := parsed["nonce"].(string)
		if !oidcNonceMatches(claimNonce, expectedNonce) {
			return false, nil, errors.New("oidc nonce mismatch")
		}
	}

	return true, parsed, nil
}

func oidcNonceMatches(claimNonce, expected string) bool {
	return subtle.ConstantTimeCompare([]byte(claimNonce), []byte(expected)) == 1
}

// isTokenExpiredError checks whether the error indicates the JWT token is expired.
// We use a string-based check because Traefik compiles plugins via Yaegi (Go interpreter),
// which may not fully support Go 1.20's multi-error unwrapping needed for errors.Is
// to traverse the joinedError wrapper used by golang-jwt/v5.
func isTokenExpiredError(err error) bool {
	if err == nil {
		return false
	}

	return strings.Contains(err.Error(), jwt.ErrTokenExpired.Error())
}

func (toa *TraefikOidcAuth) introspectToken(token string) (bool, map[string]interface{}, error) {
	ctx, cancel := toa.oidcContext()
	defer cancel()

	return toa.introspectTokenContext(ctx, token)
}

// introspectTokenContext asks the IDP whether a token is still active.
//
// CALLERS MUST HONOUR THE RETURNED BOOL. It is false only when the IDP positively
// reports {"active": false}; every other failure (transport error, non-200,
// undecodable body, missing/non-boolean "active") returns false AND a non-nil
// error. Never treat a nil error with a false bool as "active", and never ignore
// the error and use the claims.
func (toa *TraefikOidcAuth) introspectTokenContext(ctx context.Context, token string) (bool, map[string]interface{}, error) {
	if toa.DiscoveryDocument == nil || toa.DiscoveryDocument.IntrospectionEndpoint == "" {
		return false, nil, errors.New("introspection_endpoint is not set")
	}

	data := url.Values{
		"token": {token},
	}

	if toa.ClientJwtPrivateKey != nil {
		clientAssertionToken, err := toa.getClientAssertionJwtToken()
		if err != nil {
			return false, nil, err
		}

		data.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		data.Add("client_assertion", clientAssertionToken)
	}

	endpoint := toa.DiscoveryDocument.IntrospectionEndpoint

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return false, nil, err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(toa.Config.Provider.ClientId, toa.Config.Provider.ClientSecret)

	resp, err := toa.httpClient.Do(req)
	if err != nil {
		toa.logger.Log(logging.LevelError, "Error on introspection request: %v", err)
		return false, nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logIdcErrorBody(toa, "introspectToken", resp)
		return false, nil, fmt.Errorf("introspection returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOidcResponseBody+1))
	if err != nil {
		toa.logger.Log(logging.LevelError, "Failed to read introspection response: %v", err)
		return false, nil, err
	}

	if len(body) > maxOidcResponseBody {
		toa.logger.Log(logging.LevelError, "introspectToken: introspection response exceeds %d bytes", maxOidcResponseBody)
		return false, nil, errors.New("introspection response too large")
	}

	var introspectResponse map[string]interface{}
	if err := json.Unmarshal(body, &introspectResponse); err != nil {
		toa.logger.Log(logging.LevelError, "Failed to decode introspection response: %v", err)
		return false, nil, err
	}

	active, ok := introspectResponse["active"].(bool)
	if !ok {
		return false, nil, errors.New("received invalid introspection response")
	}

	return active, introspectResponse, nil
}

// revokeToken revokes a refresh token at the IDP's revocation endpoint, so a
// stolen refresh token cannot outlive the logout.
//
// Returns nil (no-op) when revocation is disabled, no endpoint is advertised, or
// there is no refresh token. The caller MUST treat a non-nil error as
// non-fatal - log it at WARN and complete the logout anyway - because a
// misbehaving revocation endpoint must not strand a user in a session they asked
// to end.
func (toa *TraefikOidcAuth) revokeToken(ctx context.Context, refreshToken string) error {
	if toa.Config == nil || toa.Config.Provider == nil || !toa.Config.Provider.RevokeTokensOnLogoutBool {
		return nil
	}

	if toa.DiscoveryDocument == nil || toa.DiscoveryDocument.RevocationEndpoint == "" {
		return nil
	}

	if refreshToken == "" {
		return nil
	}

	data := url.Values{
		"token":           {refreshToken},
		"token_type_hint": {"refresh_token"},
	}

	// Same client-authentication mechanism as introspection: private_key_jwt when a
	// client assertion key is configured, otherwise client_secret.
	if toa.ClientJwtPrivateKey != nil {
		clientAssertionToken, err := toa.getClientAssertionJwtToken()
		if err != nil {
			return err
		}

		data.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		data.Add("client_assertion", clientAssertionToken)
		data.Add("client_id", toa.Config.Provider.ClientId)
	} else {
		if toa.Config.Provider.ClientSecret == "" {
			return errors.New("cannot revoke token: neither client assertion key nor client secret is configured")
		}

		data.Add("client_id", toa.Config.Provider.ClientId)
		data.Add("client_secret", toa.Config.Provider.ClientSecret)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		toa.DiscoveryDocument.RevocationEndpoint,
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := toa.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// RFC 7009: the endpoint answers 200 even for an unknown token. Anything else
	// means the revocation did not happen.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxOidcResponseBody))
		return fmt.Errorf("revocation returned status %d: %s", resp.StatusCode, capIdcErrorBody(toa, body))
	}

	return nil
}

func (toa *TraefikOidcAuth) getClientAssertionJwtToken() (string, error) {
	claims := jwt.MapClaims{
		"iss": toa.Config.Provider.ClientId,
		"sub": toa.Config.Provider.ClientId,
		"aud": toa.Config.Provider.Url,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	}

	assertionToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	assertionToken.Header["kid"] = toa.Config.Provider.ClientJwtPrivateKeyId

	clientAssertionJwt, err := assertionToken.SignedString(toa.ClientJwtPrivateKey)
	if err != nil {
		return "", err
	}

	return clientAssertionJwt, nil
}

func (toa *TraefikOidcAuth) getUserInfo(accessToken string, idTokenSubject string) (map[string]interface{}, error) {
	ctx, cancel := toa.oidcContext()
	defer cancel()

	return toa.getUserInfoContext(ctx, accessToken, idTokenSubject)
}

func (toa *TraefikOidcAuth) getUserInfoContext(ctx context.Context, accessToken string, idTokenSubject string) (map[string]interface{}, error) {
	if toa.DiscoveryDocument == nil || toa.DiscoveryDocument.UserinfoEndpoint == "" {
		return nil, errors.New("userinfo_endpoint is not set")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, toa.DiscoveryDocument.UserinfoEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", "Bearer "+accessToken)

	resp, err := toa.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, errors.New("token is not valid")
		}
		logIdcErrorBody(toa, "getUserInfo", resp)
		return nil, fmt.Errorf("invalid status code: %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	var userInfoClaims map[string]interface{}

	switch {
	case strings.HasPrefix(contentType, "application/jwt"):
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxOidcResponseBody+1))
		if err != nil {
			return nil, err
		}

		if len(body) > maxOidcResponseBody {
			toa.logger.Log(logging.LevelError, "getUserInfo: signed userinfo response exceeds %d bytes", maxOidcResponseBody)
			return nil, errors.New("userinfo response too large")
		}

		tokenString := string(body)

		options := []jwt.ParserOption{
			jwt.WithLeeway(time.Duration(toa.Config.Provider.TokenClockSkewSeconds) * time.Second),
			jwt.WithValidMethods(oidc.AllowedAlgorithms()),
		}

		if toa.Config.Provider.ValidateIssuerBool {
			options = append(options, jwt.WithIssuer(toa.Config.Provider.ValidIssuer))
		}

		claims, err := toa.parseJwtWithJwksRetry(ctx, tokenString, options, "userinfo")
		if err != nil {
			return nil, err
		}

		userInfoClaims = claims
	case strings.HasPrefix(contentType, "application/json"):
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxOidcResponseBody)).Decode(&userInfoClaims); err != nil {
			toa.logger.Log(logging.LevelError, "getUserInfo: couldn't decode userinfo response: %v", err)
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported content type: %s", contentType)
	}

	userInfoSub, ok := userInfoClaims["sub"].(string)
	if !ok {
		toa.logger.Log(logging.LevelWarn, "getUserInfo: 'sub' claim in userinfo response is not a string or missing, discarding userinfo response")
		return map[string]interface{}{}, nil
	}

	if userInfoSub != idTokenSubject {
		toa.logger.Log(logging.LevelWarn, "getUserInfo: mismatch between 'sub' in userinfo response (%s) and 'sub' in id_token (%s), discarding userinfo response", userInfoSub, idTokenSubject)
		return map[string]interface{}{}, nil
	}

	return userInfoClaims, nil
}

// authParamsForChallenge returns extra authorization-request parameters to add when
// the login was triggered by an authorization re-check (Challenge behaviour).
//
// Step-up is the point of the Challenge behaviour: sending max_age forces the IDP to
// re-authenticate instead of silently reusing an existing IDP session, so a route
// advertised as requiring fresh authentication cannot be satisfied by an
// authentication from hours ago. Returns nil when there is nothing to add, so the
// caller can range over the result unconditionally.
func (toa *TraefikOidcAuth) authParamsForChallenge(isChallenge bool) map[string]string {
	if !isChallenge || toa.Config == nil || toa.Config.Provider == nil {
		return nil
	}

	if toa.Config.Provider.MaxAuthAgeSeconds <= 0 {
		return nil
	}

	return map[string]string{
		"max_age": strconv.Itoa(toa.Config.Provider.MaxAuthAgeSeconds),
	}
}

// authTimeIsFresh reports whether the ID token was issued from an authentication
// that is recent enough for provider.max_auth_age_seconds.
//
// A missing auth_time while the feature is enabled is treated as NOT fresh: an IDP
// that silently omits the claim must not be able to bypass step-up.
func (toa *TraefikOidcAuth) authTimeIsFresh(claims map[string]any, now time.Time) bool {
	if toa.Config == nil || toa.Config.Provider == nil || toa.Config.Provider.MaxAuthAgeSeconds <= 0 {
		return true
	}

	authTime, ok := authTimeFromClaims(claims)
	if !ok {
		return false
	}

	maxAge := time.Duration(toa.Config.Provider.MaxAuthAgeSeconds) * time.Second

	return !authTime.Add(maxAge).Before(now)
}

// authTimeFromClaims reads the OIDC auth_time claim, which providers encode either
// as a JSON number of seconds since the epoch or (less commonly) as an RFC3339
// timestamp. The second return value reports whether a usable value was found.
func authTimeFromClaims(claims map[string]any) (time.Time, bool) {
	if claims == nil {
		return time.Time{}, false
	}

	switch value := claims["auth_time"].(type) {
	case float64:
		return time.Unix(int64(value), 0).UTC(), true
	case json.Number:
		if seconds, err := value.Int64(); err == nil {
			return time.Unix(seconds, 0).UTC(), true
		}
	case int64:
		return time.Unix(value, 0).UTC(), true
	case int:
		return time.Unix(int64(value), 0).UTC(), true
	case string:
		if parsed, err := time.Parse(time.RFC3339, value); err == nil {
			return parsed.UTC(), true
		}
		if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
			return time.Unix(seconds, 0).UTC(), true
		}
	}

	return time.Time{}, false
}

// mergeClaims merges userinfo claims into token claims, preserving security-critical claims
func mergeClaims(tokenClaims, userInfoClaims map[string]interface{}) map[string]interface{} {
	// Create a copy of the token claims to avoid modifying the original
	mergedClaims := make(map[string]interface{})
	for key, value := range tokenClaims {
		mergedClaims[key] = value
	}

	// Define claims that should NOT be overwritten from userinfo
	protectedClaims := map[string]bool{
		"iss": true, // issuer
		"aud": true, // audience
		"exp": true, // expiration time
		"iat": true, // issued at
		"nbf": true, // not before
		"jti": true, // JWT ID
		"azp": true, // authorized party
	}

	// Merge userinfo claims, skipping protected claims
	for key, value := range userInfoClaims {
		if !protectedClaims[key] {
			mergedClaims[key] = value
		}
	}

	return mergedClaims
}
