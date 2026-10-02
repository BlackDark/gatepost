package config

import (
	"net"
	"text/template"

	"github.com/BlackDark/test-oidc-traefik-plugin/src/errorPages"
)

const DefaultSecret = "MLFs4TT99kOOq8h3UAVRtYoCTDYXiRcZ"

const (
	SessionStorageTypeCookie string = "Cookie"
)

type Config struct {
	LogLevel string `json:"log_level" yaml:"logLevel"`

	Secret string `json:"secret" yaml:"secret"`

	Provider *ProviderConfig `json:"provider" yaml:"provider"`
	Scopes   []string        `json:"scopes" yaml:"scopes"`

	// Can be a relative path or a full URL.
	// If a relative path is used, the scheme and domain will be taken from the incoming request.
	// In this case, the callback path will overlay all hostnames behind the middleware.
	// If a full URL is used, all callbacks are sent there.  It is the user's responsibility to ensure
	// that the callback URL is also routed to this middleware plugin.
	CallbackUri string `json:"callback_uri" yaml:"callbackUri"`

	// The URL used to start authorization when needed.
	// All other requests that are not already authorized will return a 401 Unauthorized.
	// When left empty, all requests can start authorization.
	LoginUri                    string   `json:"login_uri" yaml:"loginUri"`
	PostLoginRedirectUri        string   `json:"post_login_redirect_uri" yaml:"postLoginRedirectUri"`
	ValidPostLoginRedirectUris  []string `json:"valid_post_login_redirect_uris" yaml:"validPostLoginRedirectUris"`
	LogoutUri                   string   `json:"logout_uri" yaml:"logoutUri"`
	PostLogoutRedirectUri       string   `json:"post_logout_redirect_uri" yaml:"postLogoutRedirectUri"`
	ValidPostLogoutRedirectUris []string `json:"valid_post_logout_redirect_uris" yaml:"validPostLogoutRedirectUris"`
	FrontChannelLogoutUri       string   `json:"front_channel_logout_uri" yaml:"frontChannelLogoutUri"`

	SessionStorageType string `json:"session_storage_type" yaml:"sessionStorageType"`

	CookieNamePrefix        string                     `json:"cookie_name_prefix" yaml:"cookieNamePrefix"`
	SessionCookie           *SessionCookieConfig       `json:"session_cookie" yaml:"sessionCookie"`
	AuthorizationHeader     *AuthorizationHeaderConfig `json:"authorization_header" yaml:"authorizationHeader"`
	AuthorizationCookie     *AuthorizationCookieConfig `json:"authorization_cookie" yaml:"authorizationCookie"`
	UnauthenticatedBehavior string                     `json:"unauthenticated_behavior" yaml:"unauthenticatedBehavior"`
	UnauthorizedBehavior    string                     `json:"unauthorized_behavior" yaml:"unauthorizedBehavior"`

	Authorization *AuthorizationConfig `json:"authorization" yaml:"authorization"`

	Headers []HeaderConfig `json:"headers" yaml:"headers"`

	BypassAuthenticationRule string `json:"bypass_authentication_rule" yaml:"bypassAuthenticationRule"`

	ErrorPages *errorPages.ErrorPagesConfig `json:"error_pages" yaml:"errorPages"`

	RequestedResources []string `json:"requested_resources" yaml:"requestedResources"`

	// Additional query parameters to send to the IDP's authorization endpoint, eg. acr_values or prompt.
	// A `prompt` query parameter on the incoming /login request still takes precedence over this.
	AuthorizationParams map[string]string `json:"authorization_params" yaml:"authorizationParams"`

	// AuthorizationParamsOverridable lists the AuthorizationParams keys an incoming request is
	// allowed to override. Every key not listed here is pinned to the operator's value, because
	// an overridable key is a key an attacker can downgrade (eg. ?acr_values=loa1 against a
	// configured aal2). Empty - the default - pins all of them.
	AuthorizationParamsOverridable []string `json:"authorization_params_overridable" yaml:"authorizationParamsOverridable"`

	// TrustedProxies lists CIDR ranges of reverse proxies in front of Traefik whose
	// X-Forwarded-Proto / X-Forwarded-Host headers may be trusted when building absolute URLs
	// and the redirect_uri sent to the IDP. Empty - the default - trusts none of them, which
	// keeps the plugin fail-closed when Traefik is reachable directly.
	TrustedProxies []string `json:"trusted_proxies" yaml:"trustedProxies"`

	// TrustedProxyNets is the parsed form of TrustedProxies, filled in by src.New. It is not
	// part of the operator-facing config surface, so it is excluded from the YAML surface too:
	// writing CIDRs straight into the parsed form would bypass the startup validation that
	// rejects unparseable trustedProxies entries.
	TrustedProxyNets []*net.IPNet `json:"-" yaml:"-"`

	// MaxSessionLifetimeSeconds bounds the total lifetime of a session, independent of activity.
	// Sessions are stateless, so nothing else can terminate one: a stolen cookie keeps refreshing
	// for as long as the IDP honours the refresh token. 0 disables the bound and logs a warning
	// at startup, because an unbounded session cannot be revoked without changing the secret.
	MaxSessionLifetimeSeconds int `json:"max_session_lifetime_seconds" yaml:"maxSessionLifetimeSeconds"`

	// SessionIdleTimeoutSeconds bounds the gap between two accepted requests on the same session.
	// 0 disables the idle bound.
	SessionIdleTimeoutSeconds int `json:"session_idle_timeout_seconds" yaml:"sessionIdleTimeoutSeconds"`
}

type ProviderConfig struct {
	Url string `json:"url" yaml:"url"`

	InsecureSkipVerify     string `json:"insecure_skip_verify" yaml:"insecureSkipVerify"`
	InsecureSkipVerifyBool bool   `json:"insecure_skip_verify_bool" yaml:"insecureSkipVerifyBool"`

	// The yaml tags are the lowerCamel form of the Go field name, which is exactly what
	// Traefik's tagless mapstructure decoder matches (case-insensitively). Any other
	// spelling - notably "caBundle", which yaml.v3 would also accept because its field
	// matching is case-insensitive - is silently DROPPED by the Traefik surface, and the
	// documented remedy for a self-signed IdP is insecureSkipVerify, so a wrong spelling here
	// pushes operators onto the weaker control. src/config_dockeys_test.go enforces the
	// invariant over every field of every config struct.
	CABundle     string `json:"ca_bundle" yaml:"cABundle"`
	CABundleFile string `json:"ca_bundle_file" yaml:"cABundleFile"`

	ClientId              string `json:"client_id" yaml:"clientId"`
	ClientSecret          string `json:"client_secret" yaml:"clientSecret"`
	ClientJwtPrivateKey   string `json:"client_jwt_private_key" yaml:"clientJwtPrivateKey"`
	ClientJwtPrivateKeyId string `json:"client_jwt_private_key_id" yaml:"clientJwtPrivateKeyId"`

	UsePkce     string `json:"use_pkce" yaml:"usePkce"`
	UsePkceBool bool   `json:"use_pkce_bool" yaml:"usePkceBool"`

	ValidateAudience     string `json:"validate_audience" yaml:"validateAudience"`
	ValidateAudienceBool bool   `json:"validate_audience_bool" yaml:"validateAudienceBool"`
	ValidAudience        string `json:"valid_audience" yaml:"validAudience"`

	ValidateIssuer     string `json:"validate_issuer" yaml:"validateIssuer"`
	ValidateIssuerBool bool   `json:"validate_issuer_bool" yaml:"validateIssuerBool"`
	ValidIssuer        string `json:"valid_issuer" yaml:"validIssuer"`

	// AccessToken or IdToken or Introspection
	TokenValidation string `json:"verification_token" yaml:"tokenValidation"`

	TokenRenewalThreshold float64 `json:"token_renewal_threshold" yaml:"tokenRenewalThreshold"`

	UseClaimsFromUserInfo     string `json:"use_claims_from_user_info" yaml:"useClaimsFromUserInfo"`
	UseClaimsFromUserInfoBool bool   `json:"use_claims_from_user_info_bool" yaml:"useClaimsFromUserInfoBool"`

	// ValidateNonce requires the ID token nonce claim to match the sealed login state (OIDC Core).
	// Default true when unset via CreateConfig. Set false only if the IdP cannot return nonce.
	ValidateNonce     string `json:"validate_nonce" yaml:"validateNonce"`
	ValidateNonceBool bool   `json:"validate_nonce_bool" yaml:"validateNonceBool"`

	// TokenClockSkewSeconds is leeway for JWT nbf/exp validation (issue #236). Default 60.
	TokenClockSkewSeconds int `json:"token_clock_skew_seconds" yaml:"tokenClockSkewSeconds"`

	// RevokeTokensOnLogout posts the refresh token to the IDP's revocation endpoint on
	// user-initiated logout, so a stolen cookie or refresh token cannot outlive the session.
	// Default true. Silently skipped when the IDP advertises no revocation_endpoint.
	RevokeTokensOnLogout     string `json:"revoke_tokens_on_logout" yaml:"revokeTokensOnLogout"`
	RevokeTokensOnLogoutBool bool   `json:"revoke_tokens_on_logout_bool" yaml:"revokeTokensOnLogoutBool"`

	// MaxAuthAgeSeconds makes the challenge behaviour a real step-up: it sends max_age on
	// the authorization request and requires the resulting ID token to carry an auth_time claim
	// that recent. Without it an IDP session silently re-authorizes, so a route advertised as
	// requiring fresh authentication accepts an authentication from hours ago. 0 disables it.
	MaxAuthAgeSeconds int `json:"max_auth_age_seconds" yaml:"maxAuthAgeSeconds"`

	// OidcTimeoutSeconds bounds every outbound call to the IDP (discovery, token, JWKS,
	// introspection, userinfo). Without it a hung IDP pins a request goroutine forever.
	OidcTimeoutSeconds int `json:"oidc_timeout_seconds" yaml:"oidcTimeoutSeconds"`
}

type SessionCookieConfig struct {
	Path     string `json:"path" yaml:"path"`
	Domain   string `json:"domain" yaml:"domain"`
	Secure   bool   `json:"secure" yaml:"secure"`
	HttpOnly bool   `json:"http_only" yaml:"httpOnly"`
	SameSite string `json:"same_site" yaml:"sameSite"`
	MaxAge   int    `json:"max_age" yaml:"maxAge"`
}

type AuthorizationHeaderConfig struct {
	Name string `json:"name" yaml:"name"`
}
type AuthorizationCookieConfig struct {
	Name string `json:"name" yaml:"name"`
}

type AuthorizationConfig struct {
	AssertClaims        []ClaimAssertion `json:"assert_claims" yaml:"assertClaims"`
	CheckOnEveryRequest bool             `json:"check_on_every_request" yaml:"checkOnEveryRequest"`
}

type ClaimAssertion struct {
	Name  string   `json:"name" yaml:"name"`
	AnyOf []string `json:"anyOf" yaml:"anyOf"`
	AllOf []string `json:"allOf" yaml:"allOf"`
}

type HeaderConfig struct {
	Name        string `json:"name" yaml:"name"`
	Value       string `json:"value" yaml:"value"`
	Values      string `json:"values" yaml:"values"`
	IncludeWhen string `json:"include_when" yaml:"includeWhen"`

	// A reference to the parsed Value-template
	Template *template.Template `json:"-" yaml:"-"`
}
