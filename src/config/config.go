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
	LogLevel string `json:"log_level"`

	Secret string `json:"secret"`

	Provider *ProviderConfig `json:"provider"`
	Scopes   []string        `json:"scopes"`

	// Can be a relative path or a full URL.
	// If a relative path is used, the scheme and domain will be taken from the incoming request.
	// In this case, the callback path will overlay all hostnames behind the middleware.
	// If a full URL is used, all callbacks are sent there.  It is the user's responsibility to ensure
	// that the callback URL is also routed to this middleware plugin.
	CallbackUri string `json:"callback_uri"`

	// The URL used to start authorization when needed.
	// All other requests that are not already authorized will return a 401 Unauthorized.
	// When left empty, all requests can start authorization.
	LoginUri                    string   `json:"login_uri"`
	PostLoginRedirectUri        string   `json:"post_login_redirect_uri"`
	ValidPostLoginRedirectUris  []string `json:"valid_post_login_redirect_uris"`
	LogoutUri                   string   `json:"logout_uri"`
	PostLogoutRedirectUri       string   `json:"post_logout_redirect_uri"`
	ValidPostLogoutRedirectUris []string `json:"valid_post_logout_redirect_uris"`
	FrontChannelLogoutUri       string   `json:"front_channel_logout_uri"`

	SessionStorageType string `json:"session_storage_type"`

	CookieNamePrefix        string                     `json:"cookie_name_prefix"`
	SessionCookie           *SessionCookieConfig       `json:"session_cookie"`
	AuthorizationHeader     *AuthorizationHeaderConfig `json:"authorization_header"`
	AuthorizationCookie     *AuthorizationCookieConfig `json:"authorization_cookie"`
	UnauthenticatedBehavior string                     `json:"unauthenticated_behavior"`
	UnauthorizedBehavior    string                     `json:"unauthorized_behavior"`

	Authorization *AuthorizationConfig `json:"authorization"`

	Headers []HeaderConfig `json:"headers"`

	BypassAuthenticationRule string `json:"bypass_authentication_rule"`

	ErrorPages *errorPages.ErrorPagesConfig `json:"error_pages"`

	RequestedResources []string `json:"requested_resources"`

	// Additional query parameters to send to the IDP's authorization endpoint, eg. acr_values or prompt.
	// A `prompt` query parameter on the incoming /login request still takes precedence over this.
	AuthorizationParams map[string]string `json:"authorization_params"`

	// AuthorizationParamsOverridable lists the AuthorizationParams keys an incoming request is
	// allowed to override. Every key not listed here is pinned to the operator's value, because
	// an overridable key is a key an attacker can downgrade (eg. ?acr_values=loa1 against a
	// configured aal2). Empty - the default - pins all of them.
	AuthorizationParamsOverridable []string `json:"authorization_params_overridable"`

	// TrustedProxies lists CIDR ranges of reverse proxies in front of Traefik whose
	// X-Forwarded-Proto / X-Forwarded-Host headers may be trusted when building absolute URLs
	// and the redirect_uri sent to the IDP. Empty - the default - trusts none of them, which
	// keeps the plugin fail-closed when Traefik is reachable directly.
	TrustedProxies []string `json:"trusted_proxies"`

	// TrustedProxyNets is the parsed form of TrustedProxies, filled in by src.New. It is not
	// part of the operator-facing config surface.
	TrustedProxyNets []*net.IPNet `json:"-"`

	// MaxSessionLifetimeSeconds bounds the total lifetime of a session, independent of activity.
	// Sessions are stateless, so nothing else can terminate one: a stolen cookie keeps refreshing
	// for as long as the IDP honours the refresh token. 0 disables the bound and logs a warning
	// at startup, because an unbounded session cannot be revoked without changing the secret.
	MaxSessionLifetimeSeconds int `json:"max_session_lifetime_seconds"`

	// SessionIdleTimeoutSeconds bounds the gap between two accepted requests on the same session.
	// 0 disables the idle bound.
	SessionIdleTimeoutSeconds int `json:"session_idle_timeout_seconds"`
}

type ProviderConfig struct {
	Url string `json:"url"`

	InsecureSkipVerify     string `json:"insecure_skip_verify"`
	InsecureSkipVerifyBool bool   `json:"insecure_skip_verify_bool"`

	CABundle     string `json:"ca_bundle"`
	CABundleFile string `json:"ca_bundle_file"`

	ClientId              string `json:"client_id"`
	ClientSecret          string `json:"client_secret"`
	ClientJwtPrivateKey   string `json:"client_jwt_private_key"`
	ClientJwtPrivateKeyId string `json:"client_jwt_private_key_id"`

	UsePkce     string `json:"use_pkce"`
	UsePkceBool bool   `json:"use_pkce_bool"`

	ValidateAudience     string `json:"validate_audience"`
	ValidateAudienceBool bool   `json:"validate_audience_bool"`
	ValidAudience        string `json:"valid_audience"`

	ValidateIssuer     string `json:"validate_issuer"`
	ValidateIssuerBool bool   `json:"validate_issuer_bool"`
	ValidIssuer        string `json:"valid_issuer"`

	// AccessToken or IdToken or Introspection
	TokenValidation string `json:"verification_token"`

	TokenRenewalThreshold float64 `json:"token_renewal_threshold"`

	UseClaimsFromUserInfo     string `json:"use_claims_from_user_info"`
	UseClaimsFromUserInfoBool bool   `json:"use_claims_from_user_info_bool"`

	// ValidateNonce requires the ID token nonce claim to match the sealed login state (OIDC Core).
	// Default true when unset via CreateConfig. Set false only if the IdP cannot return nonce.
	ValidateNonce     string `json:"validate_nonce"`
	ValidateNonceBool bool   `json:"validate_nonce_bool"`

	// TokenClockSkewSeconds is leeway for JWT nbf/exp validation (issue #236). Default 60.
	TokenClockSkewSeconds int `json:"token_clock_skew_seconds"`

	// RevokeTokensOnLogout posts the refresh token to the IDP's revocation endpoint on
	// user-initiated logout, so a stolen cookie or refresh token cannot outlive the session.
	// Default true. Silently skipped when the IDP advertises no revocation_endpoint.
	RevokeTokensOnLogout     string `json:"revoke_tokens_on_logout"`
	RevokeTokensOnLogoutBool bool   `json:"revoke_tokens_on_logout_bool"`

	// MaxAuthAgeSeconds makes the challenge behaviour a real step-up: it sends max_age on the
	// authorization request and requires the resulting ID token to carry an auth_time claim
	// that recent. Without it an IDP session silently re-authorizes, so a route advertised as
	// requiring fresh authentication accepts an authentication from hours ago. 0 disables it.
	MaxAuthAgeSeconds int `json:"max_auth_age_seconds"`

	// OidcTimeoutSeconds bounds every outbound call to the IDP (discovery, token, JWKS,
	// introspection, userinfo). Without it a hung IDP pins a request goroutine forever.
	OidcTimeoutSeconds int `json:"oidc_timeout_seconds"`
}

type SessionCookieConfig struct {
	Path     string `json:"path"`
	Domain   string `json:"domain"`
	Secure   bool   `json:"secure"`
	HttpOnly bool   `json:"http_only"`
	SameSite string `json:"same_site"`
	MaxAge   int    `json:"max_age"`
}

type AuthorizationHeaderConfig struct {
	Name string `json:"name"`
}
type AuthorizationCookieConfig struct {
	Name string `json:"name"`
}

type AuthorizationConfig struct {
	AssertClaims        []ClaimAssertion `json:"assert_claims"`
	CheckOnEveryRequest bool             `json:"check_on_every_request"`
}

type ClaimAssertion struct {
	Name  string   `json:"name"`
	AnyOf []string `json:"anyOf"`
	AllOf []string `json:"allOf"`
}

type HeaderConfig struct {
	Name        string `json:"name"`
	Value       string `json:"value"`
	Values      string `json:"values"`
	IncludeWhen string `json:"include_when"`

	// A reference to the parsed Value-template
	Template *template.Template
}
