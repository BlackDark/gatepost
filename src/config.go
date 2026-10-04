package src

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/BlackDark/gatepost/src/config"
	"github.com/BlackDark/gatepost/src/errorPages"
	"github.com/BlackDark/gatepost/src/logging"
	"github.com/BlackDark/gatepost/src/rules"
	"github.com/BlackDark/gatepost/src/session"
	"github.com/BlackDark/gatepost/src/utils"
)

// Will be called by traefik
func CreateConfig() *config.Config {
	return &config.Config{
		LogLevel: logging.LevelWarn,
		Secret:   config.DefaultSecret,
		Provider: &config.ProviderConfig{
			UsePkceBool:               true,
			InsecureSkipVerifyBool:    false,
			ValidateIssuerBool:        true,
			ValidateAudienceBool:      true,
			ValidateNonceBool:         true,
			TokenValidation:           "IdToken",
			TokenRenewalThreshold:     0.75,
			UseClaimsFromUserInfoBool: false,
			TokenClockSkewSeconds:     60,
			RevokeTokensOnLogoutBool:  true,
			OidcTimeoutSeconds:        30,
		},
		// Note: It looks like we're not allowed to specify a default value for arrays here.
		// Maybe a traefik bug. So I've moved this to the New() method.
		// Scopes:                []string{"openid", "profile", "email"},
		CallbackUri:           "/oidc/callback",
		LogoutUri:             "/logout",
		FrontChannelLogoutUri: "/frontchannel-logout",
		PostLogoutRedirectUri: "/",
		CookieNamePrefix:      "Gatepost",
		SessionCookie: &config.SessionCookieConfig{
			Path:     "/",
			Domain:   "",
			Secure:   true,
			HttpOnly: true,
			SameSite: "lax",
			MaxAge:   0,
		},
		AuthorizationHeader: &config.AuthorizationHeaderConfig{},
		AuthorizationCookie: &config.AuthorizationCookieConfig{},
		// Leave empty so migrateAuthBehaviors can map legacy UnauthorizedBehavior.
		UnauthenticatedBehavior: "",
		UnauthorizedBehavior:    "",
		Authorization: &config.AuthorizationConfig{
			CheckOnEveryRequest: false,
		},
		ErrorPages: &errorPages.ErrorPagesConfig{
			Unauthenticated: &errorPages.ErrorPageConfig{},
			Unauthorized:    &errorPages.ErrorPageConfig{},
		},
	}
}

// Will be called by traefik
func New(uctx context.Context, next http.Handler, cfg *config.Config, name string) (http.Handler, error) {
	cfg.LogLevel = utils.ExpandEnvironmentVariableString(cfg.LogLevel)

	logger := logging.CreateLogger(cfg.LogLevel)

	logger.Log(logging.LevelDebug, "Loading configuration...")

	if cfg.Provider == nil {
		return nil, errors.New("missing provider configuration")
	}

	// Hack: Trick the traefik plugin catalog to successfully execute this method with the testData from .traefik.yml.
	if cfg.Provider.Url == "https://..." {
		return &Gatepost{
			next: next,
		}, nil
	}

	var err error

	cfg.Secret = utils.ExpandEnvironmentVariableString(cfg.Secret)
	cfg.CallbackUri = utils.ExpandEnvironmentVariableString(cfg.CallbackUri)
	cfg.LoginUri = utils.ExpandEnvironmentVariableString(cfg.LoginUri)
	cfg.PostLoginRedirectUri = utils.ExpandEnvironmentVariableString(cfg.PostLoginRedirectUri)
	cfg.LogoutUri = utils.ExpandEnvironmentVariableString(cfg.LogoutUri)
	cfg.PostLogoutRedirectUri = utils.ExpandEnvironmentVariableString(cfg.PostLogoutRedirectUri)
	cfg.FrontChannelLogoutUri = utils.ExpandEnvironmentVariableString(cfg.FrontChannelLogoutUri)
	cfg.CookieNamePrefix = utils.ExpandEnvironmentVariableString(cfg.CookieNamePrefix)
	cfg.UnauthenticatedBehavior = utils.ExpandEnvironmentVariableString(cfg.UnauthenticatedBehavior)
	cfg.UnauthorizedBehavior = utils.ExpandEnvironmentVariableString(cfg.UnauthorizedBehavior)
	migrateAuthBehaviors(cfg)
	cfg.BypassAuthenticationRule = utils.ExpandEnvironmentVariableString(cfg.BypassAuthenticationRule)
	cfg.Provider.Url = utils.ExpandEnvironmentVariableString(cfg.Provider.Url)
	cfg.Provider.ClientId = utils.ExpandEnvironmentVariableString(cfg.Provider.ClientId)
	cfg.Provider.ClientSecret = utils.ExpandEnvironmentVariableString(cfg.Provider.ClientSecret)
	cfg.Provider.ClientJwtPrivateKeyId = utils.ExpandEnvironmentVariableString(cfg.Provider.ClientJwtPrivateKeyId)
	cfg.Provider.ClientJwtPrivateKey = utils.ExpandEnvironmentVariableString(cfg.Provider.ClientJwtPrivateKey)
	cfg.Provider.UsePkceBool, err = utils.ExpandEnvironmentVariableBoolean(cfg.Provider.UsePkce, cfg.Provider.UsePkceBool)
	if err != nil {
		return nil, err
	}
	cfg.Provider.UseClaimsFromUserInfoBool, err = utils.ExpandEnvironmentVariableBoolean(cfg.Provider.UseClaimsFromUserInfo, cfg.Provider.UseClaimsFromUserInfoBool)
	if err != nil {
		return nil, err
	}
	cfg.Provider.ValidateIssuerBool, err = utils.ExpandEnvironmentVariableBoolean(cfg.Provider.ValidateIssuer, cfg.Provider.ValidateIssuerBool)
	if err != nil {
		return nil, err
	}
	cfg.Provider.ValidIssuer = utils.ExpandEnvironmentVariableString(cfg.Provider.ValidIssuer)
	cfg.Provider.ValidateAudienceBool, err = utils.ExpandEnvironmentVariableBoolean(cfg.Provider.ValidateAudience, cfg.Provider.ValidateAudienceBool)
	if err != nil {
		return nil, err
	}
	cfg.Provider.ValidAudience = utils.ExpandEnvironmentVariableString(cfg.Provider.ValidAudience)
	cfg.Provider.ValidateNonceBool, err = utils.ExpandEnvironmentVariableBoolean(cfg.Provider.ValidateNonce, cfg.Provider.ValidateNonceBool)
	if err != nil {
		return nil, err
	}
	if cfg.Provider.TokenClockSkewSeconds < 0 {
		cfg.Provider.TokenClockSkewSeconds = 60
	}
	cfg.Provider.InsecureSkipVerifyBool, err = utils.ExpandEnvironmentVariableBoolean(cfg.Provider.InsecureSkipVerify, cfg.Provider.InsecureSkipVerifyBool)
	if err != nil {
		return nil, err
	}

	var clientAssertionPrivateKey *rsa.PrivateKey
	if cfg.Provider.ClientJwtPrivateKey != "" && cfg.Provider.ClientJwtPrivateKeyId != "" {
		clientAssertionPrivateKey, err = jwt.ParseRSAPrivateKeyFromPEM([]byte(cfg.Provider.ClientJwtPrivateKey))
		if err != nil {
			return nil, err
		}
	}

	cfg.Provider.CABundle = utils.ExpandEnvironmentVariableString(cfg.Provider.CABundle)
	cfg.Provider.CABundleFile = utils.ExpandEnvironmentVariableString(cfg.Provider.CABundleFile)
	cfg.Provider.TokenValidation = utils.ExpandEnvironmentVariableString(cfg.Provider.TokenValidation)
	cfg.Provider.RevokeTokensOnLogout = utils.ExpandEnvironmentVariableString(cfg.Provider.RevokeTokensOnLogout)
	cfg.Provider.RevokeTokensOnLogoutBool, err = utils.ExpandEnvironmentVariableBoolean(cfg.Provider.RevokeTokensOnLogout, cfg.Provider.RevokeTokensOnLogoutBool)
	if err != nil {
		return nil, err
	}
	for _, proxy := range cfg.TrustedProxies {
		proxy = utils.ExpandEnvironmentVariableString(proxy)
		if proxy == "" {
			continue
		}
		_, network, err := net.ParseCIDR(proxy)
		if err != nil {
			logger.Log(logging.LevelError, "Invalid trustedProxies entry %q: %s", proxy, err.Error())
			return nil, fmt.Errorf("invalid trustedProxies entry %q: %w", proxy, err)
		}
		cfg.TrustedProxyNets = append(cfg.TrustedProxyNets, network)
	}

	cfg.ErrorPages.Unauthenticated.FilePath = utils.ExpandEnvironmentVariableString(cfg.ErrorPages.Unauthenticated.FilePath)
	cfg.ErrorPages.Unauthenticated.RedirectTo = utils.ExpandEnvironmentVariableString(cfg.ErrorPages.Unauthenticated.RedirectTo)
	cfg.ErrorPages.Unauthorized.FilePath = utils.ExpandEnvironmentVariableString(cfg.ErrorPages.Unauthorized.FilePath)
	cfg.ErrorPages.Unauthorized.RedirectTo = utils.ExpandEnvironmentVariableString(cfg.ErrorPages.Unauthorized.RedirectTo)

	if cfg.Secret == config.DefaultSecret {
		logger.Log(logging.LevelError, "Refusing to start with the default Secret. Set Provider Secret to a random 32 character value.")
		return nil, errors.New("default secret is not allowed")
	}

	secret := []byte(cfg.Secret)
	if len(secret) != 32 {
		logger.Log(logging.LevelError, "Invalid secret provided. Secret must be exactly 32 characters in length. The provided secret has %d characters.", len(secret))
		return nil, errors.New("invalid secret")
	}

	if cfg.Provider.CABundle != "" && cfg.Provider.CABundleFile != "" {
		logger.Log(logging.LevelError, "You can only use an inline CABundle OR CABundleFile, not both.")
		return nil, errors.New("you can only use an inline CABundle OR CABundleFile, not both")
	}

	// Specify default scopes if not provided
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "email"}
	}

	parsedURL, err := utils.ParseUrl(cfg.Provider.Url)
	if err != nil {
		logger.Log(logging.LevelError, "Error while parsing Provider.Url: %s", err.Error())
		return nil, err
	}

	parsedCallbackURL, err := url.Parse(cfg.CallbackUri)
	if err != nil {
		logger.Log(logging.LevelError, "Error while parsing CallbackUri: %s", err.Error())
		return nil, err
	}

	logger.Log(logging.LevelDebug, "Provider URL: %v", parsedURL)
	logger.Log(logging.LevelDebug, "Callback URI: %v (absolute=%t)", parsedCallbackURL, utils.UrlIsAbsolute(parsedCallbackURL))
	logger.Log(logging.LevelDebug, "Scopes: %s", strings.Join(cfg.Scopes, ", "))
	logger.Log(logging.LevelDebug, "SessionCookie: %v", cfg.SessionCookie)

	if cfg.Provider.TokenRenewalThreshold < 0.5 || cfg.Provider.TokenRenewalThreshold > 1.0 {
		logger.Log(logging.LevelError, "Invalid TokenRenewalThreshold. The value must be >= 0.5 and <= 1.0.")
		return nil, errors.New("invalid TokenRenewalThreshold")
	}

	// Reject an unusable verification_token here instead of letting every single login callback
	// hit the default branch of the switch in handleCallback.
	switch cfg.Provider.TokenValidation {
	case "AccessToken", "IdToken", "Introspection":
	default:
		logger.Log(logging.LevelError, "Invalid provider.verification_token %q. Must be one of AccessToken, IdToken, Introspection.", cfg.Provider.TokenValidation)
		return nil, fmt.Errorf("invalid provider.verification_token %q", cfg.Provider.TokenValidation)
	}

	// sessionStorageType is accepted for compatibility with configurations copied from other
	// forks, but only the cookie store exists. Silently ignoring it would give an operator who
	// asked for shared state an intermittent 401 loop across replicas instead.
	switch cfg.SessionStorageType {
	case "", config.SessionStorageTypeCookie:
	default:
		logger.Log(logging.LevelError, "Invalid session_storage_type %q. Only %q is supported.", cfg.SessionStorageType, config.SessionStorageTypeCookie)
		return nil, fmt.Errorf("invalid session_storage_type %q", cfg.SessionStorageType)
	}

	for name, value := range map[string]int{
		"max_session_lifetime_seconds":  cfg.MaxSessionLifetimeSeconds,
		"session_idle_timeout_seconds":  cfg.SessionIdleTimeoutSeconds,
		"provider.max_auth_age_seconds": cfg.Provider.MaxAuthAgeSeconds,
	} {
		if value < 0 {
			logger.Log(logging.LevelError, "Invalid %s %d. Must be >= 0 (0 disables the bound).", name, value)
			return nil, fmt.Errorf("invalid %s", name)
		}
	}

	if cfg.Provider.OidcTimeoutSeconds < 0 {
		cfg.Provider.OidcTimeoutSeconds = 30
	}
	if cfg.Provider.OidcTimeoutSeconds == 0 {
		cfg.Provider.OidcTimeoutSeconds = 30
	}

	if cfg.MaxSessionLifetimeSeconds == 0 {
		logger.Log(logging.LevelWarn, "maxSessionLifetimeSeconds is not set: sessions are stateless, so a captured session cookie can be refreshed forever and cannot be revoked without changing the secret. Set maxSessionLifetimeSeconds to bound it.")
	}

	// An empty prefix would produce a cookie literally named ".Session", and a shared prefix
	// makes two middlewares on one domain overwrite each other's session cookie.
	if cfg.CookieNamePrefix == "" {
		sum := sha256.Sum256([]byte(cfg.Provider.ClientId))
		cfg.CookieNamePrefix = "Gatepost." + hex.EncodeToString(sum[:4])
		logger.Log(logging.LevelInfo, "cookieNamePrefix is empty, derived %q from the clientId so this instance gets its own session cookie.", cfg.CookieNamePrefix)
	}

	if _, err := parseCookieSameSiteChecked(cfg.SessionCookie.SameSite); err != nil {
		logger.Log(logging.LevelError, "Invalid sessionCookie.sameSite %q: %s", cfg.SessionCookie.SameSite, err.Error())
		return nil, err
	}

	for key := range cfg.AuthorizationParams {
		if reservedAuthorizationParams[key] {
			logger.Log(logging.LevelError, "authorizationParams contains the reserved key %q, which is always set by the plugin.", key)
			return nil, fmt.Errorf("reserved authorizationParams key %q", key)
		}
	}

	var conditionalAuth *rules.RequestCondition
	if cfg.BypassAuthenticationRule != "" {
		ca, err := rules.ParseRequestCondition(cfg.BypassAuthenticationRule)
		if err != nil {
			return nil, err
		}

		conditionalAuth = ca
	}

	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	var caBundleData []byte

	if cfg.Provider.CABundle != "" {
		if strings.HasPrefix(cfg.Provider.CABundle, "base64:") {
			caBundleData, err = base64.StdEncoding.DecodeString(strings.TrimPrefix(cfg.Provider.CABundle, "base64:"))
			if err != nil {
				logger.Log(logging.LevelInfo, "Failed to base64-decode the inline CA bundle")
				return nil, err
			}
		} else {
			caBundleData = []byte(cfg.Provider.CABundle)
		}

		logger.Log(logging.LevelDebug, "Loaded CA bundle provided inline")
	} else if cfg.Provider.CABundleFile != "" {
		caBundleData, err = os.ReadFile(cfg.Provider.CABundleFile)
		if err != nil {
			logger.Log(logging.LevelInfo, "Failed to load CA bundle from %v: %v", cfg.Provider.CABundleFile, err)
			return nil, err
		}

		logger.Log(logging.LevelDebug, "Loaded CA bundle from %v", cfg.Provider.CABundleFile)
	}

	if caBundleData != nil {
		// Append our cert to the system pool
		if ok := rootCAs.AppendCertsFromPEM(caBundleData); !ok {
			logger.Log(logging.LevelWarn, "Failed to append CA bundle. Using system certificates only.")
		}
	}

	for index := range cfg.Headers {
		header := &cfg.Headers[index]

		if header.Value != "" && header.Values != "" {
			logger.Log(logging.LevelError, "Invalid Header: you can only use one of Value or Values, not both")
			return nil, errors.New("invalid Header")
		}

		// Compile here rather than on the first request. Doing it lazily would mutate a shared
		// config element from every concurrent request that arrives before the cache is warm,
		// which is a data race on the *template.Template pointer and inside text/template.
		if header.Value != "" {
			tpl, err := newTemplate().Parse(header.Value)
			if err != nil {
				logger.Log(logging.LevelError, "Invalid template in header %q: %s", header.Name, err.Error())
				return nil, fmt.Errorf("invalid template in header %q: %w", header.Name, err)
			}

			header.Template = tpl
		} else if header.Values != "" {
			tpl, err := newTemplate().Parse(header.Values)
			if err != nil {
				logger.Log(logging.LevelError, "Invalid template in header %q: %s", header.Name, err.Error())
				return nil, fmt.Errorf("invalid template in header %q: %w", header.Name, err)
			}

			header.Template = tpl
		}
	}

	// Redirect URI wildcards relax the OIDC/OAuth2 exact-match requirement, so
	// operators must opt in once for the whole Traefik process.
	redirectUriWildcardsEnabled, err := utils.ExpandEnvironmentVariableBoolean(
		os.Getenv("TOA_ENABLE_REDIRECT_URI_WILDCARDS"),
		false,
	)
	if err != nil {
		logger.Log(logging.LevelError, "Invalid TOA_ENABLE_REDIRECT_URI_WILDCARDS value: %s", err.Error())
		return nil, err
	}

	if !redirectUriWildcardsEnabled {
		warnDisabledRedirectWildcards(logger, "validPostLoginRedirectUris", cfg.ValidPostLoginRedirectUris)
		warnDisabledRedirectWildcards(logger, "validPostLogoutRedirectUris", cfg.ValidPostLogoutRedirectUris)
	}

	httpTransport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.Provider.InsecureSkipVerifyBool,
			RootCAs:            rootCAs,
		},
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// Without a client-side timeout a hung IDP pins the request goroutine forever, and because
	// discovery and JWKS loads happen under a lock that one slow dependency can stall every
	// router behind this Traefik instance.
	httpClient := &http.Client{
		Transport: httpTransport,
		Timeout:   time.Duration(cfg.Provider.OidcTimeoutSeconds) * time.Second,
	}

	logger.Log(logging.LevelInfo, "ready provider=%s clientId=%s callback=%s cookiePrefix=%s",
		parsedURL.String(), cfg.Provider.ClientId, cfg.CallbackUri, cfg.CookieNamePrefix)

	return &Gatepost{
		logger:                      logger,
		next:                        next,
		httpClient:                  httpClient,
		ProviderURL:                 parsedURL,
		ClientJwtPrivateKey:         clientAssertionPrivateKey,
		CallbackURL:                 parsedCallbackURL,
		Config:                      cfg,
		SessionStorage:              session.CreateCookieSessionStorage(),
		BypassAuthenticationRule:    conditionalAuth,
		RedirectUriWildcardsEnabled: redirectUriWildcardsEnabled,
	}, nil
}

func warnDisabledRedirectWildcards(logger *logging.Logger, field string, uris []string) {
	for _, uri := range uris {
		if strings.Contains(uri, "*") {
			logger.Log(
				logging.LevelWarn,
				"%s contains %q, but TOA_ENABLE_REDIRECT_URI_WILDCARDS is disabled; it will only match that exact string",
				field,
				uri,
			)
		}
	}
}

// migrateAuthBehaviors maps legacy single UnauthorizedBehavior onto the split
// UnauthenticatedBehavior / UnauthorizedBehavior fields when the new field is unset.
// CreateConfig leaves both empty so Traefik overlays + this migrate run in New().
func migrateAuthBehaviors(cfg *config.Config) {
	if cfg.UnauthenticatedBehavior != "" {
		if cfg.UnauthorizedBehavior == "" {
			cfg.UnauthorizedBehavior = "Unauthorized"
		}
		return
	}
	cfg.UnauthenticatedBehavior = cfg.UnauthorizedBehavior
	if cfg.UnauthenticatedBehavior == "" {
		cfg.UnauthenticatedBehavior = "Auto"
	}
	if cfg.UnauthorizedBehavior != "Forward" {
		cfg.UnauthorizedBehavior = "Unauthorized"
	}
}
