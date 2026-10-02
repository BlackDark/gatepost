package src

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/BlackDark/test-oidc-traefik-plugin/src/config"
	"github.com/BlackDark/test-oidc-traefik-plugin/src/logging"
	"github.com/BlackDark/test-oidc-traefik-plugin/src/oidc"
)

const (
	validateTestIssuer   = "https://issuer.example.com"
	validateTestAudience = "test-audience"
	validateTestKid      = "test-kid"
	validateTestEcKid    = "test-ec-kid"
)

// validateFixture serves a JWKS over httptest and wires a TraefikOidcAuth whose
// Jwks handler points at it, so validateTokenLocally exercises the real key
// fetch, cache and reload path without any network access.
type validateFixture struct {
	toa    *TraefikOidcAuth
	rsaKey *rsa.PrivateKey
	ecKey  *ecdsa.PrivateKey

	// reloads counts the JWKS fetches actually performed. validateTokenLocally
	// is expected to reload at most once per validation attempt, so this is how
	// the "one reload" bound is asserted.
	mu       sync.Mutex
	reloads  int
	server   *httptest.Server
	jwksBody func() *oidc.JwksKeys
}

// newValidateFixture builds a fixture with a locally generated RSA key and a
// P-256 key, both published by the JWKS server. providerFn lets a test tweak the
// provider config (issuer/audience/nonce/skew) after the fixture is built but
// before the first validation.
func newValidateFixture(t *testing.T, providerFn func(*config.ProviderConfig)) *validateFixture {
	t.Helper()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating the RSA test key: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating the ECDSA test key: %v", err)
	}

	f := &validateFixture{rsaKey: rsaKey, ecKey: ecKey}
	f.jwksBody = func() *oidc.JwksKeys { return f.jwks() }

	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.reloads++
		f.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(f.jwksBody()); err != nil {
			t.Errorf("encoding the JWKS response: %v", err)
		}
	}))
	t.Cleanup(f.server.Close)

	provider := &config.ProviderConfig{
		ValidateIssuerBool:    true,
		ValidIssuer:           validateTestIssuer,
		ValidateAudienceBool:  true,
		ValidAudience:         validateTestAudience,
		TokenClockSkewSeconds: 0,
	}
	if providerFn != nil {
		providerFn(provider)
	}

	toa := &TraefikOidcAuth{
		logger:     logging.CreateLogger(logging.LevelDebug),
		Config:     &config.Config{Provider: provider, Scopes: []string{"openid"}},
		httpClient: f.server.Client(),
		DiscoveryDocument: &oidc.OidcDiscovery{
			UserinfoEndpoint: f.server.URL,
		},
		Jwks: &oidc.JwksHandler{Url: f.server.URL},
	}
	f.toa = toa

	return f
}

func (f *validateFixture) jwks() *oidc.JwksKeys {
	rsaPub := &f.rsaKey.PublicKey
	// JWK wants the two coordinates as fixed-width big-endian byte strings, which
	// is exactly what ecdsa encodes at the curve's field size.
	byteLen := (f.ecKey.Curve.Params().BitSize + 7) / 8
	ecX := f.ecKey.X.FillBytes(make([]byte, byteLen))
	ecY := f.ecKey.Y.FillBytes(make([]byte, byteLen))

	return &oidc.JwksKeys{
		Keys: []oidc.JwksKey{
			{
				Kid: validateTestKid,
				Kty: "RSA",
				Use: "sig",
				N:   base64.RawURLEncoding.EncodeToString(rsaPub.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaPub.E)).Bytes()),
			},
			{
				Kid: validateTestEcKid,
				Kty: "EC",
				Use: "sig",
				Crv: "P-256",
				X:   base64.RawURLEncoding.EncodeToString(ecX[:32]),
				Y:   base64.RawURLEncoding.EncodeToString(ecY[:32]),
			},
		},
	}
}

// reloadCount returns how many times the JWKS endpoint has been contacted.
func (f *validateFixture) reloadCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reloads
}

// signRSA builds an RS256 token signed with the fixture RSA key.
func (f *validateFixture) signRSA(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()

	return f.signRSAWithKid(t, claims, validateTestKid)
}

func (f *validateFixture) signRSAWithKid(t *testing.T, claims jwt.MapClaims, kid string) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if kid != "" {
		token.Header["kid"] = kid
	}

	signed, err := token.SignedString(f.rsaKey)
	if err != nil {
		t.Fatalf("signing an RS256 token: %v", err)
	}
	return signed
}

func (f *validateFixture) signEC(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = validateTestEcKid

	signed, err := token.SignedString(f.ecKey)
	if err != nil {
		t.Fatalf("signing an ES256 token: %v", err)
	}
	return signed
}

// baseClaims returns a claim set that is valid *now* for the fixture's issuer
// and audience. Expiry is always set explicitly relative to time.Now() so no
// test ever has to sleep to make a token expire.
func baseClaims() jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss":   validateTestIssuer,
		"aud":   validateTestAudience,
		"sub":   "user-123",
		"nonce": "expected-nonce",
		"iat":   now.Add(-time.Minute).Unix(),
		"nbf":   now.Add(-time.Minute).Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	}
}

// validate runs validateTokenLocally and requires it to accept the token.
func validateAccepted(t *testing.T, f *validateFixture, token, expectedNonce string) map[string]interface{} {
	t.Helper()

	valid, claims, err := f.toa.validateTokenLocally(token, expectedNonce)
	if err != nil {
		t.Fatalf("expected the token to be accepted, got error: %v", err)
	}
	if !valid {
		t.Fatal("expected valid to be true, got false")
	}
	if claims == nil {
		t.Fatal("expected claims to be returned, got nil")
	}
	return claims
}

// validateRejected runs validateTokenLocally and requires it to refuse the
// token, asserting that it never reports a partially trusted success.
func validateRejected(t *testing.T, f *validateFixture, token, expectedNonce, wantErrSubstring string) error {
	t.Helper()

	valid, claims, err := f.toa.validateTokenLocally(token, expectedNonce)
	if err == nil {
		t.Fatalf("expected the token to be rejected, but validation succeeded with claims %v", claims)
	}
	if valid {
		t.Error("expected valid to be false on rejection")
	}
	if claims != nil {
		t.Errorf("expected no claims on rejection, got %v", claims)
	}
	if wantErrSubstring != "" && !strings.Contains(err.Error(), wantErrSubstring) {
		t.Errorf("error = %q, want it to contain %q", err.Error(), wantErrSubstring)
	}
	return err
}

func TestValidateTokenLocally_AcceptsValidToken(t *testing.T) {
	f := newValidateFixture(t, nil)

	claims := validateAccepted(t, f, f.signRSA(t, baseClaims()), "expected-nonce")

	if claims["sub"] != "user-123" {
		t.Errorf("expected sub to be \"user-123\", got %v", claims["sub"])
	}
	if claims["iss"] != validateTestIssuer {
		t.Errorf("expected iss to be %q, got %v", validateTestIssuer, claims["iss"])
	}
	if claims["aud"] != validateTestAudience {
		t.Errorf("expected aud to be %q, got %v", validateTestAudience, claims["aud"])
	}
	if claims["nonce"] != "expected-nonce" {
		t.Errorf("expected nonce to be \"expected-nonce\", got %v", claims["nonce"])
	}
	if _, ok := claims["exp"]; !ok {
		t.Error("expected the exp claim to be present in the returned claims")
	}
}

// TestValidateTokenLocally_AcceptsEcdsaToken covers the ECDSA path, which uses
// a different key lookup (getEcdsaKey) than RSA.
func TestValidateTokenLocally_AcceptsEcdsaToken(t *testing.T) {
	f := newValidateFixture(t, nil)

	claims := validateAccepted(t, f, f.signEC(t, baseClaims()), "expected-nonce")

	if claims["sub"] != "user-123" {
		t.Errorf("expected sub to be \"user-123\", got %v", claims["sub"])
	}
}

// TestValidateTokenLocally_RejectsExpiredToken covers WithExpirationRequired
// plus the expiry check. The token is generated with an expiry already in the
// past, so the test never sleeps.
func TestValidateTokenLocally_RejectsExpiredToken(t *testing.T) {
	tests := []struct {
		name      string
		expOffset time.Duration
		skew      int
		wantValid bool
	}{
		{name: "expired one second ago", expOffset: -time.Second, skew: 0, wantValid: false},
		{name: "expired one hour ago", expOffset: -time.Hour, skew: 0, wantValid: false},
		{name: "expired one year ago", expOffset: -365 * 24 * time.Hour, skew: 0, wantValid: false},
		{name: "expired within the allowed skew", expOffset: -30 * time.Second, skew: 60, wantValid: true},
		{name: "expired beyond the allowed skew", expOffset: -30 * time.Second, skew: 10, wantValid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newValidateFixture(t, func(p *config.ProviderConfig) {
				p.TokenClockSkewSeconds = tt.skew
			})

			claims := baseClaims()
			// Second-granularity exp with an explicit offset: deterministic
			// without any sleeping.
			claims["exp"] = time.Now().Add(tt.expOffset).Truncate(time.Second).Unix()

			token := f.signRSA(t, claims)
			valid, _, err := f.toa.validateTokenLocally(token, "")

			if tt.wantValid {
				if err != nil {
					t.Fatalf("expected the token to be accepted, got error: %v", err)
				}
				if !valid {
					t.Error("expected valid to be true")
				}
				return
			}

			if err == nil {
				t.Fatal("expected the token to be rejected as expired, but it was accepted")
			}
			if !strings.Contains(err.Error(), jwt.ErrTokenExpired.Error()) {
				t.Errorf("error = %q, want it to mention the token expiry", err.Error())
			}
			if valid {
				t.Error("expected valid to be false")
			}
		})
	}
}

// TestValidateTokenLocally_RequiresExpClaim covers WithExpirationRequired: a
// token with no exp at all must be refused, not treated as never-expiring.
func TestValidateTokenLocally_RequiresExpClaim(t *testing.T) {
	f := newValidateFixture(t, nil)

	claims := baseClaims()
	delete(claims, "exp")

	validateRejected(t, f, f.signRSA(t, claims), "", jwt.ErrTokenRequiredClaimMissing.Error())
}

// TestValidateTokenLocally_RejectsExpiredTokenWithoutExtraReload asserts the
// expiry path short-circuits the JWKS retry: an expired token must not trigger
// the extra reload that an unknown kid does. Reloading on expiry is pure waste
// and, on a hot path, an amplifier against the IdP.
func TestValidateTokenLocally_RejectsExpiredTokenWithoutExtraReload(t *testing.T) {
	f := newValidateFixture(t, nil)

	claims := baseClaims()
	claims["exp"] = time.Now().Add(-time.Hour).Truncate(time.Second).Unix()

	validateRejected(t, f, f.signRSA(t, claims), "", "")

	if got := f.reloadCount(); got != 1 {
		t.Errorf("expected exactly 1 JWKS fetch for an expired token, got %d", got)
	}
}

func TestValidateTokenLocally_RejectsWrongIssuer(t *testing.T) {
	tests := []struct {
		name       string
		claimIss   string
		validateIs bool
		wantValid  bool
	}{
		{name: "different issuer with validation on", claimIss: "https://evil.example.com", validateIs: true, wantValid: false},
		{name: "different issuer with validation off", claimIss: "https://evil.example.com", validateIs: false, wantValid: true},
		{name: "empty issuer with validation on", claimIss: "", validateIs: true, wantValid: false},
		{name: "matching issuer with validation on", claimIss: validateTestIssuer, validateIs: true, wantValid: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newValidateFixture(t, func(p *config.ProviderConfig) {
				p.ValidateIssuerBool = tt.validateIs
			})

			claims := baseClaims()
			if tt.claimIss == "" {
				delete(claims, "iss")
			} else {
				claims["iss"] = tt.claimIss
			}

			token := f.signRSA(t, claims)
			valid, _, err := f.toa.validateTokenLocally(token, "")

			if tt.wantValid {
				if err != nil {
					t.Fatalf("expected the token to be accepted, got error: %v", err)
				}
				if !valid {
					t.Error("expected valid to be true")
				}
				return
			}

			if err == nil {
				t.Fatal("expected the token to be rejected for an issuer mismatch, but it was accepted")
			}
			// A mismatched iss reports ErrTokenInvalidIssuer; an absent one
			// reports the missing-required-claim error. Both must reject.
			if !strings.Contains(err.Error(), jwt.ErrTokenInvalidIssuer.Error()) &&
				!strings.Contains(err.Error(), jwt.ErrTokenRequiredClaimMissing.Error()) {
				t.Errorf("error = %q, want it to mention the issuer", err.Error())
			}
		})
	}
}

func TestValidateTokenLocally_RejectsWrongAudience(t *testing.T) {
	tests := []struct {
		name       string
		claimAud   string
		validateAu bool
		wantValid  bool
	}{
		{name: "different audience with validation on", claimAud: "other-audience", validateAu: true, wantValid: false},
		{name: "different audience with validation off", claimAud: "other-audience", validateAu: false, wantValid: true},
		{name: "empty audience with validation on", claimAud: "", validateAu: true, wantValid: false},
		{name: "matching audience with validation on", claimAud: validateTestAudience, validateAu: true, wantValid: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newValidateFixture(t, func(p *config.ProviderConfig) {
				p.ValidateAudienceBool = tt.validateAu
			})

			claims := baseClaims()
			if tt.claimAud == "" {
				delete(claims, "aud")
			} else {
				claims["aud"] = tt.claimAud
			}

			token := f.signRSA(t, claims)
			valid, _, err := f.toa.validateTokenLocally(token, "")

			if tt.wantValid {
				if err != nil {
					t.Fatalf("expected the token to be accepted, got error: %v", err)
				}
				if !valid {
					t.Error("expected valid to be true")
				}
				return
			}

			if err == nil {
				t.Fatal("expected the token to be rejected for an audience mismatch, but it was accepted")
			}
			// A mismatched aud reports ErrTokenInvalidAudience; an absent one
			// reports the missing-required-claim error. Both must reject.
			if !strings.Contains(err.Error(), jwt.ErrTokenInvalidAudience.Error()) &&
				!strings.Contains(err.Error(), jwt.ErrTokenRequiredClaimMissing.Error()) {
				t.Errorf("error = %q, want it to mention the audience", err.Error())
			}
		})
	}
}

// TestValidateTokenLocally_RejectsForgedAlgorithm covers the alg-confusion
// attacks the parser options are meant to block: "none" with no signature at
// all, and an HS256 token whose kid points at a real RSA key so the key lookup
// would otherwise find something.
func TestValidateTokenLocally_RejectsForgedAlgorithm(t *testing.T) {
	t.Run("alg none", func(t *testing.T) {
		f := newValidateFixture(t, nil)

		token := jwt.NewWithClaims(jwt.SigningMethodNone, baseClaims())
		token.Header["kid"] = validateTestKid
		signed, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
		if err != nil {
			t.Fatalf("building an alg=none token: %v", err)
		}

		validateRejected(t, f, signed, "", "")
	})

	t.Run("alg HS256 with a real RSA kid", func(t *testing.T) {
		f := newValidateFixture(t, nil)

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, baseClaims())
		token.Header["kid"] = validateTestKid
		// The classic attack: sign with the RSA *public* key material as an
		// HMAC secret so a naive verifier accepts it.
		signed, err := token.SignedString(publicKeyAsHMACSecret(&f.rsaKey.PublicKey))
		if err != nil {
			t.Fatalf("building an HS256 token: %v", err)
		}

		validateRejected(t, f, signed, "", "")
	})

	t.Run("alg HS384 with a real RSA kid", func(t *testing.T) {
		f := newValidateFixture(t, nil)

		token := jwt.NewWithClaims(jwt.SigningMethodHS384, baseClaims())
		token.Header["kid"] = validateTestKid
		signed, err := token.SignedString(publicKeyAsHMACSecret(&f.rsaKey.PublicKey))
		if err != nil {
			t.Fatalf("building an HS384 token: %v", err)
		}

		validateRejected(t, f, signed, "", "")
	})

	t.Run("alg HS256 with an ECDSA kid", func(t *testing.T) {
		f := newValidateFixture(t, nil)

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, baseClaims())
		token.Header["kid"] = validateTestEcKid
		signed, err := token.SignedString([]byte("secret"))
		if err != nil {
			t.Fatalf("building an HS256 token: %v", err)
		}

		validateRejected(t, f, signed, "", "")
	})
}

func TestValidateTokenLocally_RejectsAlgNoneWithoutKid(t *testing.T) {
	f := newValidateFixture(t, nil)

	token := jwt.NewWithClaims(jwt.SigningMethodNone, baseClaims())
	signed, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("building an alg=none token: %v", err)
	}

	validateRejected(t, f, signed, "", "")
}

// publicKeyAsHMACSecret derives the bytes of an RSA public key, which is the
// canonical alg-confusion attack payload.
func publicKeyAsHMACSecret(pub *rsa.PublicKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		// A deterministic fallback still exercises the rejection path.
		return []byte("fallback")
	}
	return der
}

// TestValidateTokenLocally_RejectsSignatureFromWrongKey covers a token whose
// kid is real but whose signature was made by a different RSA key.
func TestValidateTokenLocally_RejectsSignatureFromWrongKey(t *testing.T) {
	f := newValidateFixture(t, nil)

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating the second RSA key: %v", err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, baseClaims())
	token.Header["kid"] = validateTestKid
	signed, err := token.SignedString(otherKey)
	if err != nil {
		t.Fatalf("signing with the wrong key: %v", err)
	}

	validateRejected(t, f, signed, "", "")
}

// TestValidateTokenLocally_UnknownKidReloadsAtMostOnce covers the key-rotation
// retry bound: an unknown kid may cause at most one extra JWKS fetch, never an
// unbounded retry loop, and the token is still rejected. More than one reload
// would let a caller who controls the kid amplify requests at the IdP.
//
// Note the forced reload is itself throttled: JwksHandler.needsReload only
// honours forceReload once the cache is older than five minutes, so on a freshly
// loaded handler the unknown-kid path makes zero extra fetches. Both outcomes
// are correct; the assertion is the upper bound.
func TestValidateTokenLocally_UnknownKidReloadsAtMostOnce(t *testing.T) {
	tests := []struct {
		name    string
		kid     string
		wantErr string
	}{
		{name: "kid stays unknown", kid: "kid-that-does-not-exist", wantErr: "unknown kid"},
		{name: "no kid at all", kid: "", wantErr: "missing or invalid kid"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newValidateFixture(t, nil)

			token := f.signRSAWithKid(t, baseClaims(), tt.kid)

			validateRejected(t, f, token, "", tt.wantErr)

			// One initial fetch plus at most one forced reload.
			if got := f.reloadCount(); got < 1 || got > 2 {
				t.Errorf("expected 1 or 2 JWKS fetches (initial plus at most one reload), got %d", got)
			}
		})
	}
}

// TestValidateTokenLocally_UnknownKidRecoversAfterReload covers the rotation
// case the retry exists for: the kid is genuinely unknown on the first attempt
// and the JWKS is refreshed, so the second attempt succeeds. The handler's
// cache date is backdated past the five-minute force-reload throttle so the
// reload really happens rather than being deferred.
func TestValidateTokenLocally_UnknownKidRecoversAfterReload(t *testing.T) {
	f := newValidateFixture(t, nil)

	// Publish only the ECDSA key on the first fetch, both keys afterwards, so
	// the RSA kid only becomes findable after a reload.
	var mu sync.Mutex
	served := 0
	f.jwksBody = func() *oidc.JwksKeys {
		mu.Lock()
		defer mu.Unlock()
		served++
		if served == 1 {
			full := f.jwks()
			return &oidc.JwksKeys{Keys: full.Keys[1:]}
		}
		return f.jwks()
	}

	// Prime the cache, then backdate it past the force-reload throttle so the
	// next EnsureLoadedContext with forceReload=true actually re-fetches.
	validateRejected(t, f, f.signRSA(t, baseClaims()), "", "unknown kid")
	f.toa.Jwks.Lock.Lock()
	f.toa.Jwks.CacheDate = time.Now().Add(-10 * time.Minute)
	f.toa.Jwks.Lock.Unlock()

	claims := validateAccepted(t, f, f.signRSA(t, baseClaims()), "expected-nonce")
	if claims["sub"] != "user-123" {
		t.Errorf("expected sub to be \"user-123\", got %v", claims["sub"])
	}

	if got := f.reloadCount(); got < 2 {
		t.Errorf("expected at least 2 JWKS fetches (initial plus one reload), got %d", got)
	}
}

// TestValidateTokenLocally_ReusesCachedJwks pins that a known kid does not
// trigger the reload path at all: the second validation must be served from the
// cache, so steady-state traffic never re-contacts the IdP.
func TestValidateTokenLocally_ReusesCachedJwks(t *testing.T) {
	f := newValidateFixture(t, nil)

	token := f.signRSA(t, baseClaims())

	validateAccepted(t, f, token, "expected-nonce")
	if got := f.reloadCount(); got != 1 {
		t.Fatalf("expected 1 JWKS fetch after the first validation, got %d", got)
	}

	for i := 0; i < 5; i++ {
		validateAccepted(t, f, token, "expected-nonce")
	}

	if got := f.reloadCount(); got != 1 {
		t.Errorf("expected the cached JWKS to be reused, but the endpoint was fetched %d times", got)
	}
}

func TestValidateTokenLocally_NonceValidation(t *testing.T) {
	tests := []struct {
		name           string
		claimNonce     string
		dropNonceClaim bool
		expectedNonce  string
		validateNonce  bool
		wantValid      bool
	}{
		{name: "matching nonce with validation on", claimNonce: "expected-nonce", expectedNonce: "expected-nonce", validateNonce: true, wantValid: true},
		{name: "mismatched nonce with validation on", claimNonce: "other-nonce", expectedNonce: "expected-nonce", validateNonce: true, wantValid: false},
		{name: "missing nonce claim with validation on", dropNonceClaim: true, expectedNonce: "expected-nonce", validateNonce: true, wantValid: false},
		{name: "empty claim nonce with validation on", claimNonce: "", expectedNonce: "expected-nonce", validateNonce: true, wantValid: false},
		{name: "mismatched nonce with validation off", claimNonce: "other-nonce", expectedNonce: "expected-nonce", validateNonce: false, wantValid: true},
		{name: "missing nonce claim with validation off", dropNonceClaim: true, expectedNonce: "expected-nonce", validateNonce: false, wantValid: true},
		{name: "no expected nonce skips the check", claimNonce: "other-nonce", expectedNonce: "", validateNonce: true, wantValid: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newValidateFixture(t, func(p *config.ProviderConfig) {
				p.ValidateNonceBool = tt.validateNonce
			})

			claims := baseClaims()
			if tt.dropNonceClaim {
				delete(claims, "nonce")
			} else {
				claims["nonce"] = tt.claimNonce
			}

			token := f.signRSA(t, claims)
			valid, _, err := f.toa.validateTokenLocally(token, tt.expectedNonce)

			if tt.wantValid {
				if err != nil {
					t.Fatalf("expected the token to be accepted, got error: %v", err)
				}
				if !valid {
					t.Error("expected valid to be true")
				}
				return
			}

			if err == nil {
				t.Fatal("expected the token to be rejected for a nonce problem, but it was accepted")
			}
			if !strings.Contains(err.Error(), "oidc nonce mismatch") {
				t.Errorf("error = %q, want it to mention the nonce mismatch", err.Error())
			}
			if valid {
				t.Error("expected valid to be false")
			}
		})
	}
}

// TestValidateTokenLocally_ClockSkew covers provider.tokenClockSkewSeconds at
// its boundary. Expiries are set explicitly relative to now, so the test is
// deterministic and sleeps for nothing.
func TestValidateTokenLocally_ClockSkew(t *testing.T) {
	tests := []struct {
		name      string
		skew      int
		expOffset time.Duration
		nbfOffset time.Duration
		wantValid bool
	}{
		{name: "expired 5s ago, no skew", skew: 0, expOffset: -5 * time.Second, wantValid: false},
		// Offsets stay well clear of the exact boundary: exp is truncated to
		// whole seconds, so a case sitting exactly on the skew edge would flip
		// depending on the sub-second clock reading.
		{name: "expired 3s ago, 30s skew", skew: 30, expOffset: -3 * time.Second, wantValid: true},
		{name: "expired 45s ago, 30s skew", skew: 30, expOffset: -45 * time.Second, wantValid: false},
		{name: "expired 5s ago, 30s skew", skew: 30, expOffset: -5 * time.Second, wantValid: true},
		{name: "expired 60s ago, 30s skew", skew: 30, expOffset: -60 * time.Second, wantValid: false},
		{name: "expired 120s ago, 60s skew", skew: 60, expOffset: -120 * time.Second, wantValid: false},
		{name: "expired 120s ago, 300s skew", skew: 300, expOffset: -120 * time.Second, wantValid: true},
		{name: "not yet valid within skew", skew: 30, nbfOffset: 20 * time.Second, wantValid: true},
		{name: "not yet valid beyond skew", skew: 5, nbfOffset: 60 * time.Second, wantValid: false},
		{name: "far future expiry", skew: 0, expOffset: 365 * 24 * time.Hour, wantValid: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newValidateFixture(t, func(p *config.ProviderConfig) {
				p.TokenClockSkewSeconds = tt.skew
			})

			// Drop the base nbf unless the case overrides it, so a default case
			// is not accidentally gated by a future nbf.
			claims := baseClaims()
			delete(claims, "nbf")
			if tt.nbfOffset != 0 {
				claims["nbf"] = time.Now().Add(tt.nbfOffset).Truncate(time.Second).Unix()
			}
			claims["exp"] = time.Now().Add(tt.expOffset).Truncate(time.Second).Unix()

			token := f.signRSA(t, claims)
			valid, _, err := f.toa.validateTokenLocally(token, "")

			if tt.wantValid {
				if err != nil {
					t.Fatalf("expected the token to be accepted, got error: %v", err)
				}
				if !valid {
					t.Error("expected valid to be true")
				}
				return
			}

			if err == nil {
				t.Fatal("expected the token to be rejected, but it was accepted")
			}
			if valid {
				t.Error("expected valid to be false")
			}
		})
	}
}

// TestValidateTokenLocally_MalformedTokens covers inputs that never reach the
// signature check. Each must return an error, never a panic.
func TestValidateTokenLocally_MalformedTokens(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{name: "empty string", token: ""},
		{name: "not a jwt", token: "this is not a jwt"},
		{name: "only two segments", token: "aaa.bbb"},
		{name: "only one segment", token: "aaa"},
		{name: "four segments", token: "aaa.bbb.ccc.ddd"},
		{name: "bad base64 header", token: "!!!.bbb.ccc"},
		{name: "bad base64 payload", token: "aaa.!!!.ccc"},
		{name: "trailing dot", token: "aaa.bbb."},
		{name: "dot only", token: "."},
		{name: "whitespace", token: "   "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newValidateFixture(t, nil)

			if _, _, err := f.toa.validateTokenLocally(tt.token, ""); err == nil {
				t.Fatalf("expected %q to be rejected, but validation succeeded", tt.token)
			}
		})
	}
}

// TestValidateTokenLocally_TamperedPayload covers a token whose payload was
// edited after signing: the signature must no longer verify.
func TestValidateTokenLocally_TamperedPayload(t *testing.T) {
	f := newValidateFixture(t, nil)

	token := f.signRSA(t, baseClaims())
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT segments, got %d", len(parts))
	}

	// Re-encode a payload claiming a different subject.
	tamperedPayload, err := json.Marshal(jwt.MapClaims{
		"iss":   validateTestIssuer,
		"aud":   validateTestAudience,
		"sub":   "admin",
		"nonce": "expected-nonce",
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("encoding the tampered payload: %v", err)
	}
	parts[1] = base64.RawURLEncoding.EncodeToString(tamperedPayload)

	validateRejected(t, f, strings.Join(parts, "."), "", "")
}

// TestValidateTokenLocally_JwksEndpointFailure asserts a broken JWKS endpoint is
// an error rather than a silent pass, and that no claims are returned.
func TestValidateTokenLocally_JwksEndpointFailure(t *testing.T) {
	f := newValidateFixture(t, nil)
	f.server.Close() // the fixture cleanup closes it again, which is a no-op

	valid, claims, err := f.toa.validateTokenLocally(f.signRSA(t, baseClaims()), "")
	if err == nil {
		t.Fatal("expected an error when the JWKS endpoint is unreachable")
	}
	if valid {
		t.Error("expected valid to be false")
	}
	if claims != nil {
		t.Errorf("expected no claims, got %v", claims)
	}
}

// TestValidateTokenLocally_IgnoresJunkJwksResponse asserts an unparseable JWKS
// body is rejected instead of leaving the cache in a state where later lookups
// succeed with no keys.
func TestValidateTokenLocally_IgnoresJunkJwksResponse(t *testing.T) {
	f := newValidateFixture(t, nil)
	f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, "{not json")
	})

	if _, _, err := f.toa.validateTokenLocally(f.signRSA(t, baseClaims()), ""); err == nil {
		t.Fatal("expected an error for an unparseable JWKS response")
	}
}

// TestValidateTokenLocally_Concurrent is a race-detector exercise: many
// goroutines validate at once against a shared JwksHandler. The handler must
// stay race-free and every validation must reach the same verdict.
func TestValidateTokenLocally_Concurrent(t *testing.T) {
	f := newValidateFixture(t, nil)

	validToken := f.signRSA(t, baseClaims())
	unknownKidToken := f.signRSAWithKid(t, baseClaims(), "unknown-kid")

	const goroutines = 16
	var wg sync.WaitGroup
	errs := make(chan error, goroutines*2)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			if valid, _, err := f.toa.validateTokenLocally(validToken, "expected-nonce"); err != nil || !valid {
				errs <- fmt.Errorf("valid token rejected: valid=%v err=%w", valid, err)
			}
			if valid, _, err := f.toa.validateTokenLocally(unknownKidToken, ""); err == nil || valid {
				errs <- fmt.Errorf("unknown kid token accepted: valid=%v err=%w", valid, err)
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}
