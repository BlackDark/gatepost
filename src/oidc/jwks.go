package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/BlackDark/test-oidc-traefik-plugin/src/logging"
	"github.com/BlackDark/test-oidc-traefik-plugin/src/utils"
)

// reloadFailureBackoff is how long we wait before retrying a failed reload
// when we still have usable cached keys. Without it, a failing IdP would be
// re-contacted on every single request (a hot retry storm).
const reloadFailureBackoff = time.Minute

type JwksHandler struct {
	Url       string
	RsaKeys   []*RsaKey
	EcdsaKeys []*EcdsaKey
	CacheDate time.Time

	Lock sync.RWMutex

	// reloadLock serializes reloads (check-then-reload-then-recheck) without
	// holding Lock across the network call, so that concurrent misses cannot
	// stampede the IdP while readers keep being served from the cache.
	reloadLock      sync.Mutex
	lastReloadError time.Time
}

type JwksKey struct {
	Crv string `json:"crv,omitempty"`
	E   string `json:"e,omitempty"`
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n,omitempty"`
	Use string `json:"use,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

type JwksKeys struct {
	Keys []JwksKey `json:"keys"`
}

type RsaKey struct {
	kid string
	key *rsa.PublicKey
}

type EcdsaKey struct {
	kid string
	key *ecdsa.PublicKey
}

func (h *JwksHandler) EnsureLoaded(logger *logging.Logger, httpClient *http.Client, forceReload bool) error {
	return h.EnsureLoadedContext(context.Background(), logger, httpClient, forceReload)
}

func (h *JwksHandler) EnsureLoadedContext(ctx context.Context, logger *logging.Logger, httpClient *http.Client, forceReload bool) error {
	if logger == nil {
		logger = logging.CreateLogger(logging.LevelInfo)
	}

	// Fast path: nothing to do, under the read lock only.
	h.Lock.RLock()
	needed := h.needsReload(time.Now(), forceReload)
	h.Lock.RUnlock()

	if !needed {
		return nil
	}

	// Serialize the actual reload so concurrent cache misses trigger a single
	// request to the IdP instead of one per in-flight request.
	h.reloadLock.Lock()
	defer h.reloadLock.Unlock()

	// Recheck: another goroutine may have reloaded while we waited.
	h.Lock.RLock()
	needed = h.needsReload(time.Now(), forceReload)
	hasKeys := h.hasKeys()
	h.Lock.RUnlock()

	if !needed {
		return nil
	}

	logger.Log(logging.LevelInfo, "Reloading JWKS...")

	err := h.loadKeysContext(ctx, httpClient)
	if err != nil {
		if hasKeys {
			// Fail open on the cache, not on the request: a slow or broken IdP
			// must not wedge authentication for keys we already have.
			logger.Log(logging.LevelWarn, "Error reloading JWKS, keeping cached keys: %v", err)

			h.Lock.Lock()
			h.lastReloadError = time.Now()
			h.Lock.Unlock()

			return nil
		}

		logger.Log(logging.LevelError, "Error loading JWKS: %v", err)
		return err
	}

	logger.Log(logging.LevelInfo, "...JWKS reloaded :)")

	return nil
}

// needsReload must be called while holding Lock (read or write).
func (h *JwksHandler) needsReload(now time.Time, forceReload bool) bool {
	maxCacheTimeout := now.Add(-6 * time.Hour)
	minCacheTimeout := now.Add(-5 * time.Minute)

	reload := !h.hasKeys()

	if h.CacheDate.Compare(maxCacheTimeout) == -1 {
		reload = true
	}

	if forceReload && h.CacheDate.Compare(minCacheTimeout) == -1 {
		reload = true
	}

	// Back off after a failed reload instead of hammering a broken IdP.
	if reload && !h.lastReloadError.IsZero() && now.Sub(h.lastReloadError) < reloadFailureBackoff && h.hasKeys() {
		return false
	}

	return reload
}

// hasKeys must be called while holding Lock (read or write).
func (h *JwksHandler) hasKeys() bool {
	return len(h.RsaKeys) > 0 || len(h.EcdsaKeys) > 0
}

func (h *JwksHandler) loadKeys(httpClient *http.Client) error {
	return h.loadKeysContext(context.Background(), httpClient)
}

func (h *JwksHandler) loadKeysContext(ctx context.Context, httpClient *http.Client) error {
	if ctx == nil {
		ctx = context.Background()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.Url, nil)
	if err != nil {
		return err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	// Bound the body we are willing to read: the JWKS endpoint is not a
	// trusted-size resource and we only need a small excerpt for error output.
	limited := io.LimitReader(resp.Body, maxJwksBodySize+1)

	body, err := io.ReadAll(limited)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS request to %s returned status %d: %s", h.Url, resp.StatusCode, excerptForError(body))
	}

	loaded := JwksKeys{}
	if err := json.Unmarshal(body, &loaded); err != nil {
		return err
	}

	rsaKeys, ecdsaKeys, err := extractKeys(&loaded)
	if err != nil {
		return err
	}

	h.Lock.Lock()
	h.RsaKeys = rsaKeys
	h.EcdsaKeys = ecdsaKeys
	h.CacheDate = time.Now()
	h.lastReloadError = time.Time{}
	h.Lock.Unlock()

	return nil
}

const maxJwksBodySize = 4 << 20

// maxErrorExcerpt bounds how much of a non-200 body we echo back in errors, so
// a hostile or misconfigured endpoint cannot flood the logs.
const maxErrorExcerpt = 512

func excerptForError(body []byte) string {
	if len(body) > maxErrorExcerpt {
		return string(body[:maxErrorExcerpt]) + "...(truncated)"
	}

	return string(body)
}

// allowedAlgorithms is an explicit allowlist used as defence-in-depth: without
// it any future/unknown method name that happens to match a prefix would be
// accepted, including "none".
//
// Note: the previous prefix based matching (HasPrefix "RS"/"EC"/"ES") silently
// rejected PS256/PS384/PS512, which broke RSA-PSS based IdPs. The allowlist
// fixes that as a side effect.
var allowedAlgorithms = map[string]struct{}{
	"RS256": {}, "RS384": {}, "RS512": {},
	"PS256": {}, "PS384": {}, "PS512": {},
	"ES256": {}, "ES384": {}, "ES512": {},
}

func isAlgorithmAllowed(alg string) bool {
	_, ok := allowedAlgorithms[strings.ToUpper(alg)]
	return ok
}

func (h *JwksHandler) Keyfunc(token *jwt.Token) (any, error) {
	if token == nil || token.Method == nil {
		return nil, errors.New("token has no signing method")
	}

	if !isAlgorithmAllowed(token.Method.Alg()) {
		return nil, fmt.Errorf("unsupported algorithm %s", token.Method.Alg())
	}

	alg := strings.ToUpper(token.Method.Alg())

	if alg == "RS256" || alg == "RS384" || alg == "RS512" ||
		alg == "PS256" || alg == "PS384" || alg == "PS512" {
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, errors.New("missing or invalid kid in token header")
		}

		k, err := h.getRsaKey(kid)
		if err != nil {
			return nil, err
		}

		return k, nil
	}

	if alg == "ES256" || alg == "ES384" || alg == "ES512" {
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, errors.New("missing or invalid kid in token header")
		}

		k, err := h.getEcdsaKey(kid)
		if err != nil {
			return nil, err
		}

		return k, nil
	}

	return nil, fmt.Errorf("unsupported algorithm %s", token.Method.Alg())
}

func (h *JwksHandler) getRsaKey(kid string) (*rsa.PublicKey, error) {
	// Snapshot under the read lock: a concurrent reload replaces the slices,
	// and iterating them without the lock would race and could observe a torn
	// slice.
	h.Lock.RLock()
	keys := h.RsaKeys
	h.Lock.RUnlock()

	for i := 0; i < len(keys); i++ {
		if keys[i] != nil && kid == keys[i].kid {
			return keys[i].key, nil
		}
	}

	return nil, errors.New("unknown kid " + kid)
}

func (h *JwksHandler) getEcdsaKey(kid string) (*ecdsa.PublicKey, error) {
	h.Lock.RLock()
	keys := h.EcdsaKeys
	h.Lock.RUnlock()

	for i := 0; i < len(keys); i++ {
		if keys[i] != nil && kid == keys[i].kid {
			return keys[i].key, nil
		}
	}

	return nil, errors.New("unknown kid " + kid)
}

func extractKeys(keys *JwksKeys) ([]*RsaKey, []*EcdsaKey, error) {
	var rsaKeys []*RsaKey
	var ecdsaKeys []*EcdsaKey

	for i := 0; i < len(keys.Keys); i++ {
		k := keys.Keys[i]

		if k.Use == "sig" || k.Use == "" {
			switch k.Kty {
			case "RSA":
				extracted, err := extractRsaKey(&k)

				if err == nil {
					rsaKeys = append(rsaKeys, extracted)
				}
			case "EC":
				extracted, err := extractEcdsaKey(&k)

				if err == nil {
					ecdsaKeys = append(ecdsaKeys, extracted)
				}
			}
		}
	}

	if len(ecdsaKeys) == 0 && len(rsaKeys) == 0 {
		return nil, nil, errors.New("no public Keys found")
	}

	return rsaKeys, ecdsaKeys, nil
}

func extractRsaKey(key *JwksKey) (*RsaKey, error) {
	decodedN, err := utils.ParseBigInt(key.N)
	if err != nil {
		return nil, err
	}

	decodedE, err := utils.ParseInt(key.E)
	if err != nil {
		return nil, err
	}

	return &RsaKey{
		kid: key.Kid,
		key: &rsa.PublicKey{
			N: decodedN,
			E: decodedE,
		},
	}, nil
}

func extractEcdsaKey(key *JwksKey) (*EcdsaKey, error) {
	decodedX, err := utils.ParseBigInt(key.X)
	if err != nil {
		return nil, err
	}

	decodedY, err := utils.ParseBigInt(key.Y)
	if err != nil {
		return nil, err
	}

	curve := getEllipticCurve(key.Crv)
	// crypto/ecdsa panics on a nil Curve during verification, so an
	// unsupported/missing crv must never make it into the cache.
	if curve == nil {
		return nil, fmt.Errorf("unsupported or empty elliptic curve %q for key %q", key.Crv, key.Kid)
	}

	return &EcdsaKey{
		kid: key.Kid,
		key: &ecdsa.PublicKey{
			Curve: curve,
			X:     decodedX,
			Y:     decodedY,
		},
	}, nil
}

func getEllipticCurve(crv string) elliptic.Curve {
	switch crv {
	case "P-224":
		return elliptic.P224()
	case "P-256":
		return elliptic.P256()
	case "P-384":
		return elliptic.P384()
	case "P-521":
		return elliptic.P521()
	default:
		return nil
	}
}
