package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/BlackDark/gatepost/src/logging"
)

func testLogger() *logging.Logger {
	return logging.CreateLogger(logging.LevelError)
}

func TestKeyfunc_MissingOrInvalidKid(t *testing.T) {
	tests := []struct {
		name   string
		method jwt.SigningMethod
		header map[string]any
	}{
		{
			name:   "RS256 missing kid",
			method: jwt.SigningMethodRS256,
			header: map[string]any{},
		},
		{
			name:   "RS256 invalid kid type",
			method: jwt.SigningMethodRS256,
			header: map[string]any{"kid": 123},
		},
		{
			name:   "ES256 missing kid",
			method: jwt.SigningMethodES256,
			header: map[string]any{},
		},
		{
			name:   "ES256 invalid kid type",
			method: jwt.SigningMethodES256,
			header: map[string]any{"kid": true},
		},
	}

	h := &JwksHandler{}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token := &jwt.Token{
				Method: tc.method,
				Header: tc.header,
			}

			_, err := h.Keyfunc(token)
			if err == nil {
				t.Fatal("expected error for missing or invalid kid")
			}
		})
	}
}

// fakeAlg lets us exercise alg names the JWT library does not ship with.
type fakeAlg struct {
	*jwt.SigningMethodHMAC
	alg string
}

func (f *fakeAlg) Alg() string { return f.alg }

func TestKeyfunc_RejectsDisallowedAlgorithms(t *testing.T) {
	h := &JwksHandler{
		RsaKeys: []*RsaKey{{kid: "k1", key: mustRsaKey(t, 2048)}},
	}

	tests := []struct {
		name   string
		method jwt.SigningMethod
		header map[string]any
	}{
		{"none", &fakeAlg{SigningMethodHMAC: jwt.SigningMethodHS256, alg: "none"}, map[string]any{"kid": "k1"}},
		{"HS256", jwt.SigningMethodHS256, map[string]any{"kid": "k1"}},
		{"HS512", jwt.SigningMethodHS512, map[string]any{"kid": "k1"}},
		{"unknown", &fakeAlg{SigningMethodHMAC: jwt.SigningMethodHS256, alg: "RS128"}, map[string]any{"kid": "k1"}},
		{"EdDSA", jwt.SigningMethodEdDSA, map[string]any{"kid": "k1"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token := &jwt.Token{Method: tc.method, Header: tc.header}

			if _, err := h.Keyfunc(token); err == nil {
				t.Fatalf("expected algorithm %q to be rejected", tc.method.Alg())
			}
		})
	}
}

func TestKeyfunc_RejectsNilMethod(t *testing.T) {
	h := &JwksHandler{}

	if _, err := h.Keyfunc(&jwt.Token{Header: map[string]any{"kid": "k1"}}); err == nil {
		t.Fatal("expected error for a token with no signing method")
	}

	if _, err := h.Keyfunc(nil); err == nil {
		t.Fatal("expected error for a nil token")
	}
}

func TestKeyfunc_AcceptsAllowlistedAlgorithms(t *testing.T) {
	rsaKey := mustRsaKey(t, 2048)

	h := &JwksHandler{
		RsaKeys: []*RsaKey{{kid: "rsa-kid", key: rsaKey}},
		EcdsaKeys: []*EcdsaKey{
			{kid: "ec-kid", key: mustEcdsaKey(t)},
		},
	}

	// Case-insensitive on the method name, as required.
	rsaAlgs := []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "rs256"}
	for _, alg := range rsaAlgs {
		t.Run(alg, func(t *testing.T) {
			key, err := h.Keyfunc(&jwt.Token{
				Method: &fakeAlg{SigningMethodHMAC: jwt.SigningMethodHS256, alg: alg},
				Header: map[string]any{"kid": "rsa-kid"},
			})
			if err != nil {
				t.Fatalf("algorithm %s should be allowed: %v", alg, err)
			}
			if key != rsaKey {
				t.Fatal("expected the cached RSA key")
			}
		})
	}

	ecAlgs := []string{"ES256", "ES384", "ES512"}
	for _, alg := range ecAlgs {
		t.Run(alg, func(t *testing.T) {
			if _, err := h.Keyfunc(&jwt.Token{
				Method: &fakeAlg{SigningMethodHMAC: jwt.SigningMethodHS256, alg: alg},
				Header: map[string]any{"kid": "ec-kid"},
			}); err != nil {
				t.Fatalf("algorithm %s should be allowed: %v", alg, err)
			}
		})
	}
}

func TestKeyfunc_RejectsUnknownKid(t *testing.T) {
	h := &JwksHandler{
		RsaKeys:   []*RsaKey{{kid: "known", key: mustRsaKey(t, 2048)}},
		EcdsaKeys: []*EcdsaKey{{kid: "known-ec", key: mustEcdsaKey(t)}},
	}

	if _, err := h.Keyfunc(&jwt.Token{
		Method: jwt.SigningMethodRS256,
		Header: map[string]any{"kid": "unknown"},
	}); err == nil {
		t.Fatal("expected error for an unknown RSA kid")
	}

	if _, err := h.Keyfunc(&jwt.Token{
		Method: jwt.SigningMethodES256,
		Header: map[string]any{"kid": "unknown"},
	}); err == nil {
		t.Fatal("expected error for an unknown EC kid")
	}
}

func TestKeyfunc_EmptyHandler(t *testing.T) {
	h := &JwksHandler{}

	if _, err := h.Keyfunc(&jwt.Token{
		Method: jwt.SigningMethodRS256,
		Header: map[string]any{"kid": "any"},
	}); err == nil {
		t.Fatal("expected error when no keys are cached")
	}
}

func TestLoadKeysHonoursNon200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer server.Close()

	h := &JwksHandler{Url: server.URL}

	err := h.loadKeys(server.Client())
	if err == nil {
		t.Fatal("expected an error for a 500 response")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("expected the status code in the error, got: %v", err)
	}
	if h.hasKeys() {
		t.Fatal("a failed load must not populate the cache")
	}
}

func TestLoadKeysErrorExcerptIsBounded(t *testing.T) {
	huge := strings.Repeat("A", 100_000)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(huge))
	}))
	defer server.Close()

	h := &JwksHandler{Url: server.URL}

	err := h.loadKeys(server.Client())
	if err == nil {
		t.Fatal("expected an error")
	}
	if len(err.Error()) > 2*maxErrorExcerpt {
		t.Fatalf("error message is not bounded: %d bytes", len(err.Error()))
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("expected a truncated excerpt, got: %v", err)
	}
}

func TestLoadKeysRejectsMalformedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer server.Close()

	h := &JwksHandler{Url: server.URL}

	if err := h.loadKeys(server.Client()); err == nil {
		t.Fatal("expected an error for a malformed body")
	}
	if h.hasKeys() {
		t.Fatal("cache must stay empty")
	}
}

func TestUnsupportedEcCurveIsRejected(t *testing.T) {
	keys := JwksKeys{Keys: []JwksKey{
		{
			Kty: "EC",
			Crv: "secp256k1",
			Kid: "bad-crv",
			X:   base64.RawURLEncoding.EncodeToString(big.NewInt(1).Bytes()),
			Y:   base64.RawURLEncoding.EncodeToString(big.NewInt(2).Bytes()),
		},
		{
			Kty: "EC",
			Kid: "empty-crv",
			X:   base64.RawURLEncoding.EncodeToString(big.NewInt(1).Bytes()),
			Y:   base64.RawURLEncoding.EncodeToString(big.NewInt(2).Bytes()),
		},
	}}

	if _, err := extractEcdsaKey(&keys.Keys[0]); err == nil {
		t.Fatal("expected an error for an unsupported curve")
	}
	if _, err := extractEcdsaKey(&keys.Keys[1]); err == nil {
		t.Fatal("expected an error for an empty curve")
	}

	// A JWKS made only of unusable keys must not be accepted at all.
	ecdsaKeys, rsaKeys, err := extractKeys(&keys)
	if err == nil {
		t.Fatal("expected extractKeys to fail when no usable key remains")
	}
	if len(ecdsaKeys) != 0 || len(rsaKeys) != 0 {
		t.Fatal("no keys should be extracted")
	}
}

func TestUnsupportedEcCurveDoesNotPanicThroughLoadKeys(t *testing.T) {
	payload, _ := json.Marshal(JwksKeys{Keys: []JwksKey{{
		Kty: "EC",
		Crv: "secp256k1",
		Kid: "bad",
		X:   base64.RawURLEncoding.EncodeToString(big.NewInt(1).Bytes()),
		Y:   base64.RawURLEncoding.EncodeToString(big.NewInt(2).Bytes()),
	}}})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer server.Close()

	h := &JwksHandler{Url: server.URL}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("loadKeys panicked: %v", r)
		}
	}()

	if err := h.loadKeys(server.Client()); err == nil {
		t.Fatal("expected an error for a JWKS with no usable keys")
	}

	h.Lock.RLock()
	defer h.Lock.RUnlock()

	for _, k := range h.EcdsaKeys {
		if k.key.Curve == nil {
			t.Fatal("a nil curve must never be cached")
		}
	}
}

func TestEnsureLoadedServesCacheOnReloadFailure(t *testing.T) {
	key := mustRsaKey(t, 2048)
	body, _ := json.Marshal(jwksForRsaKey(t, key, "kid-1"))

	var fail atomic.Bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("idp is down"))
			return
		}
		_, _ = w.Write(body)
	}))
	defer server.Close()

	client := server.Client()
	h := &JwksHandler{Url: server.URL}

	if err := h.EnsureLoaded(testLogger(), client, false); err != nil {
		t.Fatal(err)
	}

	if !h.hasKeys() {
		t.Fatal("expected keys to be cached after the first load")
	}

	// IdP goes down; a forced reload must not break authentication.
	fail.Store(true)
	if err := h.EnsureLoaded(testLogger(), client, true); err != nil {
		t.Fatalf("a reload failure with cached keys must not fail the request: %v", err)
	}

	if _, err := h.Keyfunc(&jwt.Token{
		Method: jwt.SigningMethodRS256,
		Header: map[string]any{"kid": "kid-1"},
	}); err != nil {
		t.Fatalf("cached keys should still be served: %v", err)
	}
}

func TestEnsureLoadedFailsClosedWithoutCache(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	h := &JwksHandler{Url: server.URL}

	if err := h.EnsureLoaded(testLogger(), server.Client(), false); err == nil {
		t.Fatal("expected an error when there are no usable keys")
	}
}

func TestEnsureLoadedSkipsHttpWhenCacheIsFresh(t *testing.T) {
	var hits atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer server.Close()

	h := &JwksHandler{Url: server.URL, CacheDate: time.Now()}

	// No keys and CacheDate is fresh: the "max cache timeout" rule still asks
	// for a reload, but not before the 5 minute force-reload window.
	if err := h.EnsureLoaded(testLogger(), server.Client(), false); err == nil {
		t.Fatal("expected an error for an empty JWKS")
	}

	h.Lock.Lock()
	h.RsaKeys = []*RsaKey{{kid: "x", key: mustRsaKey(t, 2048)}}
	h.CacheDate = time.Now()
	h.Lock.Unlock()

	before := hits.Load()
	for i := 0; i < 5; i++ {
		if err := h.EnsureLoaded(testLogger(), server.Client(), false); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	if hits.Load() != before {
		t.Fatal("a fresh cache must not trigger an HTTP request")
	}
}

func TestEnsureLoadedDoesNotStampedeTheIdp(t *testing.T) {
	var hits atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		time.Sleep(50 * time.Millisecond)
		_, _ = w.Write([]byte(`{"keys":[{"kty":"RSA","kid":"k","n":"AQAB","e":"AQAB"}]}`))
	}))
	defer server.Close()

	h := &JwksHandler{Url: server.URL}
	client := server.Client()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = h.EnsureLoaded(testLogger(), client, true)
		}()
	}
	wg.Wait()

	if hits.Load() > 2 {
		t.Fatalf("expected concurrent misses to be coalesced, got %d requests", hits.Load())
	}
}

func TestEnsureLoadedContextUsesContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer server.Close()

	h := &JwksHandler{Url: server.URL}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := h.EnsureLoadedContext(ctx, testLogger(), server.Client(), false)
	if err == nil {
		t.Fatal("expected the cancelled context to abort the request")
	}
	if time.Since(start) > time.Second {
		t.Fatal("the context deadline was not honoured")
	}
}

func TestEnsureLoadedNilLoggerDoesNotPanic(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer server.Close()

	h := &JwksHandler{Url: server.URL}

	if err := h.EnsureLoaded(nil, server.Client(), false); err == nil {
		t.Fatal("expected an error for an empty JWKS")
	}
}

// TestKeyfuncConcurrentWithReload exercises the reader snapshot while reloads
// swap the key slices: run with -race to prove there is no data race and no
// torn read.
func TestKeyfuncConcurrentWithReload(t *testing.T) {
	keysA, _ := json.Marshal(jwksForRsaKey(t, mustRsaKey(t, 2048), "kid-a"))
	keysB, _ := json.Marshal(jwksForRsaKey(t, mustRsaKey(t, 2048), "kid-b"))

	var turn atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if turn.Load()%2 == 0 {
			_, _ = w.Write(keysA)
			return
		}
		_, _ = w.Write(keysB)
	}))
	defer server.Close()

	h := &JwksHandler{Url: server.URL}
	client := server.Client()

	if err := h.EnsureLoaded(testLogger(), client, true); err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}

				turn.Add(1)
				_ = h.EnsureLoaded(testLogger(), client, true)

				for _, kid := range []string{"kid-a", "kid-b"} {
					_, _ = h.Keyfunc(&jwt.Token{
						Method: jwt.SigningMethodRS256,
						Header: map[string]any{"kid": kid},
					})
				}
			}
		}()
	}

	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()

	// Cache must be internally consistent: every cached key has a non-nil key.
	h.Lock.RLock()
	defer h.Lock.RUnlock()

	for _, k := range h.RsaKeys {
		if k == nil || k.key == nil {
			t.Fatal("observed a nil entry in the key cache")
		}
	}
}

func mustRsaKey(t *testing.T, bits int) *rsa.PublicKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}

	return &key.PublicKey
}

func mustEcdsaKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	return &key.PublicKey
}

func jwksForRsaKey(t *testing.T, key *rsa.PublicKey, kid string) JwksKeys {
	t.Helper()

	return JwksKeys{Keys: []JwksKey{{
		Kty: "RSA",
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}}}
}
