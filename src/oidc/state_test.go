package oidc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/BlackDark/test-oidc-traefik-plugin/src/utils"
)

const testSecret = "0123456789abcdef0123456789abcdef"

func TestSealUnsealState_RoundTrip(t *testing.T) {
	in := &OidcState{
		Action:          "Login",
		RedirectUrl:     "https://app.example.com/path",
		CodeVerifierEnc: "encrypted-verifier-ciphertext",
	}

	sealed, err := SealState(in, testSecret)
	if err != nil {
		t.Fatalf("SealState: %v", err)
	}
	if sealed == "" {
		t.Fatal("expected non-empty sealed state")
	}
	// Must not contain cleartext redirect URL
	if strings.Contains(sealed, "app.example.com") || strings.Contains(string(mustRawURLDecode(t, sealed)), "redirect_url") {
		t.Fatal("sealed state must not expose cleartext JSON fields")
	}

	out, err := UnsealState(sealed, testSecret)
	if err != nil {
		t.Fatalf("UnsealState: %v", err)
	}
	if out.Action != in.Action || out.RedirectUrl != in.RedirectUrl || out.CodeVerifierEnc != in.CodeVerifierEnc {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
}

func TestUnsealState_TamperedFails(t *testing.T) {
	sealed, err := SealState(&OidcState{Action: "Login", RedirectUrl: "https://evil.example/"}, testSecret)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0xff
	tampered := base64.RawURLEncoding.EncodeToString(raw)

	if _, err := UnsealState(tampered, testSecret); err == nil {
		t.Fatal("expected error for tampered state")
	}
}

func TestUnsealState_WrongSecretFails(t *testing.T) {
	sealed, err := SealState(&OidcState{Action: "Login", RedirectUrl: "https://app.example.com/"}, testSecret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnsealState(sealed, "ffffffffffffffffffffffffffffffff"); err == nil {
		t.Fatal("expected error for wrong secret")
	}
}

func TestUnsealState_PlainBase64JsonFails(t *testing.T) {
	// Old unsealed format must not be accepted
	legacy := base64.RawURLEncoding.EncodeToString([]byte(`{"action":"Login","redirect_url":"https://evil.example/"}`))
	if _, err := UnsealState(legacy, testSecret); err == nil {
		t.Fatal("legacy unsealed state must be rejected")
	}
}

func TestUnsealState_ExpiredRejected(t *testing.T) {
	// A state sealed just past the lifetime must be refused, otherwise a captured
	// callback URL replays forever.
	expired := &OidcState{
		Action:      "Login",
		RedirectUrl: "https://app.example.com/",
		Type:        stateTypeTag,
		IssuedAt:    time.Now().Add(-2 * stateLifetime),
		Expires:     time.Now().Add(-stateLifetime),
	}

	sealed, err := utils.EncryptWithPurpose(mustMarshal(t, expired), testSecret, utils.PurposeOidcState)
	if err != nil {
		t.Fatal(err)
	}

	_, err = UnsealState(base64.RawURLEncoding.EncodeToString([]byte(sealed)), testSecret)
	if !errors.Is(err, ErrStateExpired) {
		t.Fatalf("expected ErrStateExpired, got %v", err)
	}
}

func TestSealState_StampsTypeAndExpiry(t *testing.T) {
	sealed, err := SealState(&OidcState{Action: "Login", RedirectUrl: "https://app.example.com/"}, testSecret)
	if err != nil {
		t.Fatal(err)
	}

	plain, err := utils.DecryptWithPurpose(string(mustRawURLDecode(t, sealed)), testSecret, utils.PurposeOidcState)
	if err != nil {
		t.Fatal(err)
	}

	var probe OidcState
	if err := json.Unmarshal([]byte(plain), &probe); err != nil {
		t.Fatal(err)
	}

	if probe.Type != stateTypeTag {
		t.Fatalf("typ=%q", probe.Type)
	}
	if probe.IssuedAt.IsZero() || probe.Expires.IsZero() {
		t.Fatal("issued_at/expires must be stamped")
	}
	if probe.Expires.Sub(probe.IssuedAt) != stateLifetime {
		t.Fatalf("lifetime=%v", probe.Expires.Sub(probe.IssuedAt))
	}
}

func TestUnsealState_TamperedTypeRejected(t *testing.T) {
	forged := &OidcState{
		Action:      "Login",
		RedirectUrl: "https://evil.example/",
		Type:        "session",
		IssuedAt:    time.Now(),
		Expires:     time.Now().Add(stateLifetime),
	}

	sealed, err := utils.EncryptWithPurpose(mustMarshal(t, forged), testSecret, utils.PurposeOidcState)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := UnsealState(base64.RawURLEncoding.EncodeToString([]byte(sealed)), testSecret); err == nil {
		t.Fatal("a state tagged for another purpose must be rejected")
	}
}

func TestUnsealState_SessionCiphertextRejectedAsState(t *testing.T) {
	// A session cookie ciphertext submitted as ?state= must not decrypt here.
	sessionCiphertext, err := utils.EncryptWithPurpose(`{"id":"abc"}`, testSecret, utils.PurposeSession)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := UnsealState(base64.RawURLEncoding.EncodeToString([]byte(sessionCiphertext)), testSecret); err == nil {
		t.Fatal("session-purpose ciphertext must not open as state")
	}
}

func TestUnsealState_LegacyPurposeLessStateOpens(t *testing.T) {
	legacy := &OidcState{Action: "Login", RedirectUrl: "https://app.example.com/"}

	sealed, err := utils.Encrypt(mustMarshal(t, legacy), testSecret)
	if err != nil {
		t.Fatal(err)
	}

	out, err := UnsealState(base64.RawURLEncoding.EncodeToString([]byte(sealed)), testSecret)
	if err != nil {
		t.Fatalf("legacy fallback should still open in-flight logins: %v", err)
	}
	if out.Action != "Login" || out.RedirectUrl != legacy.RedirectUrl {
		t.Fatalf("legacy round-trip mismatch: %+v", out)
	}
}

func TestUnsealState_LegacyFallbackCannotBypassExpiry(t *testing.T) {
	// The legacy fallback must not become a way to skip the expiry check.
	forged := &OidcState{
		Action:      "Login",
		RedirectUrl: "https://evil.example/",
		Expires:     time.Now().Add(time.Hour),
	}

	sealed, err := utils.Encrypt(mustMarshal(t, forged), testSecret)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := UnsealState(base64.RawURLEncoding.EncodeToString([]byte(sealed)), testSecret); err == nil {
		t.Fatal("purpose-less state carrying expiry metadata must be rejected")
	}
}

// TestUnsealState_LegacyFallbackRejectsSessionShapedCiphertext pins the positive
// shape check in openState. A legacy (purpose-less) *session* cookie has no "typ"
// and no "expires", so it slips past the denylist checks - but it is not a login
// state and must not be accepted as one.
func TestUnsealState_LegacyFallbackRejectsSessionShapedCiphertext(t *testing.T) {
	// Shape taken verbatim from session.SessionState's wire tags.
	sessionJson := `{"id":"a-session-id","access_token":"an-access-token",` +
		`"id_token":"an-id-token","refresh_token":"a-refresh-token",` +
		`"is_authorized":true,"token_expires_in":3600,` +
		`"created_at":"2026-01-01T00:00:00Z","session_created_at":"2026-01-01T00:00:00Z",` +
		`"last_used_at":"2026-01-01T00:00:00Z"}`

	sealed, err := utils.Encrypt(sessionJson, testSecret)
	if err != nil {
		t.Fatal(err)
	}

	state, err := UnsealState(base64.RawURLEncoding.EncodeToString([]byte(sealed)), testSecret)
	if err == nil {
		t.Fatalf("a legacy session cookie must not be accepted as an OIDC state, got %+v", state)
	}
}

func TestUnsealState_LegacyFallbackRejectsEmptyAction(t *testing.T) {
	// A non-empty action is the positive shape requirement; an empty one is not a
	// login state and must be refused by the fallback.
	sealed, err := utils.Encrypt(`{"action":"","redirect_url":"https://app.example.com/"}`, testSecret)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := UnsealState(base64.RawURLEncoding.EncodeToString([]byte(sealed)), testSecret); err == nil {
		t.Fatal("a purpose-less ciphertext with an empty action must be rejected")
	}
}

func mustMarshal(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func mustRawURLDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
