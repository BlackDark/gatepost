package oidc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/BlackDark/gatepost/src/logging"
	"github.com/BlackDark/gatepost/src/utils"
)

// stateLifetime bounds how long a sealed login state stays usable. The state is
// carried through the user's browser and comes back on the callback, so it must
// expire: without a bound a captured ?state= value can be replayed forever.
const stateLifetime = 10 * time.Minute

// stateTypeTag binds a ciphertext to this struct. It is checked after
// decryption so a value sealed for another purpose cannot be interpreted as a
// state object (defence in depth on top of the purpose-bound AAD).
const stateTypeTag = "oidc-state"

// ErrStateExpired is returned by UnsealState when the state is well-formed but
// older than stateLifetime. Callers should treat it as a failed login and start
// a new authorization request.
var ErrStateExpired = errors.New("oidc state has expired")

type OidcState struct {
	Action      string `json:"action"`
	RedirectUrl string `json:"redirect_url"`
	// CodeVerifierEnc is the AES-GCM encrypted PKCE code_verifier (utils.Encrypt output).
	// Nested inside JSON then sealed by SealState — do not put Encrypt output bare in a query string.
	// Carried in state so parallel login redirects cannot overwrite each other via a shared cookie.
	CodeVerifierEnc string `json:"cve,omitempty"`
	// Csrf binds this authorize flow to a LoginCsrf cookie (ADR 0003).
	Csrf string `json:"csrf,omitempty"`
	// Nonce is the OIDC nonce for ID token binding (ADR 0004).
	Nonce string `json:"nonce,omitempty"`
	// IsChallenge is set when login was triggered by UnauthorizedBehavior Challenge (authorization re-check).
	IsChallenge bool `json:"is_challenge,omitempty"`
	// Type is the purpose tag this state was sealed for; see stateTypeTag.
	Type string `json:"typ,omitempty"`
	// IssuedAt is when the state was sealed.
	IssuedAt time.Time `json:"issued_at,omitempty"`
	// Expires is IssuedAt + stateLifetime. It is signed (AEAD) so it cannot be
	// extended by the holder of the value.
	Expires time.Time `json:"expires,omitempty"`
}

// SealState encrypts the full OidcState with Secret and returns a RawURL-safe opaque state string (ADR 0002).
//
// It stamps the issue/expiry times and encrypts with utils.PurposeOidcState so a ciphertext
// minted for another purpose (eg. the session cookie) fails authentication here.
func SealState(state *OidcState, secret string) (string, error) {
	if state == nil {
		return "", errors.New("state must not be nil")
	}

	now := time.Now()

	stamped := *state
	stamped.Type = stateTypeTag
	stamped.IssuedAt = now
	stamped.Expires = now.Add(stateLifetime)

	stateBytes, err := json.Marshal(&stamped)
	if err != nil {
		return "", err
	}

	encrypted, err := utils.EncryptWithPurpose(string(stateBytes), secret, utils.PurposeOidcState)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString([]byte(encrypted)), nil
}

// UnsealState decrypts an opaque state string produced by SealState.
//
// A state that decrypts but is older than stateLifetime is rejected with
// ErrStateExpired, so a captured callback URL cannot be replayed indefinitely.
func UnsealState(sealed string, secret string) (*OidcState, error) {
	encBytes, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil {
		return nil, err
	}

	plain, legacy, err := openState(encBytes, secret)
	if err != nil {
		return nil, err
	}

	var state OidcState
	if err := json.Unmarshal([]byte(plain), &state); err != nil {
		return nil, err
	}

	// A state sealed by this version always carries the type tag; only a legacy
	// purpose-less ciphertext (see openState) may omit it.
	if !legacy && state.Type != stateTypeTag {
		return nil, fmt.Errorf("unexpected oidc state type %q", state.Type)
	}

	if !state.Expires.IsZero() && time.Now().After(state.Expires) {
		return nil, ErrStateExpired
	}

	return &state, nil
}

// openState decrypts the raw (base64url-decoded) state ciphertext. The second
// return value reports whether the legacy purpose-less fallback was used.
//
// Legacy fallback lives here and nowhere else: states sealed before purpose-bound
// encryption existed carry no AAD, so a rolling upgrade would reject logins that
// were in flight. We retry those once with the purpose-less decrypt and warn.
func openState(encBytes []byte, secret string) (string, bool, error) {
	plain, err := utils.DecryptWithPurpose(string(encBytes), secret, utils.PurposeOidcState)
	if err == nil {
		return plain, false, nil
	}

	plain, legacyErr := utils.Decrypt(string(encBytes), secret)
	if legacyErr != nil {
		return "", false, err
	}

	// A legacy state has no typ tag and no expiry bookkeeping - accepting a
	// purpose-less ciphertext that does carry them would let an attacker use this
	// fallback to skip the type and expiry checks.
	var probe map[string]json.RawMessage

	if jsonErr := json.Unmarshal([]byte(plain), &probe); jsonErr != nil {
		return "", false, err
	}

	if _, ok := probe["typ"]; ok {
		return "", false, err
	}

	if raw, ok := probe["expires"]; ok {
		var expires time.Time
		if json.Unmarshal(raw, &expires) == nil && !expires.IsZero() {
			return "", false, err
		}
	}

	// Positive shape check, not just the absence of typ/expires: a purpose-less
	// *session* cookie ({"id":...,"access_token":...}) would otherwise pass the
	// denylist above and be accepted as an empty state. Every sealed state carries a
	// non-empty action.
	action, ok := probe["action"]
	if !ok {
		return "", false, err
	}

	var actionValue string
	if json.Unmarshal(action, &actionValue) != nil || actionValue == "" {
		return "", false, err
	}

	logging.CreateLogger(logging.LevelWarn).Log(
		logging.LevelWarn,
		"Accepted a legacy purpose-less OIDC state. Sessions established before the upgrade will expire; remove this fallback once all instances have been restarted.",
	)

	return plain, true, nil
}
