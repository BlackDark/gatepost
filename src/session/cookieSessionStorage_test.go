package session

import (
	"encoding/json"
	"errors"
	"math/rand"
	"testing"
	"time"

	"github.com/BlackDark/gatepost/src/utils"

	"github.com/BlackDark/gatepost/src/config"
	"github.com/BlackDark/gatepost/src/logging"
)

const storageTestSecret = "0123456789abcdef0123456789abcdef"

func storageTestConfig() *config.Config {
	return &config.Config{Secret: storageTestSecret}
}

func storageTestLogger() *logging.Logger {
	return logging.CreateLogger(logging.LevelDebug)
}

func randomStorageString(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[rand.Intn(len(alphabet))]
	}
	return string(b)
}

// TestStoreSession_RejectsOversizedTicket pins the fix for the silent truncation
// regression: a ticket that does not fit the cookie budget used to be emitted
// anyway (clamped to 32 chunks) and could never be decrypted again, which the
// user sees as a permanent re-login loop with nothing in the log.
func TestStoreSession_RejectsOversizedTicket(t *testing.T) {
	storage := CreateCookieSessionStorage()
	cfg := storageTestConfig()
	logger := storageTestLogger()

	// Comfortably over MaxTicketSize once serialized and encrypted.
	oversized := &SessionState{
		Id:             "session-id",
		AccessToken:    randomStorageString(MaxTicketSize + 4096),
		IdToken:        randomStorageString(MaxTicketSize + 4096),
		RefreshToken:   randomStorageString(1024),
		IsAuthorized:   true,
		TokenExpiresIn: 3600,
		RefreshedAt:    time.Now().UTC(),
		CreatedAt:      time.Now().UTC(),
	}

	ticket, err := storage.StoreSession(logger, cfg, "session-id", oversized)
	if err == nil {
		t.Fatalf("oversized session must be rejected, got a %d byte ticket", len(ticket))
	}
	if ticket != "" {
		t.Fatalf("no ticket may be returned alongside the error, got %d bytes", len(ticket))
	}
	if !errors.Is(err, ErrSessionTooLarge) {
		t.Fatalf("err = %v, want ErrSessionTooLarge", err)
	}
}

// TestStoreSession_AcceptsTicketUnderBudget is the positive half of the above:
// the size check must not start rejecting sessions that legitimately fit.
func TestStoreSession_AcceptsTicketUnderBudget(t *testing.T) {
	storage := CreateCookieSessionStorage()
	cfg := storageTestConfig()
	logger := storageTestLogger()

	state := &SessionState{
		Id:           "session-id",
		AccessToken:  randomStorageString(512),
		IdToken:      randomStorageString(512),
		RefreshToken: randomStorageString(64),
		IsAuthorized: true,
	}

	ticket, err := storage.StoreSession(logger, cfg, state.Id, state)
	if err != nil {
		t.Fatalf("StoreSession: %v", err)
	}
	if ticket == "" {
		t.Fatal("expected a ticket")
	}
	if len(ticket) > MaxTicketSize {
		t.Fatalf("ticket of %d bytes exceeds the %d byte budget", len(ticket), MaxTicketSize)
	}
}

// TestStoreSession_TryGetSession_RoundTrip is the assertion that would have
// caught the original truncation bug: what goes in comes back out, field for
// field, through the exact bytes that would be written to the cookie.
func TestStoreSession_TryGetSession_RoundTrip(t *testing.T) {
	storage := CreateCookieSessionStorage()
	cfg := storageTestConfig()
	logger := storageTestLogger()

	// Many chunks worth of tokens, but comfortably inside the budget: this is the
	// shape a real session has, and it must survive the store/load cycle intact.
	state := &SessionState{
		Id:                 "round-trip-session",
		AccessToken:        randomStorageString(8 * 1024),
		IdToken:            randomStorageString(8 * 1024),
		RefreshToken:       randomStorageString(1024),
		IsAuthorized:       true,
		TokenExpiresIn:     3600,
		ChallengeAttempted: true,
	}

	ticket, err := storage.StoreSession(logger, cfg, state.Id, state)
	if err != nil {
		t.Fatalf("StoreSession: %v", err)
	}
	if len(ticket) <= ChunkSize {
		t.Fatalf("ticket of %d bytes should span multiple chunks", len(ticket))
	}

	got, err := storage.TryGetSession(logger, cfg, ticket)
	if err != nil {
		t.Fatalf("TryGetSession: %v", err)
	}

	if got.Id != state.Id ||
		got.AccessToken != state.AccessToken ||
		got.IdToken != state.IdToken ||
		got.RefreshToken != state.RefreshToken ||
		got.IsAuthorized != state.IsAuthorized ||
		got.TokenExpiresIn != state.TokenExpiresIn ||
		got.ChallengeAttempted != state.ChallengeAttempted {
		t.Fatalf("round-trip mismatch:\n got  %+v\n want %+v", got, state)
	}
}

// TestMaxTicketSizeMatchesChunkBudget keeps the two constants honest: if either
// moves, the emitted header count and the stored ticket must still agree.
func TestMaxTicketSizeMatchesChunkBudget(t *testing.T) {
	if MaxTicketSize != ChunkSize*MaxChunks {
		t.Fatalf("MaxTicketSize=%d, want ChunkSize*MaxChunks=%d", MaxTicketSize, ChunkSize*MaxChunks)
	}
}

// TestTryGetSession_LegacyTicketBackfillsAndPersistsStamp is the storage half of
// the legacy-ticket fix. A ticket sealed before the lifetime bounds existed carries
// no session_created_at, so TryGetSession backfills one - but the backfill is
// in-memory only and reaches the browser when the ticket is re-sealed. Re-sealing
// must persist the stamp rather than let it restart from zero, otherwise
// maxSessionLifetimeSeconds never fires for a pre-upgrade session.
func TestTryGetSession_LegacyTicketBackfillsAndPersistsStamp(t *testing.T) {
	storage := CreateCookieSessionStorage()
	cfg := storageTestConfig()
	logger := storageTestLogger()

	// Sealed with the purpose-less helper, exactly like a ticket written before
	// purpose binding existed, and with neither lifetime timestamp present.
	legacyJson, err := json.Marshal(map[string]interface{}{
		"id":               "legacy-session",
		"access_token":     "opaque-access-token-value",
		"is_authorized":    true,
		"token_expires_in": 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	legacyTicket, err := utils.Encrypt(string(legacyJson), cfg.Secret)
	if err != nil {
		t.Fatal(err)
	}

	backfilled, err := storage.TryGetSession(logger, cfg, legacyTicket)
	if err != nil {
		t.Fatalf("a pre-upgrade ticket must still be accepted: %v", err)
	}
	if backfilled.CreatedAt.IsZero() {
		t.Fatal("the missing session_created_at must be backfilled, not left zero")
	}

	// The re-seal the middleware performs on the first authenticated request.
	resealed, err := storage.StoreSession(logger, cfg, backfilled.Id, backfilled)
	if err != nil {
		t.Fatalf("StoreSession: %v", err)
	}

	durable, err := storage.TryGetSession(logger, cfg, resealed)
	if err != nil {
		t.Fatalf("re-read: %v", err)
	}
	if durable.CreatedAt.IsZero() {
		t.Fatal("the backfilled stamp was discarded instead of persisted")
	}
	if !durable.CreatedAt.Equal(backfilled.CreatedAt.Truncate(time.Millisecond)) &&
		!durable.CreatedAt.Equal(backfilled.CreatedAt) {
		t.Fatalf("CreatedAt restarted on re-seal: %s -> %s",
			backfilled.CreatedAt.Format(time.RFC3339Nano), durable.CreatedAt.Format(time.RFC3339Nano))
	}

	// And it must not restart again on a later re-seal: StoreSession only stamps a
	// zero CreatedAt.
	later, err := storage.StoreSession(logger, cfg, durable.Id, durable)
	if err != nil {
		t.Fatalf("second StoreSession: %v", err)
	}
	again, err := storage.TryGetSession(logger, cfg, later)
	if err != nil {
		t.Fatalf("second re-read: %v", err)
	}
	if !again.CreatedAt.Equal(durable.CreatedAt) {
		t.Fatalf("CreatedAt restarted on a later re-seal: %s -> %s",
			durable.CreatedAt.Format(time.RFC3339Nano), again.CreatedAt.Format(time.RFC3339Nano))
	}
}
