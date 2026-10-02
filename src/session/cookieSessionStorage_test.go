package session

import (
	"errors"
	"math/rand"
	"testing"
	"time"

	"github.com/BlackDark/test-oidc-traefik-plugin/src/config"
	"github.com/BlackDark/test-oidc-traefik-plugin/src/logging"
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
