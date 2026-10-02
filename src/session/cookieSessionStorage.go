package session

import (
	"encoding/json"
	"time"

	"github.com/BlackDark/test-oidc-traefik-plugin/src/config"
	"github.com/BlackDark/test-oidc-traefik-plugin/src/logging"
	"github.com/BlackDark/test-oidc-traefik-plugin/src/utils"
)

type CookieSessionStorage struct{}

func CreateCookieSessionStorage() *CookieSessionStorage {
	storage := new(CookieSessionStorage)
	return storage
}

func (storage *CookieSessionStorage) StoreSession(logger *logging.Logger, config *config.Config, sessionId string, state *SessionState) (string, error) {
	now := time.Now().UTC()
	if state.CreatedAt.IsZero() {
		// Only stamped on first write: re-stamping on every renewal would make the
		// absolute lifetime bound unenforceable.
		state.CreatedAt = now
	}
	state.LastUsedAt = now

	stateJson, err := json.Marshal(*state)
	if err != nil {
		logger.Log(logging.LevelError, "Failed to marshal session state: %v", err.Error())
		return "", err
	}

	encryptedSessionTicket, err := utils.EncryptWithPurpose(string(stateJson), config.Secret, utils.PurposeSession)
	if err != nil {
		logger.Log(logging.LevelError, "Failed to encrypt session state: %s", err.Error())
		return "", err
	}

	return encryptedSessionTicket, nil
}

func (storage *CookieSessionStorage) TryGetSession(logger *logging.Logger, config *config.Config, sessionTicket string) (*SessionState, error) {
	plainSessionTicket, err := utils.DecryptWithPurpose(sessionTicket, config.Secret, utils.PurposeSession)
	if err != nil {
		// Narrow upgrade path: purpose binding invalidates every session cookie sealed
		// before this change. Accept a legacy ticket here, and only here, so a rolling
		// upgrade does not log every user out at once. The ticket is re-sealed with the
		// session purpose on the next store.
		legacyPlain, legacyErr := utils.Decrypt(sessionTicket, config.Secret)
		if legacyErr != nil {
			logger.Log(logging.LevelError, "Failed to decrypt session ticket: %v", err.Error())
			return nil, err
		}
		plainSessionTicket = legacyPlain
		logger.Log(logging.LevelInfo, "Accepted a pre-upgrade session ticket. It will be re-sealed with the session purpose on renewal.")
	}

	state := &SessionState{}

	if err := json.Unmarshal([]byte(plainSessionTicket), state); err != nil {
		return nil, err
	}

	if state.CreatedAt.IsZero() {
		// Sealed before the lifetime bounds existed. Backfill rather than reject:
		// dropping every live cookie on upgrade would be a self-inflicted outage.
		state.CreatedAt = state.LastUsedAt
		if state.CreatedAt.IsZero() {
			state.CreatedAt = time.Now()
		}
	}
	if state.LastUsedAt.IsZero() {
		state.LastUsedAt = state.CreatedAt
	}

	return state, nil
}
