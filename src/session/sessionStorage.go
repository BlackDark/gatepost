package session

import (
	"time"

	"github.com/google/uuid"

	"github.com/BlackDark/test-oidc-traefik-plugin/src/config"
	"github.com/BlackDark/test-oidc-traefik-plugin/src/logging"
)

type SessionStorage interface {
	StoreSession(logger *logging.Logger, config *config.Config, sessionId string, state *SessionState) (string, error)
	TryGetSession(logger *logging.Logger, config *config.Config, sessionTicket string) (*SessionState, error)
}

type SessionState struct {
	Id string `json:"id"`
	// RefreshedAt is when the IDP token was last renewed. It keeps the "created_at" wire tag
	// it has always had: renaming it would invalidate every live session cookie on upgrade.
	RefreshedAt    time.Time `json:"created_at"`
	AccessToken    string    `json:"access_token"`
	IdToken        string    `json:"id_token"`
	RefreshToken   string    `json:"refresh_token"`
	IsAuthorized   bool      `json:"is_authorized"`
	TokenExpiresIn int       `json:"token_expires_in"`
	// ChallengeAttempted is set when this session was (re-)established via UnauthorizedBehavior Challenge.
	// Prevents infinite IDP redirect loops when re-auth cannot satisfy AssertClaims.
	ChallengeAttempted bool `json:"challenge_attempted"`

	// CreatedAt is when this session was first established. The session state lives in a
	// sealed client-side cookie, so this is the only anchor available to bound how long a
	// captured cookie can keep being renewed.
	// The tag deliberately does not reuse "created_at": RefreshedAt already owns that key,
	// and renaming either field would break unmarshalling of every existing session cookie.
	CreatedAt time.Time `json:"session_created_at"`
	// LastUsedAt is when this session was last accepted, for the idle bound.
	LastUsedAt time.Time `json:"last_used_at"`
}

func GenerateSessionId() string {
	id := uuid.New()
	return id.String()
}
