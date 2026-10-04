package src

import (
	"testing"
	"time"

	"github.com/BlackDark/gatepost/src/config"
	"github.com/BlackDark/gatepost/src/logging"
	"github.com/BlackDark/gatepost/src/session"
)

func TestSessionIdpTokenExpiration(t *testing.T) {
	config := &config.Config{
		Provider: &config.ProviderConfig{
			TokenRenewalThreshold: 0.5,
		},
		SessionCookie: &config.SessionCookieConfig{
			MaxAge: 0,
		},
	}

	logger := logging.CreateLogger(logging.LevelDebug)

	toa := &Gatepost{
		logger: logger,
		Config: config,
	}

	now := time.Now()

	sessionState := &session.SessionState{
		RefreshedAt:    now.Add(-29 * time.Second),
		TokenExpiresIn: 60,
	}

	expiresSoon := checkIdpTokenExpiresSoon(toa, sessionState)

	if expiresSoon {
		t.Fail()
	}

	sessionState = &session.SessionState{
		RefreshedAt:    now.Add(-30 * time.Second),
		TokenExpiresIn: 60,
	}

	expiresSoon = checkIdpTokenExpiresSoon(toa, sessionState)

	if !expiresSoon {
		t.Fail()
	}
}
