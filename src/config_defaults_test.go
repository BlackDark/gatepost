package src

import (
	"context"
	"testing"

	"github.com/BlackDark/gatepost/src/config"
)

func TestNew_RefusesDefaultSecret(t *testing.T) {
	cfg := CreateConfig()
	cfg.Provider.Url = "https://idp.example.com"
	cfg.Provider.ClientId = "client"
	cfg.Secret = config.DefaultSecret

	_, err := New(context.Background(), nil, cfg, "test")
	if err == nil {
		t.Fatal("expected error for default secret")
	}
	if err.Error() != "default secret is not allowed" {
		t.Fatalf("err=%v", err)
	}
}

func TestCreateConfig_SecureDefaults(t *testing.T) {
	cfg := CreateConfig()
	if !cfg.Provider.UsePkceBool {
		t.Fatal("UsePkce should default true")
	}
	if !cfg.Provider.ValidateNonceBool {
		t.Fatal("ValidateNonce should default true")
	}
	if cfg.SessionCookie.SameSite != "lax" {
		t.Fatalf("SameSite=%q want lax", cfg.SessionCookie.SameSite)
	}
	if cfg.Provider.TokenClockSkewSeconds != 60 {
		t.Fatalf("TokenClockSkewSeconds=%d", cfg.Provider.TokenClockSkewSeconds)
	}
	if cfg.UnauthenticatedBehavior != "" {
		t.Fatalf("UnauthenticatedBehavior=%q want empty (migrate in New)", cfg.UnauthenticatedBehavior)
	}
	if cfg.UnauthorizedBehavior != "" {
		t.Fatalf("UnauthorizedBehavior=%q want empty (migrate in New)", cfg.UnauthorizedBehavior)
	}
	migrateAuthBehaviors(cfg)
	if cfg.UnauthenticatedBehavior != "Auto" {
		t.Fatalf("after migrate UnauthenticatedBehavior=%q want Auto", cfg.UnauthenticatedBehavior)
	}
	if cfg.UnauthorizedBehavior != "Unauthorized" {
		t.Fatalf("after migrate UnauthorizedBehavior=%q want Unauthorized", cfg.UnauthorizedBehavior)
	}
	if cfg.FrontChannelLogoutUri != "/frontchannel-logout" {
		t.Fatalf("FrontChannelLogoutUri=%q", cfg.FrontChannelLogoutUri)
	}
}

func TestNew_RedirectURIWildcardsOptIn(t *testing.T) {
	cfg := CreateConfig()
	cfg.Provider.Url = "https://idp.example.com"
	cfg.Provider.ClientId = "client"
	cfg.Secret = "0123456789abcdef0123456789abcdef"
	t.Setenv("TOA_ENABLE_REDIRECT_URI_WILDCARDS", "true")

	middleware, err := New(context.Background(), nil, cfg, "test")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	oidcMiddleware, ok := middleware.(*Gatepost)
	if !ok {
		t.Fatalf("New() returned %T", middleware)
	}
	if !oidcMiddleware.RedirectUriWildcardsEnabled {
		t.Fatal("RedirectUriWildcardsEnabled should be true")
	}
}

func TestNew_RejectsInvalidRedirectURIWildcardFlag(t *testing.T) {
	cfg := CreateConfig()
	cfg.Provider.Url = "https://idp.example.com"
	cfg.Provider.ClientId = "client"
	cfg.Secret = "0123456789abcdef0123456789abcdef"
	t.Setenv("TOA_ENABLE_REDIRECT_URI_WILDCARDS", "sometimes")

	_, err := New(context.Background(), nil, cfg, "test")
	if err == nil {
		t.Fatal("expected invalid wildcard flag error")
	}
}

func TestMigrateAuthBehaviors(t *testing.T) {
	tests := []struct {
		name        string
		unauthN     string
		unauthZ     string
		wantUnauthN string
		wantUnauthZ string
	}{
		{
			name:        "legacy Challenge maps to unauthenticated only",
			unauthN:     "",
			unauthZ:     "Challenge",
			wantUnauthN: "Challenge",
			wantUnauthZ: "Unauthorized",
		},
		{
			name:        "legacy Auto maps to unauthenticated Auto and unauthorized 403",
			unauthN:     "",
			unauthZ:     "Auto",
			wantUnauthN: "Auto",
			wantUnauthZ: "Unauthorized",
		},
		{
			name:        "legacy Forward preserved for both",
			unauthN:     "",
			unauthZ:     "Forward",
			wantUnauthN: "Forward",
			wantUnauthZ: "Forward",
		},
		{
			name:        "empty both defaults unauthenticated Auto",
			unauthN:     "",
			unauthZ:     "",
			wantUnauthN: "Auto",
			wantUnauthZ: "Unauthorized",
		},
		{
			name:        "already split left alone",
			unauthN:     "Auto",
			unauthZ:     "Challenge",
			wantUnauthN: "Auto",
			wantUnauthZ: "Challenge",
		},
		{
			name:        "split unauthN set fills empty unauthorized",
			unauthN:     "Auto",
			unauthZ:     "",
			wantUnauthN: "Auto",
			wantUnauthZ: "Unauthorized",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				UnauthenticatedBehavior: tt.unauthN,
				UnauthorizedBehavior:    tt.unauthZ,
			}
			migrateAuthBehaviors(cfg)
			if cfg.UnauthenticatedBehavior != tt.wantUnauthN {
				t.Fatalf("UnauthenticatedBehavior=%q want %q", cfg.UnauthenticatedBehavior, tt.wantUnauthN)
			}
			if cfg.UnauthorizedBehavior != tt.wantUnauthZ {
				t.Fatalf("UnauthorizedBehavior=%q want %q", cfg.UnauthorizedBehavior, tt.wantUnauthZ)
			}
		})
	}
}
