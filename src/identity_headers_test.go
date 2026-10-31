package src

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BlackDark/gatepost/src/config"
	"github.com/BlackDark/gatepost/src/rules"
)

// A client-supplied copy of an operator-configured header must not reach the
// backend on any path where attachHeaders does not overwrite it.
func TestSanitize_StripsConfiguredAndUnderscoreIdentityHeaders(t *testing.T) {
	cases := []struct {
		name        string
		path        string
		behavior    string
		includeWhen string
		withAuth    bool
		authorized  bool
		want        string // expected header value at the backend
	}{
		{name: "bypass_no_session", path: "/public", behavior: "Unauthorized", includeWhen: "Authorized", want: ""},
		{name: "bypass_with_session_default_gate", path: "/public", behavior: "Unauthorized", includeWhen: "Authorized", withAuth: true, authorized: true, want: ""},
		{name: "unauthenticated_forward", path: "/private", behavior: "Forward", includeWhen: "Authorized", want: ""},
		{name: "unauthorized_forward_with_session", path: "/private", behavior: "Forward", includeWhen: "Authorized", withAuth: true, want: ""},
		{name: "bypass_with_session_always_still_set", path: "/public", behavior: "Unauthorized", includeWhen: "Always", withAuth: true, authorized: true, want: "user-1"},
		{name: "authorized_route_still_set", path: "/private", behavior: "Unauthorized", includeWhen: "Authorized", withAuth: true, authorized: true, want: "user-1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			toa, closeServer := newForwardPathTestAuth(t)
			defer closeServer()

			toa.Config.UnauthenticatedBehavior = tc.behavior
			toa.Config.UnauthorizedBehavior = tc.behavior
			if tc.authorized {
				toa.Config.Authorization = &config.AuthorizationConfig{}
			}
			toa.Config.Headers = []config.HeaderConfig{
				{Name: "X-User-Email", Value: "{{ .claims.sub }}", IncludeWhen: tc.includeWhen},
			}
			condition, err := rules.ParseRequestCondition("Path(`/public`)")
			if err != nil {
				t.Fatal(err)
			}
			toa.BypassAuthenticationRule = condition

			var got http.Header
			toa.next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.Header.Clone()
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodGet, "https://app.example.com"+tc.path, nil)
			req.Header.Set("X-User-Email", "attacker@example.com")
			req.Header.Set("X_Forwarded_User", "attacker")
			req.Header.Set("X-Forwarded_User", "attacker")
			req.Header.Set("X_Forwarded-Email", "attacker@example.com")
			req.Header.Set("X_User-Email", "attacker@example.com")
			if tc.withAuth {
				req.Header.Set("Authorization", "Bearer good-token")
			}
			toa.ServeHTTP(httptest.NewRecorder(), req)

			if got == nil {
				t.Fatal("request was not forwarded")
			}
			if v := got.Get("X-User-Email"); v != tc.want {
				t.Fatalf("X-User-Email=%q want %q", v, tc.want)
			}
			for _, alias := range []string{"X_Forwarded_User", "X-Forwarded_User", "X_Forwarded-Email", "X_User-Email"} {
				if v := got.Get(alias); v != "" {
					t.Fatalf("alias spelling %s reached the backend: %q", alias, v)
				}
			}
		})
	}
}
