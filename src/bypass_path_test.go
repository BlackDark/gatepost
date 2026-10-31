package src

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BlackDark/gatepost/src/rules"
)

func TestHasDotSegments(t *testing.T) {
	cases := map[string]bool{
		"/public/x":                    false,
		"/public/../admin":             true,
		"/public/..%2Fadmin":           true, // encoded separator, decoded once more on top of URL.Path
		"/public/%252e%252e/x":         true, // double-encoded dots
		"/public/%252e%252e%252fadmin": true,
		"/public/100%25/x":             false,
		"/public/..\\admin":            true,
		"/public/..foo/x":              false,
		"/public/foo../x":              false,
		"/..":                          true,
		"/public/./x":                  false,
		"":                             false,
	}
	for path, want := range cases {
		if got := hasDotSegments(path); got != want {
			t.Errorf("hasDotSegments(%q)=%v want %v", path, got, want)
		}
	}
}

// A bypass rule that matches only because the path is uncleaned must not make
// the request public; a clean path under the same prefix still bypasses.
func TestServeHTTP_BypassRuleIgnoredForDotSegmentPaths(t *testing.T) {
	cases := []struct {
		target      string
		wantForward bool
	}{
		{"https://app.example.com/public/x", true},
		{"https://app.example.com/public/%2e%2e/admin", false},
		{"https://app.example.com/public/%2E%2E/admin", false},
		{"https://app.example.com/public/..%2Fadmin", false},
		{"https://app.example.com/public/../admin", false},
		{"https://app.example.com/public/%2e%2e%2fadmin", false},
		{"https://app.example.com/public/%252e%252e/admin", false},
		{"https://app.example.com/public/..%5cadmin", false},
	}
	for _, tc := range cases {
		t.Run(tc.target, func(t *testing.T) {
			toa, closeServer := newForwardPathTestAuth(t)
			defer closeServer()
			toa.Config.UnauthenticatedBehavior = "Unauthorized"
			condition, err := rules.ParseRequestCondition("PathPrefix(`/public`)")
			if err != nil {
				t.Fatal(err)
			}
			toa.BypassAuthenticationRule = condition

			called := false
			toa.next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			})
			rw := httptest.NewRecorder()
			toa.ServeHTTP(rw, httptest.NewRequest(http.MethodGet, tc.target, nil))

			if called != tc.wantForward {
				t.Fatalf("forwarded=%v want %v (status %d)", called, tc.wantForward, rw.Code)
			}
		})
	}
}
