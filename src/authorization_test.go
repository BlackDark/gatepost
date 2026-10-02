package src

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/BlackDark/test-oidc-traefik-plugin/src/config"
	"github.com/BlackDark/test-oidc-traefik-plugin/src/logging"
)

// captureStdout redirects os.Stdout for the duration of f and returns what was
// written. logging.Logger writes straight to os.Stdout, so this is the only way
// to observe its output without adding a dependency.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}

	orig := os.Stdout
	os.Stdout = w

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		captured strings.Builder
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		b, _ := io.ReadAll(r)
		mu.Lock()
		captured.Write(b)
		mu.Unlock()
	}()

	defer func() {
		os.Stdout = orig
		w.Close()
		wg.Wait()
		r.Close()
	}()

	f()

	// Flush: close the writer so the reader sees EOF, then restore stdout.
	os.Stdout = orig
	w.Close()
	wg.Wait()
	r.Close()

	mu.Lock()
	defer mu.Unlock()
	return captured.String()
}

func createAuthInstance(claims []config.ClaimAssertion) *config.AuthorizationConfig {
	return &config.AuthorizationConfig{
		AssertClaims: claims,
	}
}

func getTestClaims() map[string]interface{} {
	bytes := []byte(`{
		"name": "Alice",
		"age": 67,
		"children": [
			{ "name": "Bob", "age": 25 },
			{ "name": "Eve", "age": 22 }
		],
		"roles": [
			"support",
			"accountant",
			"administrator"
		],
		"address": {
			"country": "USA",
			"street": "Freedom Rd.",
			"neighbours": [
				"Joe",
				"Sam"
			]
		},
		"my:zitadel:grants": [
			"abc",
			"def",
			"ghi"
		]
	}`)

	claims := jwt.MapClaims{}
	err := json.Unmarshal(bytes, &claims)
	if err != nil {
		panic(err)
	}
	return claims
}

func TestClaimNameExists(t *testing.T) {
	logger := logging.CreateLogger(logging.LevelDebug)
	claims := getTestClaims()
	authorization := createAuthInstance([]config.ClaimAssertion{
		{Name: "name"},
	})

	if !isAuthorized(logger, authorization, claims) {
		t.Fatal("Should authorize as a claim with the provided name exists")
	}

	authorization = createAuthInstance([]config.ClaimAssertion{
		{Name: "names"},
	})

	if isAuthorized(logger, authorization, claims) {
		t.Fatal("Should not authorize as no claim with the provided name exists")
	}
}

func TestSimpleAssertions(t *testing.T) {
	logger := logging.CreateLogger(logging.LevelDebug)
	claims := getTestClaims()
	authorization := createAuthInstance([]config.ClaimAssertion{
		{Name: "name", AnyOf: []string{"Alice", "Bob", "Bruno"}},
	})

	if !isAuthorized(logger, authorization, claims) {
		t.Fatal("Should authorize since value is any of the provided values")
	}

	authorization = createAuthInstance([]config.ClaimAssertion{
		{Name: "name", AnyOf: []string{"Ben", "Joe", "Sam"}},
	})

	if isAuthorized(logger, authorization, claims) {
		t.Fatal("Should not authorize since value is none of the provided values")
	}

	authorization = createAuthInstance([]config.ClaimAssertion{
		{Name: "name", AllOf: []string{"Alice"}},
	})

	if !isAuthorized(logger, authorization, claims) {
		t.Fatal("Should authorize since the single value matches all of the provided values")
	}

	authorization = createAuthInstance([]config.ClaimAssertion{
		{Name: "name", AllOf: []string{"Alice", "Bob", "Bruno"}},
	})

	if isAuthorized(logger, authorization, claims) {
		t.Fatal("Should not authorize since the single value match cannot contain all values of array")
	}

	// We need to use ['my:zitadel:grants'] here to escape the colons in the jsonpath.
	authorization = createAuthInstance([]config.ClaimAssertion{
		{Name: "['my:zitadel:grants']", AllOf: []string{"abc", "def", "ghi"}},
	})

	if !isAuthorized(logger, authorization, claims) {
		t.Fatal("Should authorize since all values are contained in the array")
	}
}

func TestNestedAssertions(t *testing.T) {
	logger := logging.CreateLogger(logging.LevelDebug)
	claims := getTestClaims()
	authorization := createAuthInstance([]config.ClaimAssertion{
		{Name: "address.street", AnyOf: []string{"Freedom Rd.", "Eagle St."}},
	})

	if !isAuthorized(logger, authorization, claims) {
		t.Fatal("Should authorize since nested value is any of the provided values")
	}

	authorization = createAuthInstance([]config.ClaimAssertion{
		{Name: "address.street", AnyOf: []string{"Concrete HWY"}},
	})

	if isAuthorized(logger, authorization, claims) {
		t.Fatal("Should not authorize since nested value is none of the provided values")
	}

	authorization = createAuthInstance([]config.ClaimAssertion{
		{Name: "address.street", AllOf: []string{"Freedom Rd."}},
	})

	if !isAuthorized(logger, authorization, claims) {
		t.Fatal("Should authorize since the single value matches all of the provided values")
	}

	authorization = createAuthInstance([]config.ClaimAssertion{
		{Name: "address.street", AllOf: []string{"Freedom Rd.", "Eagle St."}},
	})

	if isAuthorized(logger, authorization, claims) {
		t.Fatal("Should not authorize since the single value match cannot contain all values of array")
	}
}

func TestArrayAssertions(t *testing.T) {
	logger := logging.CreateLogger(logging.LevelDebug)
	claims := getTestClaims()
	authorization := createAuthInstance([]config.ClaimAssertion{
		{Name: "children[*].name", AnyOf: []string{"Joe", "Bob", "Sam"}},
	})

	if !isAuthorized(logger, authorization, claims) {
		t.Fatal("Should authorize since some of the values are part of the provided values")
	}

	authorization = createAuthInstance([]config.ClaimAssertion{
		{Name: "children[*].name", AnyOf: []string{"Joe", "Sam", "Alex"}},
	})

	if isAuthorized(logger, authorization, claims) {
		t.Fatal("Should not authorize since values are none of the provided values")
	}

	authorization = createAuthInstance([]config.ClaimAssertion{
		{Name: "children[*].name", AllOf: []string{"Bob", "Eve"}},
	})

	if !isAuthorized(logger, authorization, claims) {
		t.Fatal("Should authorize since all of the provided values have a matching claim value")
	}

	authorization = createAuthInstance([]config.ClaimAssertion{
		{Name: "children[*].name", AllOf: []string{"Bob", "Eve", "Alex"}},
	})

	if isAuthorized(logger, authorization, claims) {
		t.Fatal("Should not authorize since not all of the provided values have a matching claim value")
	}
}

func TestCombinedAssertions(t *testing.T) {
	logger := logging.CreateLogger(logging.LevelDebug)
	claims := getTestClaims()
	authorization := createAuthInstance([]config.ClaimAssertion{
		{Name: "children[*].name", AnyOf: []string{"Joe", "Bob", "Sam"}, AllOf: []string{"Eve", "Bob"}},
	})

	if !isAuthorized(logger, authorization, claims) {
		t.Fatal("Should authorize since both assertion quantifiers have matching values")
	}

	authorization = createAuthInstance([]config.ClaimAssertion{
		{Name: "children[*].name", AnyOf: []string{"Joe", "Bob", "Sam"}, AllOf: []string{"Eve", "Bob", "Alex"}},
	})

	if isAuthorized(logger, authorization, claims) {
		t.Fatal("Should not authorize since not all values of the allOf quantifier are matched")
	}

	authorization = createAuthInstance([]config.ClaimAssertion{
		{Name: "children[*].name", AnyOf: []string{"Sam"}, AllOf: []string{"Eve", "Bob"}},
	})

	if isAuthorized(logger, authorization, claims) {
		t.Fatal("Should not authorize since no value of the anyOf quantifier is matched")
	}
}

func TestLogAvailableClaimsLogsNamesNotValues(t *testing.T) {
	// Claims values here are deliberately PII-looking. A failing assertion makes
	// the plugin dump the claims it could see, to help the operator; that dump must
	// contain claim NAMES only. Logging values would write every user's email,
	// name and group membership into the proxy log at DEBUG.
	piiValues := map[string]string{
		"email":  "alice.private.address@example.com",
		"name":   "Alice VerySecret Surname",
		"groups": "top-secret-group-membership",
	}

	claims := jwt.MapClaims{}
	for k, v := range piiValues {
		claims[k] = v
	}

	output := captureStdout(t, func() {
		logger := logging.CreateLogger(logging.LevelDebug)
		// Claim does not exist -> logAvailableClaims is reached.
		authorization := createAuthInstance([]config.ClaimAssertion{
			{Name: "nonexistent_claim", AnyOf: []string{"whatever"}},
		})
		if isAuthorized(logger, authorization, claims) {
			t.Error("expected the assertion to fail so the claims are logged")
		}
	})

	if !strings.Contains(output, "Available claims are:") {
		t.Fatalf("expected the available-claims line, got:\n%s", output)
	}
	for name := range piiValues {
		if !strings.Contains(output, name) {
			t.Errorf("expected claim name %q in output, got:\n%s", name, output)
		}
	}
	for name, value := range piiValues {
		if strings.Contains(output, value) {
			t.Errorf("claim VALUE for %q leaked into the log: %s", name, value)
		}
	}
	// Belt and braces: the raw fragment of the PII value must not appear either,
	// in case the value is ever formatted piecewise.
	if strings.Contains(output, "example.com") || strings.Contains(output, "VerySecret") {
		t.Errorf("PII leaked into the log output:\n%s", output)
	}
}

func TestMultipleAssertions(t *testing.T) {
	logger := logging.CreateLogger(logging.LevelDebug)
	claims := getTestClaims()
	authorization := createAuthInstance([]config.ClaimAssertion{
		{Name: "children[*].name", AnyOf: []string{"Joe", "Bob", "Sam"}, AllOf: []string{"Eve", "Bob"}},
		{Name: "name", AnyOf: []string{"Alice", "Alex"}},
	})

	if !isAuthorized(logger, authorization, claims) {
		t.Fatal("Should authorize since both assertions hold against the provided claims")
	}

	authorization = createAuthInstance([]config.ClaimAssertion{
		{Name: "children[*].name", AnyOf: []string{"Joe", "Bob", "Sam"}, AllOf: []string{"Eve", "Bob", "Alex"}},
		{Name: "name", AnyOf: []string{"Alice", "Alex"}},
	})

	if isAuthorized(logger, authorization, claims) {
		t.Fatal("Should not authorize since one of the assertions does not hold")
	}

	authorization = createAuthInstance([]config.ClaimAssertion{
		{Name: "children[*].name", AnyOf: []string{"Joe", "Bob", "Sam"}, AllOf: []string{"Eve", "Bob", "Alex"}},
		{Name: "name", AnyOf: []string{"Alex", "Ben"}},
	})

	if isAuthorized(logger, authorization, claims) {
		t.Fatal("Should not authorize since both of the assertions do not hold")
	}
}
