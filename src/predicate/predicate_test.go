package predicate

import (
	"strings"
	"testing"
	"time"
)

// runWithin runs fn on a goroutine and fails the test if it has not finished
// within limit. A hang fails the test rather than wedging the suite; a panic in
// fn is re-raised on the calling goroutine so it is not silently swallowed.
func runWithin(t *testing.T, limit time.Duration, fn func()) {
	t.Helper()

	done := make(chan interface{}, 1)
	go func() {
		defer func() { done <- recover() }()
		fn()
	}()

	select {
	case r := <-done:
		if r != nil {
			panic(r)
		}
	case <-time.After(limit):
		t.Fatalf("did not finish within %s", limit)
	}
}

// TestDefOperatorSurface walks the exported Operators struct so that adding or
// renaming a field is a compile-visible change and each field is exercised at
// least once by the operator table in parse_test.go.
func TestDefOperatorSurface(t *testing.T) {
	def := testDef()

	if def.Operators.AND == nil || def.Operators.OR == nil || def.Operators.NOT == nil {
		t.Error("logical operators must all be wired up")
	}
	if def.Operators.EQ == nil || def.Operators.NEQ == nil {
		t.Error("equality operators must both be wired up")
	}
	if def.Operators.LT == nil || def.Operators.GT == nil || def.Operators.LE == nil || def.Operators.GE == nil {
		t.Error("ordering operators must all be wired up")
	}
	if def.GetIdentifier == nil {
		t.Error("GetIdentifier must be wired up")
	}
	if def.GetProperty == nil {
		t.Error("GetProperty must be wired up")
	}
}

// TestParseIsReusableAcrossExpressions guards against the parser caching state
// between calls: the same Parser instance must handle a sequence of different
// expressions, and a failed parse must not poison the next one.
func TestParseIsReusableAcrossExpressions(t *testing.T) {
	p := newTestParser(t, testDef())

	steps := []struct {
		expr string
		want bool
	}{
		{expr: "num == 5", want: true},
		{expr: "num == 6", want: false},
		{expr: "doesNotExist", want: false}, // error
		{expr: "IsAdmin()", want: true},
		{expr: "num != 5", want: false},
		{expr: "IsGuest()", want: false},
		{expr: "str == \"hello\"", want: true},
	}

	for _, step := range steps {
		v, err := p.Parse(step.expr)

		if step.expr == "doesNotExist" {
			if err == nil {
				t.Fatalf("Parse(%q) unexpectedly succeeded", step.expr)
			}
			continue
		}

		if err != nil {
			t.Fatalf("Parse(%q) returned an error: %v", step.expr, err)
		}
		pred, ok := v.(BoolPredicate)
		if !ok {
			t.Fatalf("Parse(%q) returned %T, want BoolPredicate", step.expr, v)
		}
		if pred() != step.want {
			t.Errorf("Parse(%q) evaluated to %v, want %v", step.expr, pred(), step.want)
		}
	}
}

// TestParseResultIsIndependentPerCall asserts the parser does not hand back a
// shared closure whose state one request can corrupt another's.
func TestParseResultIsIndependentPerCall(t *testing.T) {
	p := newTestParser(t, testDef())

	firstV, err := p.Parse("num == 5")
	if err != nil {
		t.Fatalf("Parse returned an error: %v", err)
	}
	secondV, err := p.Parse("num == 6")
	if err != nil {
		t.Fatalf("Parse returned an error: %v", err)
	}

	first := firstV.(BoolPredicate)
	second := secondV.(BoolPredicate)

	if !first() {
		t.Error("first predicate evaluated to false, want true")
	}
	if second() {
		t.Error("second predicate evaluated to true, want false")
	}
	// Re-evaluating the first must be stable.
	if !first() {
		t.Error("first predicate is not stable across evaluations")
	}
}

// TestParseTrailingWhitespaceAndComments covers inputs a human would type.
func TestParseTrailingWhitespaceAndComments(t *testing.T) {
	p := newTestParser(t, testDef())

	for _, expr := range []string{
		"  num == 5  ",
		"num == 5 // trailing comment",
		"num == 5\n",
		"\n\tnum == 5\n",
		"((num == 5))",
	} {
		if !evalBool(t, p, expr) {
			t.Errorf("Parse(%q) evaluated to false, want true", expr)
		}
	}

	// A line comment consumes the rest of the input, so an operand after it
	// must not be silently dropped.
	if _, err := p.Parse("num == 5 // IsGuest()"); err != nil {
		t.Errorf("Parse with a trailing comment returned an error: %v", err)
	}
}

// TestParseSemanticsDoNotDependOnWhitespace guards against an operator that
// evaluates its arguments in a whitespace-sensitive way.
func TestParseSemanticsDoNotDependOnWhitespace(t *testing.T) {
	p := newTestParser(t, testDef())

	spacings := []string{
		"IsAdmin() && IsAdmin()",
		"IsAdmin()&&IsAdmin()",
		"IsAdmin()  &&  IsAdmin()",
		"IsAdmin()\t&&\tIsAdmin()",
		"IsAdmin() &&\nIsAdmin()",
	}

	for _, expr := range spacings {
		if !evalBool(t, p, expr) {
			t.Errorf("Parse(%q) evaluated to false, want true", expr)
		}
	}
}

// TestParseRealisticRuleExpression mirrors the shape src/rules/parser.go wires
// up: a function map of matchers plus AND/OR/NOT and no comparison operators at
// all. Any comparison in such a rule must be refused rather than silently
// accepted.
func TestParseRealisticRuleExpression(t *testing.T) {
	// matcher stands in for a Traefik matcher such as PathPrefix.
	matcher := func(name string) func(...string) BoolPredicate {
		return func(values ...string) BoolPredicate {
			return func() bool { return len(values) > 0 && values[0] != "" }
		}
	}

	def := Def{
		Operators: Operators{
			AND: And,
			OR:  Or,
			NOT: Not,
		},
		Functions: map[string]interface{}{
			"PathPrefix": matcher("PathPrefix"),
			"Header":     matcher("Header"),
			"ClientIP":   matcher("ClientIP"),
		},
	}
	p := newTestParser(t, def)

	tests := []struct {
		name string
		expr string
		want bool
	}{
		{name: "single matcher", expr: `PathPrefix("/api")`, want: true},
		{name: "and of matchers", expr: `PathPrefix("/api") && Header("X-A")`, want: true},
		{name: "or of matchers", expr: `PathPrefix("") || Header("X-A")`, want: true},
		{name: "negated matcher", expr: `!PathPrefix("")`, want: true},
		{name: "negated and", expr: `!PathPrefix("") && !Header("")`, want: true},
		{name: "grouped", expr: `(PathPrefix("/api") && Header("X-A")) || ClientIP("10.0.0.1")`, want: true},
		{name: "empty argument fails", expr: `PathPrefix("")`, want: false},
		{name: "empty argument in and fails", expr: `PathPrefix("/api") && Header("")`, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := evalBool(t, p, tt.expr); got != tt.want {
				t.Errorf("Parse(%q) evaluated to %v, want %v", tt.expr, got, tt.want)
			}
		})
	}

	// Comparison operators are not wired in this Def, so they must fail.
	for _, expr := range []string{
		`PathPrefix("/api") == PathPrefix("/api")`,
		`Header("X-A") != Header("X-B")`,
	} {
		if _, err := p.Parse(expr); err == nil {
			t.Errorf("Parse(%q) unexpectedly succeeded with no comparison operator wired up", expr)
		}
	}

	// An unwired matcher must fail, not resolve to a permissive predicate.
	for _, expr := range []string{`Unknown("x")`, `pathprefix("/api")`} {
		if _, err := p.Parse(expr); err == nil {
			t.Errorf("Parse(%q) unexpectedly succeeded for an unknown matcher", expr)
		}
	}
}

// TestParseIdentifierHookReceivesExactPath checks that the selector evaluator
// hands the host hook the exact dotted path, with nothing dropped, reordered or
// duplicated. This is the property the linear rewrite in evaluateSelector has
// to preserve.
func TestParseIdentifierHookReceivesExactPath(t *testing.T) {
	tests := []struct {
		expr string
		want []string
	}{
		{expr: "a", want: []string{"a"}},
		{expr: "a.b", want: []string{"a", "b"}},
		{expr: "a.b.c", want: []string{"a", "b", "c"}},
		{expr: "a.b.c.d.e.f.g", want: []string{"a", "b", "c", "d", "e", "f", "g"}},
	}

	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			var got []string

			def := Def{
				Operators: Operators{AND: And, OR: Or, NOT: Not},
				GetIdentifier: func(selector []string) (interface{}, error) {
					// Copy so a later mutation cannot mask a wrong order.
					got = append([]string(nil), selector...)
					return BoolPredicate(func() bool { return true }), nil
				},
			}
			p := newTestParser(t, def)

			if _, err := p.Parse(tt.expr); err != nil {
				t.Fatalf("Parse(%q) returned an error: %v", tt.expr, err)
			}

			if len(got) != len(tt.want) {
				t.Fatalf("GetIdentifier received %v (%d fields), want %v (%d fields)", got, len(got), tt.want, len(tt.want))
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("GetIdentifier received %v, want %v (field %d differs)", got, tt.want, i)
				}
			}
		})
	}
}

// TestParseDeepSelectorStaysLinear is the tight timing assertion for the
// quadratic fix, kept separate from the hostile-input suite so a regression
// reports as a focused failure. A linear walk handles 80k levels in
// single-digit milliseconds; the buggy prepend took over 30 seconds.
func TestParseDeepSelectorStaysLinear(t *testing.T) {
	const (
		shallow = 20000
		deep    = 80000
	)

	var got []string
	def := Def{
		Operators: Operators{AND: And, OR: Or, NOT: Not},
		GetIdentifier: func(selector []string) (interface{}, error) {
			got = selector
			return BoolPredicate(func() bool { return true }), nil
		},
	}
	p := newTestParser(t, def)

	run := func(depth int) {
		expr := strings.Repeat("a.", depth) + "b"
		if _, err := p.Parse(expr); err != nil {
			t.Fatalf("Parse of a %d-deep selector returned an error: %v", depth, err)
		}
		if len(got) != depth+1 {
			t.Fatalf("GetIdentifier received %d fields for a %d-deep selector, want %d", len(got), depth, depth+1)
		}
	}

	run(shallow)
	// Bound generously: the fixed implementation is ~1000x under this. The
	// point is that the assertion is a wall-clock guard against super-linear
	// behaviour, not a precise benchmark.
	runWithin(t, 5*time.Second, func() { run(deep) })
}
