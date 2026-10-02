package predicate

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strings"
	"testing"
	"time"
)

// testDef is a Def exercising every operator, function and resolution hook the
// evaluator supports. It mirrors how src/rules/parser.go wires the package: a
// function map for matchers plus logical operators only, which is exactly why
// the operator tests below assert that comparison operators are refused when
// they are not wired up.
func testDef() Def {
	return Def{
		Operators: Operators{
			AND: And,
			OR:  Or,
			NOT: Not,
			EQ:  testEQ,
			NEQ: func(a, b interface{}) BoolPredicate {
				eq := testEQ(a, b)
				return func() bool { return !eq() }
			},
			GT: func(a, b interface{}) BoolPredicate {
				return func() bool { return toFloat(a) > toFloat(b) }
			},
			GE: func(a, b interface{}) BoolPredicate {
				return func() bool { return toFloat(a) >= toFloat(b) }
			},
			LT: func(a, b interface{}) BoolPredicate {
				return func() bool { return toFloat(a) < toFloat(b) }
			},
			LE: func(a, b interface{}) BoolPredicate {
				return func() bool { return toFloat(a) <= toFloat(b) }
			},
		},
		Functions: map[string]interface{}{
			"IsAdmin": func() BoolPredicate { return func() bool { return true } },
			"IsGuest": func() BoolPredicate { return func() bool { return false } },
			"HasRole": func(role ...string) BoolPredicate {
				return func() bool { return len(role) > 0 && role[0] == "admin" }
			},
			"GroupCount": func(groups interface{}) BoolPredicate {
				s, ok := groups.([]string)
				return func() bool { return ok && len(s) > 1 }
			},
			"Literal": func(v interface{}) interface{} { return v },
			"Renamed": func(a, b interface{}) (interface{}, error) {
				if a == nil {
					return nil, nil
				}
				return b, nil
			},
			"NotAnError": func() (interface{}, error) { return nil, nil },
			"BadSecondReturn": func() (interface{}, string) {
				return "x", "not an error"
			},
			"NoReturn": func() {},
			"Bool":     func() interface{} { return true },
		},
		GetIdentifier: func(selector []string) (interface{}, error) {
			switch strings.Join(selector, ".") {
			case "true":
				return true, nil
			case "false":
				return false, nil
			case "num":
				return 5, nil
			case "flt":
				return 2.5, nil
			case "str":
				return "hello", nil
			case "list":
				return []string{"admin", "user"}, nil
			case "headers":
				return map[string][]string{"X-Group": {"admin"}}, nil
			case "plain":
				return map[string]string{"X-Group": "admin"}, nil
			case "nilLiteral":
				return nilLiteral, nil
			case "claim.sub":
				return "subject-1", nil
			case "claim.profile.name":
				return "Jane", nil
			case "explode":
				return nil, explodeError{}
			}
			return nil, fmt.Errorf("unknown identifier %q", strings.Join(selector, "."))
		},
		GetProperty: testGetProperty,
	}
}

// testEQ is a generic equality over the value kinds the evaluator can produce.
// lib.Equals deliberately only handles strings and string slices, so it cannot
// stand in for the host operator when comparing numbers.
func testEQ(a, b interface{}) BoolPredicate {
	return func() bool { return reflect.DeepEqual(a, b) }
}

// testGetProperty adds integer indexing on top of lib.GetStringMapValue so that
// a chained index expression (headers["X-Group"][0]) is reachable. The real
// hosts only wire GetStringMapValue, which refuses non-string keys - that
// refusal is asserted separately.
func testGetProperty(mapVal, keyVal interface{}) (interface{}, error) {
	if idx, ok := keyVal.(int); ok {
		items, ok := mapVal.([]string)
		if !ok {
			return nil, fmt.Errorf("type %T is not indexable", mapVal)
		}
		if idx < 0 || idx >= len(items) {
			return nil, fmt.Errorf("index %d out of range", idx)
		}
		return items[idx], nil
	}
	return GetStringMapValue(mapVal, keyVal)
}

type explodeError struct{}

// nilLiteral is a host identifier that resolves to an untyped nil, used to
// reach the "host function returned a nil value" branch of callFunction without
// relying on the Go `nil` keyword, which the evaluator treats as an identifier.
var nilLiteral = []string(nil)

func (explodeError) Error() string { return "identifier resolution failed" }

func toFloat(v interface{}) float64 {
	switch n := v.(type) {
	case int:
		return float64(n)
	case float64:
		return n
	}
	// Strings and anything else compare as 0 rather than panicking, so that a
	// type-mismatched comparison fails closed instead of taking down the
	// request.
	return 0
}

func newTestParser(t *testing.T, def Def) Parser {
	t.Helper()
	p, err := NewParser(def)
	if err != nil {
		t.Fatalf("NewParser returned an error: %v", err)
	}
	if p == nil {
		t.Fatal("NewParser returned a nil Parser")
	}
	return p
}

// evalBool parses expr and asserts it produced a BoolPredicate, then returns
// its value.
func evalBool(t *testing.T, p Parser, expr string) bool {
	t.Helper()

	v, err := p.Parse(expr)
	if err != nil {
		t.Fatalf("Parse(%q) returned an error: %v", expr, err)
	}
	pred, ok := v.(BoolPredicate)
	if !ok {
		t.Fatalf("Parse(%q) returned %T, want predicate.BoolPredicate", expr, v)
	}
	return pred()
}

// TestNewParser is trivial but cheap: NewParser currently never fails, and the
// test pins that so a future validation change is noticed.
func TestNewParser(t *testing.T) {
	p, err := NewParser(testDef())
	if err != nil {
		t.Fatalf("NewParser returned an error: %v", err)
	}
	if p == nil {
		t.Fatal("NewParser returned a nil Parser")
	}
}

// TestParseOperators walks every operator getJoinFunction knows about, one
// case per token, so a token added to or removed from the switch cannot slip
// through unnoticed.
func TestParseOperators(t *testing.T) {
	tests := []struct {
		name string
		expr string
		want bool
	}{
		{name: "gt true", expr: "num > 3", want: true},
		{name: "gt false", expr: "num > 6", want: false},
		{name: "gte true equal", expr: "num >= 5", want: true},
		{name: "gte true greater", expr: "num >= 4", want: true},
		{name: "gte false", expr: "num >= 6", want: false},
		{name: "lt true", expr: "num < 10", want: true},
		{name: "lt false", expr: "num < 5", want: false},
		{name: "lte true equal", expr: "num <= 5", want: true},
		{name: "lte true greater", expr: "num <= 6", want: true},
		{name: "lte false", expr: "num <= 4", want: false},
		{name: "eq int true", expr: "num == 5", want: true},
		{name: "eq int false", expr: "num == 4", want: false},
		{name: "eq string true", expr: "str == \"hello\"", want: true},
		{name: "eq string false", expr: "str == \"nope\"", want: false},
		{name: "eq slice true", expr: "list == list", want: true},
		{name: "eq slice false", expr: "list == str", want: false},
		{name: "neq true", expr: "num != 4", want: true},
		{name: "neq false", expr: "num != 5", want: false},
		{name: "neq string", expr: "str != \"nope\"", want: true},
		{name: "float literal comparison", expr: "flt >= 2.5", want: true},
		{name: "float literal comparison false", expr: "flt > 2.5", want: false},
		{name: "mixed int and float", expr: "num > 4.5", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newTestParser(t, testDef())
			if got := evalBool(t, p, tt.expr); got != tt.want {
				t.Errorf("Parse(%q) evaluated to %v, want %v", tt.expr, got, tt.want)
			}
		})
	}
}

func TestParseLogicalOperators(t *testing.T) {
	tests := []struct {
		name string
		expr string
		want bool
	}{
		{name: "and both true", expr: "IsAdmin() && IsAdmin()", want: true},
		{name: "and left false", expr: "IsGuest() && IsAdmin()", want: false},
		{name: "and right false", expr: "IsAdmin() && IsGuest()", want: false},
		{name: "or both true", expr: "IsAdmin() || IsAdmin()", want: true},
		{name: "or right true", expr: "IsGuest() || IsAdmin()", want: true},
		{name: "or both false", expr: "IsGuest() || IsGuest()", want: false},
		{name: "not of true", expr: "!IsAdmin()", want: false},
		{name: "not of false", expr: "!IsGuest()", want: true},
		{name: "not of not", expr: "!!IsAdmin()", want: true},
		{name: "parenthesised", expr: "(IsGuest() || IsAdmin()) && IsAdmin()", want: true},
		{name: "parentheses change grouping", expr: "IsGuest() || (IsAdmin() && IsGuest())", want: false},
		{name: "parenthesised comparison", expr: "(num > 1) && (num < 10)", want: true},
		{name: "parenthesised comparison false", expr: "(num > 1) && (num < 2)", want: false},
		{name: "negated comparison", expr: "!(num > 100)", want: true},
		{name: "mixed comparison and calls", expr: "HasRole(\"admin\") && num == 5", want: true},
		{name: "mixed comparison and calls false", expr: "HasRole(\"guest\") && num == 5", want: false},
		{name: "deeper nesting", expr: "((num >= 5) && (num <= 5)) || IsGuest()", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newTestParser(t, testDef())
			if got := evalBool(t, p, tt.expr); got != tt.want {
				t.Errorf("Parse(%q) evaluated to %v, want %v", tt.expr, got, tt.want)
			}
		})
	}
}

func TestParseIdentifierResolution(t *testing.T) {
	tests := []struct {
		name string
		expr string
		want interface{}
	}{
		{name: "bare identifier resolves to raw value", expr: "num", want: 5},
		{name: "bool identifier", expr: "true", want: true},
		{name: "string identifier", expr: "str", want: "hello"},
		{name: "float identifier", expr: "flt", want: 2.5},
		{name: "slice identifier", expr: "list", want: []string{"admin", "user"}},
		{name: "dotted identifier", expr: "claim.sub", want: "subject-1"},
		{name: "deeply dotted identifier", expr: "claim.profile.name", want: "Jane"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newTestParser(t, testDef())

			got, err := p.Parse(tt.expr)
			if err != nil {
				t.Fatalf("Parse(%q) returned an error: %v", tt.expr, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Parse(%q) = %#v (%T), want %#v (%T)", tt.expr, got, got, tt.want, tt.want)
			}
		})
	}
}

func TestParseIndexExpressions(t *testing.T) {
	tests := []struct {
		name string
		expr string
		want interface{}
	}{
		{name: "slice map hit", expr: "headers[\"X-Group\"]", want: []string{"admin"}},
		{name: "string map hit", expr: "plain[\"X-Group\"]", want: "admin"},
		{name: "string map miss", expr: "plain[\"X-Other\"]", want: ""},
		{name: "chained index", expr: "headers[\"X-Group\"][0]", want: "admin"},
		{name: "index inside comparison", expr: `headers["X-Group"][0] == "admin"`, want: BoolPredicate(func() bool { return true })},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newTestParser(t, testDef())

			got, err := p.Parse(tt.expr)
			if err != nil {
				t.Fatalf("Parse(%q) returned an error: %v", tt.expr, err)
			}
			if pred, ok := tt.want.(BoolPredicate); ok {
				actual, ok := got.(BoolPredicate)
				if !ok {
					t.Fatalf("Parse(%q) returned %T, want BoolPredicate", tt.expr, got)
				}
				if actual() != pred() {
					t.Errorf("Parse(%q) evaluated to %v, want %v", tt.expr, actual(), pred())
				}
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Parse(%q) = %#v (%T), want %#v (%T)", tt.expr, got, got, tt.want, tt.want)
			}
		})
	}
}

func TestParseFunctionCalls(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		want    bool
		wantErr bool
	}{
		{name: "no arguments", expr: "IsAdmin()", want: true},
		{name: "variadic arguments", expr: "HasRole(\"admin\")", want: true},
		{name: "variadic arguments false", expr: "HasRole(\"guest\")", want: false},
		{name: "argument from identifier", expr: "GroupCount(list)", want: true},
		{name: "argument from index expression", expr: `GroupCount(headers["X-Group"])`, want: false},
		{name: "bare function name is not a call", expr: "IsAdmin", wantErr: true},
		{name: "wrong case function name", expr: "isadmin()", wantErr: true},
		{name: "call result feeding an operator", expr: "GroupCount(list) && IsAdmin()", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newTestParser(t, testDef())

			got, err := p.Parse(tt.expr)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Parse(%q) unexpectedly succeeded", tt.expr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%q) returned an error: %v", tt.expr, err)
			}
			if pred, ok := got.(BoolPredicate); ok {
				if pred() != tt.want {
					t.Errorf("Parse(%q) evaluated to %v, want %v", tt.expr, pred(), tt.want)
				}
				return
			}
			t.Errorf("Parse(%q) = %#v, want a BoolPredicate", tt.expr, got)
		})
	}
}

// TestParseInvalidExpressions is the fail-closed suite. Every one of these
// inputs is reachable from a user-authored Traefik rule, so each must produce
// an error rather than a value, a panic, or a hang.
func TestParseInvalidExpressions(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		wantErr string
	}{
		{name: "empty input", expr: "", wantErr: "expected operand"},
		{name: "whitespace only", expr: "   ", wantErr: "expected operand"},
		{name: "newline only", expr: "\n", wantErr: "expected operand"},
		{name: "unterminated double quoted string", expr: `"unterminated`, wantErr: "string literal not terminated"},
		{name: "unterminated string with content", expr: `str == "abc`, wantErr: "string literal not terminated"},
		{name: "unterminated rune literal", expr: `'abc`, wantErr: "rune literal not terminated"},
		{name: "unbalanced open paren", expr: "((num > 1)", wantErr: "expected ')'"},
		{name: "unbalanced close paren", expr: "num > 1)", wantErr: "expected 'EOF', found ')'"},
		{name: "lone close paren", expr: ")", wantErr: "expected operand"},
		{name: "empty parens", expr: "()", wantErr: "expected operand"},
		{name: "missing right operand", expr: "num >", wantErr: "expected operand"},
		{name: "missing left operand", expr: "&& num", wantErr: "expected operand"},
		{name: "missing left operand of comparison", expr: "== 5", wantErr: "expected operand"},
		{name: "dangling logical and", expr: "IsAdmin() &&", wantErr: "expected operand"},
		{name: "dangling negation", expr: "!", wantErr: "expected operand"},
		{name: "unterminated call", expr: "IsAdmin(", wantErr: "expected ')', found 'EOF'"},
		{name: "unknown identifier", expr: "doesNotExist", wantErr: `unknown identifier "doesNotExist"`},
		{name: "unknown nested identifier", expr: "claim.profile.missing", wantErr: "unknown identifier"},
		{name: "unknown function", expr: "Nope()", wantErr: "unsupported function: Nope"},
		{name: "function call on non function identifier", expr: "num()", wantErr: "unsupported function: num"},
		{name: "single equals is not equality", expr: "num = 3", wantErr: "expected '=='"},
		{name: "arithmetic is unsupported", expr: "num + 3", wantErr: "+ is not supported"},
		{name: "subtraction is unsupported", expr: "num - 3", wantErr: "- is not supported"},
		{name: "multiplication is unsupported", expr: "num * 3", wantErr: "* is not supported"},
		{name: "division is unsupported", expr: "num / 3", wantErr: "/ is not supported"},
		{name: "modulo is unsupported", expr: "num % 3", wantErr: "% is not supported"},
		{name: "bitwise and is unsupported", expr: "num & 3", wantErr: "& is not supported"},
		{name: "bitwise or is unsupported", expr: "num | 3", wantErr: "| is not supported"},
		{name: "shift is unsupported", expr: "num << 3", wantErr: "<< is not supported"},
		{name: "increment is a syntax error", expr: "num++", wantErr: "expected 'EOF'"},
		{name: "decrement is a syntax error", expr: "num--", wantErr: "expected 'EOF'"},
		{name: "char literal unsupported", expr: `'x'`, wantErr: "unsupported function argument type: 'CHAR"},
		{name: "imaginary literal unsupported", expr: "3i", wantErr: "unsupported function argument type: 'IMAG"},
		{name: "hex int not parseable by Atoi", expr: "0x10", wantErr: "failed to parse argument"},
		{name: "octal int not parseable by Atoi", expr: "0o10", wantErr: "failed to parse argument"},
		{name: "underscore separated int not parseable by Atoi", expr: "1_000", wantErr: "failed to parse argument"},
		{name: "function literal unsupported", expr: "func(){}", wantErr: "*ast.FuncLit is not supported"},
		{name: "composite literal unsupported", expr: "[]int{1}", wantErr: "*ast.CompositeLit is not supported"},
		{name: "map composite literal unsupported", expr: "map[string]int{\"a\": 1}", wantErr: "*ast.CompositeLit is not supported"},
		{name: "type assertion unsupported", expr: "claim.(string)", wantErr: "*ast.TypeAssertExpr is not supported"},
		{name: "pointer dereference unsupported", expr: "*num", wantErr: "*ast.StarExpr is not supported"},
		{name: "slice expression unsupported", expr: "list[1:2]", wantErr: "*ast.SliceExpr is not supported"},
		{name: "bare brace is a syntax error", expr: `{"a": 1}`, wantErr: "expected operand, found '{'"},
		{name: "channel send is a syntax error", expr: "ch <- 1", wantErr: "expected 'EOF', found '<-'"},
		{name: "trailing garbage", expr: "num > 1 garbage", wantErr: "expected 'EOF'"},
		{name: "two statements", expr: "num > 1; num > 1", wantErr: "expected 'EOF'"},
		{name: "nil identifier", expr: "nil", wantErr: `unknown identifier "nil"`},
		{name: "identifier resolver error propagates", expr: "explode", wantErr: "identifier resolution failed"},
		{name: "unsupported selector base", expr: "1 .field", wantErr: "unsupported selector type"},
		{name: "call on a parenthesised expression", expr: "(IsAdmin)()", wantErr: "expected identifier"},
		{name: "function name via selector", expr: "IsAdmin.Nested()", wantErr: "unsupported function: IsAdmin.Nested"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newTestParser(t, testDef())

			got, err := p.Parse(tt.expr)
			if err == nil {
				t.Fatalf("Parse(%q) unexpectedly succeeded and returned %#v", tt.expr, got)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Parse(%q) error = %q, want it to contain %q", tt.expr, err.Error(), tt.wantErr)
			}
			if got != nil {
				t.Errorf("Parse(%q) returned %#v alongside an error, want nil", tt.expr, got)
			}
		})
	}
}

// TestParseTypeMismatchFailsClosed covers expressions that parse cleanly but
// compare values of unrelated types. The evaluator must not panic and must not
// treat the mismatch as a match.
func TestParseTypeMismatchFailsClosed(t *testing.T) {
	tests := []struct {
		name string
		expr string
	}{
		{name: "string equals number", expr: "str == 5"},
		{name: "number equals string", expr: "num == \"hello\""},
		{name: "slice equals string", expr: "list == \"hello\""},
		{name: "string against number comparison", expr: "str > 5"},
		{name: "slice against number comparison", expr: "list > 5"},
		{name: "indexed slice against string", expr: `headers["X-Group"] == "admin"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newTestParser(t, testDef())

			v, err := p.Parse(tt.expr)
			if err != nil {
				t.Fatalf("Parse(%q) returned an error: %v", tt.expr, err)
			}
			pred, ok := v.(BoolPredicate)
			if !ok {
				t.Fatalf("Parse(%q) returned %T, want BoolPredicate", tt.expr, v)
			}
			if pred() {
				t.Errorf("Parse(%q) evaluated to true for a type mismatch, want false", tt.expr)
			}
		})
	}
}

// TestParseGetPropertyNotWired makes sure index expressions are refused when the
// host did not supply a GetProperty hook, rather than silently resolving to
// nil.
func TestParseGetPropertyNotWired(t *testing.T) {
	def := testDef()
	def.GetProperty = nil
	p := newTestParser(t, def)

	for _, expr := range []string{`headers["X-Group"]`, `headers["X-Group"] == list`} {
		if _, err := p.Parse(expr); err == nil {
			t.Errorf("Parse(%q) unexpectedly succeeded with no GetProperty hook", expr)
		} else if !strings.Contains(err.Error(), "properties are not supported") {
			t.Errorf("Parse(%q) error = %q, want it to mention properties are not supported", expr, err.Error())
		}
	}
}

// TestParseGetIdentifierNotWired mirrors the previous test for identifiers.
func TestParseGetIdentifierNotWired(t *testing.T) {
	def := testDef()
	def.GetIdentifier = nil
	p := newTestParser(t, def)

	for _, expr := range []string{"num", "claim.sub", "num > 1"} {
		_, err := p.Parse(expr)
		if err == nil {
			t.Errorf("Parse(%q) unexpectedly succeeded with no GetIdentifier hook", expr)
			continue
		}
		if !strings.Contains(err.Error(), "is not defined") {
			t.Errorf("Parse(%q) error = %q, want it to say the identifier is not defined", expr, err.Error())
		}
	}
}

// TestParseMissingOperatorIsRefused proves the operator switch fails closed:
// an operator token the host did not wire up is an error, never a nil func
// that would be called and panic.
func TestParseMissingOperatorIsRefused(t *testing.T) {
	operators := []struct {
		name     string
		expr     string
		opName   string
		wantErr  string
		dropFunc func(*Operators)
	}{
		{name: "missing AND", expr: "IsAdmin() && IsGuest()", opName: "AND", wantErr: "&& is not supported"},
		{name: "missing OR", expr: "IsAdmin() || IsGuest()", opName: "OR", wantErr: "|| is not supported"},
		{name: "missing NOT", expr: "!IsAdmin()", opName: "NOT", wantErr: "! is not supported"},
		{name: "missing GT", expr: "num > 1", opName: "GT", wantErr: "> is not supported"},
		{name: "missing GE", expr: "num >= 1", opName: "GE", wantErr: ">= is not supported"},
		{name: "missing LT", expr: "num < 1", opName: "LT", wantErr: "< is not supported"},
		{name: "missing LE", expr: "num <= 1", opName: "LE", wantErr: "<= is not supported"},
		{name: "missing EQ", expr: "num == 1", opName: "EQ", wantErr: "== is not supported"},
		{name: "missing NEQ", expr: "num != 1", opName: "NEQ", wantErr: "!= is not supported"},
	}

	for _, tt := range operators {
		t.Run(tt.name, func(t *testing.T) {
			def := testDef()
			switch tt.opName {
			case "AND":
				def.Operators.AND = nil
			case "OR":
				def.Operators.OR = nil
			case "NOT":
				def.Operators.NOT = nil
			case "GT":
				def.Operators.GT = nil
			case "GE":
				def.Operators.GE = nil
			case "LT":
				def.Operators.LT = nil
			case "LE":
				def.Operators.LE = nil
			case "EQ":
				def.Operators.EQ = nil
			case "NEQ":
				def.Operators.NEQ = nil
			}

			p := newTestParser(t, def)

			v, err := p.Parse(tt.expr)
			if err == nil {
				t.Fatalf("Parse(%q) unexpectedly succeeded and returned %#v", tt.expr, v)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Parse(%q) error = %q, want it to contain %q", tt.expr, err.Error(), tt.wantErr)
			}
		})
	}
}

// TestParseFunctionReturnValueHandling covers callFunction's reflection on the
// host's function signatures: one return, two returns, a nil error, a
// non-error second return, and no return at all.
func TestParseFunctionReturnValueHandling(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		want    interface{}
		wantErr string
	}{
		{name: "single return value", expr: "Literal(7)", want: 7},
		{name: "single string return value", expr: "Literal(\"s\")", want: "s"},
		{name: "single bool return value", expr: "Bool()", want: true},
		{name: "two returns with nil error", expr: "Renamed(1, 2)", want: 2},
		{name: "two returns with nil error and nil value", expr: "Renamed(num, nilLiteral)", want: nilLiteral},
		{name: "two returns with nil error only", expr: "NotAnError()", want: nil},
		{name: "non error second return", expr: "BadSecondReturn()", wantErr: "expected error as a second return value"},
		{name: "no return value", expr: "NoReturn()", wantErr: "expected at least one return argument"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newTestParser(t, testDef())

			got, err := p.Parse(tt.expr)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("Parse(%q) unexpectedly succeeded and returned %#v", tt.expr, got)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("Parse(%q) error = %q, want it to contain %q", tt.expr, err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%q) returned an error: %v", tt.expr, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Parse(%q) = %#v, want %#v", tt.expr, got, tt.want)
			}
		})
	}
}

// TestParseRecoversPanickingOperator proves callFunction's recover() converts a
// panic inside a host operator into an error, so one bad rule expression cannot
// take down the middleware.
func TestParseRecoversPanickingOperator(t *testing.T) {
	def := testDef()
	def.Operators.EQ = func(a, b interface{}) BoolPredicate {
		panic("operator exploded")
	}
	p := newTestParser(t, def)

	v, err := p.Parse("num == 5")
	if err == nil {
		t.Fatalf("Parse unexpectedly succeeded and returned %#v", v)
	}
	if !strings.Contains(err.Error(), "operator exploded") {
		t.Errorf("error = %q, want it to contain the panic message", err.Error())
	}
}

// TestParseIdentifierResolverPanicPropagates documents that only calls through
// callFunction are panic-guarded. A panic raised directly by the host's
// GetIdentifier hook is *not* recovered, so the hook must not panic: neither
// production host wires GetIdentifier at all, and src/rules/parser.go passes a
// function map plus logical operators instead, so this path is unreachable from
// user-authored config.
func TestParseIdentifierResolverPanicPropagates(t *testing.T) {
	def := testDef()
	def.GetIdentifier = func([]string) (interface{}, error) { panic("resolver exploded") }
	p := newTestParser(t, def)

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected the panicking GetIdentifier hook to propagate the panic")
		}
		if got, ok := r.(string); !ok || got != "resolver exploded" {
			t.Errorf("recovered %v, want the panic message", r)
		}
	}()

	//nolint:errcheck // the panic above is the assertion
	p.Parse("num")
}

// TestParseRecoversPanickingFunction covers the same for a host function.
func TestParseRecoversPanickingFunction(t *testing.T) {
	def := testDef()
	def.Functions["Explodes"] = func() BoolPredicate { panic("function exploded") }
	p := newTestParser(t, def)

	if _, err := p.Parse("Explodes()"); err == nil {
		t.Fatal("Parse unexpectedly succeeded")
	} else if !strings.Contains(err.Error(), "function exploded") {
		t.Errorf("error = %q, want it to contain the panic message", err.Error())
	}
}

// TestParseHostileInputsDeeplyNestedParens is the stack-safety test. The
// evaluator recurses over the AST, so a rule expression with tens of thousands
// of nested parentheses is the obvious way to try to blow the stack. go/parser
// refuses anything past its nesting limit, and the evaluator must surface that
// as a plain error instead of crashing the process.
//
// The subtests are time-bounded: a hang fails the test rather than wedging CI.
func TestParseHostileInputsDeeplyNestedParens(t *testing.T) {
	tests := []struct {
		name  string
		depth int
	}{
		{name: "100 levels", depth: 100},
		{name: "10000 levels", depth: 10000},
		{name: "50000 levels", depth: 50000},
		{name: "just under the parser nesting limit", depth: 99998},
		{name: "past the parser nesting limit", depth: 100001},
		{name: "far past the parser nesting limit", depth: 200000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newTestParser(t, testDef())

			expr := strings.Repeat("(", tt.depth) + "num" + strings.Repeat(")", tt.depth)

			done := make(chan error, 1)
			go func() {
				defer func() {
					if r := recover(); r != nil {
						done <- fmt.Errorf("Parse panicked: %v", r)
					}
				}()
				_, err := p.Parse(expr)
				done <- err
			}()

			select {
			case err := <-done:
				switch tt.depth {
				case 100, 10000, 50000, 99998:
					// Deep but within the parser's limit: must still evaluate.
					if err != nil {
						t.Fatalf("Parse of %d nested parens returned an error: %v", tt.depth, err)
					}
				default:
					if err == nil {
						t.Fatalf("Parse of %d nested parens unexpectedly succeeded", tt.depth)
					}
					if !strings.Contains(err.Error(), "nesting depth") {
						t.Errorf("error = %q, want the parser nesting depth error", err.Error())
					}
				}
			case <-time.After(30 * time.Second):
				t.Fatalf("Parse of %d nested parens did not finish within 30s", tt.depth)
			}
		})
	}
}

// TestParseHostileInputsUnbalancedParens covers open-only nesting, which the
// evaluator must reject rather than leave the recursion waiting for operands.
func TestParseHostileInputsUnbalancedParens(t *testing.T) {
	p := newTestParser(t, testDef())

	for _, depth := range []int{1, 1000, 100000, 200000} {
		expr := strings.Repeat("(", depth) + "num"

		done := make(chan error, 1)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					done <- fmt.Errorf("Parse panicked: %v", r)
				}
			}()
			_, err := p.Parse(expr)
			done <- err
		}()

		select {
		case err := <-done:
			if err == nil {
				t.Fatalf("Parse of %d unbalanced open parens unexpectedly succeeded", depth)
			}
		case <-time.After(30 * time.Second):
			t.Fatalf("Parse of %d unbalanced open parens did not finish within 30s", depth)
		}
	}
}

// TestParseHostileInputsDeepSelector is the quadratic-time regression test for
// evaluateSelector. It used to prepend the accumulated field list at every
// level of selector recursion, which is O(depth^2) in both allocations and
// copies: a 120KB rule expression of the form "a.a.a…b" took ~16s of CPU and
// a 160KB one took ~32s, which is a trivial CPU-exhaustion DoS from a single
// config value. If this test is ever slow again, the prepend is back.
//
// The bound is deliberately generous: the fixed implementation handles 80k
// levels in single-digit milliseconds, so anything near a second means the
// quadratic behaviour has returned.
func TestParseHostileInputsDeepSelector(t *testing.T) {
	tests := []struct {
		name  string
		depth int
	}{
		{name: "100 levels", depth: 100},
		{name: "10000 levels", depth: 10000},
		{name: "40000 levels", depth: 40000},
		{name: "80000 levels", depth: 80000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newTestParser(t, testDef())

			expr := strings.Repeat("a.", tt.depth) + "b"

			type result struct {
				val interface{}
				err error
			}
			done := make(chan result, 1)
			go func() {
				defer func() {
					if r := recover(); r != nil {
						done <- result{err: fmt.Errorf("Parse panicked: %v", r)}
					}
				}()
				v, err := p.Parse(expr)
				done <- result{val: v, err: err}
			}()

			select {
			case res := <-done:
				// "a" is not a known identifier, so the expression is rejected.
				// The point of the test is that it is rejected *quickly*.
				if res.err == nil {
					t.Fatalf("Parse of an unknown %d-deep selector unexpectedly succeeded: %#v", tt.depth, res.val)
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("Parse of a %d-deep selector did not finish within 10s: evaluateSelector is quadratic again", tt.depth)
			}
		})
	}
}

// TestParseHostileInputsDeepSelectorResolves covers the same shape with a
// selector the host *can* resolve, so the timing assertion runs on the success
// path rather than the error path.
func TestParseHostileInputsDeepSelectorResolves(t *testing.T) {
	const depth = 80000

	def := testDef()
	def.GetIdentifier = func(selector []string) (interface{}, error) {
		if len(selector) != depth+1 {
			return nil, fmt.Errorf("selector has %d fields, want %d", len(selector), depth+1)
		}
		return "resolved", nil
	}
	p := newTestParser(t, def)

	expr := strings.Repeat("a.", depth) + "b"

	type result struct {
		val interface{}
		err error
	}
	done := make(chan result, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- result{err: fmt.Errorf("Parse panicked: %v", r)}
			}
		}()
		v, err := p.Parse(expr)
		done <- result{val: v, err: err}
	}()

	select {
	case res := <-done:
		if res.err != nil {
			t.Fatalf("Parse returned an error: %v", res.err)
		}
		if res.val != "resolved" {
			t.Errorf("Parse = %#v, want \"resolved\"", res.val)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("Parse of a %d-deep resolvable selector did not finish within 10s: evaluateSelector is quadratic again", depth)
	}
}

// TestParseHostileInputsLongFlatExpressions covers the wide (non-nested) shapes:
// long identifier chains, long call chains and long argument lists. These are
// linear and must stay well under a second.
func TestParseHostileInputsLongFlatExpressions(t *testing.T) {
	tests := []struct {
		name string
		expr string
	}{
		{name: "long and chain", expr: strings.Repeat("IsAdmin() && ", 20000) + "IsAdmin()"},
		{name: "long or chain", expr: strings.Repeat("IsGuest() || ", 20000) + "IsGuest()"},
		{name: "long comparison chain", expr: strings.Repeat("num > 1 && ", 20000) + "num > 1"},
		{name: "long nesting of call arguments", expr: "HasRole(" + strings.Repeat(`"admin", `, 2000) + `"admin")`},
		{name: "long negation chain", expr: strings.Repeat("!", 20000) + "IsAdmin()"},
		{name: "long parenthesised but balanced", expr: strings.Repeat("(", 20000) + "IsAdmin()" + strings.Repeat(")", 20000)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newTestParser(t, testDef())

			done := make(chan error, 1)
			go func() {
				defer func() {
					if r := recover(); r != nil {
						done <- fmt.Errorf("Parse panicked: %v", r)
					}
				}()
				_, err := p.Parse(tt.expr)
				done <- err
			}()

			select {
			case <-done:
				// Either an error or a value is fine; only the timing matters.
			case <-time.After(30 * time.Second):
				t.Fatalf("Parse of a %d byte expression did not finish within 30s", len(tt.expr))
			}
		})
	}
}

// TestParseHostileInputsHugeLiterals covers oversized literal payloads. A
// 500KB string or a 100k digit integer must be rejected or returned promptly,
// never used to build something pathological.
func TestParseHostileInputsHugeLiterals(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		wantErr bool
	}{
		{name: "huge string literal", expr: `"` + strings.Repeat("a", 500000) + `"`},
		{name: "huge integer literal", expr: strings.Repeat("9", 100000), wantErr: true},
		{name: "huge float literal", expr: strings.Repeat("9", 100000) + ".0", wantErr: true},
		{name: "huge exponent literal", expr: "1e" + strings.Repeat("9", 100000), wantErr: true},
		{name: "many escape sequences", expr: `"` + strings.Repeat(`\n`, 50000) + `"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newTestParser(t, testDef())

			done := make(chan error, 1)
			go func() {
				defer func() {
					if r := recover(); r != nil {
						done <- fmt.Errorf("Parse panicked: %v", r)
					}
				}()
				_, err := p.Parse(tt.expr)
				done <- err
			}()

			select {
			case err := <-done:
				if tt.wantErr && err == nil {
					t.Fatalf("Parse of %q unexpectedly succeeded", tt.name)
				}
			case <-time.After(30 * time.Second):
				t.Fatalf("Parse of a %d byte literal did not finish within 30s", len(tt.expr))
			}
		})
	}
}

// TestParseHostileInputsRegexpLikeExpressions asserts the evaluator never falls
// back to compiling user input into a regular expression. Every one of these
// looks like a catastrophic-backtracking pattern to a regexp-based evaluator;
// here they must simply be refused or compared literally.
func TestParseHostileInputsRegexpLikeExpressions(t *testing.T) {
	tests := []struct {
		name string
		expr string
	}{
		{name: "nested quantifier", expr: `str == "(a+)+"`},
		{name: "alternation with repetition", expr: `str == "(a|a)*b"`},
		{name: "repeated wildcard", expr: `str == ".*.*.*.*.*x"`},
		{name: "pattern as identifier", expr: `(a+)+`},
		{name: "pattern as function name", expr: `(a+)+()`},
		{name: "unicode class flood", expr: `"\p{L}\p{L}\p{L}\p{L}"`},
		{name: "anchored alternation", expr: `str == "^(a|a|a|a|a|b)+$"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newTestParser(t, testDef())

			done := make(chan error, 1)
			go func() {
				defer func() {
					if r := recover(); r != nil {
						done <- fmt.Errorf("Parse panicked: %v", r)
					}
				}()
				_, err := p.Parse(tt.expr)
				done <- err
			}()

			select {
			case err := <-done:
				// Whether it is accepted as a literal string comparison or
				// rejected, the point is that it terminates and never runs a
				// backtracking matcher.
				_ = err
			case <-time.After(10 * time.Second):
				t.Fatalf("Parse(%q) did not finish within 10s", tt.expr)
			}
		})
	}
}

// TestParseMalformedASTNodes calls the evaluator's internal entry point with
// hand-built AST nodes that a well-formed expression could never produce. This
// covers the default branch of both parse and evaluateExpr, and proves the
// unsupported-node error mentions the node type rather than panicking.
func TestParseMalformedASTNodes(t *testing.T) {
	p := newTestParser(t, testDef()).(*predicateParser)

	unsupported := []struct {
		name    string
		expr    ast.Expr
		wantErr string
	}{
		{name: "bad expr", expr: &ast.BadExpr{}, wantErr: "*ast.BadExpr is not supported"},
		{name: "func lit", expr: &ast.FuncLit{}, wantErr: "*ast.FuncLit is not supported"},
		{name: "composite lit", expr: &ast.CompositeLit{}, wantErr: "*ast.CompositeLit is not supported"},
		{name: "type assertion", expr: &ast.TypeAssertExpr{}, wantErr: "*ast.TypeAssertExpr is not supported"},
		{name: "star expr", expr: &ast.StarExpr{}, wantErr: "*ast.StarExpr is not supported"},
		{name: "slice expr", expr: &ast.SliceExpr{}, wantErr: "*ast.SliceExpr is not supported"},
		{name: "key value expr", expr: &ast.KeyValueExpr{}, wantErr: "*ast.KeyValueExpr is not supported"},
		{name: "array type", expr: &ast.ArrayType{}, wantErr: "*ast.ArrayType is not supported"},
		{name: "map type", expr: &ast.MapType{}, wantErr: "*ast.MapType is not supported"},
		{name: "func type", expr: &ast.FuncType{}, wantErr: "*ast.FuncType is not supported"},
		{name: "chan type", expr: &ast.ChanType{}, wantErr: "*ast.ChanType is not supported"},
		{name: "struct type", expr: &ast.StructType{}, wantErr: "*ast.StructType is not supported"},
		{name: "interface type", expr: &ast.InterfaceType{}, wantErr: "*ast.InterfaceType is not supported"},
		{name: "index with nil X", expr: &ast.IndexExpr{}, wantErr: "is not supported"},
	}

	for _, tt := range unsupported {
		t.Run(tt.name, func(t *testing.T) {
			v, err := p.evaluateExpr(tt.expr)
			if err == nil {
				t.Fatalf("evaluateExpr(%s) unexpectedly succeeded and returned %#v", tt.name, v)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("evaluateExpr(%s) error = %q, want it to contain %q", tt.name, err.Error(), tt.wantErr)
			}
			if v != nil {
				t.Errorf("evaluateExpr(%s) returned %#v alongside an error, want nil", tt.name, v)
			}
		})
	}
}

// TestParseMalformedASTBinaryExpr feeds an empty BinaryExpr to the recursive
// entry point: with no operator token wired up, and with nil operands, the
// evaluator must error rather than panic.
func TestParseMalformedASTBinaryExpr(t *testing.T) {
	t.Run("unsupported operator token", func(t *testing.T) {
		p := newTestParser(t, testDef()).(*predicateParser)

		expr := &ast.BinaryExpr{
			X:  &ast.BasicLit{Kind: token.INT, Value: "1"},
			Y:  &ast.BasicLit{Kind: token.INT, Value: "2"},
			Op: token.ADD,
		}
		v, err := p.parse(expr)
		if err == nil {
			t.Fatalf("parse unexpectedly succeeded and returned %#v", v)
		}
		if !strings.Contains(err.Error(), "+ is not supported") {
			t.Errorf("error = %q, want it to mention the unsupported operator", err.Error())
		}
	})

	t.Run("nil left operand", func(t *testing.T) {
		p := newTestParser(t, testDef()).(*predicateParser)

		expr := &ast.BinaryExpr{
			Y:  &ast.BasicLit{Kind: token.INT, Value: "2"},
			Op: token.LAND,
		}
		if _, err := p.parse(expr); err == nil {
			t.Fatal("parse unexpectedly succeeded with a nil left operand")
		}
	})

	t.Run("nil right operand", func(t *testing.T) {
		p := newTestParser(t, testDef()).(*predicateParser)

		expr := &ast.BinaryExpr{
			X:  &ast.BasicLit{Kind: token.INT, Value: "1"},
			Op: token.LOR,
		}
		if _, err := p.parse(expr); err == nil {
			t.Fatal("parse unexpectedly succeeded with a nil right operand")
		}
	})
}

// TestParseMalformedASTUnaryAndParen covers the remaining top-level branches of
// parse: a ParenExpr with a nil inner expression and a UnaryExpr with no
// operator.
func TestParseMalformedASTUnaryAndParen(t *testing.T) {
	t.Run("paren with nil inner", func(t *testing.T) {
		p := newTestParser(t, testDef()).(*predicateParser)

		if _, err := p.parse(&ast.ParenExpr{}); err == nil {
			t.Fatal("parse unexpectedly succeeded with a nil inner expression")
		}
	})

	t.Run("unary with no operator", func(t *testing.T) {
		p := newTestParser(t, testDef()).(*predicateParser)

		expr := &ast.UnaryExpr{X: &ast.BasicLit{Kind: token.INT, Value: "1"}}
		if _, err := p.parse(expr); err == nil {
			t.Fatal("parse unexpectedly succeeded with no unary operator")
		}
	})
}

// TestParseMalformedASTCallAndIndex covers the call and index branches of
// evaluateExpr with malformed nodes.
func TestParseMalformedASTCallAndIndex(t *testing.T) {
	t.Run("call with nil function", func(t *testing.T) {
		p := newTestParser(t, testDef()).(*predicateParser)

		if _, err := p.evaluateExpr(&ast.CallExpr{}); err == nil {
			t.Fatal("evaluateExpr unexpectedly succeeded with a nil callee")
		}
	})

	t.Run("call with a non identifier callee", func(t *testing.T) {
		p := newTestParser(t, testDef()).(*predicateParser)

		expr := &ast.CallExpr{Fun: &ast.BasicLit{Kind: token.INT, Value: "1"}}
		if _, err := p.evaluateExpr(expr); err == nil {
			t.Fatal("evaluateExpr unexpectedly succeeded with a literal callee")
		}
	})

	t.Run("call with a selector callee rooted at a selector", func(t *testing.T) {
		p := newTestParser(t, testDef()).(*predicateParser)

		expr := &ast.CallExpr{
			Fun: &ast.SelectorExpr{
				X:   &ast.SelectorExpr{Sel: ast.NewIdent("inner")},
				Sel: ast.NewIdent("outer"),
			},
		}
		if _, err := p.evaluateExpr(expr); err == nil {
			t.Fatal("evaluateExpr unexpectedly succeeded with a doubly nested selector callee")
		}
	})

	t.Run("index with a bad argument", func(t *testing.T) {
		p := newTestParser(t, testDef()).(*predicateParser)

		expr := &ast.IndexExpr{
			X:     &ast.Ident{Name: "headers"},
			Index: &ast.BadExpr{},
		}
		if _, err := p.evaluateExpr(expr); err == nil {
			t.Fatal("evaluateExpr unexpectedly succeeded with a malformed index")
		}
	})
}

// TestParseArgumentEvaluationPropagatesErrors checks that a bad argument fails
// the whole call rather than being silently coerced.
func TestParseArgumentEvaluationPropagatesErrors(t *testing.T) {
	p := newTestParser(t, testDef())

	if _, err := p.Parse("GroupCount(doesNotExist)"); err == nil {
		t.Fatal("Parse unexpectedly succeeded with an unresolvable argument")
	}
}

// TestEvaluateSelectorOrdering pins the field order the selector evaluator
// produces, since a mis-ordered list would silently send the wrong path to the
// host's GetIdentifier hook.
func TestEvaluateSelectorOrdering(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   []string
	}{
		{name: "two fields", source: "a.b", want: []string{"a", "b"}},
		{name: "three fields", source: "a.b.c", want: []string{"a", "b", "c"}},
		{name: "many fields", source: "a.b.c.d.e", want: []string{"a", "b", "c", "d", "e"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr, err := parser.ParseExpr(tt.source)
			if err != nil {
				t.Fatalf("ParseExpr(%q) failed: %v", tt.source, err)
			}
			sel, ok := expr.(*ast.SelectorExpr)
			if !ok {
				t.Fatalf("ParseExpr(%q) did not produce a SelectorExpr", tt.source)
			}

			got, err := evaluateSelector(sel, []string{})
			if err != nil {
				t.Fatalf("evaluateSelector(%q) returned an error: %v", tt.source, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("evaluateSelector(%q) = %v, want %v", tt.source, got, tt.want)
			}
		})
	}
}

// TestEvaluateSelectorRejectsNonIdentBase covers the error branch of
// evaluateSelector for every base expression kind that is not a plain
// identifier.
func TestEvaluateSelectorRejectsNonIdentBase(t *testing.T) {
	tests := []struct {
		name string
		expr ast.Expr
	}{
		{name: "numeric literal base", expr: &ast.SelectorExpr{X: &ast.BasicLit{Kind: token.INT, Value: "1"}, Sel: ast.NewIdent("b")}},
		{name: "string literal base", expr: &ast.SelectorExpr{X: &ast.BasicLit{Kind: token.STRING, Value: `"s"`}, Sel: ast.NewIdent("b")}},
		{name: "call base", expr: &ast.SelectorExpr{X: &ast.CallExpr{Fun: ast.NewIdent("f")}, Sel: ast.NewIdent("b")}},
		{name: "index base", expr: &ast.SelectorExpr{X: &ast.IndexExpr{X: ast.NewIdent("m"), Index: &ast.BasicLit{Kind: token.STRING, Value: `"k"`}}, Sel: ast.NewIdent("b")}},
		{name: "paren base", expr: &ast.SelectorExpr{X: &ast.ParenExpr{X: ast.NewIdent("a")}, Sel: ast.NewIdent("b")}},
		{name: "nil base", expr: &ast.SelectorExpr{Sel: ast.NewIdent("b")}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := evaluateSelector(tt.expr.(*ast.SelectorExpr), []string{})
			if err == nil {
				t.Fatalf("evaluateSelector unexpectedly succeeded and returned %v", got)
			}
			if !strings.Contains(err.Error(), "unsupported selector type") {
				t.Errorf("error = %q, want it to mention an unsupported selector type", err.Error())
			}
		})
	}
}

// TestEvaluateSelectorPreservesInheritedFields checks the recursion appends the
// inherited prefix after the selector's own fields. Every reachable caller
// passes an empty prefix, so this pins the contract only.
func TestEvaluateSelectorPreservesInheritedFields(t *testing.T) {
	sel := &ast.SelectorExpr{X: ast.NewIdent("a"), Sel: ast.NewIdent("b")}

	got, err := evaluateSelector(sel, []string{"prefix"})
	if err != nil {
		t.Fatalf("evaluateSelector returned an error: %v", err)
	}
	want := []string{"a", "b", "prefix"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("evaluateSelector = %v, want %v", got, want)
	}
}

// TestLiteralToValue walks the literal kinds go/parser can produce, including
// the ones the evaluator refuses.
func TestLiteralToValue(t *testing.T) {
	tests := []struct {
		name    string
		lit     *ast.BasicLit
		want    interface{}
		wantErr string
	}{
		{name: "integer", lit: &ast.BasicLit{Kind: token.INT, Value: "42"}, want: 42},
		{name: "negative integer", lit: &ast.BasicLit{Kind: token.INT, Value: "-42"}, want: -42},
		{name: "zero", lit: &ast.BasicLit{Kind: token.INT, Value: "0"}, want: 0},
		{name: "integer overflow is rejected", lit: &ast.BasicLit{Kind: token.INT, Value: "99999999999999999999"}, wantErr: "failed to parse argument"},
		{name: "float", lit: &ast.BasicLit{Kind: token.FLOAT, Value: "1.5"}, want: 1.5},
		{name: "negative float", lit: &ast.BasicLit{Kind: token.FLOAT, Value: "-1.5"}, want: -1.5},
		{name: "float exponent", lit: &ast.BasicLit{Kind: token.FLOAT, Value: "1e3"}, want: float64(1000)},
		{name: "float overflow", lit: &ast.BasicLit{Kind: token.FLOAT, Value: "1e999"}, wantErr: "failed to parse argument"},
		{name: "string", lit: &ast.BasicLit{Kind: token.STRING, Value: `"hello"`}, want: "hello"},
		{name: "escaped string", lit: &ast.BasicLit{Kind: token.STRING, Value: `"a\nb"`}, want: "a\nb"},
		{name: "raw string", lit: &ast.BasicLit{Kind: token.STRING, Value: "`raw\nvalue`"}, want: "raw\nvalue"},
		{name: "empty string", lit: &ast.BasicLit{Kind: token.STRING, Value: `""`}, want: ""},
		{name: "bad escape", lit: &ast.BasicLit{Kind: token.STRING, Value: `"\q"`}, wantErr: "failed to parse argument"},
		{name: "char is unsupported", lit: &ast.BasicLit{Kind: token.CHAR, Value: `'a'`}, wantErr: "unsupported function argument type: 'CHAR'"},
		{name: "imaginary is unsupported", lit: &ast.BasicLit{Kind: token.IMAG, Value: "3i"}, wantErr: "unsupported function argument type: 'IMAG'"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := literalToValue(tt.lit)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("literalToValue(%s) unexpectedly succeeded and returned %#v", tt.lit.Value, got)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("literalToValue(%s) error = %q, want it to contain %q", tt.lit.Value, err.Error(), tt.wantErr)
				}
				if got != nil {
					t.Errorf("literalToValue(%s) returned %#v alongside an error, want nil", tt.lit.Value, got)
				}
				return
			}

			if err != nil {
				t.Fatalf("literalToValue(%s) returned an error: %v", tt.lit.Value, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("literalToValue(%s) = %#v (%T), want %#v (%T)", tt.lit.Value, got, got, tt.want, tt.want)
			}
		})
	}
}

// TestGetIdentifierNode covers the helper that extracts a call target name.
func TestGetIdentifierNode(t *testing.T) {
	tests := []struct {
		name    string
		node    ast.Node
		want    string
		wantErr string
	}{
		{name: "plain identifier", node: ast.NewIdent("IsAdmin"), want: "IsAdmin"},
		{name: "one level selector", node: &ast.SelectorExpr{X: ast.NewIdent("pkg"), Sel: ast.NewIdent("Fn")}, want: "pkg.Fn"},
		{name: "two level selector", node: &ast.SelectorExpr{X: &ast.SelectorExpr{X: ast.NewIdent("a"), Sel: ast.NewIdent("b")}, Sel: ast.NewIdent("c")}, wantErr: "expected selector identifier"},
		{name: "literal", node: &ast.BasicLit{Kind: token.STRING, Value: `"s"`}, wantErr: "expected identifier"},
		{name: "call", node: &ast.CallExpr{Fun: ast.NewIdent("f")}, wantErr: "expected identifier"},
		{name: "parens", node: &ast.ParenExpr{X: ast.NewIdent("a")}, wantErr: "expected identifier"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getIdentifier(tt.node)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("getIdentifier unexpectedly succeeded and returned %q", got)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("getIdentifier error = %q, want it to contain %q", err.Error(), tt.wantErr)
				}
				if got != "" {
					t.Errorf("getIdentifier returned %q alongside an error, want an empty string", got)
				}
				return
			}

			if err != nil {
				t.Fatalf("getIdentifier returned an error: %v", err)
			}
			if got != tt.want {
				t.Errorf("getIdentifier = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestGetJoinFunctionRefusesUnwiredTokens covers the operator lookup directly,
// including the tokens the switch does not name at all.
func TestGetJoinFunctionRefuseUnwiredTokens(t *testing.T) {
	p := &predicateParser{}

	tokens := []struct {
		name    string
		op      token.Token
		wantErr string
	}{
		{name: "AND", op: token.LAND, wantErr: "&& is not supported"},
		{name: "OR", op: token.LOR, wantErr: "|| is not supported"},
		{name: "NOT", op: token.NOT, wantErr: "! is not supported"},
		{name: "GT", op: token.GTR, wantErr: "> is not supported"},
		{name: "GE", op: token.GEQ, wantErr: ">= is not supported"},
		{name: "LT", op: token.LSS, wantErr: "< is not supported"},
		{name: "LE", op: token.LEQ, wantErr: "<= is not supported"},
		{name: "EQ", op: token.EQL, wantErr: "== is not supported"},
		{name: "NEQ", op: token.NEQ, wantErr: "!= is not supported"},
		{name: "ADD", op: token.ADD, wantErr: "+ is not supported"},
		{name: "SUB", op: token.SUB, wantErr: "- is not supported"},
		{name: "MUL", op: token.MUL, wantErr: "* is not supported"},
		{name: "QUO", op: token.QUO, wantErr: "/ is not supported"},
		{name: "REM", op: token.REM, wantErr: "% is not supported"},
		{name: "AND_NOT", op: token.AND_NOT, wantErr: "&^ is not supported"},
		{name: "XOR", op: token.XOR, wantErr: "^ is not supported"},
		{name: "SHL", op: token.SHL, wantErr: "<< is not supported"},
		{name: "ARROW", op: token.ARROW, wantErr: "<- is not supported"},
		{name: "ILLEGAL", op: token.ILLEGAL, wantErr: "is not supported"},
		{name: "EOF", op: token.EOF, wantErr: "is not supported"},
	}

	for _, tt := range tokens {
		t.Run(tt.name, func(t *testing.T) {
			fn, err := p.getJoinFunction(tt.op)
			if err == nil {
				t.Fatalf("getJoinFunction(%s) unexpectedly succeeded and returned %#v", tt.op, fn)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("getJoinFunction(%s) error = %q, want it to contain %q", tt.op, err.Error(), tt.wantErr)
			}
			if fn != nil {
				t.Errorf("getJoinFunction(%s) returned %#v alongside an error, want nil", tt.op, fn)
			}
		})
	}
}

// TestGetJoinFunctionResolvesWiredTokens is the positive half of the previous
// test: with a full Operators block every named token resolves.
func TestGetJoinFunctionResolvesWiredTokens(t *testing.T) {
	p := newTestParser(t, testDef()).(*predicateParser)

	tokens := []token.Token{token.NOT, token.LAND, token.LOR, token.GTR, token.GEQ, token.LSS, token.LEQ, token.EQL, token.NEQ}

	for _, op := range tokens {
		fn, err := p.getJoinFunction(op)
		if err != nil {
			t.Errorf("getJoinFunction(%s) returned an error: %v", op, err)
			continue
		}
		if fn == nil {
			t.Errorf("getJoinFunction(%s) returned a nil function", op)
		}
	}
}

// TestGetFunctionUnknown covers the function map lookup error.
func TestGetFunctionUnknown(t *testing.T) {
	p := newTestParser(t, testDef()).(*predicateParser)

	if _, err := p.getFunction("DoesNotExist"); err == nil {
		t.Fatal("getFunction unexpectedly succeeded for an unknown name")
	} else if !strings.Contains(err.Error(), "unsupported function: DoesNotExist") {
		t.Errorf("error = %q, want it to name the unsupported function", err.Error())
	}

	fn, err := p.getFunction("IsAdmin")
	if err != nil {
		t.Fatalf("getFunction returned an error: %v", err)
	}
	if fn == nil {
		t.Error("getFunction returned a nil function for a known name")
	}
}

// TestCallFunctionNilAndNonFunc covers the reflection entry point being handed
// something it cannot call.
func TestCallFunctionNilAndNonFunc(t *testing.T) {
	t.Run("nil function", func(t *testing.T) {
		// reflect.ValueOf(nil).Call panics; the recover() must turn it into an
		// error rather than letting it escape.
		_, err := callFunction(nil, []interface{}{})
		if err == nil {
			t.Fatal("callFunction with a nil function unexpectedly succeeded")
		}
	})

	t.Run("non function value", func(t *testing.T) {
		_, err := callFunction(42, []interface{}{})
		if err == nil {
			t.Fatal("callFunction with a non function unexpectedly succeeded")
		}
	})

	t.Run("wrong argument count", func(t *testing.T) {
		_, err := callFunction(func(a int) bool { return true }, []interface{}{1, 2})
		if err == nil {
			t.Fatal("callFunction with too many arguments unexpectedly succeeded")
		}
	})

	t.Run("wrong argument type", func(t *testing.T) {
		_, err := callFunction(func(a int) bool { return true }, []interface{}{"not an int"})
		if err == nil {
			t.Fatal("callFunction with a wrong argument type unexpectedly succeeded")
		}
	})

	t.Run("single return value", func(t *testing.T) {
		got, err := callFunction(func(a int) int { return a * 2 }, []interface{}{21})
		if err != nil {
			t.Fatalf("callFunction returned an error: %v", err)
		}
		if got != 42 {
			t.Errorf("callFunction = %#v, want 42", got)
		}
	})

	t.Run("two returns with error", func(t *testing.T) {
		_, err := callFunction(func() (int, error) { return 0, errors.New("boom") }, nil)
		if err == nil || err.Error() != "boom" {
			t.Errorf("callFunction error = %v, want boom", err)
		}
	})
}
