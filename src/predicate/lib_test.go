package predicate

import (
	"reflect"
	"testing"
)

func TestGetStringMapValue(t *testing.T) {
	tests := []struct {
		name    string
		mapVal  interface{}
		keyVal  interface{}
		want    interface{}
		wantErr string
	}{
		{
			name:   "string map hit",
			mapVal: map[string]string{"foo": "bar"},
			keyVal: "foo",
			want:   "bar",
		},
		{
			name:   "string map miss yields empty string not nil",
			mapVal: map[string]string{"foo": "bar"},
			keyVal: "nope",
			want:   "",
		},
		{
			name:   "empty string map yields typed empty string",
			mapVal: map[string]string{},
			keyVal: "foo",
			want:   "",
		},
		{
			name:   "slice map hit",
			mapVal: map[string][]string{"foo": {"bar", "baz"}},
			keyVal: "foo",
			want:   []string{"bar", "baz"},
		},
		{
			name:   "slice map miss yields typed nil slice",
			mapVal: map[string][]string{"foo": {"bar"}},
			keyVal: "nope",
			want:   []string(nil),
		},
		{
			name:   "empty slice map yields typed nil slice",
			mapVal: map[string][]string{},
			keyVal: "foo",
			want:   []string(nil),
		},
		{
			name:    "non string key rejected",
			mapVal:  map[string]string{"foo": "bar"},
			keyVal:  42,
			wantErr: "only string keys are supported",
		},
		{
			name:    "unsupported map type rejected",
			mapVal:  map[string]int{"foo": 1},
			keyVal:  "foo",
			wantErr: "type map[string]int is not supported",
		},
		{
			name:    "nil map rejected",
			mapVal:  nil,
			keyVal:  "foo",
			wantErr: "type <nil> is not supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetStringMapValue(tt.mapVal, tt.keyVal)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error %q, got nil", tt.wantErr)
				}
				if err.Error() != tt.wantErr {
					t.Errorf("expected error %q, got %q", tt.wantErr, err.Error())
				}
				if got != nil {
					t.Errorf("expected nil value on error, got %#v", got)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			// reflect.DeepEqual distinguishes the typed-empty-string / typed-nil-slice
			// cases from a bare nil, which is the whole point of the helper.
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("expected %#v (%T), got %#v (%T)", tt.want, tt.want, got, got)
			}
		})
	}
}

func TestEquals(t *testing.T) {
	tests := []struct {
		name string
		a    interface{}
		b    interface{}
		want bool
	}{
		{name: "equal strings", a: "a", b: "a", want: true},
		{name: "different strings", a: "a", b: "b", want: false},
		{name: "string vs number", a: "a", b: 1, want: false},
		{name: "number vs string", a: 1, b: "a", want: false},
		{name: "equal slices", a: []string{"a", "b"}, b: []string{"a", "b"}, want: true},
		{name: "different order slices", a: []string{"a", "b"}, b: []string{"b", "a"}, want: false},
		{name: "different length slices", a: []string{"a"}, b: []string{"a", "b"}, want: false},
		{name: "slice vs string", a: []string{"a"}, b: "a", want: false},
		{name: "two empty slices", a: []string{}, b: []string{}, want: true},
		{name: "unsupported type", a: 1, b: 1, want: false},
		{name: "bool vs bool", a: true, b: true, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Equals(tt.a, tt.b)(); got != tt.want {
				t.Errorf("Equals(%#v, %#v) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		name string
		a    interface{}
		b    interface{}
		want bool
	}{
		{name: "present", a: []string{"a", "b"}, b: "b", want: true},
		{name: "absent", a: []string{"a", "b"}, b: "c", want: false},
		{name: "empty slice", a: []string{}, b: "a", want: false},
		{name: "nil slice", a: []string(nil), b: "a", want: false},
		{name: "non slice left operand", a: "a", b: "a", want: false},
		{name: "non string right operand", a: []string{"a"}, b: 1, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Contains(tt.a, tt.b)(); got != tt.want {
				t.Errorf("Contains(%#v, %#v) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestAndOrNot(t *testing.T) {
	tr := BoolPredicate(func() bool { return true })
	fa := BoolPredicate(func() bool { return false })

	tests := []struct {
		name string
		got  bool
		want bool
	}{
		{name: "and true true", got: And(tr, tr)(), want: true},
		{name: "and true false", got: And(tr, fa)(), want: false},
		{name: "and false true", got: And(fa, tr)(), want: false},
		{name: "and false false", got: And(fa, fa)(), want: false},
		{name: "or true true", got: Or(tr, tr)(), want: true},
		{name: "or true false", got: Or(tr, fa)(), want: true},
		{name: "or false true", got: Or(fa, tr)(), want: true},
		{name: "or false false", got: Or(fa, fa)(), want: false},
		{name: "not true", got: Not(tr)(), want: false},
		{name: "not false", got: Not(fa)(), want: true},
		{name: "double negation", got: Not(Not(tr))(), want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("expected %v, got %v", tt.want, tt.got)
			}
		})
	}
}

// TestAndShortCircuit guards the && semantics the parser relies on: the right
// operand must not be evaluated when the left one is false, otherwise an
// expression like "false && Undefined()" would blow up at evaluation time
// instead of evaluating to false.
func TestAndShortCircuit(t *testing.T) {
	evaluated := false
	boom := BoolPredicate(func() bool {
		evaluated = true
		return true
	})

	if And(BoolPredicate(func() bool { return false }), boom)() {
		t.Fatal("expected false && x to be false")
	}
	if evaluated {
		t.Error("And evaluated its right operand despite a false left operand")
	}

	if !And(BoolPredicate(func() bool { return true }), boom)() {
		t.Fatal("expected true && x to be true")
	}
	if !evaluated {
		t.Error("And did not evaluate its right operand when the left was true")
	}
}

type taggedInner struct {
	Alpha string `json:"alpha"`
}

type taggedOuter struct {
	Inner    taggedInner  `json:"inner"`
	PtrInner *taggedInner `json:"ptrInner"`
	Count    int          `json:"count"`
	private  string       //nolint:unused // intentionally untagged/ignored by GetFieldByTag
}

func TestGetFieldByTag(t *testing.T) {
	inner := taggedInner{Alpha: "value"}
	obj := taggedOuter{Inner: inner, PtrInner: &inner, Count: 7}

	// GetFieldByTag walks pointers/interfaces on the way down but must not
	// dereference a nil pointer into a panic.
	nilPtrObj := taggedOuter{Count: 1}

	tests := []struct {
		name       string
		ival       interface{}
		fieldNames []string
		want       interface{}
		wantErr    string
	}{
		{name: "top level field", ival: obj, fieldNames: []string{"count"}, want: 7},
		{name: "nested field", ival: obj, fieldNames: []string{"inner", "alpha"}, want: "value"},
		{name: "through pointer field", ival: obj, fieldNames: []string{"ptrInner", "alpha"}, want: "value"},
		{name: "intermediate struct", ival: obj, fieldNames: []string{"inner"}, want: inner},
		{name: "pointer to struct root", ival: &obj, fieldNames: []string{"count"}, want: 7},
		{name: "unknown top level field", ival: obj, fieldNames: []string{"nope"}, wantErr: "field name nope is not found"},
		// Note: the recursive call passes only the remaining path, so the error
		// message reports the remaining segment rather than the full dotted path.
		{name: "unknown nested field", ival: obj, fieldNames: []string{"inner", "nope"}, wantErr: "field name nope is not found"},
		{name: "path deeper than struct", ival: obj, fieldNames: []string{"inner", "alpha", "deeper"}, wantErr: "field name deeper is not found"},
		{name: "empty field names", ival: obj, fieldNames: nil, wantErr: "missing field names"},
		{name: "nil root", ival: nil, fieldNames: []string{"count"}, wantErr: "field name count is not found"},
		{name: "non struct root", ival: "a string", fieldNames: []string{"count"}, wantErr: "field name count is not found"},
		{name: "nil pointer field traversal does not panic", ival: nilPtrObj, fieldNames: []string{"ptrInner", "alpha"}, wantErr: "field name alpha is not found"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetFieldByTag(tt.ival, "json", tt.fieldNames)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error %q, got nil", tt.wantErr)
				}
				if err.Error() != tt.wantErr {
					t.Errorf("expected error %q, got %q", tt.wantErr, err.Error())
				}
				if got != nil {
					t.Errorf("expected nil value on error, got %#v", got)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("expected %#v, got %#v", tt.want, got)
			}
		})
	}
}

// TestGetFieldByTagUntaggedFieldIgnored documents that fields without the
// requested tag are never matched, so an unexported or differently-tagged
// field cannot be reached by an expression.
func TestGetFieldByTagUntaggedFieldIgnored(t *testing.T) {
	obj := taggedOuter{Count: 7}

	_, err := GetFieldByTag(obj, "json", []string{"private"})
	if err == nil {
		t.Fatal("expected an untagged field to be unreachable, got nil error")
	}
	if err.Error() != "field name private is not found" {
		t.Errorf("unexpected error: %v", err)
	}
}
