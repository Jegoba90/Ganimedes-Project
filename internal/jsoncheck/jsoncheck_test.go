package jsoncheck

import (
	"strings"
	"testing"
)

func TestValidateAcceptsUnambiguousJSON(t *testing.T) {
	for _, raw := range []string{
		`null`, `true`, `false`, `0`, `-0.25e+12`, `1e400`, `9007199254740993`,
		`"text"`, `"\ud83d\ude00"`, `"\uD83D\uDE00"`, `"\ufffd"`,
		`{"first":{"name":1},"second":{"name":2}}`,
		`{"a":1,"A":2,"escaped":"\\ud800\"quoted\""}`,
		" \r\n [1, true, {\"é\": \"😀\"}] \t ",
	} {
		t.Run(raw, func(t *testing.T) {
			if err := Validate([]byte(raw)); err != nil {
				t.Fatalf("valid JSON rejected: %v", err)
			}
		})
	}
}

func TestValidateRejectsAmbiguousJSON(t *testing.T) {
	cases := []struct{ name, raw string }{
		{"duplicate", `{"name":1,"name":2}`},
		{"escaped duplicate", `{"name":1,"\u006eame":2}`},
		{"nested duplicate", `[{"outer":{"key":1,"key":2}}]`},
		{"high surrogate", `"\ud800"`},
		{"low surrogate", `"\udc00"`},
		{"two high surrogates", `"\ud800\udbff"`},
		{"high then normal", `"\ud800\u0061"`},
		{"surrogate key", `{"\ud800":1}`},
		{"invalid UTF8", "{\"name\":\"\xff\"}"},
		{"multiple values", `{} []`},
		{"trailing garbage", `{} garbage`},
		{"empty", ``},
		{"incomplete", `{"name":`},
		{"malformed escape", `"\u00xy"`},
		{"truncated escape", `"\u0`},
		{"truncated pair", `"\ud800\u`},
		{"leading zero", `01`},
		{"nonfinite", `NaN`},
		{"trailing comma", `[1,]`},
		{"wrong close", `{"name":1]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := Validate([]byte(tc.raw)); err == nil {
				t.Fatal("ambiguous or malformed JSON accepted")
			}
		})
	}
}

func TestValidateBoundsNesting(t *testing.T) {
	if err := Validate([]byte(strings.Repeat("[", 10000) + "0" + strings.Repeat("]", 10000))); err != nil {
		t.Fatalf("encoding/json depth boundary rejected: %v", err)
	}
	if err := Validate([]byte(strings.Repeat("[", 10001) + "0" + strings.Repeat("]", 10001))); err == nil {
		t.Fatal("unbounded nesting accepted")
	}
}
