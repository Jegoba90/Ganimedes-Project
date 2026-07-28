package audit

import (
	"math"
	"testing"
)

// TestCanonicalize_StringEscaping checks RFC 8785 string serialization on the
// tricky characters from the spec's own §3.2.3 example: a non-ASCII code point
// (kept literal), a control with no shortcut (), a control with one (\n),
// and an escaped quote and backslash. The solidus is NOT escaped. The literals
// are written with Go escapes so the source stays single-line and unambiguous.
func TestCanonicalize_StringEscaping(t *testing.T) {
	// JSON input whose "s" value is: € $ U+000F <newline> A ' B " \ /
	input := "{\"s\":\"\\u20ac$\\u000f\\nA'B\\\"\\\\/\"}"
	want := "{\"s\":\"€$\\u000f\\nA'B\\\"\\\\/\"}"

	got, err := canonicalizeJSON([]byte(input))
	if err != nil {
		t.Fatalf("canonicalizeJSON: %v", err)
	}
	if string(got) != want {
		t.Errorf("string escaping:\n got: %s\nwant: %s", got, want)
	}
}

// TestCanonicalize_RFC8785Numbers reproduces the number column of the RFC 8785
// §3.2.3 example: the same literals the spec shows, canonicalized inside a JSON
// array so both the ECMAScript number format and array-order preservation are
// exercised.
func TestCanonicalize_RFC8785Numbers(t *testing.T) {
	input := `{"n":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001]}`
	want := `{"n":[333333333.3333333,1e+30,4.5,0.002,1e-27]}`

	got, err := canonicalizeJSON([]byte(input))
	if err != nil {
		t.Fatalf("canonicalizeJSON: %v", err)
	}
	if string(got) != want {
		t.Errorf("number canonicalization:\n got: %s\nwant: %s", got, want)
	}
}

// TestES6Number pins the ECMAScript number formatting across the interesting
// boundaries: the positional/exponential switchover, exponent zero-stripping,
// signed zero, and trailing-zero removal.
func TestES6Number(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{0, "0"},
		{math.Copysign(0, -1), "0"}, // negative zero normalizes to "0"
		{1, "1"},
		{-5, "-5"},
		{4.50, "4.5"},
		{100, "100"},
		{0.002, "0.002"},
		{1e-6, "0.000001"},
		{1e-7, "1e-7"},
		{1.5e-7, "1.5e-7"},
		{1e-27, "1e-27"},
		{1e20, "100000000000000000000"},
		{1e21, "1e+21"},
		{1e30, "1e+30"},
		{1.5e21, "1.5e+21"},
		{9007199254740992, "9007199254740992"},
	}
	for _, c := range cases {
		got, err := es6Number(c.in)
		if err != nil {
			t.Errorf("es6Number(%v): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("es6Number(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestES6Number_RejectsNonFinite: NaN and infinities are not valid JSON numbers.
func TestES6Number_RejectsNonFinite(t *testing.T) {
	for _, f := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		if _, err := es6Number(f); err == nil {
			t.Errorf("es6Number(%v) returned nil error, want rejection", f)
		}
	}
}

// TestCanonicalize_KeyOrder confirms members are re-ordered by name regardless of
// input order, at the top level and nested.
func TestCanonicalize_KeyOrder(t *testing.T) {
	got, err := canonicalizeJSON([]byte(`{"b":1,"a":{"y":2,"x":3},"A":4}`))
	if err != nil {
		t.Fatalf("canonicalizeJSON: %v", err)
	}
	// Uppercase 'A' (U+0041) sorts before lowercase letters (U+006x) by code unit.
	want := `{"A":4,"a":{"x":3,"y":2},"b":1}`
	if string(got) != want {
		t.Errorf("key order:\n got: %s\nwant: %s", got, want)
	}
}

// TestCanonicalize_Deterministic confirms two logically-equal inputs that differ
// only in whitespace, key order, and number spelling canonicalize identically:
// the property the hash and signature rely on.
func TestCanonicalize_Deterministic(t *testing.T) {
	a, err := canonicalizeJSON([]byte(`{ "z": 1.0 , "a": [ 1, 2 ] }`))
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	b, err := canonicalizeJSON([]byte(`{"a":[1,2],"z":1}`))
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if string(a) != string(b) {
		t.Errorf("not deterministic:\n a: %s\n b: %s", a, b)
	}
}

// TestCanonicalize_RejectsNonJSON: malformed input is a clear error, not a panic
// or silent empty output.
func TestCanonicalize_RejectsNonJSON(t *testing.T) {
	if _, err := canonicalizeJSON([]byte(`{not json`)); err == nil {
		t.Fatal("canonicalizeJSON accepted malformed input, want an error")
	}
}

// TestCanonicalize_RejectsOverflowNumber: a number too large for a double is not
// a valid JSON number under the JCS model, so canonicalization fails rather than
// silently emitting Infinity. It also exercises error propagation out of a nested
// array element.
func TestCanonicalize_RejectsOverflowNumber(t *testing.T) {
	if _, err := canonicalizeJSON([]byte(`{"n":[1e400]}`)); err == nil {
		t.Fatal("canonicalizeJSON accepted an out-of-range number, want an error")
	}
}
