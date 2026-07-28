package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"unicode/utf16"
)

// canonicalizeJSON returns the RFC 8785 (JSON Canonicalization Scheme) form of
// the JSON value in raw: object keys sorted by their UTF-16 code units,
// ECMAScript-style number formatting, minimal string escaping, and no
// insignificant whitespace.
//
// This is the single source of canonical bytes for both the writer (Append) and
// the verifier (Verify), per Constitution Art. 2.3: the digest and signature are
// taken over exactly these bytes, so a third party holding the log and the
// public key can reproduce them with any RFC 8785 implementation and check the
// chain offline.
//
// Numbers follow the JCS model: every JSON number is an IEEE-754 double and is
// re-emitted via the ECMAScript Number-to-string algorithm (§3.2.2.3). A value
// outside the finite double range (it would decode to Inf) is rejected, since it
// is not a valid JSON number.
func canonicalizeJSON(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // keep number literals exact until we format them per JCS
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("decoding JSON to canonicalize: %w", err)
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// writeCanonical writes the RFC 8785 form of one decoded JSON value to buf. The
// value comes from encoding/json with UseNumber, so it is one of: nil, bool,
// string, json.Number, []any, or map[string]any.
func writeCanonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writeCanonicalString(buf, t)
	case json.Number:
		s, err := canonicalNumber(t)
		if err != nil {
			return err
		}
		buf.WriteString(s)
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		// RFC 8785 sorts members by the UTF-16 code units of their names.
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCanonicalString(buf, k)
			buf.WriteByte(':')
			if err := writeCanonical(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("canonicalize: unexpected JSON type %T", v)
	}
	return nil
}

// lessUTF16 reports whether a sorts before b by UTF-16 code units, the ordering
// RFC 8785 requires for object member names. For BMP text this matches rune
// order; it differs only for supplementary characters (surrogate pairs), which
// is exactly where byte or rune order would be wrong.
func lessUTF16(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// writeCanonicalString writes s as an RFC 8785 JSON string: the two-character
// escapes for the controls that have them, \u00xx (lowercase) for the remaining
// controls, escaped quote and backslash, and every other code point as literal
// UTF-8. Notably the solidus (/) and the HTML-sensitive < > & are NOT escaped,
// unlike Go's encoding/json default, which is why this cannot go through
// json.Marshal.
func writeCanonicalString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\t':
			buf.WriteString(`\t`)
		case '\n':
			buf.WriteString(`\n`)
		case '\f':
			buf.WriteString(`\f`)
		case '\r':
			buf.WriteString(`\r`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

// canonicalNumber formats a JSON number per RFC 8785 by treating it as an
// IEEE-754 double (the JCS number model) and applying the ECMAScript
// Number-to-string algorithm.
func canonicalNumber(n json.Number) (string, error) {
	f, err := strconv.ParseFloat(n.String(), 64)
	if err != nil {
		return "", fmt.Errorf("canonicalize: invalid number %q: %w", n.String(), err)
	}
	return es6Number(f)
}

// es6Number renders f the way ECMAScript's Number.prototype.toString does, which
// RFC 8785 §3.2.2.3 adopts for JSON numbers. Go's strconv gives the same
// shortest round-tripping digits; the only fix-up needed is the exponent, where
// Go zero-pads to two digits ("1e+09") and ECMAScript does not ("1e+9").
func es6Number(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", errors.New("canonicalize: NaN and Infinity are not valid JSON numbers")
	}
	if f == 0 { // also normalizes -0 to 0
		return "0", nil
	}

	var out []byte
	if f < 0 {
		out = append(out, '-')
		f = -f
	}

	// ECMAScript uses positional notation in [1e-6, 1e21) and exponential form
	// outside it.
	format := byte('e')
	if f >= 1e-6 && f < 1e21 {
		format = 'f'
	}
	s := strconv.AppendFloat(nil, f, format, -1, 64)

	if format == 'e' {
		// "1e+09" -> "1e+9": drop a single leading zero in the exponent. Go never
		// emits more than one leading zero, so one strip is enough.
		if i := bytes.IndexByte(s, 'e'); i >= 0 && i+2 < len(s) && s[i+2] == '0' {
			s = append(s[:i+2], s[i+3:]...)
		}
	}
	return string(append(out, s...)), nil
}
