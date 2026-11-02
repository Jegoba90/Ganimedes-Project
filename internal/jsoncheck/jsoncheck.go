// Package jsoncheck rejects JSON whose meaning would depend on a parser's
// treatment of duplicate members or invalid Unicode. The gateway forwards the
// original bytes, so accepting a lossy interpretation here would let its
// security decision disagree with the receiving server (Art. 2.1).
package jsoncheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// Validate checks that raw contains exactly one JSON value, with unique object
// member names and well-formed Unicode. Names are compared after JSON escape
// decoding, so "name" and "\u006eame" are the same member. It accepts any root
// value and does not impose a schema or IEEE-754 rounding on JSON numbers.
//
// Like encoding/json, nesting is limited to 10000 containers. That keeps both
// validation and the consumers' subsequent decoding bounded in stack depth.
func Validate(raw []byte) error {
	if !utf8.Valid(raw) {
		return errors.New("JSON contains invalid UTF-8")
	}
	if err := checkSurrogates(raw); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := checkValue(dec, 0); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		if err != nil {
			return fmt.Errorf("after JSON value: %w", err)
		}
		return errors.New("multiple JSON values")
	}
	return nil
}

func checkValue(dec *json.Decoder, depth int) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, container := token.(json.Delim)
	if !container {
		return nil
	}
	if depth >= 10000 {
		return errors.New("JSON exceeds maximum nesting depth of 10000")
	}
	switch delim {
	case '{':
		seen := make(map[string]bool)
		for dec.More() {
			name, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := name.(string)
			if !ok {
				return errors.New("object member name is not a string")
			}
			if seen[key] {
				return fmt.Errorf("duplicate object member %q", key)
			}
			seen[key] = true
			if err := checkValue(dec, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := checkValue(dec, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected delimiter %q", delim)
	}
	_, err = dec.Token() // Decoder checks that the closing delimiter matches.
	return err
}

// encoding/json replaces unpaired UTF-16 surrogates with U+FFFD. That is useful
// for displaying damaged text but unsafe when comparing names or signing JSON:
// distinct byte strings would acquire the same interpreted value. Examine the
// escapes before decoding; syntax outside these escapes remains Decoder's job.
func checkSurrogates(raw []byte) error {
	inString := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || raw[i] != '\\' || i+1 >= len(raw) {
			continue
		}
		if raw[i+1] != 'u' {
			i++ // An escaped quote does not end the string.
			continue
		}
		value, ok := hex4(raw[i+2:])
		if !ok {
			return errors.New("invalid JSON Unicode escape")
		}
		switch {
		case value >= 0xd800 && value <= 0xdbff:
			if i+8 > len(raw) || raw[i+6] != '\\' || raw[i+7] != 'u' {
				return errors.New("JSON contains an unpaired UTF-16 surrogate")
			}
			low, valid := hex4(raw[i+8:])
			if !valid || low < 0xdc00 || low > 0xdfff {
				return errors.New("JSON contains an unpaired UTF-16 surrogate")
			}
			i += 11
		case value >= 0xdc00 && value <= 0xdfff:
			return errors.New("JSON contains an unpaired UTF-16 surrogate")
		default:
			i += 5
		}
	}
	return nil
}

func hex4(raw []byte) (uint16, bool) {
	if len(raw) < 4 {
		return 0, false
	}
	var value uint16
	for _, c := range raw[:4] {
		value <<= 4
		switch {
		case c >= '0' && c <= '9':
			value += uint16(c - '0')
		case c >= 'a' && c <= 'f':
			value += uint16(c-'a') + 10
		case c >= 'A' && c <= 'F':
			value += uint16(c-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}
