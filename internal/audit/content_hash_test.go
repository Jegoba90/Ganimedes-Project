package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A receiving server may preserve number precision beyond binary64. These edits
// all collapse to the same RFC 8785 bytes, but must change the content commitment
// and therefore fail verification of a newly written record.
func TestVerifyDetectsNumberEditsBeyondIEEE754(t *testing.T) {
	for _, numbers := range [][2]string{
		{"9007199254740992", "9007199254740993"},
		{"333333333.33333329", "333333333.3333333"},
		{"1e300", "1.0000000000000001e300"},
		{"1e-400", "2e-400"},
	} {
		for _, field := range []string{"args", "result", "error"} {
			t.Run(field+" "+numbers[0], func(t *testing.T) {
				before, after := `{"number":`+numbers[0]+`}`, `{"number":`+numbers[1]+`}`
				c1, err := canonicalizeJSON([]byte(before))
				if err != nil {
					t.Fatalf("canonicalizing original number: %v", err)
				}
				c2, err := canonicalizeJSON([]byte(after))
				if err != nil || !bytes.Equal(c1, c2) {
					t.Fatalf("test requires equal binary64 canonical values: %s / %s, %v", c1, c2, err)
				}
				path := filepath.Join(t.TempDir(), "audit.jsonl")
				priv, pub := newTestKey(t)
				l := openLog(t, path, "session", priv)
				var args, result, rpcErr json.RawMessage
				switch field {
				case "args":
					args = json.RawMessage(before)
				case "result":
					result = json.RawMessage(before)
				case "error":
					rpcErr = json.RawMessage(before)
				}
				e, err := l.Append("read_file", args, result, rpcErr, DecisionAllow)
				if err != nil {
					t.Fatalf("Append: %v", err)
				}
				if len(e.ContentHash) != 64 {
					t.Fatalf("new call has no content commitment: %q", e.ContentHash)
				}
				closeLog(t, l)
				original, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("ReadFile: %v", err)
				}
				modified := strings.Replace(string(original), before, after, 1)
				if modified == string(original) {
					t.Fatal("test did not edit the stored number")
				}
				if err := os.WriteFile(path, []byte(modified), 0o600); err != nil {
					t.Fatalf("WriteFile: %v", err)
				}
				res, err := Verify(path, pub)
				if err != nil || res.OK || !strings.Contains(res.Reason, "content_hash") {
					t.Fatalf("number edit escaped its commitment: %+v, %v", res, err)
				}
			})
		}
	}
}

func TestContentHashNormalizesEncodingWithoutRoundingNumbers(t *testing.T) {
	first := payload{Args: json.RawMessage(`{ "number" : 9007199254740993, "text" : "<&>" }`)}
	second := payload{Args: json.RawMessage(`{"number":9007199254740993,"text":"\u003c\u0026\u003e"}`)}
	h1, err := first.contentDigest()
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	h2, err := second.contentDigest()
	if err != nil || h1 != h2 {
		t.Fatalf("encoding normalization changed the commitment: %s / %s, %v", h1, h2, err)
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	priv, pub := newTestKey(t)
	l := openLog(t, path, "session", priv)
	if _, err := l.Append("read_file", first.Args, nil, nil, DecisionAllow); err != nil {
		t.Fatalf("Append: %v", err)
	}
	closeLog(t, l)
	if res, err := Verify(path, pub); err != nil || !res.OK {
		t.Fatalf("normalized stored content: %+v, %v", res, err)
	}
}
