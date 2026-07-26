package policy

import "testing"

// TestDecide covers the deny-list decision table: listed tools are denied,
// everything else is allowed (default-allow), matching is exact and
// case-sensitive.
func TestDecide(t *testing.T) {
	eng := New([]string{"fs.delete", "db.dropTable", ""}) // empty entry ignored

	cases := []struct {
		tool string
		want Decision
	}{
		{"fs.delete", Deny},
		{"db.dropTable", Deny},
		{"fs.read", Allow},         // not listed
		{"", Allow},                // empty tool name is not on the list
		{"FS.DELETE", Allow},       // exact match is case-sensitive
		{"fs.delete ", Allow},      // trailing space is a different name
		{"db.dropTableXYZ", Allow}, // not a prefix/substring match
	}
	for _, c := range cases {
		if got := eng.Decide(c.tool); got != c.want {
			t.Errorf("Decide(%q) = %v, want %v", c.tool, got, c.want)
		}
	}
}

// TestDecide_EmptyList: an engine with no rules allows everything (this is the
// milestone-1/2 passthrough case).
func TestDecide_EmptyList(t *testing.T) {
	for _, eng := range []*Engine{New(nil), New([]string{})} {
		if got := eng.Decide("anything"); got != Allow {
			t.Errorf("empty engine Decide = %v, want Allow", got)
		}
	}
}

// TestDecide_NilEngine: a nil engine must not panic (Constitution Art. 1.2, no
// panics in library code) and allows everything.
func TestDecide_NilEngine(t *testing.T) {
	var eng *Engine
	if got := eng.Decide("fs.delete"); got != Allow {
		t.Errorf("nil engine Decide = %v, want Allow", got)
	}
}
