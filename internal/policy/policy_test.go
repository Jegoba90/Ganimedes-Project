package policy

import "testing"

// TestDecide covers the decision table across both lists: denied tools are
// denied, approval-listed tools require approval, a tool on both lists is denied
// (deny wins, the stricter verdict), everything else is allowed (default-allow).
// Matching is exact and case-sensitive on both lists.
func TestDecide(t *testing.T) {
	eng := New(
		[]string{"fs.delete", "db.dropTable", "", "both.tool"}, // empty entry ignored
		[]string{"email.send", "payment.execute", "", "both.tool"},
	)

	cases := []struct {
		tool string
		want Decision
	}{
		{"fs.delete", Deny},
		{"db.dropTable", Deny},
		{"email.send", RequireApproval},
		{"payment.execute", RequireApproval},
		{"both.tool", Deny},        // on both lists: deny wins (stricter)
		{"fs.read", Allow},         // on neither list
		{"", Allow},                // empty tool name is on neither list
		{"FS.DELETE", Allow},       // deny match is case-sensitive
		{"EMAIL.SEND", Allow},      // approval match is case-sensitive too
		{"fs.delete ", Allow},      // trailing space is a different name
		{"db.dropTableXYZ", Allow}, // not a prefix/substring match
	}
	for _, c := range cases {
		if got := eng.Decide(c.tool); got != c.want {
			t.Errorf("Decide(%q) = %v, want %v", c.tool, got, c.want)
		}
	}
}

// TestDecide_EmptyLists: an engine with no rules allows everything (this is the
// milestone-1/2 passthrough case), whether the lists are nil or empty slices.
func TestDecide_EmptyLists(t *testing.T) {
	for _, eng := range []*Engine{New(nil, nil), New([]string{}, []string{})} {
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
