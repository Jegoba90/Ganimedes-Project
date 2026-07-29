// Package policy is Ganimedes' deterministic decision engine: given a tool name
// it returns a Decision (Allow, Deny, or RequireApproval) based on simple,
// readable rules.
//
// v0 milestone 3 implemented the deny-list; milestone 4 adds the approval-list.
// The policy model is default-allow, so only tool names on the deny-list are
// blocked and only names on the approval-list are held for a human; everything
// else is allowed. Matching is exact by name, deterministic, and has no ML (see
// docs/DESIGN.md). When a tool appears on both lists, Deny wins: the engine
// always returns the stricter verdict.
//
// This package is pure logic: no IO, no JSON-RPC or MCP knowledge, no audit
// vocabulary. The proxy calls Decide and, separately, records the outcome to the
// audit log. Keeping policy free of those concerns is what makes it trivially
// testable and keeps the decision auditable in one obvious place.
package policy

// Decision is the verdict for a single tool call.
type Decision int

const (
	// Allow lets the call reach the real MCP server. It is the default for any
	// tool on neither list.
	Allow Decision = iota
	// Deny blocks the call before it reaches the server.
	Deny
	// RequireApproval pauses the call for a human decision before it reaches the
	// server (milestone 4, human-in-the-loop). It is enforced by the proxy via an
	// approver; the timeout fails closed to a denial (Constitution Art. 2.1, 3.4).
	RequireApproval
)

// Engine decides tool calls against a deny-list and an approval-list. It is safe
// for concurrent use: after New returns, neither set is mutated, so Decide only
// reads them.
type Engine struct {
	deny    map[string]struct{}
	approve map[string]struct{}
}

// New builds an Engine from a deny-list and an approval-list of tool names. Empty
// names are ignored. The returned Engine is default-allow: with empty (or nil)
// lists it allows everything, which is exactly milestone-1/2 passthrough behavior.
// A name on both lists is denied (Decide returns the stricter verdict).
func New(deny, approve []string) *Engine {
	return &Engine{deny: toSet(deny), approve: toSet(approve)}
}

// toSet builds a lookup set from a list of names, skipping empty ones.
func toSet(names []string) map[string]struct{} {
	m := make(map[string]struct{}, len(names))
	for _, name := range names {
		if name == "" {
			continue
		}
		m[name] = struct{}{}
	}
	return m
}

// Decide returns the verdict for a tool call by name: Deny if the tool is on the
// deny-list, RequireApproval if it is on the approval-list (and not denied), and
// Allow otherwise. Deny is checked first, so a tool on both lists is denied. A
// nil Engine allows everything, so a proxy running without a policy configured
// behaves as a transparent passthrough.
func (e *Engine) Decide(tool string) Decision {
	if e == nil {
		return Allow
	}
	if _, blocked := e.deny[tool]; blocked {
		return Deny
	}
	if _, held := e.approve[tool]; held {
		return RequireApproval
	}
	return Allow
}
