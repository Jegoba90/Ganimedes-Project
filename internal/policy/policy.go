// Package policy is Ganimedes' deterministic decision engine: given a tool name
// it returns a Decision (Allow or Deny) based on simple, readable rules.
//
// v0 milestone 3 implements the deny-list: the policy model is default-allow, so
// only tool names on the deny-list are blocked; everything else is allowed. The
// matching is exact by name, deterministic, and has no ML (see docs/DESIGN.md).
//
// This package is pure logic: no IO, no JSON-RPC or MCP knowledge, no audit
// vocabulary. The proxy calls Decide and, separately, records the outcome to the
// audit log. Keeping policy free of those concerns is what makes it trivially
// testable and keeps the ALLOW/DENY decision auditable in one obvious place.
//
// REQUIRE_APPROVAL (the human-in-the-loop decision) is milestone 4; it is not a
// Decision value here yet, because there is nothing in v0 that returns or
// enforces it. Adding it before it is enforced would claim more than the code
// does (Constitution Art. 2.4).
package policy

// Decision is the verdict for a single tool call.
type Decision int

const (
	// Allow lets the call reach the real MCP server. It is the default for any
	// tool not on the deny-list.
	Allow Decision = iota
	// Deny blocks the call before it reaches the server.
	Deny
)

// Engine decides tool calls against a deny-list. It is safe for concurrent use:
// after New returns, the deny set is never mutated, so Decide only reads it.
type Engine struct {
	deny map[string]struct{}
}

// New builds an Engine from a deny-list of tool names. Empty names are ignored.
// The returned Engine is default-allow: with an empty (or nil) list it allows
// everything, which is exactly milestone-1/2 passthrough behavior.
func New(deny []string) *Engine {
	m := make(map[string]struct{}, len(deny))
	for _, name := range deny {
		if name == "" {
			continue
		}
		m[name] = struct{}{}
	}
	return &Engine{deny: m}
}

// Decide returns the verdict for a tool call by name: Deny if the tool is on the
// deny-list, Allow otherwise. A nil Engine allows everything, so a proxy running
// without a policy configured behaves as a transparent passthrough.
func (e *Engine) Decide(tool string) Decision {
	if e == nil {
		return Allow
	}
	if _, blocked := e.deny[tool]; blocked {
		return Deny
	}
	return Allow
}
