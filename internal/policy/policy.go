// Package policy will hold the deterministic decision engine: given a tool
// call (name + arguments) it returns ALLOW / DENY / REQUIRE_APPROVAL based on
// simple, readable rules loaded from the config.
//
// No logic yet. Implementation lands in build-order step 3 (deny-list).
package policy
