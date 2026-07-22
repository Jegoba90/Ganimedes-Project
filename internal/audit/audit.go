// Package audit will hold the tamper-evident, hash-chained audit log: each
// tool call is appended as an entry whose SHA-256 hash includes the previous
// entry's hash, so any later edit breaks the chain. Includes a verify pass.
//
// No logic yet. Implementation lands in build-order step 2 (audit log).
package audit
