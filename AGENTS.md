# Working on Ganimedes

Instructions for an AI agent contributing to this repository. If you are looking
for how to *use* Ganimedes rather than change it, read [llms.txt](llms.txt).

## Read this first

[`TECHNICAL_CONSTITUTION.md`](TECHNICAL_CONSTITUTION.md) is not a style guide.
It is the set of rules the code is held to, and the codebase cites it by article
number in comments, commit messages and docs (`Art. 2.1`, `Art. 3.1`, and so
on). A change that breaks one of those articles is wrong even if it compiles and
passes. The ones that bite most often:

- **Art. 1.1 — standard library only.** `go.mod` has no third-party
  dependencies and that is a product property, not an accident: it is what makes
  the binary static and the attack surface auditable. Do not add a dependency.
  If something seems to need one, that is the discussion, not the patch.
- **Art. 2.1 — fail closed.** Ambiguity resolves to a denial, never to
  permission. A call the gateway cannot judge is refused, not waved through.
- **Art. 2.4 — claim nothing that is not enforced.** This applies to docs,
  errors, help text and comments equally. If a guarantee is partial, the text
  says which part.
- **Art. 3.1 — stdout carries protocol bytes only.** Every diagnostic, warning
  and announcement goes to stderr. Anything else corrupts the MCP session.
- **Art. 1.3 — the wire bytes never change.** Messages are forwarded exactly as
  read. The only messages Ganimedes authors are the ones it deliberately blocks.

## Build, test, verify

```sh
go build ./...
go vet ./...
gofmt -l .            # must print nothing
go test ./... -cover
golangci-lint run ./...
```

`-race` is part of CI but runs on Linux only: Windows has no C compiler and the
macOS cgo test binary hits an `LC_UUID` dyld issue. If you are on Windows, say
that the race detector was not run rather than implying it passed.

Coverage must not decrease (Art. 4.2). Current levels are in
[`docs/GO_NO_GO.md`](docs/GO_NO_GO.md) §3.

## Conventions this repository actually holds to

- **Comments explain why, not what.** The existing ones are long and teach the
  reasoning, including what was rejected. Match that; do not strip it.
- **A security test must be seen to fail.** After writing one, break the code it
  covers on purpose, confirm the test fails, then restore. Both 2026-09-22 fixes
  and the 2026-08-01 compatibility test were checked this way, and it is recorded
  in [`docs/TESTING.md`](docs/TESTING.md) §L4.
- **Docs move in the same change as the code (Art. 6.2).** A behavior change
  that leaves `README`, `SECURITY.md`, `docs/ARCHITECTURE.md` or
  `docs/DESIGN.md` describing the old behavior is an incomplete change. Known
  gaps that stay open go in [`docs/TECH_DEBT.md`](docs/TECH_DEBT.md) with the
  reasoning for deferring them, not in a comment.
- **Commit messages are prose, conventional-commit prefixed** (`fix(proxy):`,
  `docs(release-notes):`). They explain what forced the change and what it
  costs. Read `git log` before writing one.
- **No AI attribution in commits or PRs.** No `Co-Authored-By` trailer, no
  "generated with" line.

## Releasing

A release is a deliberate act, never automatic on merge:

1. Write `docs/release-notes/vX.Y.Z.md` (same shape as the existing ones: what
   changed, how it was found, why patch or minor).
2. Commit and push to `main`.
3. Tag `vX.Y.Z` and push the tag. That triggers
   `.github/workflows/release.yml`, which tests at the exact commit,
   cross-compiles six targets, attaches `SHA256SUMS` and a Sigstore build
   provenance attestation, and publishes the GitHub Release.

Publishing is irreversible and public. Confirm with the maintainer before
pushing a tag.

## Layout

- `cmd/ganimedes/` — the binary's entrypoint, deliberately tiny.
- `internal/proxy/` — the stdio proxy: framing, policy enforcement, correlation.
- `internal/audit/` — the hash-chained, signed log, RFC 8785 canonicalization, and `verify`.
- `internal/approval/` — the loopback approval page and the human-in-the-loop wait.
- `internal/policy/` — pure decision logic, no I/O.
- `internal/config/`, `internal/cli/`, `internal/scan/` — config loading, subcommands, the pre-flight tool scanner.
