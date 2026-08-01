# Security Policy

Ganimedes exists to make what an AI agent does verifiable, so it owes you the
same treatment of itself: how to report a problem in it, what it is built to
stop, and what it deliberately does not stop.

## Reporting a vulnerability

Report privately, not in a public issue:

**[Open a private security advisory](https://github.com/Jegoba90/Ganimedes-Project/security/advisories/new)**
(the repository's Security tab, "Report a vulnerability").

That channel is visible only to you and the maintainer, so a fix can exist
before the problem is public. If you cannot use it for any reason, open a public
issue saying only that you have a security report and asking for a private
channel, with no details in it.

Useful in a report, in rough order of usefulness: the version (`ganimedes
version`), the OS, what you expected the gateway to do, what it did instead, and
the smallest reproduction you have. A config file and the MCP server you wrapped
are usually enough. Do not attach an audit log without reading it first, because
audit logs hold whatever flowed through them, secrets included.

## What this project can honestly promise

Ganimedes is maintained by one person, unpaid, and this section says what that
means instead of implying a service level it does not have:

- **Acknowledgement:** best effort, normally within a few days.
- **Assessment and fix:** no fixed timeline. A confirmed bypass of a control the
  README claims (deny, approval, audit integrity) is treated as the top of the
  queue, ahead of features.
- **Disclosure:** coordinated. Report privately, and the fix and the advisory go
  out together; credit in the advisory unless you would rather not have it.
- **No bug bounty.** There is no money behind this project (see the licence and
  the absence of a hosted tier). Nothing here is an offer of payment.

## Supported versions

One version is supported: the **latest release**. v0 is pre-1.0, moves in one
direction, and has no long-term-support branch and no backports. A fix ships in
the next release, and upgrading is a matter of replacing one static binary.

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Anything older | No. Upgrade first, then report if it persists |

## In scope

Anything that breaks a guarantee the docs actually make:

- A `tools/call` reaching the wrapped server that the policy should have denied
  or held for approval, or a way to make the gateway forward without a decision.
- An altered audit log that `ganimedes verify` still accepts: a forged hash
  chain, a forged Ed25519 signature, or a canonicalisation gap that lets two
  different payloads hash the same.
- The approval page deciding without a human: a call approved by something other
  than a click, a cross-site request that decides for you, or script injected
  through tool arguments rendered on that page.
- Anything but MCP protocol bytes reaching stdout, which corrupts the session
  (Constitution Art. 3.1).
- A signing key or audit log written more permissively than intended on a system
  that enforces file modes.
- The release pipeline: any way to land bytes in a release, or an attestation,
  that did not come from this repository's own workflow.

## Out of scope, because it is already known and written down

These are recorded limitations, not undiscovered bugs. Each one is documented in
`docs/GO_NO_GO.md` §6, `docs/ARCHITECTURE.md` §4 or `docs/TECH_DEBT.md`, and
reporting them is welcome only if you have found that the documented reasoning is
wrong:

- **The approval page has no authentication.** It binds to loopback, and anyone
  with local access to that port can approve or reject. That is the v0 design,
  stated in the README.
- **The audit log holds secrets.** Entries store full arguments and results, so
  the log is as sensitive as the traffic that produced it (Art. 2.5). Redaction
  is a later feature.
- **Truncating the tail of the log is not detectable.** Removing entries from the
  end leaves a shorter but internally consistent chain. Edits and deletions
  anywhere else are caught. Detecting truncation needs an external anchor.
- **Auditing fails open.** If an append fails, the proxy logs to stderr and keeps
  forwarding. Losing a record is judged the lesser harm against taking the
  agent down.
- **`0600` is not enforced on Windows.** The audit log and the signing key are
  created with mode `0600`; POSIX honours it, Windows does not, so there the
  secrecy of the key rests on the directory's ACL.
- **Whoever holds both the log and the signing key can rewrite history.** The
  chain plus signature proves the log was not altered by someone without the key.
  It was never claimed to survive an attacker who has the key, and the docs say
  so rather than implying otherwise.
- **A wrapped server's scope can change without the log saying so.** The session
  header records the conditions at launch, including the command and arguments
  the server was given, but a server may renegotiate its own scope with the
  client afterwards (MCP Roots is the case that surfaced this). The gateway
  forwards that exchange and records only tool calls, so the log can show a
  directory the server was handed and not the one it ended up using. See
  `docs/TECH_DEBT.md` TD-4.
- **Ganimedes is not a sandbox.** It governs what an agent does *through the MCP
  server it wraps*. An agent that can execute arbitrary code, reach the server
  directly instead of through the gateway, or exploit something below the
  protocol layer, is outside what a proxy can control. The threat model is an
  agent misbehaving through its tools, not an attacker who owns the machine.

## Verifying what you downloaded

Every release ships `SHA256SUMS`, covering the binaries themselves rather than an
archive, so what you check is byte for byte the file you run. That proves
integrity: the download matches what was published.

It does not prove origin, because the checksums sit on the same page as the
binaries. Releases from `v0.2.0` on therefore also carry a **build provenance
attestation**, a signed statement recorded outside the release itself:

```sh
gh attestation verify ganimedes_<version>_<os>_<arch> --repo Jegoba90/Ganimedes-Project
```

That confirms the file came out of this repository's release workflow, at a
specific commit. It proves where the binary came from, not that the code is
correct or benign. `v0.1.0` predates the attestation and has checksums only,
though its binaries are reproducible: rebuilding the tagged commit with the same
Go version and flags gives back the published bytes, differing only in the Go
build ID that records which machine did the building.

If you would rather trust nothing that was built elsewhere, the project has no
dependencies to audit beyond its own source, and a Go toolchain builds it
directly:

```sh
go install github.com/Jegoba90/Ganimedes-Project/cmd/ganimedes@latest
```

## Where the security reasoning lives

- [`TECHNICAL_CONSTITUTION.md`](TECHNICAL_CONSTITUTION.md) §2, the rules the code
  is held to, including the one that forbids claiming more than is enforced.
- [`docs/GO_NO_GO.md`](docs/GO_NO_GO.md) §5 and §6, the security posture checked
  before v0 shipped and the limitations accepted with it.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) §4, how the audit chain works
  and what it does and does not detect.
