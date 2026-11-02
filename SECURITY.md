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

One version is supported: the **latest release**. There is no long-term-support
branch and there are no backports. A fix ships in the next release, and
upgrading is a matter of replacing one static binary. Within 1.x an upgrade does
not break the CLI, exit codes, config files or the verification of existing
logs; the README's Stability section lists what that covers and what it does
not. Upgrading is therefore the fix, not a migration.

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
- An audit entry that was written wrong in the first place: a call that reached
  the server and left no entry, or one recorded under a tool name, arguments or
  decision that were not its own. The line above covers attacks on the record
  after the fact and quietly assumes the writing of it is faithful; this line
  exists because that assumption failed once already (the reused request id
  fixed in `v0.3.3`), and a log that is sealed honestly around a false statement
  is one `verify` will call intact forever.
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
  with local access to that port can approve or reject. That is the current
  design, stated in the README. What it does have, since `v0.3.2`, is a CSRF token: a
  decision POST must carry the random value embedded in the page Ganimedes
  rendered. The Host must match the advertised numeric loopback authority,
  closing the DNS-rebinding route to reading that token, and CSP/X-Frame-Options
  disallow embedding the page for clickjacking. These controls do not
  authenticate a local process, because anyone who can load the page can read the token
  it carries. The two are different attackers and only one of them is accepted.
- **JSON-RPC batching is refused, not supported.** A request line holding an
  array rather than a single object is blocked whole, with one error returned
  per id in it. The policy engine and the audit log both work one call at a
  time, so a batch is something the gateway cannot judge, and ambiguity fails closed
  (Art. 2.1). Batching was removed from the MCP spec in `2025-06-18`; a client
  still sending one gets a clear error rather than silent passage, which is
  what `v0.3.3` changed.
- **A call the server never answers holds its request id.** Pending entries are
  cleared by their response, so an unanswered call keeps its id occupied for
  the rest of the session and a later call reusing that id is refused too. No
  expiry: a timeout short enough to free a stuck id would also free one whose
  response is merely slow, which is the misattribution `v0.3.3` closed. The
  pending count/byte caps still apply; unresolved calls can eventually exhaust
  that budget and later requests will be refused until space is released.
- **The audit log holds secrets.** Entries store full arguments and results, so
  the log is as sensitive as the traffic that produced it (Art. 2.5). Redaction
  is a later feature.
- **Truncating the tail of the log is not detectable.** Removing entries from the
  end leaves a shorter but internally consistent chain. Edits and deletions
  anywhere else are caught. Detecting truncation needs an external anchor.
- **Legacy numeric precision.** Calls written without `content_hash` use only
  RFC 8785's IEEE-754 canonical number model. A numeric edit that rounds to the
  same binary64 value can retain a valid seal. New calls additionally sign a
  digest of encoded args/result/error without converting numbers to float64;
  old seals cannot be strengthened retroactively by a verifier. The reverse
  does not hold: a `ganimedes verify` from v0.3.3 or earlier does not know
  `content_hash` and reports a genuine new call record as tampered. Verify a
  log with a binary at least as new as the one that wrote it.
- **The log lock binds writers that ask for it.** The writer holds a kernel lock
  on the log file itself (`flock` on Linux, macOS and the BSDs; `LockFileEx` on
  Windows), so a second gateway on the same file, by any path or hard link, is
  refused. The kernel releases it when the writer exits or is killed, so no
  manual cleanup is ever needed. On Unix the lock is advisory: a program that
  writes without taking it, such as an editor or a Ganimedes older than this
  lock, is not stopped. On other platforms the log refuses to open.
- **Auditing fails open.** If an append fails, the proxy logs to stderr and keeps
  forwarding. Losing a record is judged the lesser harm against taking the
  agent down.
- **An unanswered allowed call has no completed audit entry.** The record is
  written when its response arrives. The absence of an entry therefore does not
  prove that no request reached the wrapped server. Writes are not fsync'ed per
  entry, so a power failure can also lose recent records.
- **`0600` is not enforced on Windows.** The audit log and the signing key are
  created with mode `0600`; POSIX honours it, Windows does not, so there the
  secrecy of the key rests on the directory's ACL.
- **Key-pair publication is not atomic.** A failed public-file write can leave a
  valid private key. On restart a missing public half is derived from it;
  existing public files are never overwritten. An orphaned, corrupt or mismatched
  public half prevents startup and requires manual recovery from trusted copies.
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
- **The client may not use the server you wrapped.** A host brings tools of its
  own and prefers them for ordinary requests, so a plain-language instruction can
  be answered by the client's own reader or writer without the wrapped server
  being consulted at all. Nothing is evading the gateway there, because no call
  was ever made to it; the consequence is that an empty log means no traffic
  through this server rather than an agent that did nothing.
- **Ganimedes is not a sandbox.** It governs what an agent does *through the MCP
  server it wraps*. An agent that can execute arbitrary code, reach the server
  directly instead of through the gateway, or exploit something below the
  protocol layer, is outside what a proxy can control. The threat model is an
  agent misbehaving through its tools, not an attacker who owns the machine.

## Verifying what you downloaded

Source builds require Go 1.26.10 or newer. Having no third-party modules does
not remove standard-library vulnerabilities: the compiler and library must be
kept patched, and `govulncheck ./...` remains part of the gate.

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
  before the first release shipped and the limitations accepted with it.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) §4, how the audit chain works
  and what it does and does not detect.
