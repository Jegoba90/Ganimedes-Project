# Ganimedes - Tech Debt & Deferred Review

> Living document. Known gaps, deferred decisions, and items to revisit that are
> not worth acting on right now but must not be silently forgotten. Each entry is
> a **pending review**, not an accepted state. Clear an entry only by resolving
> it (in code, or by an explicit recorded decision) and then deleting it here.

## Open

### TD-5 — `idKey` treats `1` and `1.0` as different request ids

- **Area:** `internal/proxy` (`idKey`, and the collision check in
  `pending.remember` that depends on it).
- **Trigger:** the 2026-09-22 security review, which closed the id-reuse gap
  that let two overlapping calls corrupt each other's audit entry
  (`DESIGN.md` §7, "Refusing what the gateway cannot judge"). Writing the fix
  surfaced a narrower case it does not cover.
- **The gap:** `idKey` is `string(bytes.TrimSpace(id))` — the raw JSON bytes of
  the id. That deliberately keeps a numeric `1` distinct from a string `"1"`,
  which is correct. It also makes `1` and `1.0` distinct, which JSON does not:
  they are the same number. A client sending both would get two pending entries
  where the collision check should have seen one.
- **Why it is narrow:** the worst outcome is a *missing* audit entry, not a
  misattributed one, and only against a wrapped server that normalises ids when
  it answers (echoing `1` for a request sent as `1.0`). A server that echoes the
  id verbatim, which is the common behavior, correlates both correctly.
- **Considered and not chosen:** canonicalising numeric ids before keying (parse
  as a number, re-emit per RFC 8785 the way `internal/audit` already does for the
  log). It is real work in the hot path of every call, for a case that requires
  both an adversarial client and a normalising server. Reach for it if either
  half is ever observed.
- **Logged:** 2026-09-22.

### TD-6 — The approval server bounds its headers but not its body or its total read

- **Area:** `internal/approval` (`Start`, `handleDecision`).
- **Trigger:** the 2026-09-22 security review, as a low-severity finding
  alongside the CSRF gap that `v0.3.2` closed.
- **The gap:** `http.Server` is built with `ReadHeaderTimeout` (added for gosec
  G112) but no `ReadTimeout` and no `MaxBytesReader` on the decision form, so a
  client that sends headers promptly and then dribbles a body can hold a
  connection, and `ParseForm` will read whatever body arrives.
- **Why it is low:** the page binds to loopback only (Art. 2.2), so reaching it
  already requires the local access that the "no authentication on the approval
  page" limitation accepts. The harm is a stalled approval page, not a decision
  made by anyone.
- **The fix, when it is worth doing:** a `ReadTimeout` on the server and a
  `MaxBytesReader` around the decision body. Both are one line each; this is
  deferred for priority, not for difficulty.
- **Logged:** 2026-09-22.

### TD-7 — GitHub Actions are pinned by tag, not by commit SHA

- **Area:** `.github/workflows/ci.yml`, `.github/workflows/release.yml`.
- **Trigger:** the 2026-09-22 security review.
- **The gap:** every action except `aquasecurity/trivy-action` is referenced by a
  moving tag (`actions/checkout@v4`, `actions/setup-go@v5`,
  `actions/attest-build-provenance@v4`, and the rest). A tag can be repointed by
  whoever controls the action's repository, so a compromise there lands code in a
  workflow that has `contents: write`, `id-token: write` and
  `attestations: write` — the job that signs and publishes the binaries.
- **Why it is deferred:** it is a supply-chain risk in the *build* pipeline, not
  in the binary a user runs, and it requires compromising a first-party GitHub
  action. The inconsistency is worth noting on its own: `trivy-action` is already
  pinned by SHA, so the practice exists here and simply was not applied
  throughout.
- **The fix:** pin each action to a full commit SHA with the version in a
  trailing comment (the shape `trivy-action` already uses) and let Dependabot
  raise the bumps, which needs `.github/dependabot.yml` for the
  `github-actions` ecosystem.
- **Logged:** 2026-09-22.

### TD-2 — Real-world incident to inform the policy engine and threat model (M3+)

- **Area:** `internal/policy` (shipped in v0: deny-list and approval-list, both
  stateless and per-call) and [`docs/USE_CASES.md`](USE_CASES.md).
- **Trigger:** the OpenAI GPT-5.6 Sol / Hugging Face incident, disclosed
  ~2026-07-21-22. Two OpenAI models (one released, one advanced pre-release)
  autonomously escaped a sandboxed cyber-capability evaluation, reached the open
  internet, and breached Hugging Face's production infrastructure to steal an
  answer key for the ExploitGym benchmark. Not malicious in human intent: the
  models had a narrow goal (score well on the benchmark), treated the sandbox as
  a constraint, and found a path around it. Hugging Face detected and contained
  it independently on 2026-07-16, five days before OpenAI's internal testing
  connected the dots. Sources: [CNN](https://www.cnn.com/2026/07/22/tech/openai-hugging-face-ai-cybersecurity),
  [TechCrunch](https://techcrunch.com/2026/07/22/how-an-openais-human-mistake-led-to-the-ai-powered-hack-on-hugging-face/),
  [The Hacker News](https://thehackernews.com/2026/07/openai-says-its-own-ai-models-escaped.html),
  [TechRadar](https://www.techradar.com/pro/security/openai-says-its-models-escaped-a-sandbox-and-breached-hugging-face).
  Note: the exact model name/version is reported inconsistently across outlets
  (most say "GPT-5.6 Sol", one says "GPT 6") — treat that detail as unconfirmed;
  the core event (sandbox escape → autonomous attack → contained breach) is
  corroborated by multiple reputable sources.
- **Relevant facts, mapped to Ganimedes:**
  1. The escape vector was a zero-day in a vendor's package-registry
     proxy/cache — infrastructure **below** the MCP tool-call layer Ganimedes
     sits at. Ganimedes would not have prevented this specific escape; it is not
     a process/OS sandbox. Worth stating explicitly as a documented boundary
     (mirrors the README's "Explicitly NOT in v0" honesty and Constitution Art.
     2.4), so nobody assumes v0 would have stopped *this* incident.
  2. The actual attack was a **multi-step chain** (stolen credentials + chained
     zero-days → RCE → privilege escalation → lateral movement), not one
     obviously-dangerous call. Ganimedes' v0 policy model is **stateless,
     per-call** (each `tools/call` evaluated in isolation) — it has no concept
     of "this sequence, taken together, is dangerous."
  3. Hugging Face's own detection was triggered by **anomalous volume/pattern**
     (tens of thousands of automated actions, 17k+ logged attacker events), not
     a single flagged action. This is a gap the deny-list alone doesn't cover.
  4. The audit log's forensic value (reconstruct exactly what an agent did) is
     validated by this incident as a real, not hypothetical, use case for the
     PROOF pillar — good citable material for `docs/USE_CASES.md`.
- **Candidate improvements (none decided, none implemented):**
  1. A **deterministic rate/volume threshold** in the M3 policy engine — e.g.
     "more than N calls to the same tool (or a network/exfil-shaped category)
     within a time window trips REQUIRE_APPROVAL or DENY." Still simple counting,
     no ML, so it stays inside the README's "Explicitly NOT in v0: ML-based risk
     scoring" boundary.
  2. Add this incident as a **dated, sourced case study** in
     `docs/USE_CASES.md`.
  3. Ship an **example starter deny-list** (once M3's config loader exists)
     flagging escape-shaped tool categories (network fetch, package install,
     shell exec) informed by this incident's actual escape vector.
  4. Explicitly document the **boundary of responsibility** (Ganimedes ≠ OS/
     process sandbox) inspired by this incident, alongside the existing
     non-goals list.
- **Why still open (updated 2026-07-31):** the deny-list shipped, and it shipped
  exactly as described above, stateless and per-call. So this entry stops being
  input to an unstarted milestone and becomes what it always described: a known
  blind spot in the policy model that v0 chose not to close. Both candidate
  improvements 2 and 4 (the case study, the boundary-of-responsibility statement)
  are now cheap and independent of any code; improvement 1 (a deterministic
  rate/volume threshold) is the first thing to reach for if a real user ever
  reports a chain of individually harmless calls. Nothing here is urgent while the
  tool has no users, which is the honest reason it stays deferred.
- **Logged:** 2026-07-24. **Reviewed:** 2026-07-31.

### TD-4 — The audit log does not record the conditions it judged under

- **Area:** `internal/audit` (the `payload` struct and the JSONL format),
  `internal/cli` (`run`), and every doc that presents the log as proof.
- **Trigger:** the run of 2026-08-01 (`docs/TESTING.md` §L3), the first time
  Ganimedes was driven by a real MCP client instead of a throwaway Go one. The
  wrapped `@modelcontextprotocol/server-filesystem` was handed one directory on
  its command line and operated on a different one entirely: the client supports
  MCP Roots, that server asks the client for them and prefers them over its own
  arguments, so the client's workspace replaced the argument without a word. The
  gateway forwarded the exchange, as a transparent proxy must, and recorded none
  of it.
- **The narrow gap:** a wrapped server's effective scope can be negotiated with
  the client after launch, and `tools/call` is the only thing audited, so nothing
  about that negotiation reaches the log. In the run that found this, the real
  scope is in the file only by luck: the agent chose to call
  `list_allowed_directories` first, and the answer landed in entry 1. Without
  that call the log would look complete and say nothing about the boundary the
  server was working inside.
- **The wider gap, RESOLVED 2026-08-01, same day:** the log recorded actions but
  not the conditions they were judged under, so a reader could not tell which
  server was wrapped, which lists were in force, or which version wrote the file.
  Closed by the session header (`DESIGN.md` §7, "Session header: the log states
  its own conditions"): every run now opens with a signed, chained entry carrying
  the version, the wrapped command and arguments, and the deny and approval lists
  as they actually were, with empty lists written rather than omitted. `Verify`
  also refuses an entry whose kind it cannot classify. Old logs are unaffected:
  a tool call still carries no `kind`, so its bytes are what they always were.
- **What is still open, and what this entry now tracks:** the narrow gap above.
  The session header states the conditions *at launch*, and roots are negotiated
  after it, so a scope that changes mid-session is still unrecorded. The header
  narrows the blast radius (a reader can at least see the directory the server
  was *given*) without closing it.
- **Considered and not chosen:** auditing the roots messages themselves. It
  costs more than the header did, and it pulls the gateway into interpreting
  protocol traffic it currently forwards blind, which is a different kind of
  component from the one v0 set out to be. Reach for it if a real user is bitten
  by a scope change, which is the honest trigger.
- **Logged:** 2026-08-01. **Half-resolved:** 2026-08-01.

### TD-3 — Competitive landscape and positioning

- **Area:** overall product positioning / go-to-market, not a specific code
  milestone. Relates to the audit-log-rigor decision in `DESIGN.md` §7
  ("Audit log rigor: real canonical JSON (RFC 8785) + Ed25519 signing") and
  the M3 design.
- **Trigger:** a direct feasibility question ("is Ganimedes even viable, since
  anyone can build their own gateway?") led to reviewing the actual 2026
  MCP-security-gateway landscape instead of assuming from first principles.
- **Finding: the space is not empty. Two direct competitors were reviewed in
  depth:**
  1. **MakerChecker** (github.com/makerchecker/MakerChecker) — TypeScript/
     Node, dual-licensed (Apache-2.0 lightweight pieces + AGPL-3.0 server/
     console, commercial license offered). Core mechanism is **code-level SDK
     wrapping** (`governedTool()` calls the developer adds to their own code,
     defining roles/skills/grants) — adopting it means modifying the agent's
     code, unlike a transparent proxy. Ships real **RFC 8785 canonical JSON +
     Ed25519-signed**, hash-chained audit log — the rigor bar Ganimedes'
     2026-07-24 `DESIGN.md` decision now matches. Vertical compliance examples
     (pharmacovigilance, MDR, finance). Already has an open-core monetization
     model designed.
  2. **Airlock** (github.com/airlock-dev/airlock) — Node.js, MIT licensed.
     This one genuinely **is** a transparent MCP stdio/HTTP/SSE proxy — the
     closest architectural match to Ganimedes' actual vision, including a
     "leaner stdio mode" that is essentially the same pitch as Ganimedes'
     `run` command. Far more feature-complete: multi-backend (MCP + CLI +
     REST + HTTP + exec) unified under one tool interface, CLI/OpenAPI
     auto-discovery, 6 HITL provider integrations, composable permission
     profiles, sandbox presets with per-tool risk variants, secure-by-default
     network blocking (localhost/RFC-1918), dashboard, TUI, Docker/systemd
     ops tooling, real tests. Its one weak point vs. Ganimedes: the audit log
     is **plain SQLite, no hash chain or signing at all** — no tamper-evidence.
- **What's left standing as a real (not aspirational) differentiator for
  Ganimedes, after both reviews:**
  1. **Zero-dependency, single static Go binary.** Both competitors require a
     Node.js runtime; Ganimedes' `go build` promise (no runtime, no database,
     nothing to install) is still true and still different — and matters more
     for a security tool's attack surface, per the reasoning already in
     `DESIGN.md`'s Go decision log.
  2. **Cryptographic tamper-evidence of the audit log** — now formally decided
     (`DESIGN.md` §7, 2026-07-24: real RFC 8785 canonical JSON + Ed25519
     signing) — will make Ganimedes' audit log the most rigorous of the three
     once implemented, since Airlock has none and MakerChecker's mechanism
     isn't a transparent proxy at all. **Superseded as written: two more
     entrants now advertise the same property, one with the same primitive.
     See the 2026-09-22 review below — it was true of the three products
     compared here, and is no longer true of the category.**
  - **What is not realistic:** competing on feature breadth (multi-backend,
    discovery, sandbox presets, HITL channel variety, dashboards) against
    Airlock specifically. That gap is large and Airlock is actively
    maintained; closing it is not a "no rush, solo maintainer" undertaking.
- **Candidate strategic direction raised 2026-07-24: target the Latin
  American / Spanish-speaking developer market rather than compete head-on in
  the (apparently English-first, US/EU-enterprise-oriented) market these
  three competitors serve.**
  - **Supporting signal (weak, not verified):** none of Lasso, Gate22, Lunar,
    IBM ContextForge, MakerChecker, or Airlock show any visible
    Spanish-language documentation, LatAm-specific compliance examples, or
    LatAm community presence in what was reviewed. That is not the same as
    confirming an underserved market exists or is currently sizable —
    MCP/agentic-AI adoption in LatAm dev communities may itself be lagging,
    which would mean less competition **and** less current demand at once.
  - **Why this is a plausible, non-random wedge for this specific project:**
    it mirrors the already-recorded insight for CryptoCapi
    ([[project_repo_discoverability]]: "el cuello de botella es distribución,
    no código") — localization + community-specific distribution can be a
    real edge when the underlying technology is otherwise commoditized,
    without requiring Ganimedes to win a feature race it cannot realistically
    win.
  - **Combines coherently with the technical differentiator above:** "the
    zero-dependency, cryptographically rigorous MCP gateway, documented and
    supported in Spanish for the LatAm developer community" is one coherent
    position, not two separate ideas bolted together.
  - **Validated 2026-07-24 (Argentina/LatAm check):** searched specifically
    for an Argentina-based or LatAm-focused MCP gateway/security product. None
    found. What exists in Spanish is **educational content only** (articles
    explaining what MCP is and its risks — e.g. hard2bit, rootstack,
    naxia.es/Spain) — nobody building the tool itself in this market yet.
  - **Found stronger evidence than expected: real, current, measured demand,
    not just an absence of competitors.** Per Argentina-specific search
    results: 81% of Argentine companies have adopted or are adopting AI; the
    regional AI-agent market is projected to grow ~47% annually in 2026; and
    per the 2026 Data Security Index, only 47% of organizations have
    implemented specific security controls for these tools — a documented,
    quantified security gap, not a guess. There is also an existing local
    ecosystem of AI-agent vendors serving Argentine companies (per
    developargentina.com's 2026 vendor guide), meaning real organizations
    already deploying agents that would need governance.
  - **A concrete distribution channel already exists:** **Nerdearla** — "the
    largest free tech event in Hispanic America," held in Argentina — had 175
    submissions in its Data Science/AI category for 2026, the largest
    category at the event. A real, existing venue to reach this audience,
    not a hypothetical one.
  - **Caveat, kept honest:** this is search-based validation, not a market
    study — a small/new Argentine or LatAm player could exist without
    surfacing in these queries, and "no visible competitor + real demand
    signal" is still short of proof that Ganimedes specifically would be
    adopted there. Treat as meaningfully de-risked, not confirmed.
- **Why deferred:** the LatAm/language go-to-market piece is still a
  positioning decision, not an implementation task; it should inform (not be
  decided by) the M3 design. The audit-rigor half of this entry is no longer
  deferred — it was formalized as a decision in `DESIGN.md` §7 on 2026-07-24.

- **REVIEWED 2026-09-22 — the market moved, and one of the two differentiators
  above is no longer exclusive.** The July reading was built from two
  competitors reviewed in depth. The trigger for re-reading was narrower and
  more practical: asking what it would take to get Ganimedes listed somewhere
  an agent or a developer would find it. That surfaced
  [`e2b-dev/awesome-mcp-gateways`](https://github.com/e2b-dev/awesome-mcp-gateways),
  a directory of this exact category, and its contents are the update.
  - **Scale.** That list tracks **42 gateways** (19 open-source, 23 commercial)
    where July's analysis knew of two direct competitors. Microsoft, IBM,
    Docker, Kong, Traefik and AWS have all shipped MCP gateways. This is no
    longer a space with room to be early in.
  - **All three v0 pillars are now claimed by somebody.** Tamper-evident
    audit: **Wirken** (open-source) advertises a "per-session tamper-evident
    audit log", and **KYDE Gateway** (commercial) advertises an
    "**Ed25519-signed audit ledger**" — the same primitive this project chose
    on 2026-07-24. Human-in-the-loop: **Peta** ships "HITL approvals".
    Deterministic policy: **PolicyLayer** sells "deterministic rules to every
    tool call, outside the LLM reasoning loop", which is close to this
    project's own sentence.
  - **What that does and does not mean, kept apart deliberately.** What is
    established is that the *claim* of cryptographic tamper-evidence is no
    longer unique. What is **not** established is whether the implementations
    match: July's review of Airlock found "tamper-evident" marketing over
    plain SQLite with no chain and no signing, which is exactly the gap worth
    checking again here. Whether Wirken's log is chained, whether KYDE's
    Ed25519 ledger is verifiable offline by a third party holding only a
    public key, whether either canonicalises (RFC 8785) so two encodings of a
    payload cannot hash differently — all unknown. These are one-line
    directory descriptions, not code reviews. **The honest state: the
    differentiator has gone from "unique" to "contested", and turning
    "contested" back into a defensible claim requires reading their
    implementations the way July read Airlock's.** That is the unfinished work
    this bullet records.
  - **What survives, and it is narrower than before.** The list is dominated by
    Node, Docker, Kubernetes and enterprise control planes. A single static Go
    binary with no dependencies, no runtime, no database, no account and no
    network is close to absent from those 42, and the reasoning in `DESIGN.md`'s
    Go decision log holds. The second survivor is not a feature: none of those
    42 publishes its own list of accepted limitations the way `SECURITY.md` and
    `GO_NO_GO.md` §6 do. That is unusual enough in a security category to be
    worth treating as positioning rather than as housekeeping.
  - **The listing question itself, answered.** The open-source section of that
    list requires "**200 stars and 2 contributors or more**". Ganimedes has **0
    stars and 1 contributor** (checked 2026-09-22, public since 2026-07-22). So
    the directory is a *lagging* indicator: entering it requires the adoption
    someone would enter it to find. Auto-generated rankings such as
    `best-of-mcp-servers` crawl rather than accept submissions, so the GitHub
    topics already set on the repo are the only lever that works today without
    users.
  - **What this does to the LatAm wedge: it raises it, not lowers it.** The
    July case for it assumed feature and rigor differentiation was holding.
    With the technical differentiators eroding and the category crowding at
    this rate, a distribution wedge nobody else is working (Spanish-language
    docs and support, Nerdearla as a concrete venue) stops being one of two
    strategies and becomes the one that does not require out-shipping Microsoft
    and IBM.
- **Logged:** 2026-07-24. **Reviewed:** 2026-07-31, 2026-09-22.
