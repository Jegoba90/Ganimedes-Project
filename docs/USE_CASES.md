# Ganimedes - Use Cases

> Living document. Each use case below is tied to one of the three v0
> features in [`DESIGN.md`](DESIGN.md) (audit log, deny-list, human-in-the-loop).
> If a scenario needs something v0 does not have, it is listed separately
> under "Later", so this file does not overstate what is actually buildable
> right now.
>
> Note: v0 is **default-allow**. The deny-list blocks only the tools you list;
> everything else passes through.

## v0 (buildable now)

### 1. "What did my agent do while I was asleep?"

- **Actor:** a solo developer running an agent unattended (overnight batch job,
  autonomous coding/ops agent).
- **Problem:** the agent has MCP access to several tools and nobody is watching
  it live.
- **Without Ganimedes:** the only record is whatever the agent chooses to
  summarize, or whatever logs the model provider happens to keep.
- **With Ganimedes:** every `tools/call` is written to the local hash-chained
  audit log. `ganimedes verify` proves the log was not edited after the fact.
- **v0 feature:** audit log

### 2. Preventing an accidental destructive action

- **Actor:** a developer who gave an agent a database or filesystem MCP server.
- **Problem:** a bad prompt, a hallucinated call, or a reasoning bug can trigger
  something like `db.dropTable` or `fs.delete` on something that matters.
- **Without Ganimedes:** the tool just runs, whatever triggered it.
- **With Ganimedes:** destructive tool names go in the deny-list; the call is
  rejected before it reaches the real MCP server.
- **v0 feature:** deny-list

### 3. Requiring a human OK before something irreversible

- **Actor:** a developer letting an agent send email, push to git, or call an
  external webhook.
- **Problem:** some actions are fine most of the time but should never be fully
  autonomous (force-push to `main`, an outbound email, a webhook call). Today
  the only choice is all-or-nothing: give the agent the tool, or don't.
- **Without Ganimedes:** no middle ground between "agent can always do this" and
  "agent can never do this".
- **With Ganimedes:** mark the tool as requiring approval. The call pauses, a
  human sees it on the local approval page and approves or rejects it, with a
  timeout that defaults to deny.
- **v0 feature:** human-in-the-loop

### 4. Debugging a misbehaving agent

- **Actor:** a developer whose agent did something wrong or unexpected.
- **Problem:** reconstructing exactly which tools were called, with what
  arguments, in what order, is hard without a dedicated record.
- **Without Ganimedes:** scraping chat transcripts or provider-specific logs, if
  they exist at all.
- **With Ganimedes:** the JSONL audit log is a precise, ordered record of each
  call (tool, arguments, and result), independent of which model or provider was
  used.
- **v0 feature:** audit log

### 5. Evaluating a third-party MCP server before trusting it

- **Actor:** a developer about to plug in an MCP server they did not write
  (community server, vendor-provided server).
- **Problem:** no visibility into what the server's tools actually do, only
  what they claim to do.
- **Without Ganimedes:** trust the server blindly.
- **With Ganimedes:** run it through the gateway first. The audit log shows
  every call it makes; the deny-list acts as training wheels while evaluating
  it.
- **v0 feature:** audit log + deny-list

## Later (not v0, listed to keep scope honest)

### Compliance evidence across a team

- **Actor:** a team lead or compliance function that needs to show what an
  org's agents did over months, across many developers.
- **Needs:** centralized log storage, retention policy, aggregation across
  many local Ganimedes instances, a dashboard.
- **Why not v0:** this needs a hosted or shared component, not a single local
  JSONL file. This is the seed of the open-core model: the gateway stays local
  and free, and the hosted layer (centralized storage, retention, dashboard) is
  what a team would pay for.

### Team-wide approval workflow

- **Actor:** an engineering team where more than one person may need to review
  a high-risk action, not just whoever is at the keyboard.
- **Needs:** notifications, roles, a shared approval inbox.
- **Why not v0:** v0's approval UX is a single local page for a single human.
  Multi-user workflow is a hosted concern, same as above.
