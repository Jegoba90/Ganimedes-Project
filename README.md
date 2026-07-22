# Ganimedes

> The control and security layer for autonomous AI agents.
> We secure what AI agents **do**, not just what they know.

AI agents can now read data, call APIs, move money, deploy code, and take real
actions inside company systems. They are getting autonomy faster than anyone can
control it. Traditional security protects data, endpoints, and human identities.
Ganimedes protects a new entity: the autonomous agent that has an identity,
permissions, tools, and the power to execute actions.

Ganimedes sits between your agents and your systems, and answers four questions
about every action an agent takes:

```
        AI AGENT
           │
           ▼
      ┌──────────┐
      │ GANIMEDES│
      └────┬─────┘
           │
   ┌───────┼─────────┬─────────┐
   ▼       ▼         ▼         ▼
  WHO?    CAN?     SHOULD?   PROOF?
   │       │         │         │
identity capab.   policy+   verifiable
                   risk       audit
           │
     ┌─────┴─────┐
     ▼           ▼
   ALLOW       BLOCK
     │
     ▼
   SYSTEMS
```

- **WHO** is the agent? (identity)
- What **CAN** it do? (capabilities)
- What **SHOULD** it do right now? (policy and risk)
- Can we **PROVE** what it did? (verifiable audit)

## Status

Early. Work in progress. v0 does **one thing well** instead of ten things badly.

## v0 scope

A lightweight **MCP gateway** you drop between an AI agent and its MCP tools.
It does three things, and nothing more:

1. **Tamper-evident audit.** Every tool call (arguments and result) is recorded
   in a hash-chained log, so you can answer "what did my agent actually do?" and
   prove the log was not altered after the fact.
2. **Deny-list policy.** Simple YAML rules. Block `payment.execute` and
   `database.delete`, allow the rest. Deterministic, readable, no surprises.
3. **Human-in-the-loop.** Flagged tools pause and require explicit approval
   before they run. Deterministic rules, no ML.

If you are a developer building an agent, this is useful on day one, even if all
you ever use is the audit log.

## Explicitly NOT in v0

Multi-level identity, ML-based risk scoring, dashboards, blockchain anchoring,
pricing tiers, hosted SaaS. All of that comes later, and only if real users ask
for it. Building those now would be building what nobody requested.

## The bigger picture

The v0 gateway is the seed of a larger control plane. The roadmap follows the
same four pillars, each earned by real adoption before it is built:

| Pillar     | Question                        | v0            | Later                          |
|------------|---------------------------------|---------------|--------------------------------|
| Identity   | Who is the agent?               | -             | Agent identity and ownership   |
| Capability | What can it do?                 | Deny-list     | Fine-grained capabilities      |
| Policy     | What should it do right now?    | YAML rules    | Policy engine + risk scoring   |
| Proof      | Can we prove what it did?       | Hash-chain    | Verifiable audit trail         |

## Tech

Go. Distributed as a single static binary, no runtime required.

## License

To be defined before the repository goes public.
