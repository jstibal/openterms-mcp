# GitHub Discussion: Roadmap

**Category:** Announcements (pin this)
**Title:** Roadmap — Where Openterms is going

---

Openterms is open source and we want the roadmap to be driven by what people actually need. Here's what's shipped, what's in progress, and what's planned.

## Shipped

**MVP1 — Signed Receipts.** Ed25519-signed consent receipts. RFC 8785 canonical JSON, SHA-256 hashing. Public verification. The foundation.

**MVP2 — Policy Engine.** Programmable guardrails: spending caps, action whitelists, escalation thresholds, PII detection. Policy evaluates before the receipt is signed. Denied actions never get a receipt.

**MVP3 — Provider Verification.** API providers register, get webhooks, and verify agent consent with a single public GET call. Both sides of the transaction trust the proof.

## In Progress

**Open Receipt Specification (ORS).** A portable, versioned format for agent consent receipts — independent of Openterms as a product. Published at [github.com/jstibal/ors-spec](https://github.com/jstibal/ors-spec). Feedback and contributions welcome.

**Framework Integrations.** LangChain callback handler, CrewAI plugin — one-line integration that auto-receipts every tool call. Looking for contributors on other frameworks.

## Planned (waiting for signal)

**Receipt Chaining.** Formal parent-child linking for multi-agent workflows. Chain validation, depth limits, policy inheritance. We'll build this when people are actually running multi-agent workflows against Openterms.

**Agent Certification.** Trust levels derived from receipt history — provable track record backed by cryptographic evidence. Maps to governance frameworks like AOS for regulated industries.

**Signed Tool Results.** Extending the receipt pattern to tool outputs — not just "the agent was authorized" but "the tool returned this specific result." Anti-hallucination auditable proof.

## What should we build next?

Tell us what matters to you. The most useful feedback is:
- "I'm building X and I need Y"
- "I tried to use Openterms for X and it didn't work because Y"
- "I would use this if it had X"
