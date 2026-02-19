# GitHub Discussion: RFC — Open Receipt Specification

**Category:** Ideas
**Title:** RFC: Open Receipt Specification (ORS) — feedback wanted

---

We're publishing the Open Receipt Specification — a portable, versioned format for cryptographic agent consent receipts. The goal is a standard that anyone can implement, not just Openterms.

The spec lives at [github.com/jstibal/ors-spec](https://github.com/jstibal/ors-spec).

## Why an open spec?

Openterms is a product. A receipt format should be a standard. If agent consent receipts are going to matter, they need to be portable — verifiable by any system, producible by any system, not locked to one vendor.

## What the spec covers

- Receipt schema (JSON Schema, annotated)
- Required vs. optional fields
- Canonicalization: JCS per RFC 8785
- Signature algorithm: Ed25519 minimum, extensible
- Verification algorithm: step-by-step pseudocode
- JWKS endpoint convention for public key distribution
- Header conventions (X-Openterms-Receipt, X-Openterms-Verify)
- Chain fields (parent_receipt_id, chain_id, depth) — defined but marked "future"
- Schema versioning and backward compatibility rules

## What we want feedback on

1. **Schema design** — Are the required fields right? Too many? Too few? What's missing?
2. **Signature algorithms** — Ed25519 is the minimum. Should the spec support other algorithms (ECDSA, RSA) for environments that require them?
3. **Chain format** — The parent-child linking for multi-agent workflows. Is the proposed approach reasonable?
4. **Header naming** — `X-Openterms-Receipt` ties the header to the product. Should it be `X-Agent-Consent-Receipt` or something vendor-neutral?
5. **Verification flow** — Is the step-by-step verification algorithm clear enough for someone to implement without looking at our code?
6. **What standard body?** — Is IETF the right place? W3C? Something else? Or just a community spec on GitHub?

If you're building agents, building APIs that agents call, or working on AI governance — your perspective would be valuable. File issues on the spec repo or comment here.
