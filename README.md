# openterms-mcp

When your AI agent calls an API on your behalf, where's the proof it agreed to the terms?

**Openterms issues Ed25519-signed receipts before your agent takes action.** Cryptographic proof of consent — independently verifiable by anyone, forever.

## What it does

Your agent gets a `issue_receipt` tool. Before any significant action (API call, data access, purchase), it requests a signed receipt. The server:

1. Validates the payload and rejects any PII (emails, SSNs)
2. Canonicalizes the JSON (deterministic, byte-for-byte stable)
3. Computes a SHA-256 hash
4. Signs with Ed25519
5. Atomically debits the workspace balance
6. Returns the receipt with `receipt_id`, `canonical_hash`, `signature`, `key_id`

Anyone can verify the receipt later using the public keys at `/.well-known/` — no API key, no trust in the server. Just math.

## Quick start

### 1. Install

```bash
git clone https://github.com/jstibal/openterms-mcp.git
cd openterms-mcp
pip install mcp httpx
```

### 2. Get an API key

Open the console at **https://openterms.com/console**, connect with any wallet address, credit yourself some demo USDC, and create an API key.

Or do it from the command line:

```bash
# Authenticate
NONCE=$(curl -s -X POST https://openterms.com/v1/auth/nonce \
  -H 'Content-Type: application/json' \
  -d '{"wallet_address":"0xdemo"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['nonce'])")

TOKEN=$(curl -s -X POST https://openterms.com/v1/auth/siwe \
  -H 'Content-Type: application/json' \
  -d "{\"wallet_address\":\"0xdemo\",\"nonce\":\"$NONCE\"}" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# Fund your workspace (10 USDC demo)
curl -s -X POST https://openterms.com/console/deposit \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"amount": 10000000}'

# Create an API key
curl -s -X POST https://openterms.com/v1/keys \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"label":"my-agent"}' | python3 -m json.tool
```

Save the `raw_key` from the response — it's shown once.

### 3. Add to your MCP client

#### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "openterms": {
      "command": "python3",
      "args": ["/full/path/to/openterms-mcp/openterms_mcp_server.py"],
      "env": {
        "OPENTERMS_API_URL": "https://openterms.com",
        "OPENTERMS_API_KEY": "openterms_sk_YOUR_KEY_HERE"
      }
    }
  }
}
```

#### Cursor

Add to `.cursor/mcp.json` in your project:

```json
{
  "mcpServers": {
    "openterms": {
      "command": "python3",
      "args": ["./openterms_mcp_server.py"],
      "env": {
        "OPENTERMS_API_URL": "https://openterms.com",
        "OPENTERMS_API_KEY": "openterms_sk_YOUR_KEY_HERE"
      }
    }
  }
}
```

### 4. Tell your agent to use it

> "Before making any external API call, use the `issue_receipt` tool to create a terms receipt. If the receipt fails, stop and notify me."

## Tools

| Tool | Auth | Description |
|------|------|-------------|
| `issue_receipt` | Yes | Issue a signed receipt before taking an action |
| `verify_receipt` | No | Verify any receipt's cryptographic integrity |
| `check_balance` | Yes | Check workspace USDC balance |
| `get_pricing` | No | Get current per-receipt pricing |
| `list_receipts` | Yes | View recent receipt history |
| `get_policy` | Yes | Read active policy (guardrails) for this workspace |
| `simulate_policy` | Yes | Test if an action would be allowed without issuing a receipt |
| `policy_decisions` | Yes | View recent policy evaluation decisions (audit trail) |

## Demo

Run the demo agent to see the full flow — discovery, pricing, receipt issuance, verification, and tamper detection:

```bash
export OPENTERMS_API_URL="https://openterms.com"
python3 demo_agent.py
```

No API key needed — it auto-provisions a workspace.

## CLI mode (no MCP SDK)

Works without the `mcp` package as a standalone CLI:

```bash
export OPENTERMS_API_KEY="openterms_sk_YOUR_KEY_HERE"

python3 openterms_mcp_server.py pricing
python3 openterms_mcp_server.py balance
python3 openterms_mcp_server.py issue my-agent api_call https://example.com/terms aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
python3 openterms_mcp_server.py list 5
python3 openterms_mcp_server.py policy
python3 openterms_mcp_server.py simulate api_call https://example.com/terms
python3 openterms_mcp_server.py decisions 10 deny
```

## Direct API usage (no MCP)

```python
import requests

receipt = requests.post(
    "https://openterms.com/v1/receipts",
    headers={"Authorization": f"Bearer {API_KEY}"},
    json={
        "agent_id": "my-agent",
        "action_type": "api_call",
        "terms_url": "https://openai.com/policies/terms-of-use",
        "terms_hash": "a" * 64,
        "timestamp": "2025-06-15T12:00:00.000Z",
        "pricing_version": "2025-01",
        "action_context": {
            "provider": "openai",
            "model": "gpt-4",
            "endpoint": "/v1/chat/completions"
        }
    }
).json()

# Verify independently (public, no auth)
verify = requests.post(
    "https://openterms.com/v1/receipts/verify",
    json=receipt
).json()
# {"valid": true, "hash_matches": true, "signature_valid": true}
```

## What's real

- **Ed25519 signatures** — real cryptography, not mocked
- **Deterministic canonicalization** — byte-for-byte stable JSON
- **PII detection** — rejects emails, SSNs, phone numbers before they hit the ledger
- **Policy engine** — 7 rule types including spending caps and action whitelists
- **Overdraft protection** — atomic balance deduction, can't go negative
- **Key rotation** — old keys archived at `/.well-known/` so historical receipts stay verifiable

## Links

- **Landing page:** https://openterms.com
- **Console:** https://openterms.com/console
- **Agent manifest:** https://openterms.com/.well-known/openterms-agent.json
- **Public keys:** https://openterms.com/.well-known/openterms-keys/
- **OpenAPI spec:** https://openterms.com/openapi.json
- **Verify endpoint:** `POST https://openterms.com/v1/receipts/verify`

## License

MIT
