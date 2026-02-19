Openterms
Open source cryptographic consent receipts + programmable guardrails + provider verification for AI agents.

Your agent proves what it agreed to. Your policy controls what it's allowed to do. The API provider can verify both.

License Tests

Live Demo · Quickstart · Self-Host · MCP Server · Contributing · Open Receipt Spec

What It Does
Openterms sits between your AI agent and the actions it takes. Three layers:

1. Receipts — Before your agent calls an API, it gets an Ed25519-signed receipt. Canonical JSON (RFC 8785), SHA-256 hash, real cryptography. Anyone can verify it using public keys — no API key needed, no trust in the server required.

2. Policy Engine — Daily spending caps, action type whitelists, escalation thresholds. The policy engine evaluates before the receipt is signed. Denied actions never get a receipt.

3. Provider Verification — API providers register their terms URL and verify agent consent before serving requests. One public GET call. Both sides of the transaction trust the proof.

Quickstart
60 seconds to your first receipt:

git clone https://github.com/jstibal/openterms.git
cd openterms
pip install flask pyjwt cryptography pyyaml
bash quickstart.sh
Or with Docker:

git clone https://github.com/jstibal/openterms.git
cd openterms
docker compose up --build
# In another terminal:
bash quickstart.sh
Receipt issuance is free — no wallet, no deposit, no payment required.

Self-Host
Run your own Openterms instance:

# Option 1: Direct
pip install flask pyjwt cryptography pyyaml
python run.py
# Server at http://localhost:5000

# Option 2: Docker
docker compose up --build

# Option 3: Point MCP server at your instance
export OPENTERMS_API_URL=http://localhost:5000
python openterms_mcp_server.py
Everything runs locally. SQLite database, no external dependencies.

Hosted Service
Don't want to self-host? Use the hosted instance at openterms.com — same open source code, managed for you.

MCP Server
10 tools for AI agents:

Tool	What it does
issue_receipt	Signed receipt before any action, with provider verification headers
verify_receipt	Verify receipt cryptographic integrity (public)
verify_receipt_by_hash	Look up and verify by canonical hash (public)
check_balance	Workspace balance
get_pricing	Per-receipt pricing
list_receipts	Recent receipts
get_policy	Active guardrails — call on startup
simulate_policy	Pre-check: would this action be allowed?
policy_decisions	Audit trail of every allow/deny/escalate
provider_activity	Receipt stats for your API (provider auth)
MCP Config
{
  "mcpServers": {
    "openterms": {
      "command": "python3",
      "args": ["openterms_mcp_server.py"],
      "env": {
        "OPENTERMS_API_URL": "https://openterms.com",
        "OPENTERMS_API_KEY": "openterms_your_key_here"
      }
    }
  }
}
How Provider Verification Works
Agent                    Openterms                  API Provider
  |                         |                           |
  |-- issue_receipt ------->|                           |
  |<-- receipt + headers ---|                           |
  |                         |-- webhook notification -->|
  |                         |                           |
  |-- API call + headers ---|-------------------------->|
  |                         |<-- verify/{hash} ---------|
  |                         |-- receipt data ---------->|
  |<--------- response -----|---------------------------|
Agent issues receipt → gets X-Openterms-Receipt header
Agent includes header in API call
Provider calls GET /v1/receipts/verify/{hash} — public, no auth
Valid → serve. Invalid → reject.
API Endpoints
Core
Method	Path	Auth	Description
POST	/v1/receipts	Bearer	Issue signed receipt
POST	/v1/receipts/verify	None	Verify receipt
GET	/v1/receipts/verify/{hash}	None	Verify by hash
GET	/v1/receipts	Bearer	List receipts
GET	/.well-known/jwks.json	None	Public signing keys
Policy Engine
Method	Path	Auth	Description
GET	/v1/policy	Bearer	Active policy
PUT	/v1/policy	Admin	Create/update policy
POST	/v1/policy/simulate	Bearer	Test hypothetical action
GET	/v1/policy/decisions	Bearer	Decision audit trail
Provider Verification
Method	Path	Auth	Description
POST	/v1/providers	None	Register as provider
POST	/v1/providers/verify	Provider	Verify domain
GET	/v1/provider/stats	Provider	Receipt stats
GET	/v1/provider/receipts	Provider	Recent receipts
Tests
make test
# 120 tests passing (80 core + 40 provider verification)
Architecture
openterms/
├── app.py                    # Flask API (1135 lines)
├── db.py                     # SQLite database (15 tables)
├── openterms_mcp_server.py   # MCP server + CLI (10 tools)
├── core/
│   ├── canonical.py          # RFC 8785 canonicalization
│   └── signing.py            # Ed25519 signing + JWKS
├── services/
│   ├── receipt_service.py    # Receipt pipeline
│   ├── ledger_service.py     # Balance tracking
│   └── policy_engine.py      # Rule evaluation
├── tests/
│   ├── test_core.py          # 80 tests
│   └── test_mvp3.py          # 40 tests
├── Dockerfile
├── docker-compose.yml
├── quickstart.sh
└── .env.example
Roadmap
Phase	Status	What it does
MVP1	✅ Shipped	Signed receipts — record what happened
MVP2	✅ Shipped	Policy engine — enforce what's allowed
MVP3	✅ Shipped	Provider verification — both sides trust the proof
ORS Spec	🔄 In progress	Open Receipt Specification — portable format
Integrations	🔄 In progress	LangChain, CrewAI one-line callbacks
MVP4	Planned	Receipt chaining, agent certification
Contributing
See CONTRIBUTING.md. We especially welcome framework integrations, language SDKs, and feedback on the Open Receipt Specification.

License
Apache 2.0 — see LICENSE.

Copyright 2026 Staticlabs Inc.
