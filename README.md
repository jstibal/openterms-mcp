# openterms-mcp

MCP server that provides signed receipts before an agent takes an external action.

## What it does
- Creates a signed consent receipt for a requested action
- Returns the receipt to the agent for verification and logging
- Enables auditability of tool calls and user consent

## Quick start

### Prerequisites
- Node 18+ OR Python 3.10+ (use whichever this repo supports)

### Install
1) Clone:
   git clone https://github.com/<YOUR_GH_USERNAME>/openterms-mcp.git
   cd openterms-mcp

2) Install dependencies:
   - If Node:
     npm install
   - If Python:
     pip install -r requirements.txt

### Run
- If Node:
  npm run start
- If Python:
  python server.py

## Configure your MCP client
Add this server to your MCP config:

Example (edit paths and command):
{
  "mcpServers": {
    "openterms": {
      "command": "node",
      "args": ["<PATH_TO_REPO>/server.js"]
    }
  }
}

## Test it quickly
Call the tool:
- tool: create_consent_receipt
- input: { "action": "...", "target": "...", "reason": "..." }

Expected output:
- receipt_id
- signature
- timestamp
- payload_hash

## License
MIT
