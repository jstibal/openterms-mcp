"""
Openterms MCP Server
====================

An MCP (Model Context Protocol) server that exposes Openterms receipt
issuance and verification as tools for any MCP-compatible AI agent.

Compatible with: Claude Desktop, Cursor, Windsurf, any MCP client.

Setup:
  1. pip install mcp httpx
  2. Set OPENTERMS_API_URL and OPENTERMS_API_KEY environment variables
  3. Add to your MCP client config (see README)

What agents can do with this:
  - issue_receipt: Create a signed terms receipt before taking an action
  - verify_receipt: Verify any receipt's cryptographic integrity
  - check_balance: Check workspace balance before issuing
  - get_pricing: Discover current receipt pricing
  - list_receipts: View recent receipt history
"""

import os
import json
import urllib.request
import urllib.error
from datetime import datetime, timezone

# ============================================================
# CONFIG
# ============================================================

OPENTERMS_API_URL = os.environ.get("OPENTERMS_API_URL", "https://openterms.com")
OPENTERMS_API_KEY = os.environ.get("OPENTERMS_API_KEY", "")

# ============================================================
# HTTP CLIENT (stdlib — no dependencies)
# ============================================================

def _api_call(method: str, path: str, body: dict = None, auth: bool = True) -> dict:
    """Make an HTTP request to the Openterms API."""
    url = f"{OPENTERMS_API_URL.rstrip('/')}{path}"
    
    headers = {"Content-Type": "application/json"}
    if auth and OPENTERMS_API_KEY:
        headers["Authorization"] = f"Bearer {OPENTERMS_API_KEY}"
    
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        error_body = e.read().decode()
        try:
            return json.loads(error_body)
        except json.JSONDecodeError:
            return {"error": {"code": "HTTP_ERROR", "message": f"{e.code}: {error_body[:200]}"}}
    except Exception as e:
        return {"error": {"code": "CONNECTION_ERROR", "message": str(e)}}


# ============================================================
# MCP SERVER (using the `mcp` SDK)
# ============================================================

try:
    from mcp.server.fastmcp import FastMCP
    HAS_MCP_SDK = True
except ImportError:
    HAS_MCP_SDK = False

if HAS_MCP_SDK:
    mcp = FastMCP(
        "openterms",
        description="Issue and verify cryptographic terms receipts for agent actions"
    )

    @mcp.tool()
    def issue_receipt(
        agent_id: str,
        action_type: str,
        terms_url: str,
        terms_hash: str,
        action_context: dict = None,
        idempotency_key: str = None,
    ) -> str:
        """
        Issue a signed terms receipt before taking an action.
        
        Call this BEFORE performing any significant action (API call, data access,
        purchase) to create a cryptographic record of consent.
        
        Args:
            agent_id: Your agent identifier (e.g., "my-research-agent")
            action_type: One of "api_call", "data_access", "purchase", "custom"
            terms_url: URL of the terms being agreed to
            terms_hash: SHA-256 hash of the terms document (64 hex chars)
            action_context: Optional dict with action details (model, endpoint, etc.)
            idempotency_key: Optional key to prevent duplicate receipts
            
        Returns:
            JSON string with the signed receipt (includes receipt_id, signature, 
            canonical_hash, key_id) or an error message.
        """
        payload = {
            "agent_id": agent_id,
            "action_type": action_type,
            "terms_url": terms_url,
            "terms_hash": terms_hash,
            "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
            "pricing_version": "2025-01",
        }
        if action_context:
            payload["action_context"] = action_context
        
        result = _api_call("POST", "/v1/receipts", payload)
        return json.dumps(result, indent=2)

    @mcp.tool()
    def verify_receipt(receipt_json: str) -> str:
        """
        Verify a receipt's cryptographic integrity.
        
        This is a public endpoint — no authentication required.
        Paste the full receipt JSON to check if it's valid.
        
        Args:
            receipt_json: Full receipt JSON string to verify
            
        Returns:
            JSON with verification result (valid: true/false, details)
        """
        try:
            receipt_data = json.loads(receipt_json)
        except json.JSONDecodeError:
            return json.dumps({"valid": False, "error": "Invalid JSON"})
        
        result = _api_call("POST", "/v1/receipts/verify", receipt_data, auth=False)
        return json.dumps(result, indent=2)

    @mcp.tool()
    def check_balance() -> str:
        """
        Check the current workspace balance.
        
        Returns balance in USDC (6 decimal places), deposit address,
        and workspace ID.
        """
        result = _api_call("GET", "/v1/balance")
        if "balance" in result:
            result["balance_usdc"] = f"${result['balance'] / 1_000_000:.6f}"
        return json.dumps(result, indent=2)

    @mcp.tool()
    def get_pricing() -> str:
        """
        Get current receipt pricing.
        
        Returns the cost per receipt in USDC minor units.
        No authentication required.
        """
        result = _api_call("GET", "/v1/pricing", auth=False)
        if "price_per_receipt" in result:
            result["price_usdc"] = f"${result['price_per_receipt'] / 1_000_000:.6f}"
        return json.dumps(result, indent=2)

    @mcp.tool()
    def list_receipts(limit: int = 10, action_type: str = None) -> str:
        """
        List recent receipts for this workspace.
        
        Args:
            limit: Number of receipts to return (max 100)
            action_type: Optional filter: "api_call", "data_access", "purchase", "custom"
            
        Returns:
            JSON array of recent receipts with pagination info.
        """
        params = f"?limit={min(limit, 100)}"
        if action_type:
            params += f"&action_type={action_type}"
        result = _api_call("GET", f"/v1/receipts{params}")
        return json.dumps(result, indent=2)


# ============================================================
# STANDALONE MODE (no MCP SDK — works as a CLI tool)
# ============================================================

def _cli_mode():
    """Fallback CLI mode when MCP SDK isn't installed."""
    import sys
    
    usage = """
Openterms CLI — Terms Receipt Management

Usage:
  python openterms_mcp_server.py issue <agent_id> <action_type> <terms_url> <terms_hash>
  python openterms_mcp_server.py verify '<receipt_json>'
  python openterms_mcp_server.py balance
  python openterms_mcp_server.py pricing
  python openterms_mcp_server.py list [limit]

Environment:
  OPENTERMS_API_URL  — API base URL (default: Manus deployment)
  OPENTERMS_API_KEY  — Your openterms_* API key

Examples:
  export OPENTERMS_API_KEY="openterms_sk_your_key_here"
  python openterms_mcp_server.py pricing
  python openterms_mcp_server.py issue my-agent api_call https://example.com/terms a1b2c3d4...
  python openterms_mcp_server.py balance
"""
    
    if len(sys.argv) < 2:
        print(usage)
        return
    
    cmd = sys.argv[1]
    
    if cmd == "issue" and len(sys.argv) >= 6:
        payload = {
            "agent_id": sys.argv[2],
            "action_type": sys.argv[3],
            "terms_url": sys.argv[4],
            "terms_hash": sys.argv[5],
            "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
            "pricing_version": "2025-01",
        }
        result = _api_call("POST", "/v1/receipts", payload)
        print(json.dumps(result, indent=2))
    
    elif cmd == "verify" and len(sys.argv) >= 3:
        receipt_data = json.loads(sys.argv[2])
        result = _api_call("POST", "/v1/receipts/verify", receipt_data, auth=False)
        print(json.dumps(result, indent=2))
    
    elif cmd == "balance":
        result = _api_call("GET", "/v1/balance")
        print(json.dumps(result, indent=2))
    
    elif cmd == "pricing":
        result = _api_call("GET", "/v1/pricing", auth=False)
        print(json.dumps(result, indent=2))
    
    elif cmd == "list":
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 10
        result = _api_call("GET", f"/v1/receipts?limit={limit}")
        print(json.dumps(result, indent=2))
    
    else:
        print(usage)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    if HAS_MCP_SDK:
        # Run as MCP server (stdio transport)
        mcp.run()
    else:
        _cli_mode()
