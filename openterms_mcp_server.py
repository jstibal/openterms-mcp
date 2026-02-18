#!/usr/bin/env python3
"""
Openterms MCP Server — MVP 2
Provides 8 MCP tools for AI agents:
  MVP1: issue_receipt, verify_receipt, check_balance, get_pricing, list_receipts
  MVP2: get_policy, simulate_policy, policy_decisions
Also works as a standalone CLI.
"""

import os
import sys
import json
import httpx
from datetime import datetime, timezone

API_URL = os.environ.get("OPENTERMS_API_URL", "https://openterms.com")
API_KEY = os.environ.get("OPENTERMS_API_KEY", "")

TOOLS = [
    # --- MVP 1 Tools ---
    {
        "name": "issue_receipt",
        "description": (
            "Issue a cryptographically signed terms receipt BEFORE your agent takes an action. "
            "Returns an Ed25519-signed receipt proving consent to terms. "
            "If this returns POLICY_DENIED or POLICY_ESCALATION_REQUIRED, STOP and notify the user."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["agent_id", "action_type", "terms_url", "terms_hash"],
            "properties": {
                "agent_id": {"type": "string", "description": "Identifier for this agent"},
                "action_type": {"type": "string", "enum": ["api_call", "data_access", "purchase", "custom"]},
                "terms_url": {"type": "string", "description": "URL of the terms being agreed to"},
                "terms_hash": {"type": "string", "description": "SHA-256 hash of the terms document (64 hex chars)"},
                "timestamp": {"type": "string", "description": "ISO 8601 timestamp (defaults to now)"},
                "pricing_version": {"type": "string", "description": "Pricing version (defaults to 2025-01)"},
                "action_context": {"type": "object", "description": "Optional metadata (provider, model, endpoint, etc.)"},
            },
        },
    },
    {
        "name": "verify_receipt",
        "description": "Verify a receipt's cryptographic integrity. Public — no API key needed.",
        "inputSchema": {
            "type": "object",
            "required": ["receipt_id", "canonical_hash", "signature", "key_id"],
            "properties": {
                "receipt_id": {"type": "string"},
                "canonical_hash": {"type": "string"},
                "signature": {"type": "string"},
                "key_id": {"type": "string"},
            },
        },
    },
    {
        "name": "check_balance",
        "description": "Check workspace USDC balance (minor units, 1 USDC = 1,000,000).",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "get_pricing",
        "description": "Get current per-receipt pricing. Public — no API key needed.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "list_receipts",
        "description": "List recent receipts for this workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Max receipts to return (default 10, max 50)"},
                "action_type": {"type": "string", "description": "Filter by action type"},
            },
        },
    },
    # --- MVP 2: Policy Tools ---
    {
        "name": "get_policy",
        "description": (
            "Get the active policy (guardrails) for this workspace. "
            "Returns the rules that govern what this agent is allowed to do. "
            "An agent SHOULD call this on startup to understand its constraints."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "simulate_policy",
        "description": (
            "Test whether a hypothetical action would be allowed by the current policy "
            "WITHOUT actually issuing a receipt. Use this to pre-check before acting."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["action_type", "terms_url"],
            "properties": {
                "action_type": {"type": "string", "enum": ["api_call", "data_access", "purchase", "custom"]},
                "terms_url": {"type": "string", "description": "URL of the terms"},
                "action_context": {"type": "object", "description": "Optional context metadata"},
            },
        },
    },
    {
        "name": "policy_decisions",
        "description": (
            "View recent policy evaluation decisions (allow/deny/escalate) for this workspace. "
            "Useful for auditing and understanding what the policy engine has been doing."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Max decisions to return (default 10)"},
                "decision": {"type": "string", "enum": ["allow", "deny", "escalate"], "description": "Filter by decision type"},
            },
        },
    },
]


def _headers(auth=True):
    h = {"Content-Type": "application/json"}
    if auth and API_KEY:
        h["Authorization"] = f"Bearer {API_KEY}"
    return h


def _format_error(resp):
    try:
        err = resp.json()
        if "error" in err:
            e = err["error"]
            msg = f"[{e.get('code', 'ERROR')}] {e.get('message', 'Unknown error')}"
            if e.get("details"):
                msg += f"\nDetails: {json.dumps(e['details'], indent=2)}"
            return msg
    except Exception:
        pass
    return f"HTTP {resp.status_code}: {resp.text[:500]}"


def handle_tool(name, arguments):
    """Execute a tool and return the result text."""
    client = httpx.Client(base_url=API_URL, timeout=30)

    try:
        # --- MVP 1 Tools ---
        if name == "issue_receipt":
            payload = {
                "agent_id": arguments["agent_id"],
                "action_type": arguments["action_type"],
                "terms_url": arguments["terms_url"],
                "terms_hash": arguments["terms_hash"],
                "timestamp": arguments.get("timestamp",
                    datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"),
                "pricing_version": arguments.get("pricing_version", "2025-01"),
            }
            if arguments.get("action_context"):
                payload["action_context"] = arguments["action_context"]

            resp = client.post("/v1/receipts", json=payload, headers=_headers())

            if resp.status_code == 201:
                receipt = resp.json()
                return (
                    f"✅ Receipt issued successfully\n"
                    f"  receipt_id: {receipt['receipt_id']}\n"
                    f"  canonical_hash: {receipt['canonical_hash']}\n"
                    f"  signature: {receipt['signature'][:32]}...\n"
                    f"  key_id: {receipt['key_id']}\n"
                    f"  amount_charged: {receipt['amount_charged']} (USDC minor units)"
                )
            elif resp.status_code == 403:
                err = resp.json().get("error", {})
                code = err.get("code", "")
                if code == "POLICY_DENIED":
                    details = err.get("details", {})
                    return (
                        f"🚫 POLICY DENIED — Action blocked by workspace policy\n"
                        f"  Policy version: {details.get('policy_version', '?')}\n"
                        f"  Reasons: {', '.join(details.get('reasons', ['Unknown']))}\n"
                        f"  ⚠️  Do NOT proceed with this action. Notify the user."
                    )
                elif code == "POLICY_ESCALATION_REQUIRED":
                    details = err.get("details", {})
                    return (
                        f"⏸️  ESCALATION REQUIRED — Human approval needed\n"
                        f"  Policy version: {details.get('policy_version', '?')}\n"
                        f"  Reasons: {', '.join(details.get('reasons', ['Unknown']))}\n"
                        f"  ⚠️  Do NOT proceed. Ask the user to approve this action."
                    )
            return _format_error(resp)

        elif name == "verify_receipt":
            resp = client.post("/v1/receipts/verify", json=arguments, headers=_headers(auth=False))
            if resp.status_code == 200:
                v = resp.json()
                status = "✅ VALID" if v.get("valid") else "❌ INVALID"
                return (
                    f"{status}\n"
                    f"  hash_matches: {v.get('hash_matches')}\n"
                    f"  signature_valid: {v.get('signature_valid')}"
                )
            return _format_error(resp)

        elif name == "check_balance":
            resp = client.get("/v1/ledger", headers=_headers())
            if resp.status_code == 200:
                data = resp.json()
                entries = data.get("entries", [])
                balance = sum(e["amount"] for e in entries) if entries else 0
                return f"Balance: {balance:,} USDC minor units (${balance / 1_000_000:.2f} USDC)"
            return _format_error(resp)

        elif name == "get_pricing":
            resp = client.get("/v1/pricing", headers=_headers(auth=False))
            if resp.status_code == 200:
                p = resp.json()
                return (
                    f"Pricing version: {p.get('version', '?')}\n"
                    f"  Per receipt: {p.get('per_receipt', '?')} USDC minor units\n"
                    f"  Currency: {p.get('currency', 'USDC')}"
                )
            return _format_error(resp)

        elif name == "list_receipts":
            params = {}
            if arguments.get("limit"):
                params["limit"] = min(arguments["limit"], 50)
            if arguments.get("action_type"):
                params["action_type"] = arguments["action_type"]
            resp = client.get("/v1/receipts", params=params, headers=_headers())
            if resp.status_code == 200:
                data = resp.json()
                receipts = data.get("receipts", data) if isinstance(data, dict) else data
                if not receipts:
                    return "No receipts found."
                lines = [f"Found {len(receipts)} receipt(s):"]
                for r in receipts[:10]:
                    lines.append(
                        f"  [{r.get('action_type')}] {r.get('receipt_id', '?')[:12]}... "
                        f"— {r.get('terms_url', '?')} ({r.get('created_at', '?')})"
                    )
                if len(receipts) > 10:
                    lines.append(f"  ... and {len(receipts) - 10} more")
                return "\n".join(lines)
            return _format_error(resp)

        # --- MVP 2: Policy Tools ---
        elif name == "get_policy":
            resp = client.get("/v1/policy", headers=_headers())
            if resp.status_code == 200:
                policy = resp.json()
                if not policy.get("active") and policy.get("active") is not True:
                    if policy.get("version", 0) == 0:
                        return "No active policy. All actions are allowed."
                rules = policy.get("rules", [])
                lines = [
                    f"Active policy (version {policy.get('version', '?')}):",
                    f"  Rules ({len(rules)}):"
                ]
                for i, rule in enumerate(rules):
                    rtype = rule.get("type", "unknown")
                    if rtype in ("max_amount_per_receipt", "daily_spend_cap", "max_action_context_keys"):
                        lines.append(f"    {i+1}. {rtype}: limit={rule.get('limit')}")
                    elif rtype == "escalate_above_amount":
                        lines.append(f"    {i+1}. {rtype}: threshold={rule.get('threshold')}")
                    elif rtype in ("allowed_action_types", "blocked_action_types"):
                        lines.append(f"    {i+1}. {rtype}: {rule.get('values')}")
                    elif rtype == "required_terms_url_prefix":
                        lines.append(f"    {i+1}. {rtype}: {rule.get('prefix')}")
                    else:
                        lines.append(f"    {i+1}. {rtype}: {json.dumps(rule)}")
                return "\n".join(lines)
            return _format_error(resp)

        elif name == "simulate_policy":
            payload = {
                "payload": {
                    "action_type": arguments["action_type"],
                    "terms_url": arguments["terms_url"],
                }
            }
            if arguments.get("action_context"):
                payload["payload"]["action_context"] = arguments["action_context"]

            resp = client.post("/v1/policy/simulate", json=payload, headers=_headers())
            if resp.status_code == 200:
                result = resp.json()
                decision = result.get("decision", "unknown")
                icon = {"allow": "✅", "deny": "🚫", "escalate": "⏸️"}.get(decision, "❓")
                lines = [f"{icon} Simulation result: {decision.upper()}"]
                reasons = result.get("reasons", [])
                if reasons:
                    lines.append(f"  Reasons: {', '.join(reasons)}")
                for rr in result.get("rule_results", []):
                    lines.append(f"  Rule {rr.get('rule_index', '?')}: {rr.get('rule_type')} → {rr.get('decision')}")
                ctx = result.get("context", {})
                if ctx:
                    lines.append(f"  Context: daily_spend={ctx.get('daily_spend', 0)}, balance={ctx.get('current_balance', 0)}")
                return "\n".join(lines)
            return _format_error(resp)

        elif name == "policy_decisions":
            params = {"limit": min(arguments.get("limit", 10), 50)}
            if arguments.get("decision"):
                params["decision"] = arguments["decision"]
            resp = client.get("/v1/policy/decisions", params=params, headers=_headers())
            if resp.status_code == 200:
                data = resp.json()
                decisions = data.get("decisions", [])
                if not decisions:
                    return "No policy decisions recorded yet."
                lines = [f"Recent policy decisions ({len(decisions)}):"]
                for d in decisions:
                    icon = {"allow": "✅", "deny": "🚫", "escalate": "⏸️"}.get(d.get("decision"), "❓")
                    reasons = d.get("reasons", [])
                    reason_str = f" — {reasons[0]}" if reasons else ""
                    lines.append(
                        f"  {icon} {d.get('decision', '?').upper()} v{d.get('profile_version', '?')} "
                        f"receipt={d.get('receipt_id', 'n/a')[:12]}...{reason_str} ({d.get('evaluated_at', '?')})"
                    )
                return "\n".join(lines)
            return _format_error(resp)

        else:
            return f"Unknown tool: {name}"

    except httpx.ConnectError:
        return f"Connection error: Could not reach {API_URL}. Is the server running?"
    except Exception as e:
        return f"Error: {e}"
    finally:
        client.close()


# ============================================================
# MCP Server (stdio transport)
# ============================================================

def run_mcp_server():
    """Run as an MCP server over stdio."""
    try:
        from mcp.server import Server
        from mcp.server.stdio import stdio_server
        from mcp import types
    except ImportError:
        print("MCP SDK not installed. Install with: pip install mcp", file=sys.stderr)
        print("Falling back to CLI mode.", file=sys.stderr)
        run_cli()
        return

    server = Server("openterms")

    @server.list_tools()
    async def list_tools():
        return [types.Tool(**t) for t in TOOLS]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict):
        result = handle_tool(name, arguments or {})
        return [types.TextContent(type="text", text=result)]

    import asyncio
    async def main():
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())

    asyncio.run(main())


# ============================================================
# CLI Mode (no MCP SDK required)
# ============================================================

def run_cli():
    """Standalone CLI — works without the MCP SDK."""
    if len(sys.argv) < 2:
        print("Openterms MCP Server — MVP 2")
        print(f"API: {API_URL}")
        print(f"Key: {'***' + API_KEY[-8:] if API_KEY else '(not set)'}")
        print()
        print("Usage:")
        print("  python3 openterms_mcp_server.py pricing")
        print("  python3 openterms_mcp_server.py balance")
        print("  python3 openterms_mcp_server.py issue <agent_id> <action_type> <terms_url> <terms_hash>")
        print("  python3 openterms_mcp_server.py list [limit]")
        print("  python3 openterms_mcp_server.py policy")
        print("  python3 openterms_mcp_server.py simulate <action_type> <terms_url>")
        print("  python3 openterms_mcp_server.py decisions [limit] [allow|deny|escalate]")
        return

    cmd = sys.argv[1]
    if cmd == "pricing":
        print(handle_tool("get_pricing", {}))
    elif cmd == "balance":
        print(handle_tool("check_balance", {}))
    elif cmd == "issue" and len(sys.argv) >= 6:
        print(handle_tool("issue_receipt", {
            "agent_id": sys.argv[2], "action_type": sys.argv[3],
            "terms_url": sys.argv[4], "terms_hash": sys.argv[5],
        }))
    elif cmd == "list":
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 10
        print(handle_tool("list_receipts", {"limit": limit}))
    elif cmd == "policy":
        print(handle_tool("get_policy", {}))
    elif cmd == "simulate" and len(sys.argv) >= 4:
        print(handle_tool("simulate_policy", {
            "action_type": sys.argv[2], "terms_url": sys.argv[3],
        }))
    elif cmd == "decisions":
        args = {}
        if len(sys.argv) > 2:
            args["limit"] = int(sys.argv[2])
        if len(sys.argv) > 3:
            args["decision"] = sys.argv[3]
        print(handle_tool("policy_decisions", args))
    else:
        print(f"Unknown command: {cmd}")


if __name__ == "__main__":
    if sys.stdin.isatty():
        run_cli()
    else:
        run_mcp_server()
