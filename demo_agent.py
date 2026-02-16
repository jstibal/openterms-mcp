#!/usr/bin/env python3
"""
Openterms Demo Agent
====================

A simple agent that demonstrates the Openterms receipt flow:
  1. Discovers the API via /.well-known/openterms-agent.json
  2. Checks pricing
  3. Issues a terms receipt BEFORE each action
  4. Performs the action
  5. Verifies the receipt independently

This shows the complete "consent-before-action" pattern that
Openterms enables for autonomous agents.

Usage:
  export OPENTERMS_API_URL="https://openterms.com"
  export OPENTERMS_API_KEY="openterms_sk_YOUR_KEY_HERE"
  python3 demo_agent.py

If no API key is set, the script will create a workspace and key automatically.
"""

import json
import hashlib
import urllib.request
import urllib.error
import os
import sys
import time
from datetime import datetime, timezone

# ============================================================
# CONFIG
# ============================================================

API_URL = os.environ.get("OPENTERMS_API_URL", "https://openterms.com")
API_KEY = os.environ.get("OPENTERMS_API_KEY", "")

# ============================================================
# HTTP HELPERS
# ============================================================

def api(method, path, body=None, headers_override=None):
    url = f"{API_URL.rstrip('/')}{path}"
    headers = {"Content-Type": "application/json"}
    if headers_override:
        headers.update(headers_override)
    elif API_KEY:
        headers["Authorization"] = f"Bearer {API_KEY}"
    
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body_text = e.read().decode()
        try:
            return e.code, json.loads(body_text)
        except:
            return e.code, {"error": body_text}
    except Exception as e:
        return 0, {"error": str(e)}


def log(emoji, msg):
    print(f"  {emoji}  {msg}")


def section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


# ============================================================
# SIMULATED AGENT ACTIONS
# ============================================================

SIMULATED_ACTIONS = [
    {
        "description": "Call OpenAI GPT-4 to summarize a document",
        "action_type": "api_call",
        "terms_url": "https://openai.com/policies/terms-of-use",
        "action_context": {
            "provider": "openai",
            "model": "gpt-4",
            "endpoint": "/v1/chat/completions",
            "tokens_estimated": 2500,
            "purpose": "document_summarization"
        }
    },
    {
        "description": "Access customer database to retrieve account info",
        "action_type": "data_access",
        "terms_url": "https://example.com/data-access-policy/v2",
        "action_context": {
            "database": "customers_prod",
            "query_type": "read_only",
            "table": "accounts",
            "filter": "account_id=12345",
            "purpose": "customer_support_lookup"
        }
    },
    {
        "description": "Purchase cloud compute resources on AWS",
        "action_type": "purchase",
        "terms_url": "https://aws.amazon.com/service-terms/",
        "action_context": {
            "provider": "aws",
            "service": "ec2",
            "instance_type": "t3.medium",
            "duration_hours": 1,
            "estimated_cost_usd": "0.0416"
        }
    },
]


# ============================================================
# DEMO FLOW
# ============================================================

def main():
    global API_KEY
    
    print()
    print("╔══════════════════════════════════════════════════════╗")
    print("║       Openterms Demo Agent — Consent Before Action  ║")
    print("╚══════════════════════════════════════════════════════╝")

    # ---- Step 0: Setup (auto-provision if no API key) ----
    section("Step 0: Setup")
    
    if not API_KEY:
        log("🔧", "No API key found. Auto-provisioning a workspace...")
        
        # Get nonce
        status, data = api("POST", "/v1/auth/nonce", {"wallet_address": "0xdemo_agent_test"})
        if status != 200:
            log("❌", f"Failed to get nonce: {data}")
            return
        nonce = data["nonce"]
        
        # Authenticate
        status, data = api("POST", "/v1/auth/siwe", {"wallet_address": "0xdemo_agent_test", "nonce": nonce})
        if status != 200:
            log("❌", f"Failed to authenticate: {data}")
            return
        token = data["token"]
        workspace_id = data["workspace_id"]
        log("✅", f"Workspace created: {workspace_id[:12]}...")
        
        auth_header = {"Authorization": f"Bearer {token}"}
        
        # Fund with demo deposit
        status, data = api("POST", "/console/deposit", {"amount": 10_000_000}, auth_header)
        log("💰", f"Funded workspace with 10 USDC (demo). Balance: {data.get('new_balance', 0) / 1_000_000:.6f} USDC")
        
        # Create API key
        status, data = api("POST", "/v1/keys", {"label": "demo-agent"}, auth_header)
        if status != 201:
            log("❌", f"Failed to create API key: {data}")
            return
        API_KEY = data["raw_key"]
        log("🔑", f"API key created: {API_KEY[:24]}...")
    else:
        log("🔑", f"Using API key: {API_KEY[:24]}...")

    # ---- Step 1: Discovery ----
    section("Step 1: Agent Discovery")
    
    status, manifest = api("GET", "/.well-known/openterms-agent.json", headers_override={})
    if status == 200:
        log("🔍", f"Discovered API: {manifest.get('name')} ({manifest.get('api_version')})")
        log("📋", f"Issue receipts at: {manifest['endpoints']['issue_receipt']}")
        log("🔓", f"Verify receipts at: {manifest['endpoints']['verify_receipt']}")
        log("💲", f"Check pricing at: {manifest['endpoints']['pricing']}")
    else:
        log("❌", f"Discovery failed: {manifest}")
        return

    # ---- Step 2: Check Pricing ----
    section("Step 2: Check Pricing")
    
    status, pricing = api("GET", "/v1/pricing", headers_override={})
    price = pricing.get("price_per_receipt", 0)
    log("💲", f"Price per receipt: {price} USDC minor units (${price / 1_000_000:.6f})")
    log("📌", f"Pricing version: {pricing.get('version')}")

    # ---- Step 3: Check Balance ----
    section("Step 3: Check Balance")
    
    status, balance = api("GET", "/v1/balance")
    bal = balance.get("balance", 0)
    log("💰", f"Current balance: {bal} ({bal / 1_000_000:.6f} USDC)")
    log("📊", f"Can issue ~{bal // max(price, 1)} receipts at current pricing")

    # ---- Step 4: Execute Actions with Receipts ----
    section("Step 4: Execute Actions (Consent → Receipt → Action)")
    
    issued_receipts = []
    
    for i, action in enumerate(SIMULATED_ACTIONS, 1):
        print(f"\n  ┌─ Action {i}: {action['description']}")
        print(f"  │")
        
        # Compute terms hash (in production, this would be a hash of the actual terms document)
        terms_hash = hashlib.sha256(action["terms_url"].encode()).hexdigest()
        
        # Issue receipt BEFORE the action
        payload = {
            "agent_id": "demo-agent-v1",
            "action_type": action["action_type"],
            "terms_url": action["terms_url"],
            "terms_hash": terms_hash,
            "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
            "pricing_version": pricing.get("version", "2025-01"),
            "action_context": action["action_context"],
        }
        
        print(f"  │  📝 Requesting terms receipt...")
        status, receipt = api("POST", "/v1/receipts", payload)
        
        if status == 201:
            print(f"  │  ✅ Receipt issued!")
            print(f"  │     receipt_id:     {receipt['receipt_id'][:16]}...")
            print(f"  │     canonical_hash: {receipt['canonical_hash'][:16]}...")
            print(f"  │     signature:      {receipt['signature'][:20]}...")
            print(f"  │     key_id:         {receipt['key_id']}")
            issued_receipts.append(receipt)
            
            # Now "perform" the action
            print(f"  │  🚀 Performing action: {action['description'][:40]}...")
            time.sleep(0.3)  # Simulate action
            print(f"  │  ✅ Action completed successfully.")
        else:
            error = receipt.get("error", {})
            print(f"  │  ❌ Receipt denied: {error.get('code', 'UNKNOWN')} — {error.get('message', '')}")
            print(f"  │  🛑 Action BLOCKED (no consent recorded).")
        
        print(f"  └─")

    # ---- Step 5: Independent Verification ----
    section("Step 5: Independent Verification (Public, No Auth)")
    
    if issued_receipts:
        receipt = issued_receipts[0]
        log("🔍", f"Verifying receipt {receipt['receipt_id'][:16]}...")
        
        status, result = api("POST", "/v1/receipts/verify", receipt, headers_override={})
        
        if result.get("valid"):
            log("✅", "VALID — Signature and hash verified independently!")
            log("🔐", f"Signed by key: {result.get('key_id')}")
            log("📐", f"Hash matches: {result.get('hash_matches')}")
        else:
            log("❌", f"INVALID — {result.get('reason', 'Unknown')}")
        
        # Now tamper and verify again
        print()
        log("🧪", "Tampering test: changing action_type to prove integrity...")
        tampered = dict(receipt)
        tampered["action_type"] = "purchase"
        
        status, result = api("POST", "/v1/receipts/verify", tampered, headers_override={})
        if not result.get("valid"):
            log("✅", f"CORRECTLY REJECTED — Tampered receipt detected!")
            log("🛡️", "This proves the receipt cannot be modified after issuance.")
        else:
            log("⚠️", "Unexpected: tampered receipt passed verification")

    # ---- Step 6: Final Balance ----
    section("Step 6: Final Balance")
    
    status, balance = api("GET", "/v1/balance")
    final_bal = balance.get("balance", 0)
    spent = bal - final_bal
    log("💰", f"Starting balance: {bal / 1_000_000:.6f} USDC")
    log("💸", f"Total spent:     {spent / 1_000_000:.6f} USDC ({len(issued_receipts)} receipts)")
    log("💰", f"Final balance:   {final_bal / 1_000_000:.6f} USDC")

    # ---- Summary ----
    section("Summary")
    
    print("""
  What just happened:
  
    1. The agent discovered the Openterms API via /.well-known/
    2. Before each action, the agent requested a signed receipt
    3. The server validated the payload, checked for PII, canonicalized
       the JSON, hashed it with SHA-256, signed with Ed25519, and 
       atomically debited the balance
    4. Only AFTER receiving the receipt did the agent proceed
    5. Anyone can verify any receipt using the public endpoint —
       no API key, no trust in the server, just math
    
  This is "consent before action" — cryptographic proof that your
  agent agreed to specific terms at a specific time, before it did
  anything. The receipt is independently verifiable forever.
  
  Learn more: https://openterms.com
""")


if __name__ == "__main__":
    main()
