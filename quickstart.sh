#!/bin/bash
# Openterms Quickstart
# Creates a workspace, gets an API key, and issues your first receipt.
# Usage: bash quickstart.sh

set -e

BASE_URL="${OPENTERMS_URL:-http://localhost:5000}"

echo "=== Openterms Quickstart ==="
echo "Server: $BASE_URL"
echo ""

# Check if server is running
if ! curl -s "$BASE_URL/v1/pricing" > /dev/null 2>&1; then
    echo "Server not running. Starting it..."
    python run.py &
    SERVER_PID=$!
    sleep 3
    if ! curl -s "$BASE_URL/v1/pricing" > /dev/null 2>&1; then
        echo "ERROR: Could not start server. Run 'pip install flask pyjwt cryptography pyyaml' first."
        kill $SERVER_PID 2>/dev/null
        exit 1
    fi
    echo "Server started (PID $SERVER_PID)"
    echo ""
fi

# 1. Create workspace
echo "[1/4] Creating workspace..."
NONCE=$(curl -s -X POST "$BASE_URL/v1/auth/nonce" \
    -H 'Content-Type: application/json' \
    -d '{"wallet_address":"0xquickstart"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['nonce'])")

TOKEN=$(curl -s -X POST "$BASE_URL/v1/auth/siwe" \
    -H 'Content-Type: application/json' \
    -d "{\"wallet_address\":\"0xquickstart\",\"nonce\":\"$NONCE\"}" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

echo "       Workspace created."

# 2. Create API key
echo "[2/4] Creating API key..."
KEY=$(curl -s -X POST "$BASE_URL/v1/keys" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"label":"quickstart-agent"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['raw_key'])")

echo "       API key: $KEY"

# 3. Issue first receipt
echo "[3/4] Issuing your first receipt..."
TERMS_HASH=$(python3 -c "import hashlib; print(hashlib.sha256(b'example terms of service').hexdigest())")

RECEIPT=$(curl -s -X POST "$BASE_URL/v1/receipts" \
    -H "Authorization: Bearer $KEY" \
    -H 'Content-Type: application/json' \
    -d "{
        \"agent_id\": \"quickstart-agent\",
        \"action_type\": \"api_call\",
        \"terms_url\": \"https://example.com/tos\",
        \"terms_hash\": \"$TERMS_HASH\"
    }")

RECEIPT_ID=$(echo "$RECEIPT" | python3 -c "import sys,json; print(json.load(sys.stdin)['receipt_id'])")
HASH=$(echo "$RECEIPT" | python3 -c "import sys,json; print(json.load(sys.stdin)['canonical_hash'])")

echo "       Receipt issued: $RECEIPT_ID"

# 4. Verify it
echo "[4/4] Verifying receipt..."
VALID=$(curl -s "$BASE_URL/v1/receipts/verify/$HASH" | python3 -c "import sys,json; print(json.load(sys.stdin)['valid'])")
echo "       Verified: $VALID"

echo ""
echo "=== Done ==="
echo ""
echo "Your API key:      $KEY"
echo "Receipt ID:        $RECEIPT_ID"
echo "Canonical hash:    $HASH"
echo ""
echo "Next steps:"
echo "  - Set a policy:    curl -X PUT $BASE_URL/v1/policy -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' -d '{\"rules\":[{\"type\":\"daily_spend_cap\",\"limit\":5000000}]}'"
echo "  - Verify receipt:  curl $BASE_URL/v1/receipts/verify/$HASH"
echo "  - MCP config:      Set OPENTERMS_API_KEY=$KEY in your MCP server config"
