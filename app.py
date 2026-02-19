"""
Openterms API Server — Flask application (MVP 1).
Implements all MVP 1 endpoints from the OpenAPI spec.
Uses SQLite for development (swap to Postgres for production).
"""

import os
import json
import hashlib
import secrets
import uuid
import csv
import io
import time
import functools
from datetime import datetime, timezone, timedelta

import jwt
from flask import Flask, request, jsonify, g, render_template, redirect, url_for, Response, make_response

import db
from core.canonical import canonicalize, canonicalize_str
from core.signing import (
    SigningKey as CryptoSigningKey,
    compute_hash,
    compute_hash_hex,
    sign as crypto_sign,
    verify as crypto_verify,
    base64url_encode,
    base64url_decode,
    KeyManager,
)
from services.receipt_service import ReceiptService, validate_receipt_payload
from services.policy_engine import evaluate as evaluate_policy, LedgerContext, Decision, POLICY_PROFILE_SCHEMA

# ============================================================
# APP SETUP
# ============================================================

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = os.environ.get('JWT_SECRET', secrets.token_hex(32))

JWT_SECRET = app.secret_key
JWT_ALGORITHM = 'HS256'
JWT_EXPIRY_HOURS = 1

INTERNAL_SECRET = os.environ.get('INTERNAL_SECRET', 'dev-internal-secret')
PRICE_PER_RECEIPT = int(os.environ.get('PRICE_PER_RECEIPT', '1000'))  # USDC minor units
PRICING_VERSION = os.environ.get('PRICING_VERSION', '2025-01')
FREE_MODE = os.environ.get('FREE_MODE', 'true').lower() in ('true', '1', 'yes')

# Rate limiting (in-memory, per-workspace)
_rate_limits = {}
RATE_LIMIT_PER_WORKSPACE = 100
RATE_LIMIT_WINDOW = 60

_key_manager = None


def get_key_manager() -> KeyManager:
    global _key_manager
    if _key_manager is None:
        _key_manager = KeyManager()
        active = db.get_active_signing_key()
        if active:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            private_key = Ed25519PrivateKey.from_private_bytes(active['private_key_enc'])
            public_key = private_key.public_key()
            key = CryptoSigningKey(
                key_id=active['key_id'],
                private_key=private_key,
                public_key=public_key,
                created_at=datetime.now(timezone.utc),
                active=True,
            )
            _key_manager._keys[key.key_id] = key
            _key_manager._active_key_id = key.key_id
        else:
            key = _key_manager.generate_and_activate()
            db.store_signing_key(key.key_id, key.public_key_bytes(), key.private_key_bytes())
        for sk in db.list_signing_keys():
            if sk['key_id'] not in _key_manager._keys:
                sk_data = db.get_signing_key_by_id(sk['key_id'])
                if sk_data:
                    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
                    pk = Ed25519PrivateKey.from_private_bytes(sk_data['private_key_enc'])
                    loaded = CryptoSigningKey(
                        key_id=sk_data['key_id'],
                        private_key=pk,
                        public_key=pk.public_key(),
                        created_at=datetime.now(timezone.utc),
                        active=bool(sk_data['active']),
                    )
                    _key_manager._keys[loaded.key_id] = loaded
    return _key_manager


# ============================================================
# AUTH MIDDLEWARE
# ============================================================

def error_response(code, message, status, details=None):
    body = {"error": {"code": code, "message": message}}
    if details:
        body["error"]["details"] = details
    return jsonify(body), status


def require_auth(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return error_response('UNAUTHORIZED', 'Authorization header required', 401)
        token = auth_header[7:]
        # API key auth
        if token.startswith('openterms_'):
            key_info = db.verify_api_key(token)
            if not key_info:
                return error_response('UNAUTHORIZED', 'Invalid or revoked API key', 401)
            g.workspace_id = key_info['workspace_id']
            g.auth_type = 'api_key'
            g.key_id = key_info['key_id']
            g.agent_id = key_info.get('label', key_info['key_id'])
            g.role = 'admin'
            return f(*args, **kwargs)
        # JWT auth
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            g.workspace_id = payload['workspace_id']
            g.auth_type = 'jwt'
            g.wallet_address = payload['sub']
            g.role = payload.get('role', 'viewer')
            g.user_id = payload.get('user_id')
            return f(*args, **kwargs)
        except jwt.ExpiredSignatureError:
            return error_response('UNAUTHORIZED', 'Token expired', 401)
        except jwt.InvalidTokenError:
            return error_response('UNAUTHORIZED', 'Invalid token', 401)
    return decorated


def require_admin(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if g.get('role') != 'admin':
            return error_response('FORBIDDEN', 'Admin role required', 403)
        return f(*args, **kwargs)
    return decorated


def require_provider_auth(f):
    """Auth middleware for provider endpoints. Uses provider API key."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return error_response('UNAUTHORIZED', 'Authorization header required', 401)
        token = auth_header[7:]
        if not token.startswith('openterms_pk_'):
            return error_response('UNAUTHORIZED', 'Invalid provider API key', 401)
        provider = db.verify_provider_key(token)
        if not provider:
            return error_response('UNAUTHORIZED', 'Invalid or unknown provider API key', 401)
        g.provider_id = provider['provider_id']
        g.provider = provider
        return f(*args, **kwargs)
    return decorated


# ============================================================
# RATE LIMITING
# ============================================================

def check_rate_limit(workspace_id, limit=RATE_LIMIT_PER_WORKSPACE):
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW
    if workspace_id not in _rate_limits:
        _rate_limits[workspace_id] = []
    _rate_limits[workspace_id] = [t for t in _rate_limits[workspace_id] if t > window_start]
    remaining = limit - len(_rate_limits[workspace_id])
    headers = {
        'X-RateLimit-Limit': str(limit),
        'X-RateLimit-Remaining': str(max(0, remaining)),
        'X-RateLimit-Reset': str(int(now + RATE_LIMIT_WINDOW)),
    }
    if remaining <= 0:
        headers['Retry-After'] = str(RATE_LIMIT_WINDOW)
        return False, headers
    _rate_limits[workspace_id].append(now)
    return True, headers


# ============================================================
# AUTH ENDPOINTS
# ============================================================

@app.route('/v1/auth/nonce', methods=['POST'])
def request_nonce():
    nonce = secrets.token_urlsafe(24)
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    wallet_address = None
    if request.json:
        wallet_address = request.json.get('wallet_address')
    conn = db.get_db()
    conn.execute(
        "INSERT INTO auth_nonce (nonce, wallet_address, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (nonce, wallet_address, db.now_iso(), expires_at))
    conn.commit()
    conn.close()
    return jsonify({"nonce": nonce, "expires_at": expires_at})


@app.route('/v1/auth/siwe', methods=['POST'])
def authenticate_siwe():
    """Demo SIWE auth. In production, verify real EIP-191 signature."""
    data = request.json or {}
    wallet_address = data.get('wallet_address', '').lower()
    nonce = data.get('nonce')
    if not wallet_address or not nonce:
        return error_response('INVALID_SIGNATURE', 'wallet_address and nonce required', 401)
    conn = db.get_db()
    nonce_row = conn.execute(
        "SELECT * FROM auth_nonce WHERE nonce = ? AND used = 0 AND expires_at > ?",
        (nonce, db.now_iso())).fetchone()
    if not nonce_row:
        conn.close()
        return error_response('INVALID_NONCE', 'Nonce is invalid, expired, or already used', 401)
    conn.execute("UPDATE auth_nonce SET used = 1 WHERE nonce = ?", (nonce,))
    conn.commit()
    conn.close()
    user = db.get_user_by_wallet(wallet_address)
    if not user:
        ws = db.create_workspace(f"Workspace for {wallet_address[:10]}...")
        user = db.create_user(wallet_address, ws['workspace_id'], 'admin')
    workspace = db.get_workspace(user['workspace_id'])
    now = datetime.now(timezone.utc)
    token_payload = {
        'sub': wallet_address,
        'workspace_id': user['workspace_id'],
        'role': user['role'],
        'user_id': user['user_id'],
        'iat': now,
        'exp': now + timedelta(hours=JWT_EXPIRY_HOURS),
    }
    token = jwt.encode(token_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return jsonify({
        "token": token,
        "expires_at": (now + timedelta(hours=JWT_EXPIRY_HOURS)).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
        "workspace_id": user['workspace_id'],
    })


# ============================================================
# WORKSPACE / BALANCE ENDPOINTS
# ============================================================

@app.route('/v1/balance', methods=['GET'])
@require_auth
def get_balance():
    workspace = db.get_workspace(g.workspace_id)
    if not workspace:
        return error_response('WORKSPACE_NOT_FOUND', 'Workspace not found', 404)
    balance = db.get_balance(g.workspace_id)
    return jsonify({
        "workspace_id": g.workspace_id,
        "balance": balance,
        "currency": "USDC",
        "decimals": 6,
        "deposit_address": workspace['deposit_address'],
    })


@app.route('/v1/pricing', methods=['GET'])
def get_pricing():
    if FREE_MODE:
        return jsonify({
            "version": PRICING_VERSION,
            "price_per_receipt": 0,
            "currency": "USDC",
            "decimals": 6,
            "free_mode": True,
            "message": "Receipt issuance is free during beta.",
        })
    return jsonify({
        "version": PRICING_VERSION,
        "price_per_receipt": PRICE_PER_RECEIPT,
        "currency": "USDC",
        "decimals": 6,
        "free_mode": False,
    })


# ============================================================
# API KEY ENDPOINTS
# ============================================================

@app.route('/v1/keys', methods=['POST'])
@require_auth
@require_admin
def create_key():
    data = request.json or {}
    label = data.get('label')
    user_id = g.get('user_id')
    result = db.create_api_key(g.workspace_id, label, user_id)
    db.log_audit(g.workspace_id, user_id, 'api_key.create', 'api_key', result['key_id'])
    return jsonify(result), 201


@app.route('/v1/keys', methods=['GET'])
@require_auth
@require_admin
def list_keys():
    keys = db.list_api_keys(g.workspace_id)
    return jsonify({"keys": keys})


@app.route('/v1/keys/<key_id>', methods=['DELETE'])
@require_auth
@require_admin
def revoke_key(key_id):
    success = db.revoke_api_key(key_id, g.workspace_id)
    if not success:
        return error_response('KEY_NOT_FOUND', 'API key not found or already revoked', 404)
    db.log_audit(g.workspace_id, g.get('user_id'), 'api_key.revoke', 'api_key', key_id)
    return jsonify({"key_id": key_id, "revoked_at": db.now_iso()})


# ============================================================
# RECEIPT ENDPOINTS
# ============================================================

@app.route('/v1/receipts', methods=['POST'])
@require_auth
def issue_receipt():
    allowed, rl_headers = check_rate_limit(g.workspace_id)
    if not allowed:
        resp = make_response(error_response('RATE_LIMITED', 'Rate limit exceeded', 429))
        for k, v in rl_headers.items():
            resp.headers[k] = v
        return resp

    payload = request.json
    if not payload:
        return error_response('INVALID_RECEIPT_PAYLOAD', 'Request body required', 400)

    payload['workspace_id'] = g.workspace_id
    if g.auth_type == 'api_key':
        payload['agent_id'] = g.agent_id

    # Idempotency check
    idem_key = request.headers.get('Idempotency-Key')
    if idem_key:
        request_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        stored, conflict = db.check_idempotency(g.workspace_id, idem_key, request_hash)
        if conflict:
            return error_response('IDEMPOTENCY_CONFLICT', 'Idempotency key used with different payload', 409)
        if stored:
            resp = jsonify(stored)
            for k, v in rl_headers.items():
                resp.headers[k] = v
            return resp, 201

    km = get_key_manager()
    service = ReceiptService(km)

    # --- MVP 2: Policy Engine Evaluation ---
    active_policy = db.get_active_policy(g.workspace_id)
    policy_result = None
    if active_policy:
        daily_spend = db.get_daily_spend(g.workspace_id)
        balance = db.get_balance(g.workspace_id)
        ledger_ctx = LedgerContext(daily_spend=daily_spend, current_balance=balance)
        policy_result = evaluate_policy(active_policy, payload, ledger_ctx, PRICE_PER_RECEIPT)

        if policy_result.decision == Decision.DENY:
            # --- MVP 3: Notify providers of denied action ---
            deny_info = {
                'agent_id': payload.get('agent_id', ''),
                'action_type': payload.get('action_type', ''),
                'terms_url': payload.get('terms_url', ''),
                'amount_charged': payload.get('amount', 0),
                'timestamp': payload.get('timestamp', db.now_iso()),
            }
            notify_providers(deny_info, 'receipt.denied')

            return error_response('POLICY_DENIED', policy_result.reasons[0] if policy_result.reasons else 'Denied by policy', 403,
                {'policy_version': policy_result.profile_version,
                 'decision': 'deny',
                 'reasons': policy_result.reasons,
                 'rule_results': [{'rule_type': r.rule_type, 'decision': r.decision.value, 'reason': r.reason}
                                  for r in policy_result.rule_results]})

        if policy_result.decision == Decision.ESCALATE:
            # --- MVP 3: Notify providers of escalated action ---
            escalate_info = {
                'agent_id': payload.get('agent_id', ''),
                'action_type': payload.get('action_type', ''),
                'terms_url': payload.get('terms_url', ''),
                'amount_charged': payload.get('amount', 0),
                'timestamp': payload.get('timestamp', db.now_iso()),
            }
            notify_providers(escalate_info, 'receipt.escalated')

            return error_response('POLICY_ESCALATION_REQUIRED',
                'Human approval required before this action can proceed', 202,
                {'policy_version': policy_result.profile_version,
                 'decision': 'escalate',
                 'reasons': policy_result.reasons,
                 'rule_results': [{'rule_type': r.rule_type, 'decision': r.decision.value, 'reason': r.reason}
                                  for r in policy_result.rule_results]})

    price = 0 if FREE_MODE else PRICE_PER_RECEIPT
    receipt, errors = service.issue(payload, price if price > 0 else 1)  # DB requires amount > 0

    if errors:
        error_details = [{"code": e.code, "message": e.message, "field": e.field} for e in errors]
        return error_response('INVALID_RECEIPT_PAYLOAD', 'Validation failed', 400, {"errors": error_details})

    # Atomic: store receipt (and debit balance if not in free mode)
    try:
        with db.transaction() as conn:
            if not FREE_MODE:
                debit_error = db.debit_receipt_atomic(conn, g.workspace_id, PRICE_PER_RECEIPT, receipt.receipt_id)
                if debit_error:
                    return error_response('INSUFFICIENT_BALANCE', 'Workspace balance insufficient', 402,
                                          {"balance": db.get_balance(g.workspace_id), "required": PRICE_PER_RECEIPT})
            db.insert_receipt(conn, receipt.to_dict())
    except Exception as e:
        return error_response('INTERNAL_ERROR', f'Receipt issuance failed: {str(e)}', 500)

    receipt_dict = receipt.to_dict()

    # --- MVP 3: Add headers convenience field ---
    receipt_dict['headers'] = {
        'X-Openterms-Receipt': receipt_dict.get('canonical_hash', ''),
        'X-Openterms-Verify': f"/v1/receipts/verify/{receipt_dict.get('canonical_hash', '')}",
    }

    # --- MVP 2: Log policy decision ---
    if policy_result:
        db.log_policy_decision(
            receipt.receipt_id, g.workspace_id,
            policy_result.profile_version, policy_result.decision.value,
            policy_result.reasons)

    # --- MVP 3: Notify matching providers ---
    notify_providers(receipt_dict, 'receipt.issued')

    if idem_key:
        request_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        db.store_idempotency(g.workspace_id, idem_key, request_hash, 201, receipt_dict)

    resp = jsonify(receipt_dict)
    resp.status_code = 201
    for k, v in rl_headers.items():
        resp.headers[k] = v
    return resp


@app.route('/v1/receipts/<receipt_id>', methods=['GET'])
@require_auth
def get_receipt_by_id(receipt_id):
    receipt = db.get_receipt(receipt_id)
    if not receipt or receipt['workspace_id'] != g.workspace_id:
        return error_response('RECEIPT_NOT_FOUND', 'Receipt not found', 404)
    return jsonify(receipt)


@app.route('/v1/receipts', methods=['GET'])
@require_auth
def list_receipts():
    cursor = request.args.get('cursor')
    limit = min(int(request.args.get('limit', 50)), 100)
    action_type = request.args.get('action_type')
    agent_id = request.args.get('agent_id')
    date_from = request.args.get('from')
    date_to = request.args.get('to')
    receipts, next_cursor = db.list_receipts(
        g.workspace_id, limit, cursor, action_type, agent_id, date_from, date_to)
    total = db.count_receipts(g.workspace_id)
    return jsonify({"receipts": receipts, "next_cursor": next_cursor, "total_count": total})


@app.route('/v1/receipts/export', methods=['GET'])
@require_auth
def export_receipts():
    accept = request.headers.get('Accept', 'application/json')
    action_type = request.args.get('action_type')
    date_from = request.args.get('from')
    date_to = request.args.get('to')
    receipts, _ = db.list_receipts(
        g.workspace_id, limit=10000, action_type=action_type,
        date_from=date_from, date_to=date_to)
    if 'text/csv' in accept:
        si = io.StringIO()
        if receipts:
            writer = csv.DictWriter(si, fieldnames=receipts[0].keys())
            writer.writeheader()
            for r in receipts:
                row = dict(r)
                if row.get('action_context') and isinstance(row['action_context'], dict):
                    row['action_context'] = json.dumps(row['action_context'])
                writer.writerow(row)
        resp = Response(si.getvalue(), mimetype='text/csv')
        resp.headers['Content-Disposition'] = 'attachment; filename="receipts_export.csv"'
        return resp
    resp = jsonify(receipts)
    resp.headers['Content-Disposition'] = 'attachment; filename="receipts_export.json"'
    return resp


@app.route('/v1/receipts/verify', methods=['POST'])
def verify_receipt():
    receipt_data = request.json
    if not receipt_data:
        return error_response('INVALID_RECEIPT_PAYLOAD', 'Receipt data required', 400)
    km = get_key_manager()
    service = ReceiptService(km)
    result = service.verify_receipt(receipt_data)
    return jsonify(result)


@app.route('/v1/receipts/verify/<canonical_hash>', methods=['GET'])
def verify_receipt_by_hash(canonical_hash):
    """Public endpoint: verify a receipt by its canonical hash. No auth required.
    This is the endpoint providers' SDKs call to verify an agent's receipt."""
    receipt = db.get_receipt_by_hash(canonical_hash)
    if not receipt:
        return error_response('RECEIPT_NOT_FOUND', 'No receipt found with this hash', 404)

    # Verify the cryptographic signature
    km = get_key_manager()
    service = ReceiptService(km)

    # Build minimal receipt dict for verification
    verify_result = service.verify_receipt(receipt)

    # Return public-safe receipt data (strip workspace_id for privacy)
    return jsonify({
        'valid': verify_result.get('valid', False),
        'receipt_id': receipt['receipt_id'],
        'canonical_hash': receipt['canonical_hash'],
        'agent_id': receipt['agent_id'],
        'action_type': receipt['action_type'],
        'terms_url': receipt['terms_url'],
        'terms_hash': receipt['terms_hash'],
        'amount_charged': receipt['amount_charged'],
        'timestamp': receipt['timestamp'],
        'signature': receipt['signature'],
        'key_id': receipt['key_id'],
        'created_at': receipt['created_at'],
        'verification': verify_result,
    })


@app.route('/.well-known/jwks.json')
def jwks_endpoint():
    """JWKS endpoint for provider SDKs to fetch and cache public signing keys."""
    km = get_key_manager()
    key_ids = km.list_all_key_ids()
    keys = []
    for kid in key_ids:
        key = km.get_key_by_id(kid)
        if key:
            jwk = key.to_public_jwk()
            keys.append(jwk)
    resp = jsonify({"keys": keys})
    resp.headers['Cache-Control'] = 'public, max-age=86400'
    return resp


# ============================================================
# LEDGER ENDPOINTS (new — was missing from Claude's build)
# ============================================================

@app.route('/v1/ledger', methods=['GET'])
@require_auth
def list_ledger():
    limit = min(int(request.args.get('limit', 100)), 500)
    entry_type = request.args.get('entry_type')
    entries = db.list_ledger_entries(g.workspace_id, limit, entry_type)
    return jsonify({"entries": entries, "total_count": len(entries)})


# ============================================================
# DEPOSITS ENDPOINTS (new — was missing from Claude's build)
# ============================================================

@app.route('/v1/deposits', methods=['GET'])
@require_auth
def list_deposits():
    limit = min(int(request.args.get('limit', 50)), 100)
    deposits = db.list_deposits(g.workspace_id, limit)
    return jsonify({"deposits": deposits})


# ============================================================
# POLICY ENGINE ENDPOINTS (MVP 2)
# ============================================================

@app.route('/v1/policy', methods=['GET'])
@require_auth
def get_policy():
    """Get the active policy profile for the workspace."""
    policy = db.get_active_policy(g.workspace_id)
    if not policy:
        return jsonify({'active': False, 'version': 0, 'rules': []})
    return jsonify(policy)


@app.route('/v1/policy', methods=['PUT'])
@require_auth
@require_admin
def update_policy():
    """Create a new policy version. The previous version is deactivated."""
    data = request.json
    if not data or 'rules' not in data:
        return error_response('INVALID_PAYLOAD', 'Request body must contain "rules" array', 400)
    rules = data['rules']
    if not isinstance(rules, list):
        return error_response('INVALID_PAYLOAD', '"rules" must be an array', 400)

    # Validate each rule against known types
    valid_types = {'max_amount_per_receipt', 'daily_spend_cap', 'allowed_action_types',
                   'blocked_action_types', 'required_terms_url_prefix',
                   'max_action_context_keys', 'escalate_above_amount'}
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            return error_response('INVALID_PAYLOAD', f'Rule {i} must be an object', 400)
        rule_type = rule.get('type')
        if rule_type not in valid_types:
            return error_response('INVALID_PAYLOAD',
                f'Rule {i}: unknown type "{rule_type}". Valid types: {sorted(valid_types)}', 400)
        # Type-specific validation
        if rule_type in ('max_amount_per_receipt', 'daily_spend_cap', 'max_action_context_keys'):
            if not isinstance(rule.get('limit'), (int, float)) or rule['limit'] < 0:
                return error_response('INVALID_PAYLOAD', f'Rule {i}: "limit" must be a non-negative number', 400)
        if rule_type == 'escalate_above_amount':
            if not isinstance(rule.get('threshold'), (int, float)) or rule['threshold'] < 0:
                return error_response('INVALID_PAYLOAD', f'Rule {i}: "threshold" must be a non-negative number', 400)
        if rule_type in ('allowed_action_types', 'blocked_action_types'):
            if not isinstance(rule.get('values'), list) or len(rule['values']) == 0:
                return error_response('INVALID_PAYLOAD', f'Rule {i}: "values" must be a non-empty array', 400)
        if rule_type == 'required_terms_url_prefix':
            if not isinstance(rule.get('prefix'), str) or len(rule['prefix']) == 0:
                return error_response('INVALID_PAYLOAD', f'Rule {i}: "prefix" must be a non-empty string', 400)

    user_id = g.get('user_id')
    result = db.create_policy_version(g.workspace_id, rules, created_by=user_id)
    db.log_audit(g.workspace_id, user_id, 'policy.update', 'policy_profile', result['profile_id'],
                 {'version': result['version'], 'rule_count': len(rules)})
    return jsonify(result), 201


@app.route('/v1/policy', methods=['DELETE'])
@require_auth
@require_admin
def delete_policy():
    """Deactivate the current policy. No policy = allow all receipts."""
    db.delete_active_policy(g.workspace_id)
    db.log_audit(g.workspace_id, g.get('user_id'), 'policy.delete', 'policy_profile')
    return jsonify({'status': 'deactivated', 'message': 'Policy removed. All receipts will be allowed.'})


@app.route('/v1/policy/versions', methods=['GET'])
@require_auth
def list_policy_versions():
    """List all policy versions for the workspace."""
    limit = min(int(request.args.get('limit', 20)), 100)
    versions = db.list_policy_versions(g.workspace_id, limit)
    return jsonify({'versions': versions})


@app.route('/v1/policy/versions/<int:version>', methods=['GET'])
@require_auth
def get_policy_version(version):
    """Get a specific policy version."""
    policy = db.get_policy_version(g.workspace_id, version)
    if not policy:
        return error_response('NOT_FOUND', f'Policy version {version} not found', 404)
    return jsonify(policy)


@app.route('/v1/policy/simulate', methods=['POST'])
@require_auth
def simulate_policy():
    """Test a policy (or the active policy) against a hypothetical payload without issuing a receipt."""
    data = request.json or {}
    test_payload = data.get('payload')
    if not test_payload:
        return error_response('INVALID_PAYLOAD', '"payload" is required (the hypothetical receipt payload)', 400)

    # Use provided rules or fall back to active policy
    rules = data.get('rules')
    if rules is not None:
        profile = {'version': 0, 'rules': rules}
    else:
        profile = db.get_active_policy(g.workspace_id)
        if not profile:
            return jsonify({'decision': 'allow', 'reasons': [], 'rule_results': [],
                           'message': 'No active policy — all receipts are allowed'})

    daily_spend = db.get_daily_spend(g.workspace_id)
    balance = db.get_balance(g.workspace_id)
    ledger_ctx = LedgerContext(daily_spend=daily_spend, current_balance=balance)

    result = evaluate_policy(profile, test_payload, ledger_ctx, PRICE_PER_RECEIPT)
    return jsonify({
        'decision': result.decision.value,
        'reasons': result.reasons,
        'profile_version': result.profile_version,
        'rule_results': [
            {'rule_index': r.rule_index, 'rule_type': r.rule_type,
             'decision': r.decision.value, 'reason': r.reason}
            for r in result.rule_results
        ],
        'context': {
            'daily_spend': daily_spend,
            'current_balance': balance,
            'price_per_receipt': PRICE_PER_RECEIPT,
        }
    })


@app.route('/v1/policy/decisions', methods=['GET'])
@require_auth
def list_policy_decisions():
    """List policy evaluation decisions for the workspace."""
    limit = min(int(request.args.get('limit', 50)), 500)
    decision_filter = request.args.get('decision')  # 'allow', 'deny', 'escalate'
    decisions = db.list_policy_decisions(g.workspace_id, limit, decision_filter)
    return jsonify({'decisions': decisions, 'total_count': len(decisions)})


@app.route('/v1/policy/stats', methods=['GET'])
@require_auth
def policy_stats():
    """Get policy evaluation statistics."""
    from datetime import timedelta
    cutoff_24h = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    return jsonify({
        'total_evaluations': db.count_policy_decisions(g.workspace_id),
        'total_denials': db.count_policy_decisions(g.workspace_id, 'deny'),
        'total_escalations': db.count_policy_decisions(g.workspace_id, 'escalate'),
        'denials_24h': db.count_policy_decisions(g.workspace_id, 'deny', since=cutoff_24h),
        'escalations_24h': db.count_policy_decisions(g.workspace_id, 'escalate', since=cutoff_24h),
        'active_policy': db.get_active_policy(g.workspace_id) is not None,
    })


# ============================================================
# WEBHOOK DELIVERY (MVP 3)
# ============================================================

import threading
import hmac as hmac_mod

WEBHOOK_HMAC_SECRET = os.environ.get('WEBHOOK_HMAC_SECRET', 'dev-webhook-secret')


def deliver_webhook(provider, event_type, receipt_dict, receipt_id=None):
    """Fire-and-forget webhook delivery to a provider. Runs in background thread."""
    if not provider.get('webhook_url'):
        return

    payload = {
        'event': event_type,
        'receipt_id': receipt_dict.get('receipt_id', receipt_id),
        'canonical_hash': receipt_dict.get('canonical_hash'),
        'agent_id': receipt_dict.get('agent_id'),
        'action_type': receipt_dict.get('action_type'),
        'terms_url': receipt_dict.get('terms_url'),
        'amount': receipt_dict.get('amount_charged'),
        'timestamp': receipt_dict.get('timestamp'),
    }

    # Sign the webhook payload
    payload_bytes = json.dumps(payload, sort_keys=True).encode()
    signature = hmac_mod.new(WEBHOOK_HMAC_SECRET.encode(), payload_bytes, hashlib.sha256).hexdigest()

    def _send():
        import urllib.request
        import urllib.error
        status_code = None
        try:
            req = urllib.request.Request(
                provider['webhook_url'],
                data=payload_bytes,
                headers={
                    'Content-Type': 'application/json',
                    'X-Openterms-Signature': f'sha256={signature}',
                    'X-Openterms-Event': event_type,
                },
                method='POST',
            )
            resp = urllib.request.urlopen(req, timeout=10)
            status_code = resp.getcode()
            db.log_webhook(provider['provider_id'], event_type, receipt_id,
                          payload, status_code=status_code, delivered_at=db.now_iso())
        except Exception as e:
            db.log_webhook(provider['provider_id'], event_type, receipt_id,
                          payload, status_code=status_code)

    thread = threading.Thread(target=_send, daemon=True)
    thread.start()


def notify_providers(receipt_dict, event_type='receipt.issued'):
    """Find matching providers and deliver webhooks for a receipt."""
    terms_url = receipt_dict.get('terms_url', '')
    providers = db.find_providers_for_terms_url(terms_url)
    for provider in providers:
        deliver_webhook(provider, event_type, receipt_dict, receipt_dict.get('receipt_id'))


# ============================================================
# PROVIDER ENDPOINTS (MVP 3)
# ============================================================

@app.route('/v1/providers', methods=['POST'])
def register_provider():
    """Register as an API provider. No auth required (creates account)."""
    data = request.json or {}
    required = ['name', 'terms_url_prefix', 'contact_email']
    missing = [f for f in required if not data.get(f)]
    if missing:
        return error_response('INVALID_PAYLOAD', f'Missing required fields: {missing}', 400)

    name = data['name']
    terms_url_prefix = data['terms_url_prefix']
    contact_email = data['contact_email']
    webhook_url = data.get('webhook_url')

    if not terms_url_prefix.startswith('https://'):
        return error_response('INVALID_PAYLOAD', 'terms_url_prefix must start with https://', 400)

    # Generate provider API key
    api_key_raw = f"openterms_pk_{secrets.token_urlsafe(32)}"

    try:
        provider = db.create_provider(name, terms_url_prefix, contact_email, api_key_raw, webhook_url)
    except Exception as e:
        if 'UNIQUE' in str(e):
            return error_response('CONFLICT', 'A provider with this terms_url_prefix already exists', 409)
        raise

    return jsonify({
        'provider_id': provider['provider_id'],
        'name': provider['name'],
        'terms_url_prefix': provider['terms_url_prefix'],
        'api_key': api_key_raw,
        'verified': False,
        'verification_token': provider['verification_token'],
        'verification_instructions': (
            f'Place a JSON file at {terms_url_prefix}.well-known/openterms-verify.json '
            f'containing: {{"provider_id": "{provider["provider_id"]}", '
            f'"verification_token": "{provider["verification_token"]}"}}'
        ),
        'created_at': provider['created_at'],
    }), 201


@app.route('/v1/providers/verify', methods=['POST'])
@require_provider_auth
def verify_provider():
    """Verify provider ownership of terms URL by checking the verification file."""
    provider = g.provider

    if provider['verified']:
        return jsonify({'provider_id': provider['provider_id'], 'verified': True,
                       'message': 'Already verified'})

    # Try to fetch the verification file
    verify_url = provider['terms_url_prefix']
    if not verify_url.endswith('/'):
        verify_url += '/'
    verify_url += '.well-known/openterms-verify.json'

    try:
        import urllib.request
        req = urllib.request.Request(verify_url, method='GET')
        resp = urllib.request.urlopen(req, timeout=10)
        verify_data = json.loads(resp.read())

        if (verify_data.get('provider_id') == provider['provider_id'] and
                verify_data.get('verification_token') == provider['verification_token']):
            db.verify_provider(provider['provider_id'])
            return jsonify({'provider_id': provider['provider_id'], 'verified': True,
                           'message': 'Verification successful'})
        else:
            return error_response('VERIFICATION_FAILED',
                'Verification file found but content does not match', 400)
    except Exception as e:
        return error_response('VERIFICATION_FAILED',
            f'Could not fetch verification file at {verify_url}: {str(e)}', 400)


@app.route('/v1/provider/stats', methods=['GET'])
@require_provider_auth
def provider_stats():
    """Get receipt statistics for this provider."""
    prefix = g.provider['terms_url_prefix']
    cutoff_24h = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    cutoff_7d = (datetime.now(timezone.utc) - timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    cutoff_30d = (datetime.now(timezone.utc) - timedelta(days=30)).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

    return jsonify({
        'provider_id': g.provider['provider_id'],
        'verified': bool(g.provider['verified']),
        'receipts_total': db.count_receipts_for_provider(prefix),
        'receipts_24h': db.count_receipts_for_provider(prefix, since=cutoff_24h),
        'receipts_7d': db.count_receipts_for_provider(prefix, since=cutoff_7d),
        'receipts_30d': db.count_receipts_for_provider(prefix, since=cutoff_30d),
        'unique_agents': len(db.unique_agents_for_provider(prefix)),
        'action_type_breakdown': db.action_type_breakdown_for_provider(prefix),
    })


@app.route('/v1/provider/receipts', methods=['GET'])
@require_provider_auth
def provider_receipts():
    """List recent receipts against this provider's terms URL."""
    if not g.provider['verified']:
        return error_response('FORBIDDEN', 'Provider must be verified to access receipt data', 403)

    prefix = g.provider['terms_url_prefix']
    limit = min(int(request.args.get('limit', 50)), 100)
    date_from = request.args.get('from')
    date_to = request.args.get('to')
    receipts = db.list_receipts_for_provider(prefix, limit, date_from, date_to)
    return jsonify({'receipts': receipts, 'count': len(receipts)})


@app.route('/v1/provider/agents', methods=['GET'])
@require_provider_auth
def provider_agents():
    """List unique agents that have receipts against this provider."""
    if not g.provider['verified']:
        return error_response('FORBIDDEN', 'Provider must be verified to access agent data', 403)

    prefix = g.provider['terms_url_prefix']
    agents = db.unique_agents_for_provider(prefix)
    return jsonify({'agents': agents, 'count': len(agents)})


@app.route('/v1/providers/webhook', methods=['PATCH'])
@require_provider_auth
def update_provider_webhook():
    """Update the provider's webhook URL."""
    data = request.json or {}
    webhook_url = data.get('webhook_url')
    if webhook_url and not webhook_url.startswith('https://'):
        return error_response('INVALID_PAYLOAD', 'webhook_url must start with https://', 400)
    db.update_provider_webhook(g.provider['provider_id'], webhook_url)
    return jsonify({'provider_id': g.provider['provider_id'], 'webhook_url': webhook_url,
                   'message': 'Webhook URL updated'})


@app.route('/v1/provider/webhooks', methods=['GET'])
@require_provider_auth
def provider_webhook_logs():
    """List webhook delivery logs for this provider."""
    limit = min(int(request.args.get('limit', 50)), 100)
    logs = db.list_webhook_logs(g.provider['provider_id'], limit)
    return jsonify({'webhooks': logs, 'count': len(logs)})


# ============================================================
# DISCOVERY ENDPOINTS
# ============================================================

@app.route('/.well-known/openterms-agent.json')
def agent_manifest():
    return jsonify({
        "name": "Openterms",
        "description": "Machine-readable terms receipts for autonomous agents with programmable guardrails and provider verification network",
        "api_version": "v1",
        "openapi_url": "/openapi.json",
        "endpoints": {
            "issue_receipt": "/v1/receipts",
            "verify_receipt": "/v1/receipts/verify",
            "verify_receipt_by_hash": "/v1/receipts/verify/{canonical_hash}",
            "pricing": "/v1/pricing",
            "policy": "/v1/policy",
            "policy_simulate": "/v1/policy/simulate",
            "providers": "/v1/providers",
            "provider_stats": "/v1/provider/stats",
            "provider_receipts": "/v1/provider/receipts",
        },
        "signing_keys_url": "/.well-known/openterms-keys/",
        "jwks_url": "/.well-known/jwks.json",
        "auth_methods": ["siwe", "api_key", "provider_key"],
        "features": ["policy_engine", "pii_detection", "spending_controls",
                     "provider_verification", "webhook_notifications"],
        "headers": {
            "X-Openterms-Receipt": "Canonical hash of the receipt (for provider verification)",
            "X-Openterms-Verify": "URL to verify the receipt",
        },
    })


@app.route('/.well-known/openterms-keys/<key_id>.json')
def get_public_key(key_id):
    km = get_key_manager()
    key = km.get_key_by_id(key_id)
    if not key:
        return error_response('KEY_NOT_FOUND', f'Key {key_id} not found', 404)
    jwk = key.to_public_jwk()
    resp = jsonify(jwk)
    resp.headers['Cache-Control'] = 'public, max-age=86400'
    return resp


@app.route('/.well-known/openterms-keys/')
def list_public_keys():
    km = get_key_manager()
    key_ids = km.list_all_key_ids()
    keys = []
    for kid in key_ids:
        key = km.get_key_by_id(kid)
        if key:
            keys.append({
                "key_id": kid,
                "active": key.active,
                "jwk_url": f"/.well-known/openterms-keys/{kid}.json",
            })
    return jsonify({"keys": keys})


@app.route('/openapi.json')
def openapi_spec():
    import yaml
    spec_path = os.path.join(os.path.dirname(__file__), 'schemas', 'openapi.yaml')
    with open(spec_path) as f:
        spec = yaml.safe_load(f)
    return jsonify(spec)


# ============================================================
# INTERNAL ENDPOINTS
# ============================================================

@app.route('/internal/deposits/ingest', methods=['POST'])
def ingest_deposit():
    secret = request.headers.get('X-Internal-Secret')
    if secret != INTERNAL_SECRET:
        return error_response('UNAUTHORIZED', 'Invalid internal secret', 401)
    data = request.json or {}
    required = ['tx_hash', 'log_index', 'to_address', 'amount', 'block_number', 'chain_id']
    missing = [f for f in required if f not in data]
    if missing:
        return error_response('INVALID_PAYLOAD', f'Missing fields: {missing}', 400)
    conn = db.get_db()
    ws = conn.execute("SELECT workspace_id FROM workspace WHERE deposit_address = ?",
                      (data['to_address'],)).fetchone()
    conn.close()
    if not ws:
        return error_response('WORKSPACE_NOT_FOUND', 'No workspace for this deposit address', 404)
    deposit_id = db.insert_deposit(
        workspace_id=ws['workspace_id'],
        tx_hash=data['tx_hash'],
        log_index=data['log_index'],
        from_address=data.get('from_address', '0x0'),
        amount=data['amount'],
        block_number=data['block_number'],
        chain_id=data['chain_id'],
    )
    if deposit_id:
        return jsonify({"deposit_id": deposit_id, "status": "created"})
    else:
        return jsonify({"deposit_id": None, "status": "duplicate"})


# ============================================================
# ADMIN CONSOLE (Manual Deposit for Demo)
# ============================================================

@app.route('/console/deposit', methods=['POST'])
@require_auth
@require_admin
def manual_deposit():
    data = request.json or {}
    amount = int(data.get('amount', 0))
    if amount <= 0:
        return error_response('INVALID_PAYLOAD', 'Amount must be positive', 400)
    tx_hash = f"0xdemo_{secrets.token_hex(16)}"
    deposit_id = db.insert_deposit(
        workspace_id=g.workspace_id,
        tx_hash=tx_hash, log_index=0,
        from_address="0xmanual", amount=amount,
        block_number=0, chain_id=0,
    )
    db.log_audit(g.workspace_id, g.get('user_id'), 'deposit.manual', 'deposit', deposit_id,
                 {"amount": amount})
    return jsonify({
        "deposit_id": deposit_id,
        "amount": amount,
        "new_balance": db.get_balance(g.workspace_id),
    })


# ============================================================
# LANDING PAGE & CONSOLE ROUTES
# ============================================================

@app.route('/')
def landing():
    return render_template('landing.html')


@app.route('/console')
def console_index():
    return render_template('console.html')


# ============================================================
# TRACE ID MIDDLEWARE
# ============================================================

@app.before_request
def add_trace_id():
    g.trace_id = request.headers.get('X-Trace-Id', str(uuid.uuid4())[:8])


@app.after_request
def add_trace_header(response):
    if hasattr(g, 'trace_id'):
        response.headers['X-Trace-Id'] = g.trace_id
    return response


# ============================================================
# STARTUP
# ============================================================

def init_app():
    db.init_db()
    get_key_manager()


init_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
