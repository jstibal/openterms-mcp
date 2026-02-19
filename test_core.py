"""
Openterms Test Suite — Canonicalization, Signing, Receipts, Ledger, Policy Engine.

Run with: python3 -m pytest tests/test_core.py -v
Or standalone: python3 tests/test_core.py
"""

import sys
import os
import json
import hashlib
import unittest

# Add parent dir to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.canonical import canonicalize, canonicalize_str, _strip_nulls, _sort_keys_recursive
from core.signing import (
    SigningKey, KeyManager, compute_hash, compute_hash_hex,
    sign, verify, base64url_encode, base64url_decode,
)
from services.receipt_service import (
    ReceiptService, validate_receipt_payload, ValidationError,
)
from services.ledger_service import LedgerService, LedgerEntryType
from services.policy_engine import (
    evaluate, Decision, LedgerContext, POLICY_PROFILE_SCHEMA,
)


# ============================================================
# CANONICAL JSON TESTS
# ============================================================

class TestCanonicalJSON(unittest.TestCase):
    """Canonicalization must be byte-for-byte deterministic."""

    def test_key_sorting(self):
        """Keys must be sorted lexicographically."""
        payload = {"zebra": 1, "apple": 2, "mango": 3}
        result = canonicalize_str(payload)
        self.assertEqual(result, '{"apple":2,"mango":3,"zebra":1}')

    def test_nested_key_sorting(self):
        """Nested objects must also have sorted keys."""
        payload = {"b": {"z": 1, "a": 2}, "a": 1}
        result = canonicalize_str(payload)
        self.assertEqual(result, '{"a":1,"b":{"a":2,"z":1}}')

    def test_deeply_nested_sorting(self):
        """3+ levels of nesting."""
        payload = {"c": {"b": {"z": 1, "a": 2}, "a": 3}, "a": 0}
        result = canonicalize_str(payload)
        self.assertEqual(result, '{"a":0,"c":{"a":3,"b":{"a":2,"z":1}}}')

    def test_no_whitespace(self):
        """Compact JSON, no spaces."""
        payload = {"key": "value"}
        result = canonicalize_str(payload)
        self.assertNotIn(' ', result)
        self.assertNotIn('\n', result)

    def test_null_omission(self):
        """null values must be omitted."""
        payload = {"keep": "yes", "drop": None, "nested": {"also_drop": None, "keep2": "ok"}}
        result = canonicalize_str(payload)
        parsed = json.loads(result)
        self.assertNotIn("drop", parsed)
        self.assertNotIn("also_drop", parsed["nested"])
        self.assertEqual(parsed["keep"], "yes")
        self.assertEqual(parsed["nested"]["keep2"], "ok")

    def test_empty_objects_preserved(self):
        """Empty objects and arrays are permitted."""
        payload = {"empty_obj": {}, "empty_arr": [], "val": 1}
        result = canonicalize_str(payload)
        self.assertIn('"empty_arr":[]', result)
        self.assertIn('"empty_obj":{}', result)

    def test_integer_representation(self):
        """Integers stay as integers."""
        payload = {"count": 42}
        result = canonicalize_str(payload)
        self.assertIn('"count":42', result)

    def test_unicode_preserved(self):
        """Non-ASCII unicode should not be escaped (ensure_ascii=False)."""
        payload = {"name": "日本語"}
        result = canonicalize_str(payload)
        self.assertIn("日本語", result)

    def test_boolean_representation(self):
        """Booleans: true/false in JSON."""
        payload = {"active": True, "deleted": False}
        result = canonicalize_str(payload)
        self.assertIn('"active":true', result)
        self.assertIn('"deleted":false', result)

    def test_array_order_preserved(self):
        """Array element order must be preserved (not sorted)."""
        payload = {"items": [3, 1, 2]}
        result = canonicalize_str(payload)
        self.assertEqual(result, '{"items":[3,1,2]}')

    def test_deterministic_bytes(self):
        """Same input → identical bytes every time."""
        payload = {"z": [1, {"b": 2, "a": 1}], "a": "hello"}
        b1 = canonicalize(payload)
        b2 = canonicalize(payload)
        self.assertEqual(b1, b2)

    def test_reordered_input_same_output(self):
        """Different key orderings produce identical output."""
        p1 = {"b": 1, "a": 2}
        p2 = {"a": 2, "b": 1}
        self.assertEqual(canonicalize(p1), canonicalize(p2))

    def test_type_error_on_non_dict(self):
        """Must reject non-dict input."""
        with self.assertRaises(TypeError):
            canonicalize([1, 2, 3])
        with self.assertRaises(TypeError):
            canonicalize("string")

    def test_utf8_encoding(self):
        """Output must be valid UTF-8."""
        payload = {"emoji": "🚀", "accented": "café"}
        result = canonicalize(payload)
        decoded = result.decode('utf-8')
        self.assertIn("🚀", decoded)
        self.assertIn("café", decoded)


# ============================================================
# ED25519 SIGNING TESTS
# ============================================================

class TestSigning(unittest.TestCase):

    def setUp(self):
        self.key = SigningKey.generate()

    def test_key_generation(self):
        """Generated key has correct structure."""
        self.assertTrue(self.key.key_id.startswith('key_'))
        self.assertEqual(len(self.key.public_key_bytes()), 32)
        self.assertEqual(len(self.key.private_key_bytes()), 32)
        self.assertTrue(self.key.active)

    def test_sign_and_verify(self):
        """Sign → verify round-trip succeeds."""
        data = b"test payload"
        hash_bytes = compute_hash(data)
        signature = sign(self.key, hash_bytes)

        self.assertTrue(verify(
            self.key.public_key_bytes(), hash_bytes, signature
        ))

    def test_verify_wrong_data(self):
        """Verification fails with wrong data."""
        data = b"test payload"
        hash_bytes = compute_hash(data)
        signature = sign(self.key, hash_bytes)

        wrong_hash = compute_hash(b"wrong payload")
        self.assertFalse(verify(
            self.key.public_key_bytes(), wrong_hash, signature
        ))

    def test_verify_wrong_key(self):
        """Verification fails with wrong public key."""
        data = b"test payload"
        hash_bytes = compute_hash(data)
        signature = sign(self.key, hash_bytes)

        other_key = SigningKey.generate()
        self.assertFalse(verify(
            other_key.public_key_bytes(), hash_bytes, signature
        ))

    def test_base64url_roundtrip(self):
        """base64url encode → decode round-trip."""
        data = b"\x00\x01\x02\xff\xfe\xfd"
        encoded = base64url_encode(data)
        decoded = base64url_decode(encoded)
        self.assertEqual(data, decoded)
        # No padding in encoded
        self.assertNotIn('=', encoded)

    def test_jwk_export(self):
        """JWK export has required fields."""
        jwk = self.key.to_public_jwk()
        self.assertEqual(jwk['kty'], 'OKP')
        self.assertEqual(jwk['crv'], 'Ed25519')
        self.assertEqual(jwk['use'], 'sig')
        self.assertEqual(jwk['kid'], self.key.key_id)
        self.assertIn('x', jwk)

    def test_key_deactivation(self):
        """Deactivated key has rotated_at timestamp."""
        self.key.deactivate()
        self.assertFalse(self.key.active)
        self.assertIsNotNone(self.key.rotated_at)

    def test_hash_hex(self):
        """Hash hex is correct length and lowercase."""
        hash_hex = compute_hash_hex(b"test")
        self.assertEqual(len(hash_hex), 64)
        self.assertEqual(hash_hex, hash_hex.lower())


class TestKeyManager(unittest.TestCase):

    def test_generate_and_activate(self):
        """First key becomes active."""
        km = KeyManager()
        key = km.generate_and_activate()
        self.assertEqual(km.get_active_key(), key)

    def test_rotation(self):
        """New key deactivates old key."""
        km = KeyManager()
        key1 = km.generate_and_activate()
        key2 = km.generate_and_activate()

        self.assertEqual(km.get_active_key(), key2)
        self.assertFalse(key1.active)
        self.assertTrue(key2.active)

    def test_old_key_still_retrievable(self):
        """Rotated keys are still accessible by ID."""
        km = KeyManager()
        key1 = km.generate_and_activate()
        key1_id = key1.key_id
        km.generate_and_activate()

        retrieved = km.get_key_by_id(key1_id)
        self.assertIsNotNone(retrieved)
        self.assertFalse(retrieved.active)

    def test_list_all_keys(self):
        """All key IDs listed."""
        km = KeyManager()
        km.generate_and_activate()
        km.generate_and_activate()
        km.generate_and_activate()
        self.assertEqual(len(km.list_all_key_ids()), 3)


# ============================================================
# RECEIPT SERVICE TESTS
# ============================================================

class TestReceiptValidation(unittest.TestCase):

    def _valid_payload(self):
        return {
            "workspace_id": "550e8400-e29b-41d4-a716-446655440000",
            "agent_id": "test-agent",
            "action_type": "api_call",
            "terms_url": "https://example.com/terms/v1",
            "terms_hash": "a" * 64,
            "timestamp": "2025-06-15T12:00:00.000Z",
            "pricing_version": "2025-01",
        }

    def test_valid_payload_passes(self):
        errors = validate_receipt_payload(self._valid_payload())
        self.assertEqual(len(errors), 0)

    def test_missing_required_field(self):
        payload = self._valid_payload()
        del payload['action_type']
        errors = validate_receipt_payload(payload)
        self.assertTrue(any(e.code == 'MISSING_FIELD' for e in errors))

    def test_invalid_action_type(self):
        payload = self._valid_payload()
        payload['action_type'] = 'invalid_type'
        errors = validate_receipt_payload(payload)
        self.assertTrue(any(e.code == 'INVALID_ACTION_TYPE' for e in errors))

    def test_invalid_uuid(self):
        payload = self._valid_payload()
        payload['workspace_id'] = 'not-a-uuid'
        errors = validate_receipt_payload(payload)
        self.assertTrue(any(e.code == 'INVALID_UUID' for e in errors))

    def test_invalid_terms_hash(self):
        payload = self._valid_payload()
        payload['terms_hash'] = 'tooshort'
        errors = validate_receipt_payload(payload)
        self.assertTrue(any(e.code == 'INVALID_TERMS_HASH' for e in errors))

    def test_timestamp_without_z(self):
        payload = self._valid_payload()
        payload['timestamp'] = '2025-06-15T12:00:00.000'
        errors = validate_receipt_payload(payload)
        self.assertTrue(any(e.code == 'INVALID_TIMESTAMP' for e in errors))

    def test_pii_detection_email(self):
        payload = self._valid_payload()
        payload['action_context'] = {'user_email': 'test@example.com'}
        errors = validate_receipt_payload(payload)
        self.assertTrue(any(e.code == 'PII_DETECTED' for e in errors))

    def test_pii_detection_ssn(self):
        payload = self._valid_payload()
        payload['action_context'] = {'id': '123-45-6789'}
        errors = validate_receipt_payload(payload)
        self.assertTrue(any(e.code == 'PII_DETECTED' for e in errors))

    def test_action_context_too_many_keys(self):
        payload = self._valid_payload()
        payload['action_context'] = {f'key_{i}': i for i in range(51)}
        errors = validate_receipt_payload(payload)
        self.assertTrue(any(e.code == 'TOO_MANY_CONTEXT_KEYS' for e in errors))

    def test_valid_with_action_context(self):
        payload = self._valid_payload()
        payload['action_context'] = {'model': 'gpt-4', 'tokens': 150}
        errors = validate_receipt_payload(payload)
        self.assertEqual(len(errors), 0)


class TestReceiptService(unittest.TestCase):

    def setUp(self):
        self.km = KeyManager()
        self.km.generate_and_activate()
        self.service = ReceiptService(self.km)

    def _valid_payload(self):
        return {
            "workspace_id": "550e8400-e29b-41d4-a716-446655440000",
            "agent_id": "test-agent",
            "action_type": "api_call",
            "terms_url": "https://example.com/terms/v1",
            "terms_hash": "a" * 64,
            "timestamp": "2025-06-15T12:00:00.000Z",
            "pricing_version": "2025-01",
        }

    def test_issue_receipt(self):
        """Happy path: issue a valid receipt."""
        receipt, errors = self.service.issue(self._valid_payload(), 1000)
        self.assertIsNotNone(receipt)
        self.assertEqual(len(errors), 0)
        self.assertIsNotNone(receipt.receipt_id)
        self.assertIsNotNone(receipt.canonical_hash)
        self.assertIsNotNone(receipt.signature)
        self.assertEqual(receipt.amount_charged, 1000)

    def test_issue_invalid_payload(self):
        """Invalid payload returns errors, no receipt."""
        payload = {"bad": "data"}
        receipt, errors = self.service.issue(payload, 1000)
        self.assertIsNone(receipt)
        self.assertTrue(len(errors) > 0)

    def test_verify_receipt(self):
        """Issued receipt verifies successfully."""
        receipt, _ = self.service.issue(self._valid_payload(), 1000)
        result = self.service.verify_receipt(receipt.to_dict())
        self.assertTrue(result['valid'])

    def test_verify_tampered_receipt(self):
        """Tampered receipt fails verification."""
        receipt, _ = self.service.issue(self._valid_payload(), 1000)
        receipt_dict = receipt.to_dict()
        receipt_dict['action_type'] = 'purchase'  # Tamper
        result = self.service.verify_receipt(receipt_dict)
        self.assertFalse(result['valid'])
        self.assertEqual(result['error'], 'HASH_MISMATCH')

    def test_verify_with_rotated_key(self):
        """Receipt signed with old key still verifies after rotation."""
        receipt, _ = self.service.issue(self._valid_payload(), 1000)
        # Rotate key
        self.km.generate_and_activate()
        # Old receipt should still verify
        result = self.service.verify_receipt(receipt.to_dict())
        self.assertTrue(result['valid'])

    def test_canonical_hash_deterministic(self):
        """Same payload always produces the same canonical hash."""
        payload = self._valid_payload()
        r1, _ = self.service.issue(payload, 1000)
        r2, _ = self.service.issue(payload, 1000)
        self.assertEqual(r1.canonical_hash, r2.canonical_hash)


# ============================================================
# LEDGER TESTS
# ============================================================

class TestLedgerService(unittest.TestCase):

    def setUp(self):
        self.ledger = LedgerService()
        self.ws_id = "550e8400-e29b-41d4-a716-446655440000"

    def test_initial_balance_zero(self):
        self.assertEqual(self.ledger.get_balance(self.ws_id), 0)

    def test_credit_deposit(self):
        self.ledger.credit(self.ws_id, 5_000_000, "dep-1")  # 5 USDC
        self.assertEqual(self.ledger.get_balance(self.ws_id), 5_000_000)

    def test_debit_receipt(self):
        self.ledger.credit(self.ws_id, 5_000_000, "dep-1")
        entry, error = self.ledger.debit_for_receipt(self.ws_id, 1000, "rcpt-1")
        self.assertIsNotNone(entry)
        self.assertIsNone(error)
        self.assertEqual(self.ledger.get_balance(self.ws_id), 5_000_000 - 1000)

    def test_insufficient_balance(self):
        entry, error = self.ledger.debit_for_receipt(self.ws_id, 1000, "rcpt-1")
        self.assertIsNone(entry)
        self.assertEqual(error, 'INSUFFICIENT_BALANCE')

    def test_exact_balance_debit(self):
        """Can debit exact balance (leaves 0)."""
        self.ledger.credit(self.ws_id, 1000, "dep-1")
        entry, error = self.ledger.debit_for_receipt(self.ws_id, 1000, "rcpt-1")
        self.assertIsNotNone(entry)
        self.assertEqual(self.ledger.get_balance(self.ws_id), 0)

    def test_multiple_deposits_and_debits(self):
        self.ledger.credit(self.ws_id, 1_000_000, "dep-1")
        self.ledger.credit(self.ws_id, 2_000_000, "dep-2")
        self.ledger.debit_for_receipt(self.ws_id, 500_000, "rcpt-1")
        self.assertEqual(self.ledger.get_balance(self.ws_id), 2_500_000)

    def test_workspace_isolation(self):
        """Different workspaces have independent balances."""
        ws2 = "660e8400-e29b-41d4-a716-446655440000"
        self.ledger.credit(self.ws_id, 1_000_000, "dep-1")
        self.assertEqual(self.ledger.get_balance(ws2), 0)

    def test_daily_spend(self):
        self.ledger.credit(self.ws_id, 10_000_000, "dep-1")
        self.ledger.debit_for_receipt(self.ws_id, 1000, "rcpt-1")
        self.ledger.debit_for_receipt(self.ws_id, 2000, "rcpt-2")
        self.assertEqual(self.ledger.get_daily_spend(self.ws_id), 3000)

    def test_credit_must_be_positive(self):
        with self.assertRaises(ValueError):
            self.ledger.credit(self.ws_id, -100, "dep-1")


# ============================================================
# POLICY ENGINE TESTS
# ============================================================

class TestPolicyEngine(unittest.TestCase):

    def _payload(self, **overrides):
        base = {
            "workspace_id": "550e8400-e29b-41d4-a716-446655440000",
            "agent_id": "test-agent",
            "action_type": "api_call",
            "terms_url": "https://example.com/terms/v1",
            "terms_hash": "a" * 64,
            "timestamp": "2025-06-15T12:00:00.000Z",
            "pricing_version": "2025-01",
        }
        base.update(overrides)
        return base

    def _context(self, daily_spend=0, balance=10_000_000):
        return LedgerContext(daily_spend=daily_spend, current_balance=balance)

    def test_empty_rules_allows(self):
        profile = {"version": 1, "rules": []}
        result = evaluate(profile, self._payload(), self._context(), 1000)
        self.assertEqual(result.decision, Decision.ALLOW)

    def test_allowed_action_types_pass(self):
        profile = {"version": 1, "rules": [
            {"type": "allowed_action_types", "values": ["api_call", "data_access"]}
        ]}
        result = evaluate(profile, self._payload(), self._context(), 1000)
        self.assertEqual(result.decision, Decision.ALLOW)

    def test_allowed_action_types_deny(self):
        profile = {"version": 1, "rules": [
            {"type": "allowed_action_types", "values": ["purchase"]}
        ]}
        result = evaluate(profile, self._payload(action_type="api_call"), self._context(), 1000)
        self.assertEqual(result.decision, Decision.DENY)

    def test_blocked_action_types(self):
        profile = {"version": 1, "rules": [
            {"type": "blocked_action_types", "values": ["purchase"]}
        ]}
        result = evaluate(profile, self._payload(action_type="purchase"), self._context(), 1000)
        self.assertEqual(result.decision, Decision.DENY)

    def test_daily_spend_cap_allow(self):
        profile = {"version": 1, "rules": [
            {"type": "daily_spend_cap", "limit": 5_000_000}
        ]}
        result = evaluate(profile, self._payload(), self._context(daily_spend=100_000), 1000)
        self.assertEqual(result.decision, Decision.ALLOW)

    def test_daily_spend_cap_deny(self):
        profile = {"version": 1, "rules": [
            {"type": "daily_spend_cap", "limit": 5_000_000}
        ]}
        result = evaluate(profile, self._payload(), self._context(daily_spend=4_999_500), 1000)
        self.assertEqual(result.decision, Decision.DENY)

    def test_max_amount_per_receipt_deny(self):
        profile = {"version": 1, "rules": [
            {"type": "max_amount_per_receipt", "limit": 500}
        ]}
        result = evaluate(profile, self._payload(), self._context(), 1000)
        self.assertEqual(result.decision, Decision.DENY)

    def test_required_terms_url_prefix_deny(self):
        profile = {"version": 1, "rules": [
            {"type": "required_terms_url_prefix", "prefix": "https://mycompany.com/"}
        ]}
        result = evaluate(profile, self._payload(), self._context(), 1000)
        self.assertEqual(result.decision, Decision.DENY)

    def test_required_terms_url_prefix_allow(self):
        profile = {"version": 1, "rules": [
            {"type": "required_terms_url_prefix", "prefix": "https://example.com/"}
        ]}
        result = evaluate(profile, self._payload(), self._context(), 1000)
        self.assertEqual(result.decision, Decision.ALLOW)

    def test_escalation(self):
        profile = {"version": 1, "rules": [
            {"type": "escalate_above_amount", "threshold": 500}
        ]}
        result = evaluate(profile, self._payload(), self._context(), 1000)
        self.assertEqual(result.decision, Decision.ESCALATE)

    def test_deny_short_circuits(self):
        """First deny stops evaluation — escalate after deny is never reached."""
        profile = {"version": 1, "rules": [
            {"type": "max_amount_per_receipt", "limit": 500},
            {"type": "escalate_above_amount", "threshold": 100},
        ]}
        result = evaluate(profile, self._payload(), self._context(), 1000)
        self.assertEqual(result.decision, Decision.DENY)
        # Only one rule result (short-circuited)
        self.assertEqual(len(result.rule_results), 1)

    def test_multiple_rules_all_allow(self):
        profile = {"version": 1, "rules": [
            {"type": "allowed_action_types", "values": ["api_call"]},
            {"type": "daily_spend_cap", "limit": 10_000_000},
            {"type": "max_amount_per_receipt", "limit": 5000},
        ]}
        result = evaluate(profile, self._payload(), self._context(), 1000)
        self.assertEqual(result.decision, Decision.ALLOW)
        self.assertEqual(len(result.rule_results), 3)

    def test_profile_version_in_result(self):
        profile = {"version": 7, "rules": []}
        result = evaluate(profile, self._payload(), self._context(), 1000)
        self.assertEqual(result.profile_version, 7)

    def test_unknown_rule_type_skipped(self):
        profile = {"version": 1, "rules": [
            {"type": "some_future_rule", "value": 42}
        ]}
        result = evaluate(profile, self._payload(), self._context(), 1000)
        self.assertEqual(result.decision, Decision.ALLOW)
        self.assertIn('Unknown rule type', result.rule_results[0].reason)


# ============================================================
# MVP 2: POLICY API INTEGRATION TESTS
# ============================================================

class TestPolicyAPI(unittest.TestCase):
    """Integration tests for the policy engine API endpoints and receipt flow."""

    def _auth(self, wallet_suffix):
        """Create an authenticated session with a fresh workspace."""
        wallet = f'0xpolicytest_{wallet_suffix}'
        resp = self.app.post('/v1/auth/nonce', json={'wallet_address': wallet})
        nonce = resp.get_json()['nonce']
        resp = self.app.post('/v1/auth/siwe', json={'wallet_address': wallet, 'nonce': nonce})
        data = resp.get_json()
        headers = {'Authorization': f'Bearer {data["token"]}', 'Content-Type': 'application/json'}
        # Fund workspace
        self.app.post('/console/deposit', json={'amount': 10_000_000}, headers=headers)
        return headers

    def setUp(self):
        import app as app_module
        app_module.app.config['TESTING'] = True
        self.app = app_module.app.test_client()

    def test_no_policy_returns_inactive(self):
        self.headers = self._auth("nopol")
        resp = self.app.get('/v1/policy', headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertFalse(data['active'])

    def test_create_policy(self):
        self.headers = self._auth("create")
        rules = [
            {"type": "daily_spend_cap", "limit": 5_000_000},
            {"type": "allowed_action_types", "values": ["api_call", "data_access"]}
        ]
        resp = self.app.put('/v1/policy', json={'rules': rules}, headers=self.headers)
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertEqual(data['version'], 1)
        self.assertTrue(data['active'])
        self.assertEqual(len(data['rules']), 2)

    def test_get_active_policy(self):
        self.headers = self._auth("getact")
        rules = [{"type": "daily_spend_cap", "limit": 1_000_000}]
        self.app.put('/v1/policy', json={'rules': rules}, headers=self.headers)
        resp = self.app.get('/v1/policy', headers=self.headers)
        data = resp.get_json()
        self.assertEqual(data['version'], 1)
        self.assertEqual(data['rules'][0]['type'], 'daily_spend_cap')

    def test_policy_versioning(self):
        self.headers = self._auth("versn")
        self.app.put('/v1/policy', json={'rules': [{"type": "daily_spend_cap", "limit": 1_000_000}]}, headers=self.headers)
        self.app.put('/v1/policy', json={'rules': [{"type": "daily_spend_cap", "limit": 2_000_000}]}, headers=self.headers)
        resp = self.app.get('/v1/policy', headers=self.headers)
        data = resp.get_json()
        self.assertEqual(data['version'], 2)
        self.assertEqual(data['rules'][0]['limit'], 2_000_000)

    def test_delete_policy(self):
        self.headers = self._auth("delpol")
        self.app.put('/v1/policy', json={'rules': [{"type": "daily_spend_cap", "limit": 1_000_000}]}, headers=self.headers)
        resp = self.app.delete('/v1/policy', headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        resp = self.app.get('/v1/policy', headers=self.headers)
        self.assertFalse(resp.get_json()['active'])

    def test_simulate_policy_allow(self):
        self.headers = self._auth("simal")
        rules = [{"type": "allowed_action_types", "values": ["api_call"]}]
        payload = {"action_type": "api_call", "terms_url": "https://example.com/tos"}
        resp = self.app.post('/v1/policy/simulate',
            json={'rules': rules, 'payload': payload}, headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['decision'], 'allow')

    def test_simulate_policy_deny(self):
        self.headers = self._auth("simdn")
        rules = [{"type": "allowed_action_types", "values": ["purchase"]}]
        payload = {"action_type": "api_call", "terms_url": "https://example.com/tos"}
        resp = self.app.post('/v1/policy/simulate',
            json={'rules': rules, 'payload': payload}, headers=self.headers)
        data = resp.get_json()
        self.assertEqual(data['decision'], 'deny')

    def test_receipt_denied_by_policy(self):
        self.headers = self._auth("rcdeny")
        """When policy blocks an action type, receipt issuance should fail with 403."""
        # Create API key
        resp = self.app.post('/v1/keys', json={'label': 'policy-test-agent'}, headers=self.headers)
        api_key = resp.get_json()['raw_key']
        key_headers = {'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'}

        # Set policy: only allow 'purchase'
        self.app.put('/v1/policy',
            json={'rules': [{"type": "allowed_action_types", "values": ["purchase"]}]},
            headers=self.headers)

        # Try to issue receipt with action_type 'api_call' — should be denied
        receipt_payload = {
            "agent_id": "policy-test-agent",
            "action_type": "api_call",
            "terms_url": "https://example.com/terms/v1",
            "terms_hash": "a" * 64,
            "timestamp": "2025-06-15T12:00:00.000Z",
            "pricing_version": "2025-01",
        }
        resp = self.app.post('/v1/receipts', json=receipt_payload, headers=key_headers)
        self.assertEqual(resp.status_code, 403)
        data = resp.get_json()
        self.assertEqual(data['error']['code'], 'POLICY_DENIED')

    def test_receipt_allowed_by_policy(self):
        self.headers = self._auth("rcallow")
        """When policy allows the action, receipt should be issued normally."""
        resp = self.app.post('/v1/keys', json={'label': 'policy-allow-agent'}, headers=self.headers)
        api_key = resp.get_json()['raw_key']
        key_headers = {'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'}

        # Set policy: allow api_call
        self.app.put('/v1/policy',
            json={'rules': [{"type": "allowed_action_types", "values": ["api_call"]}]},
            headers=self.headers)

        receipt_payload = {
            "agent_id": "policy-allow-agent",
            "action_type": "api_call",
            "terms_url": "https://example.com/terms/v1",
            "terms_hash": "a" * 64,
            "timestamp": "2025-06-15T12:00:00.000Z",
            "pricing_version": "2025-01",
        }
        resp = self.app.post('/v1/receipts', json=receipt_payload, headers=key_headers)
        self.assertEqual(resp.status_code, 201)

    def test_receipt_no_policy_allows(self):
        self.headers = self._auth("rcnopol")
        """With no active policy, receipts should be issued normally."""
        resp = self.app.post('/v1/keys', json={'label': 'no-policy-agent'}, headers=self.headers)
        api_key = resp.get_json()['raw_key']
        key_headers = {'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'}

        receipt_payload = {
            "agent_id": "no-policy-agent",
            "action_type": "api_call",
            "terms_url": "https://example.com/terms/v1",
            "terms_hash": "a" * 64,
            "timestamp": "2025-06-15T12:00:00.000Z",
            "pricing_version": "2025-01",
        }
        resp = self.app.post('/v1/receipts', json=receipt_payload, headers=key_headers)
        self.assertEqual(resp.status_code, 201)

    def test_policy_decisions_logged(self):
        self.headers = self._auth("pdlog")
        """Policy decisions should appear in the decision log."""
        resp = self.app.post('/v1/keys', json={'label': 'log-agent'}, headers=self.headers)
        api_key = resp.get_json()['raw_key']
        key_headers = {'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'}

        self.app.put('/v1/policy',
            json={'rules': [{"type": "allowed_action_types", "values": ["api_call"]}]},
            headers=self.headers)

        # Issue a receipt (should be allowed and logged)
        self.app.post('/v1/receipts', json={
            "agent_id": "log-agent", "action_type": "api_call",
            "terms_url": "https://example.com/terms/v1", "terms_hash": "a" * 64,
            "timestamp": "2025-06-15T12:00:00.000Z", "pricing_version": "2025-01",
        }, headers=key_headers)

        resp = self.app.get('/v1/policy/decisions', headers=self.headers)
        data = resp.get_json()
        self.assertGreaterEqual(len(data['decisions']), 1)
        self.assertEqual(data['decisions'][0]['decision'], 'allow')

    def test_policy_stats(self):
        self.headers = self._auth("stats")
        resp = self.app.get('/v1/policy/stats', headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn('total_evaluations', data)
        self.assertIn('total_denials', data)

    def test_invalid_rule_type_rejected(self):
        self.headers = self._auth("invrl")
        resp = self.app.put('/v1/policy',
            json={'rules': [{"type": "nonexistent_rule", "limit": 100}]},
            headers=self.headers)
        self.assertEqual(resp.status_code, 400)

    def test_policy_version_history(self):
        self.headers = self._auth("vhist")
        self.app.put('/v1/policy', json={'rules': [{"type": "daily_spend_cap", "limit": 1_000}]}, headers=self.headers)
        self.app.put('/v1/policy', json={'rules': [{"type": "daily_spend_cap", "limit": 2_000}]}, headers=self.headers)
        resp = self.app.get('/v1/policy/versions', headers=self.headers)
        data = resp.get_json()
        self.assertEqual(len(data['versions']), 2)

    def test_spending_cap_blocks_after_threshold(self):
        self.headers = self._auth("spcap")
        """Daily spend cap should deny receipts after the cap is reached."""
        # Temporarily disable FREE_MODE for this test (spending cap needs real prices)
        import app as app_module
        original_free_mode = app_module.FREE_MODE
        app_module.FREE_MODE = False

        try:
            resp = self.app.post('/v1/keys', json={'label': 'cap-agent'}, headers=self.headers)
            api_key = resp.get_json()['raw_key']
            key_headers = {'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'}

            # Set a very low daily cap (just above 1 receipt's cost)
            self.app.put('/v1/policy',
                json={'rules': [{"type": "daily_spend_cap", "limit": 1500}]},
                headers=self.headers)

            receipt_payload = {
                "agent_id": "cap-agent", "action_type": "api_call",
                "terms_url": "https://example.com/terms/v1", "terms_hash": "a" * 64,
                "timestamp": "2025-06-15T12:00:00.000Z", "pricing_version": "2025-01",
            }

            # First receipt: should succeed (daily_spend=0, price=1000, cap=1500)
            resp1 = self.app.post('/v1/receipts', json=receipt_payload, headers=key_headers)
            self.assertEqual(resp1.status_code, 201)

            # Second receipt: should be denied (daily_spend=1000, projected=2000, cap=1500)
            receipt_payload['timestamp'] = "2025-06-15T12:01:00.000Z"
            resp2 = self.app.post('/v1/receipts', json=receipt_payload, headers=key_headers)
            self.assertEqual(resp2.status_code, 403)
            self.assertEqual(resp2.get_json()['error']['code'], 'POLICY_DENIED')
        finally:
            app_module.FREE_MODE = original_free_mode


# ============================================================
# RUN
# ============================================================

if __name__ == '__main__':
    unittest.main(verbosity=2)
