"""
Openterms MVP3 Test Suite — Provider Verification Network.

Tests: provider registration, verification, stats, receipts, webhooks,
       public verify-by-hash, JWKS endpoint, headers convenience field,
       auth boundaries, and end-to-end flows.

Run with: python3 -m unittest tests.test_mvp3 -v
"""

import sys
import os
import json
import hashlib
import unittest
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestProviderRegistration(unittest.TestCase):
    """Test provider registration and auth."""

    def setUp(self):
        import app as app_module
        app_module.app.config['TESTING'] = True
        self.app = app_module.app.test_client()

    def test_register_provider(self):
        """Provider registration creates account with API key."""
        resp = self.app.post('/v1/providers', json={
            'name': 'Test API',
            'terms_url_prefix': 'https://testapi.com/terms/',
            'contact_email': 'dev@testapi.com',
        })
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertIn('provider_id', data)
        self.assertTrue(data['provider_id'].startswith('prov_'))
        self.assertIn('api_key', data)
        self.assertTrue(data['api_key'].startswith('openterms_pk_'))
        self.assertFalse(data['verified'])
        self.assertIn('verification_token', data)
        self.assertIn('verification_instructions', data)

    def test_register_provider_missing_fields(self):
        """Registration fails with missing required fields."""
        resp = self.app.post('/v1/providers', json={'name': 'Test'})
        self.assertEqual(resp.status_code, 400)

    def test_register_provider_invalid_prefix(self):
        """Registration fails if terms_url_prefix doesn't start with https."""
        resp = self.app.post('/v1/providers', json={
            'name': 'Test',
            'terms_url_prefix': 'http://insecure.com/terms/',
            'contact_email': 'dev@test.com',
        })
        self.assertEqual(resp.status_code, 400)

    def test_register_provider_duplicate_prefix(self):
        """Registration fails for duplicate terms_url_prefix."""
        payload = {
            'name': 'Test',
            'terms_url_prefix': 'https://unique-dup-test.com/terms/',
            'contact_email': 'dev@test.com',
        }
        resp1 = self.app.post('/v1/providers', json=payload)
        self.assertEqual(resp1.status_code, 201)
        resp2 = self.app.post('/v1/providers', json=payload)
        self.assertEqual(resp2.status_code, 409)

    def test_register_provider_with_webhook(self):
        """Registration accepts optional webhook URL."""
        resp = self.app.post('/v1/providers', json={
            'name': 'Webhook API',
            'terms_url_prefix': 'https://webhook-api.com/terms/',
            'contact_email': 'dev@webhook-api.com',
            'webhook_url': 'https://webhook-api.com/hooks/openterms',
        })
        self.assertEqual(resp.status_code, 201)


class TestProviderAuth(unittest.TestCase):
    """Test provider authentication middleware."""

    def setUp(self):
        import app as app_module
        app_module.app.config['TESTING'] = True
        self.app = app_module.app.test_client()

    def _register_provider(self, suffix="auth"):
        resp = self.app.post('/v1/providers', json={
            'name': f'Auth Test {suffix}',
            'terms_url_prefix': f'https://auth-test-{suffix}.com/terms/',
            'contact_email': f'dev@auth-test-{suffix}.com',
        })
        return resp.get_json()

    def test_provider_auth_with_valid_key(self):
        """Provider stats endpoint works with valid API key."""
        provider = self._register_provider("valid")
        headers = {'Authorization': f'Bearer {provider["api_key"]}'}
        resp = self.app.get('/v1/provider/stats', headers=headers)
        self.assertEqual(resp.status_code, 200)

    def test_provider_auth_without_key(self):
        """Provider endpoints require auth."""
        resp = self.app.get('/v1/provider/stats')
        self.assertEqual(resp.status_code, 401)

    def test_provider_auth_with_invalid_key(self):
        """Provider endpoints reject invalid keys."""
        headers = {'Authorization': 'Bearer openterms_pk_invalid_key'}
        resp = self.app.get('/v1/provider/stats', headers=headers)
        self.assertEqual(resp.status_code, 401)

    def test_provider_auth_with_workspace_key(self):
        """Provider endpoints reject workspace API keys."""
        headers = {'Authorization': 'Bearer openterms_some_workspace_key'}
        resp = self.app.get('/v1/provider/stats', headers=headers)
        self.assertEqual(resp.status_code, 401)


class TestProviderStats(unittest.TestCase):
    """Test provider stats, receipts, and agents endpoints."""

    def setUp(self):
        import app as app_module
        app_module.app.config['TESTING'] = True
        self.app = app_module.app.test_client()

    def _register_provider(self, suffix):
        resp = self.app.post('/v1/providers', json={
            'name': f'Stats Test {suffix}',
            'terms_url_prefix': f'https://stats-test-{suffix}.com/terms/',
            'contact_email': f'dev@stats-test-{suffix}.com',
        })
        data = resp.get_json()
        return data, {'Authorization': f'Bearer {data["api_key"]}'}

    def _auth_workspace(self, wallet_suffix):
        """Create an authenticated workspace session."""
        wallet = f'0xprovtest_{wallet_suffix}'
        resp = self.app.post('/v1/auth/nonce', json={'wallet_address': wallet})
        nonce = resp.get_json()['nonce']
        resp = self.app.post('/v1/auth/siwe', json={'wallet_address': wallet, 'nonce': nonce})
        data = resp.get_json()
        headers = {'Authorization': f'Bearer {data["token"]}', 'Content-Type': 'application/json'}
        self.app.post('/console/deposit', json={'amount': 10_000_000}, headers=headers)
        return headers

    def _issue_receipt(self, ws_headers, terms_url):
        return self.app.post('/v1/receipts', json={
            'agent_id': 'test-agent-mvp3',
            'action_type': 'api_call',
            'terms_url': terms_url,
            'terms_hash': 'a' * 64,
            'timestamp': '2026-02-18T10:00:00.000Z',
            'pricing_version': '2025-01',
        }, headers=ws_headers)

    def test_stats_empty(self):
        """Stats with no receipts returns zeros."""
        provider, p_headers = self._register_provider("empty")
        resp = self.app.get('/v1/provider/stats', headers=p_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['receipts_total'], 0)
        self.assertEqual(data['unique_agents'], 0)

    def test_stats_with_receipts(self):
        """Stats reflect receipts issued against provider's terms URL."""
        provider, p_headers = self._register_provider("withrcpt")
        ws_headers = self._auth_workspace("statsrcpt")

        # Issue receipts against this provider's terms
        terms_url = f'https://stats-test-withrcpt.com/terms/v1'
        for _ in range(3):
            resp = self._issue_receipt(ws_headers, terms_url)
            self.assertEqual(resp.status_code, 201)

        resp = self.app.get('/v1/provider/stats', headers=p_headers)
        data = resp.get_json()
        self.assertEqual(data['receipts_total'], 3)
        self.assertEqual(data['unique_agents'], 1)
        self.assertIn('api_call', data['action_type_breakdown'])

    def test_stats_ignores_other_providers(self):
        """Stats only count receipts matching this provider's prefix."""
        provider, p_headers = self._register_provider("isolated")
        ws_headers = self._auth_workspace("statsisolated")

        # Issue receipt against a DIFFERENT terms URL
        resp = self._issue_receipt(ws_headers, 'https://other-provider.com/terms/v1')
        self.assertEqual(resp.status_code, 201)

        resp = self.app.get('/v1/provider/stats', headers=p_headers)
        data = resp.get_json()
        self.assertEqual(data['receipts_total'], 0)

    def test_receipts_requires_verified(self):
        """Unverified providers can't access receipt details."""
        provider, p_headers = self._register_provider("unverified")
        resp = self.app.get('/v1/provider/receipts', headers=p_headers)
        self.assertEqual(resp.status_code, 403)

    def test_agents_requires_verified(self):
        """Unverified providers can't access agent list."""
        provider, p_headers = self._register_provider("unverifagent")
        resp = self.app.get('/v1/provider/agents', headers=p_headers)
        self.assertEqual(resp.status_code, 403)


class TestProviderWebhook(unittest.TestCase):
    """Test webhook URL management and delivery logs."""

    def setUp(self):
        import app as app_module
        app_module.app.config['TESTING'] = True
        self.app = app_module.app.test_client()

    def _register_provider(self, suffix):
        resp = self.app.post('/v1/providers', json={
            'name': f'Webhook Test {suffix}',
            'terms_url_prefix': f'https://webhook-test-{suffix}.com/terms/',
            'contact_email': f'dev@webhook-test-{suffix}.com',
        })
        data = resp.get_json()
        return data, {'Authorization': f'Bearer {data["api_key"]}'}

    def test_update_webhook_url(self):
        """Provider can update webhook URL."""
        provider, headers = self._register_provider("update")
        resp = self.app.patch('/v1/providers/webhook', json={
            'webhook_url': 'https://webhook-test-update.com/hooks/new',
        }, headers=headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['webhook_url'], 'https://webhook-test-update.com/hooks/new')

    def test_update_webhook_rejects_http(self):
        """Webhook URL must be https."""
        provider, headers = self._register_provider("httprej")
        resp = self.app.patch('/v1/providers/webhook', json={
            'webhook_url': 'http://insecure.com/hooks',
        }, headers=headers)
        self.assertEqual(resp.status_code, 400)

    def test_update_webhook_null_clears(self):
        """Setting webhook_url to null clears it."""
        provider, headers = self._register_provider("clear")
        resp = self.app.patch('/v1/providers/webhook', json={
            'webhook_url': None,
        }, headers=headers)
        self.assertEqual(resp.status_code, 200)

    def test_webhook_logs_empty(self):
        """Webhook logs are empty for new provider."""
        provider, headers = self._register_provider("logsempty")
        resp = self.app.get('/v1/provider/webhooks', headers=headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['count'], 0)


class TestVerifyByHash(unittest.TestCase):
    """Test public verify-by-hash endpoint."""

    def setUp(self):
        import app as app_module
        app_module.app.config['TESTING'] = True
        self.app = app_module.app.test_client()

    def _auth_workspace(self, wallet_suffix):
        wallet = f'0xhashtest_{wallet_suffix}'
        resp = self.app.post('/v1/auth/nonce', json={'wallet_address': wallet})
        nonce = resp.get_json()['nonce']
        resp = self.app.post('/v1/auth/siwe', json={'wallet_address': wallet, 'nonce': nonce})
        data = resp.get_json()
        headers = {'Authorization': f'Bearer {data["token"]}', 'Content-Type': 'application/json'}
        self.app.post('/console/deposit', json={'amount': 10_000_000}, headers=headers)
        return headers

    def test_verify_valid_receipt_by_hash(self):
        """Verify-by-hash returns receipt data for a valid hash."""
        ws_headers = self._auth_workspace("verifyhash")
        # Issue a receipt
        resp = self.app.post('/v1/receipts', json={
            'agent_id': 'hash-verify-agent',
            'action_type': 'api_call',
            'terms_url': 'https://example.com/tos',
            'terms_hash': 'b' * 64,
            'timestamp': '2026-02-18T10:00:00.000Z',
            'pricing_version': '2025-01',
        }, headers=ws_headers)
        self.assertEqual(resp.status_code, 201)
        receipt = resp.get_json()
        canonical_hash = receipt['canonical_hash']

        # Verify by hash — no auth needed
        resp = self.app.get(f'/v1/receipts/verify/{canonical_hash}')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data['valid'])
        self.assertEqual(data['receipt_id'], receipt['receipt_id'])
        self.assertEqual(data['agent_id'], 'hash-verify-agent')
        self.assertEqual(data['action_type'], 'api_call')
        self.assertEqual(data['terms_url'], 'https://example.com/tos')
        # Ensure workspace_id is NOT leaked
        self.assertNotIn('workspace_id', data)

    def test_verify_nonexistent_hash(self):
        """Verify-by-hash returns 404 for unknown hash."""
        resp = self.app.get('/v1/receipts/verify/deadbeef' * 8)
        self.assertEqual(resp.status_code, 404)

    def test_verify_by_hash_no_auth_needed(self):
        """Verify-by-hash is public — no Authorization header needed."""
        resp = self.app.get('/v1/receipts/verify/nonexistent_hash')
        # Should get 404 (not found), NOT 401 (unauthorized)
        self.assertEqual(resp.status_code, 404)


class TestHeadersConvenience(unittest.TestCase):
    """Test that receipt issuance returns headers convenience field."""

    def setUp(self):
        import app as app_module
        app_module.app.config['TESTING'] = True
        self.app = app_module.app.test_client()

    def _auth_workspace(self, wallet_suffix):
        wallet = f'0xheaders_{wallet_suffix}'
        resp = self.app.post('/v1/auth/nonce', json={'wallet_address': wallet})
        nonce = resp.get_json()['nonce']
        resp = self.app.post('/v1/auth/siwe', json={'wallet_address': wallet, 'nonce': nonce})
        data = resp.get_json()
        headers = {'Authorization': f'Bearer {data["token"]}', 'Content-Type': 'application/json'}
        self.app.post('/console/deposit', json={'amount': 10_000_000}, headers=headers)
        return headers

    def test_receipt_includes_headers(self):
        """Receipt response includes X-Openterms-Receipt and X-Openterms-Verify headers."""
        ws_headers = self._auth_workspace("hdrs")
        resp = self.app.post('/v1/receipts', json={
            'agent_id': 'headers-agent',
            'action_type': 'data_access',
            'terms_url': 'https://example.com/tos',
            'terms_hash': 'c' * 64,
            'timestamp': '2026-02-18T10:00:00.000Z',
            'pricing_version': '2025-01',
        }, headers=ws_headers)
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertIn('headers', data)
        self.assertIn('X-Openterms-Receipt', data['headers'])
        self.assertIn('X-Openterms-Verify', data['headers'])
        self.assertEqual(data['headers']['X-Openterms-Receipt'], data['canonical_hash'])
        self.assertIn(data['canonical_hash'], data['headers']['X-Openterms-Verify'])


class TestJWKS(unittest.TestCase):
    """Test JWKS endpoint for provider SDK key fetching."""

    def setUp(self):
        import app as app_module
        app_module.app.config['TESTING'] = True
        self.app = app_module.app.test_client()

    def test_jwks_endpoint(self):
        """JWKS endpoint returns valid key set."""
        resp = self.app.get('/.well-known/jwks.json')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn('keys', data)
        self.assertIsInstance(data['keys'], list)
        self.assertGreater(len(data['keys']), 0)
        # Check key structure
        key = data['keys'][0]
        self.assertIn('kty', key)
        self.assertIn('kid', key)

    def test_jwks_cache_header(self):
        """JWKS endpoint returns cache control header."""
        resp = self.app.get('/.well-known/jwks.json')
        self.assertIn('Cache-Control', resp.headers)
        self.assertIn('public', resp.headers['Cache-Control'])

    def test_jwks_no_auth_needed(self):
        """JWKS endpoint is public."""
        resp = self.app.get('/.well-known/jwks.json')
        self.assertEqual(resp.status_code, 200)


class TestAgentManifest(unittest.TestCase):
    """Test updated agent manifest with MVP3 features."""

    def setUp(self):
        import app as app_module
        app_module.app.config['TESTING'] = True
        self.app = app_module.app.test_client()

    def test_manifest_includes_mvp3(self):
        """Agent manifest includes MVP3 endpoints and features."""
        resp = self.app.get('/.well-known/openterms-agent.json')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn('providers', data['endpoints'])
        self.assertIn('provider_stats', data['endpoints'])
        self.assertIn('verify_receipt_by_hash', data['endpoints'])
        self.assertIn('jwks_url', data)
        self.assertIn('provider_verification', data['features'])
        self.assertIn('webhook_notifications', data['features'])
        self.assertIn('provider_key', data['auth_methods'])
        self.assertIn('headers', data)


class TestEndToEndFlow(unittest.TestCase):
    """Integration test: full provider → workspace → receipt → verify flow."""

    def setUp(self):
        import app as app_module
        app_module.app.config['TESTING'] = True
        self.app = app_module.app.test_client()

    def _auth_workspace(self, wallet_suffix):
        wallet = f'0xe2e_{wallet_suffix}'
        resp = self.app.post('/v1/auth/nonce', json={'wallet_address': wallet})
        nonce = resp.get_json()['nonce']
        resp = self.app.post('/v1/auth/siwe', json={'wallet_address': wallet, 'nonce': nonce})
        data = resp.get_json()
        headers = {'Authorization': f'Bearer {data["token"]}', 'Content-Type': 'application/json'}
        self.app.post('/console/deposit', json={'amount': 10_000_000}, headers=headers)
        return headers

    def test_full_provider_verification_flow(self):
        """
        End-to-end:
        1. Provider registers
        2. Workspace issues receipt against provider's terms
        3. Receipt includes headers convenience field
        4. Verify-by-hash confirms receipt is valid
        5. Provider stats show the receipt
        """
        # 1. Register provider
        resp = self.app.post('/v1/providers', json={
            'name': 'E2E Provider',
            'terms_url_prefix': 'https://e2e-provider.com/terms/',
            'contact_email': 'dev@e2e-provider.com',
        })
        self.assertEqual(resp.status_code, 201)
        provider = resp.get_json()
        p_headers = {'Authorization': f'Bearer {provider["api_key"]}'}

        # 2. Issue receipt from workspace
        ws_headers = self._auth_workspace("e2e_full")
        resp = self.app.post('/v1/receipts', json={
            'agent_id': 'e2e-agent',
            'action_type': 'api_call',
            'terms_url': 'https://e2e-provider.com/terms/v2',
            'terms_hash': 'd' * 64,
            'timestamp': '2026-02-18T12:00:00.000Z',
            'pricing_version': '2025-01',
        }, headers=ws_headers)
        self.assertEqual(resp.status_code, 201)
        receipt = resp.get_json()

        # 3. Verify headers are present
        self.assertIn('headers', receipt)
        canonical_hash = receipt['canonical_hash']
        self.assertEqual(receipt['headers']['X-Openterms-Receipt'], canonical_hash)

        # 4. Public verify-by-hash
        resp = self.app.get(f'/v1/receipts/verify/{canonical_hash}')
        self.assertEqual(resp.status_code, 200)
        verify = resp.get_json()
        self.assertTrue(verify['valid'])
        self.assertEqual(verify['terms_url'], 'https://e2e-provider.com/terms/v2')

        # 5. Provider stats reflect the receipt
        resp = self.app.get('/v1/provider/stats', headers=p_headers)
        self.assertEqual(resp.status_code, 200)
        stats = resp.get_json()
        self.assertEqual(stats['receipts_total'], 1)
        self.assertEqual(stats['unique_agents'], 1)

    def test_receipt_with_policy_deny_flow(self):
        """
        End-to-end: policy deny still works with MVP3 additions.
        """
        ws_headers = self._auth_workspace("e2e_deny")
        # Set policy blocking purchases
        resp = self.app.put('/v1/policy', json={
            'rules': [{'type': 'allowed_action_types', 'values': ['api_call']}]
        }, headers=ws_headers)
        self.assertEqual(resp.status_code, 201)

        # Try to issue purchase receipt — should be denied
        resp = self.app.post('/v1/receipts', json={
            'agent_id': 'e2e-agent-deny',
            'action_type': 'purchase',
            'terms_url': 'https://example.com/tos',
            'terms_hash': 'e' * 64,
            'timestamp': '2026-02-18T12:00:00.000Z',
            'pricing_version': '2025-01',
        }, headers=ws_headers)
        self.assertEqual(resp.status_code, 403)

    def test_multiple_receipts_different_providers(self):
        """Receipts correctly attribute to their respective providers."""
        # Register two providers
        resp1 = self.app.post('/v1/providers', json={
            'name': 'Provider A',
            'terms_url_prefix': 'https://provider-a-multi.com/terms/',
            'contact_email': 'dev@a.com',
        })
        prov_a = resp1.get_json()
        a_headers = {'Authorization': f'Bearer {prov_a["api_key"]}'}

        resp2 = self.app.post('/v1/providers', json={
            'name': 'Provider B',
            'terms_url_prefix': 'https://provider-b-multi.com/terms/',
            'contact_email': 'dev@b.com',
        })
        prov_b = resp2.get_json()
        b_headers = {'Authorization': f'Bearer {prov_b["api_key"]}'}

        ws_headers = self._auth_workspace("e2e_multi")

        # Issue 2 receipts for provider A, 1 for provider B
        for i in range(2):
            self.app.post('/v1/receipts', json={
                'agent_id': 'multi-agent',
                'action_type': 'api_call',
                'terms_url': 'https://provider-a-multi.com/terms/v1',
                'terms_hash': 'f' * 64,
                'timestamp': f'2026-02-18T1{i}:00:00.000Z',
                'pricing_version': '2025-01',
            }, headers=ws_headers)

        self.app.post('/v1/receipts', json={
            'agent_id': 'multi-agent',
            'action_type': 'data_access',
            'terms_url': 'https://provider-b-multi.com/terms/v1',
            'terms_hash': 'f' * 64,
            'timestamp': '2026-02-18T13:00:00.000Z',
            'pricing_version': '2025-01',
        }, headers=ws_headers)

        # Provider A sees 2
        resp = self.app.get('/v1/provider/stats', headers=a_headers)
        self.assertEqual(resp.get_json()['receipts_total'], 2)

        # Provider B sees 1
        resp = self.app.get('/v1/provider/stats', headers=b_headers)
        self.assertEqual(resp.get_json()['receipts_total'], 1)


class TestDBProviderFunctions(unittest.TestCase):
    """Test db.py provider helper functions directly."""

    def setUp(self):
        import db as db_module
        self.db = db_module
        self.db.init_db()

    def test_create_provider(self):
        prov = self.db.create_provider(
            'DB Test Provider', 'https://db-test-prov.com/terms/',
            'dev@db-test.com', 'openterms_pk_test123')
        self.assertTrue(prov['provider_id'].startswith('prov_'))
        self.assertFalse(prov['verified'])

    def test_verify_provider_key(self):
        self.db.create_provider(
            'Key Test', 'https://key-test-prov.com/terms/',
            'dev@key-test.com', 'openterms_pk_keytest456')
        found = self.db.verify_provider_key('openterms_pk_keytest456')
        self.assertIsNotNone(found)
        self.assertEqual(found['name'], 'Key Test')

    def test_verify_provider_key_not_found(self):
        found = self.db.verify_provider_key('openterms_pk_nonexistent')
        self.assertIsNone(found)

    def test_find_providers_for_terms_url(self):
        # Create and verify a provider
        prov = self.db.create_provider(
            'Match Test', 'https://match-test-unique.com/terms/',
            'dev@match.com', 'openterms_pk_matchtest',
            webhook_url='https://match-test-unique.com/hook')
        self.db.verify_provider(prov['provider_id'])

        matches = self.db.find_providers_for_terms_url('https://match-test-unique.com/terms/v1')
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]['provider_id'], prov['provider_id'])

    def test_find_providers_no_match(self):
        matches = self.db.find_providers_for_terms_url('https://nonexistent.com/terms/v1')
        self.assertEqual(len(matches), 0)

    def test_webhook_log(self):
        prov = self.db.create_provider(
            'Log Test', 'https://log-test-uniq.com/terms/',
            'dev@log.com', 'openterms_pk_logtest')
        self.db.log_webhook(prov['provider_id'], 'receipt.issued', 'rcpt_test',
                           {'event': 'receipt.issued'}, status_code=200,
                           delivered_at=self.db.now_iso())
        logs = self.db.list_webhook_logs(prov['provider_id'])
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]['event_type'], 'receipt.issued')
        self.assertEqual(logs[0]['status_code'], 200)


class TestExistingFeaturesUnbroken(unittest.TestCase):
    """Regression: ensure MVP1+MVP2 features still work after MVP3 additions."""

    def setUp(self):
        import app as app_module
        app_module.app.config['TESTING'] = True
        self.app = app_module.app.test_client()

    def _auth(self, wallet_suffix):
        wallet = f'0xregression_{wallet_suffix}'
        resp = self.app.post('/v1/auth/nonce', json={'wallet_address': wallet})
        nonce = resp.get_json()['nonce']
        resp = self.app.post('/v1/auth/siwe', json={'wallet_address': wallet, 'nonce': nonce})
        data = resp.get_json()
        headers = {'Authorization': f'Bearer {data["token"]}', 'Content-Type': 'application/json'}
        self.app.post('/console/deposit', json={'amount': 10_000_000}, headers=headers)
        return headers

    def test_issue_and_verify_receipt(self):
        """MVP1 receipt issuance + POST verification still works."""
        headers = self._auth("regr_issue")
        resp = self.app.post('/v1/receipts', json={
            'agent_id': 'regression-agent',
            'action_type': 'api_call',
            'terms_url': 'https://example.com/tos',
            'terms_hash': 'a' * 64,
            'timestamp': '2026-02-18T10:00:00.000Z',
            'pricing_version': '2025-01',
        }, headers=headers)
        self.assertEqual(resp.status_code, 201)
        receipt = resp.get_json()
        # POST verify
        resp = self.app.post('/v1/receipts/verify', json=receipt)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.get_json()['valid'])

    def test_policy_crud(self):
        """MVP2 policy CRUD still works."""
        headers = self._auth("regr_policy")
        # Create
        resp = self.app.put('/v1/policy', json={
            'rules': [{'type': 'daily_spend_cap', 'limit': 5_000_000}]
        }, headers=headers)
        self.assertEqual(resp.status_code, 201)
        # Read
        resp = self.app.get('/v1/policy', headers=headers)
        data = resp.get_json()
        self.assertTrue(data['active'])
        # Delete
        resp = self.app.delete('/v1/policy', headers=headers)
        self.assertEqual(resp.status_code, 200)

    def test_simulate_policy(self):
        """MVP2 policy simulation still works."""
        headers = self._auth("regr_sim")
        resp = self.app.post('/v1/policy/simulate', json={
            'rules': [{'type': 'allowed_action_types', 'values': ['api_call']}],
            'payload': {'action_type': 'api_call', 'terms_url': 'https://example.com/tos'}
        }, headers=headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()['decision'], 'allow')

    def test_discovery_endpoints(self):
        """Discovery endpoints still work."""
        resp = self.app.get('/.well-known/openterms-agent.json')
        self.assertEqual(resp.status_code, 200)
        resp = self.app.get('/.well-known/openterms-keys/')
        self.assertEqual(resp.status_code, 200)

    def test_pricing_endpoint(self):
        """Pricing endpoint still works."""
        resp = self.app.get('/v1/pricing')
        self.assertEqual(resp.status_code, 200)


if __name__ == '__main__':
    unittest.main()
