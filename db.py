"""
Database layer for Openterms MVP 1.
Uses SQLite for development/demo.
"""

import sqlite3
import uuid
import hashlib
import secrets
import json
import os
from datetime import datetime, timezone, timedelta
from contextlib import contextmanager
from typing import Optional

DB_PATH = os.environ.get("OPENTERMS_DB_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "openterms.db"))


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def transaction():
    conn = get_db()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS workspace (
            workspace_id    TEXT PRIMARY KEY,
            name            TEXT NOT NULL,
            deposit_address TEXT NOT NULL UNIQUE,
            chain_id        INTEGER NOT NULL DEFAULT 8453,
            created_at      TEXT NOT NULL,
            updated_at      TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS user (
            user_id         TEXT PRIMARY KEY,
            wallet_address  TEXT NOT NULL,
            workspace_id    TEXT NOT NULL REFERENCES workspace(workspace_id),
            role            TEXT NOT NULL DEFAULT 'admin' CHECK (role IN ('admin', 'viewer')),
            created_at      TEXT NOT NULL,
            UNIQUE (wallet_address, workspace_id)
        );
        CREATE TABLE IF NOT EXISTS api_key (
            key_id          TEXT PRIMARY KEY,
            workspace_id    TEXT NOT NULL REFERENCES workspace(workspace_id),
            key_hash        TEXT NOT NULL,
            label           TEXT,
            created_by      TEXT REFERENCES user(user_id),
            created_at      TEXT NOT NULL,
            last_used_at    TEXT,
            revoked_at      TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_api_key_hash ON api_key (key_hash) WHERE revoked_at IS NULL;
        CREATE TABLE IF NOT EXISTS signing_key (
            key_id          TEXT PRIMARY KEY,
            public_key_raw  BLOB NOT NULL,
            private_key_enc BLOB NOT NULL,
            active          INTEGER NOT NULL DEFAULT 1,
            created_at      TEXT NOT NULL,
            rotated_at      TEXT
        );
        CREATE TABLE IF NOT EXISTS receipt (
            receipt_id      TEXT PRIMARY KEY,
            workspace_id    TEXT NOT NULL REFERENCES workspace(workspace_id),
            agent_id        TEXT NOT NULL,
            action_type     TEXT NOT NULL CHECK (action_type IN ('api_call', 'data_access', 'purchase', 'custom')),
            action_context  TEXT,
            terms_url       TEXT NOT NULL,
            terms_hash      TEXT NOT NULL,
            timestamp       TEXT NOT NULL,
            pricing_version TEXT NOT NULL,
            canonical_hash  TEXT NOT NULL,
            signature       TEXT NOT NULL,
            key_id          TEXT NOT NULL REFERENCES signing_key(key_id),
            amount_charged  INTEGER NOT NULL CHECK (amount_charged > 0),
            created_at      TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_receipt_workspace ON receipt (workspace_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_receipt_hash ON receipt (canonical_hash);
        CREATE TABLE IF NOT EXISTS deposit (
            deposit_id      TEXT PRIMARY KEY,
            workspace_id    TEXT NOT NULL REFERENCES workspace(workspace_id),
            tx_hash         TEXT NOT NULL,
            log_index       INTEGER NOT NULL,
            from_address    TEXT NOT NULL,
            amount          INTEGER NOT NULL CHECK (amount > 0),
            block_number    INTEGER NOT NULL,
            chain_id        INTEGER NOT NULL,
            confirmed_at    TEXT NOT NULL,
            created_at      TEXT NOT NULL,
            UNIQUE (tx_hash, log_index)
        );
        CREATE INDEX IF NOT EXISTS idx_deposit_workspace ON deposit (workspace_id, confirmed_at DESC);
        CREATE TABLE IF NOT EXISTS ledger_entry (
            entry_id        TEXT PRIMARY KEY,
            workspace_id    TEXT NOT NULL REFERENCES workspace(workspace_id),
            entry_type      TEXT NOT NULL CHECK (entry_type IN (
                'credit_deposit', 'debit_receipt', 'credit_adjustment', 'debit_adjustment'
            )),
            amount          INTEGER NOT NULL,
            reference_type  TEXT CHECK (reference_type IN ('deposit', 'receipt', 'adjustment')),
            reference_id    TEXT,
            description     TEXT,
            created_at      TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_ledger_workspace ON ledger_entry (workspace_id, created_at DESC);
        CREATE TABLE IF NOT EXISTS idempotency_key (
            workspace_id    TEXT NOT NULL,
            idempotency_key TEXT NOT NULL,
            request_hash    TEXT NOT NULL,
            response_code   INTEGER NOT NULL,
            response_body   TEXT NOT NULL,
            created_at      TEXT NOT NULL,
            expires_at      TEXT NOT NULL,
            PRIMARY KEY (workspace_id, idempotency_key)
        );
        CREATE TABLE IF NOT EXISTS auth_nonce (
            nonce           TEXT PRIMARY KEY,
            wallet_address  TEXT,
            created_at      TEXT NOT NULL,
            expires_at      TEXT NOT NULL,
            used            INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            log_id          TEXT PRIMARY KEY,
            workspace_id    TEXT NOT NULL,
            actor_user_id   TEXT,
            action          TEXT NOT NULL,
            target_type     TEXT,
            target_id       TEXT,
            metadata        TEXT,
            created_at      TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS policy_profile (
            profile_id      TEXT PRIMARY KEY,
            workspace_id    TEXT NOT NULL REFERENCES workspace(workspace_id),
            version         INTEGER NOT NULL CHECK (version > 0),
            rules           TEXT NOT NULL,
            active          INTEGER NOT NULL DEFAULT 1,
            created_by      TEXT,
            created_at      TEXT NOT NULL,
            UNIQUE (workspace_id, version)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_policy_active
            ON policy_profile (workspace_id) WHERE active = 1;
        CREATE TABLE IF NOT EXISTS policy_decision_log (
            log_id          TEXT PRIMARY KEY,
            receipt_id      TEXT,
            workspace_id    TEXT NOT NULL,
            profile_version INTEGER NOT NULL,
            decision        TEXT NOT NULL CHECK (decision IN ('allow', 'deny', 'escalate')),
            reasons         TEXT NOT NULL DEFAULT '[]',
            evaluated_at    TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_policy_decision_workspace
            ON policy_decision_log (workspace_id, evaluated_at DESC);

        -- MVP 3: Provider tables
        CREATE TABLE IF NOT EXISTS provider (
            provider_id         TEXT PRIMARY KEY,
            name                TEXT NOT NULL,
            terms_url_prefix    TEXT NOT NULL UNIQUE,
            webhook_url         TEXT,
            contact_email       TEXT NOT NULL,
            api_key_hash        TEXT NOT NULL,
            verified            INTEGER NOT NULL DEFAULT 0,
            verification_token  TEXT,
            created_at          TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_provider_prefix ON provider (terms_url_prefix);

        CREATE TABLE IF NOT EXISTS webhook_log (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            provider_id         TEXT NOT NULL REFERENCES provider(provider_id),
            event_type          TEXT NOT NULL,
            receipt_id          TEXT,
            payload             TEXT NOT NULL,
            status_code         INTEGER,
            attempts            INTEGER NOT NULL DEFAULT 0,
            delivered_at        TEXT,
            created_at          TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_webhook_provider ON webhook_log (provider_id, created_at DESC);

        -- Index for provider receipt lookups by terms_url
        CREATE INDEX IF NOT EXISTS idx_receipt_terms_url ON receipt (terms_url);
    """)
    conn.close()


def now_iso():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'


# --- Workspace ---
def create_workspace(name, deposit_address=None):
    workspace_id = str(uuid.uuid4())
    if not deposit_address:
        deposit_address = "0x" + secrets.token_hex(20)
    now = now_iso()
    with transaction() as conn:
        conn.execute(
            "INSERT INTO workspace (workspace_id, name, deposit_address, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (workspace_id, name, deposit_address, now, now))
    return {"workspace_id": workspace_id, "name": name, "deposit_address": deposit_address}

def get_workspace(workspace_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM workspace WHERE workspace_id = ?", (workspace_id,)).fetchone()
    conn.close()
    return dict(row) if row else None

# --- Users ---
def create_user(wallet_address, workspace_id, role="admin"):
    user_id = str(uuid.uuid4())
    now = now_iso()
    with transaction() as conn:
        conn.execute(
            "INSERT INTO user (user_id, wallet_address, workspace_id, role, created_at) VALUES (?, ?, ?, ?, ?)",
            (user_id, wallet_address, workspace_id, role, now))
    return {"user_id": user_id, "wallet_address": wallet_address, "workspace_id": workspace_id, "role": role}

def get_user_by_wallet(wallet_address):
    conn = get_db()
    row = conn.execute("SELECT * FROM user WHERE wallet_address = ? LIMIT 1", (wallet_address,)).fetchone()
    conn.close()
    return dict(row) if row else None

# --- API Keys ---
def create_api_key(workspace_id, label=None, created_by=None):
    key_id = str(uuid.uuid4())
    raw_key = f"openterms_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    now = now_iso()
    with transaction() as conn:
        conn.execute(
            "INSERT INTO api_key (key_id, workspace_id, key_hash, label, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (key_id, workspace_id, key_hash, label, created_by, now))
    return {"key_id": key_id, "raw_key": raw_key, "label": label, "created_at": now}

def verify_api_key(raw_key):
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    conn = get_db()
    row = conn.execute(
        "SELECT ak.*, w.name as workspace_name FROM api_key ak JOIN workspace w ON ak.workspace_id = w.workspace_id WHERE ak.key_hash = ? AND ak.revoked_at IS NULL",
        (key_hash,)).fetchone()
    if row:
        conn.execute("UPDATE api_key SET last_used_at = ? WHERE key_id = ?", (now_iso(), row['key_id']))
        conn.commit()
    conn.close()
    return dict(row) if row else None

def list_api_keys(workspace_id):
    conn = get_db()
    rows = conn.execute(
        "SELECT key_id, workspace_id, label, created_at, last_used_at, revoked_at FROM api_key WHERE workspace_id = ? ORDER BY created_at DESC",
        (workspace_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def revoke_api_key(key_id, workspace_id):
    now = now_iso()
    with transaction() as conn:
        cursor = conn.execute(
            "UPDATE api_key SET revoked_at = ? WHERE key_id = ? AND workspace_id = ? AND revoked_at IS NULL",
            (now, key_id, workspace_id))
    return cursor.rowcount > 0

# --- Ledger ---
def get_balance(workspace_id):
    conn = get_db()
    row = conn.execute(
        "SELECT COALESCE(SUM(amount), 0) as balance FROM ledger_entry WHERE workspace_id = ?",
        (workspace_id,)).fetchone()
    conn.close()
    return row['balance']

def get_daily_spend(workspace_id):
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    conn = get_db()
    row = conn.execute(
        "SELECT COALESCE(ABS(SUM(amount)), 0) as spend FROM ledger_entry WHERE workspace_id = ? AND entry_type = 'debit_receipt' AND created_at > ?",
        (workspace_id, cutoff)).fetchone()
    conn.close()
    return row['spend']

def debit_receipt_atomic(conn, workspace_id, amount, receipt_id):
    row = conn.execute(
        "SELECT COALESCE(SUM(amount), 0) as balance FROM ledger_entry WHERE workspace_id = ?",
        (workspace_id,)).fetchone()
    balance = row['balance']
    if balance < amount:
        return 'INSUFFICIENT_BALANCE'
    entry_id = str(uuid.uuid4())
    now = now_iso()
    conn.execute(
        "INSERT INTO ledger_entry (entry_id, workspace_id, entry_type, amount, reference_type, reference_id, created_at) VALUES (?, ?, 'debit_receipt', ?, 'receipt', ?, ?)",
        (entry_id, workspace_id, -amount, receipt_id, now))
    return None

def list_ledger_entries(workspace_id, limit=100, entry_type=None):
    conn = get_db()
    query = "SELECT * FROM ledger_entry WHERE workspace_id = ?"
    params = [workspace_id]
    if entry_type:
        query += " AND entry_type = ?"
        params.append(entry_type)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# --- Receipts ---
def insert_receipt(conn, receipt_dict):
    ac = receipt_dict.get('action_context')
    if ac is not None and isinstance(ac, dict):
        ac = json.dumps(ac)
    conn.execute(
        """INSERT INTO receipt (receipt_id, workspace_id, agent_id, action_type, action_context,
           terms_url, terms_hash, timestamp, pricing_version, canonical_hash, signature, key_id,
           amount_charged, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (receipt_dict['receipt_id'], receipt_dict['workspace_id'], receipt_dict['agent_id'],
         receipt_dict['action_type'], ac,
         receipt_dict['terms_url'], receipt_dict['terms_hash'], receipt_dict['timestamp'],
         receipt_dict['pricing_version'], receipt_dict['canonical_hash'], receipt_dict['signature'],
         receipt_dict['key_id'], receipt_dict['amount_charged'], receipt_dict['created_at']))

def get_receipt(receipt_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM receipt WHERE receipt_id = ?", (receipt_id,)).fetchone()
    conn.close()
    if row:
        d = dict(row)
        if d.get('action_context'):
            try: d['action_context'] = json.loads(d['action_context'])
            except: pass
        return d
    return None


def get_receipt_by_hash(canonical_hash):
    """Look up a receipt by its canonical hash. Public endpoint."""
    conn = get_db()
    row = conn.execute("SELECT * FROM receipt WHERE canonical_hash = ?", (canonical_hash,)).fetchone()
    conn.close()
    if row:
        d = dict(row)
        if d.get('action_context'):
            try: d['action_context'] = json.loads(d['action_context'])
            except: pass
        return d
    return None

def list_receipts(workspace_id, limit=50, cursor=None, action_type=None,
                  agent_id=None, date_from=None, date_to=None):
    conn = get_db()
    query = "SELECT * FROM receipt WHERE workspace_id = ?"
    params = [workspace_id]
    if cursor:
        query += " AND created_at < ?"
        params.append(cursor)
    if action_type:
        query += " AND action_type = ?"
        params.append(action_type)
    if agent_id:
        query += " AND agent_id = ?"
        params.append(agent_id)
    if date_from:
        query += " AND created_at >= ?"
        params.append(date_from)
    if date_to:
        query += " AND created_at < ?"
        params.append(date_to)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit + 1)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    results = [dict(r) for r in rows[:limit]]
    for r in results:
        if r.get('action_context'):
            try: r['action_context'] = json.loads(r['action_context'])
            except: pass
    next_cursor = results[-1]['created_at'] if len(rows) > limit else None
    return results, next_cursor

def count_receipts(workspace_id):
    conn = get_db()
    row = conn.execute("SELECT COUNT(*) as cnt FROM receipt WHERE workspace_id = ?", (workspace_id,)).fetchone()
    conn.close()
    return row['cnt']

# --- Deposits ---
def insert_deposit(workspace_id, tx_hash, log_index, from_address, amount, block_number, chain_id):
    deposit_id = str(uuid.uuid4())
    now = now_iso()
    try:
        with transaction() as conn:
            conn.execute(
                """INSERT INTO deposit (deposit_id, workspace_id, tx_hash, log_index, from_address,
                   amount, block_number, chain_id, confirmed_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (deposit_id, workspace_id, tx_hash, log_index, from_address, amount, block_number, chain_id, now, now))
            entry_id = str(uuid.uuid4())
            conn.execute(
                "INSERT INTO ledger_entry (entry_id, workspace_id, entry_type, amount, reference_type, reference_id, created_at) VALUES (?, ?, 'credit_deposit', ?, 'deposit', ?, ?)",
                (entry_id, workspace_id, amount, deposit_id, now))
        return deposit_id
    except sqlite3.IntegrityError:
        return None

def list_deposits(workspace_id, limit=50):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM deposit WHERE workspace_id = ? ORDER BY confirmed_at DESC LIMIT ?",
        (workspace_id, limit)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# --- Signing Keys ---
def store_signing_key(key_id, public_key_raw, private_key_enc):
    now = now_iso()
    with transaction() as conn:
        conn.execute("UPDATE signing_key SET active = 0, rotated_at = ? WHERE active = 1", (now,))
        conn.execute(
            "INSERT INTO signing_key (key_id, public_key_raw, private_key_enc, active, created_at) VALUES (?, ?, ?, 1, ?)",
            (key_id, public_key_raw, private_key_enc, now))

def get_active_signing_key():
    conn = get_db()
    row = conn.execute("SELECT * FROM signing_key WHERE active = 1 LIMIT 1").fetchone()
    conn.close()
    return dict(row) if row else None

def get_signing_key_by_id(key_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM signing_key WHERE key_id = ?", (key_id,)).fetchone()
    conn.close()
    return dict(row) if row else None

def list_signing_keys():
    conn = get_db()
    rows = conn.execute("SELECT key_id, active, created_at, rotated_at FROM signing_key ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

# --- Idempotency ---
def check_idempotency(workspace_id, key, request_hash):
    conn = get_db()
    now = now_iso()
    conn.execute("DELETE FROM idempotency_key WHERE expires_at < ?", (now,))
    conn.commit()
    row = conn.execute(
        "SELECT * FROM idempotency_key WHERE workspace_id = ? AND idempotency_key = ?",
        (workspace_id, key)).fetchone()
    conn.close()
    if row:
        if row['request_hash'] == request_hash:
            return json.loads(row['response_body']), None
        else:
            return None, 'IDEMPOTENCY_CONFLICT'
    return None, None

def store_idempotency(workspace_id, key, request_hash, response_code, response_body):
    now = now_iso()
    expires = (datetime.now(timezone.utc) + timedelta(hours=24)).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    with transaction() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO idempotency_key (workspace_id, idempotency_key, request_hash, response_code, response_body, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (workspace_id, key, request_hash, response_code, json.dumps(response_body), now, expires))

# --- Audit Log ---
def log_audit(workspace_id, actor_user_id, action, target_type=None, target_id=None, metadata=None):
    log_id = str(uuid.uuid4())
    now = now_iso()
    with transaction() as conn:
        conn.execute(
            "INSERT INTO audit_log (log_id, workspace_id, actor_user_id, action, target_type, target_id, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (log_id, workspace_id, actor_user_id, action, target_type, target_id, json.dumps(metadata) if metadata else None, now))


# --- Policy Profiles (MVP 2) ---

def get_active_policy(workspace_id):
    """Get the active policy profile for a workspace, or None."""
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM policy_profile WHERE workspace_id = ? AND active = 1",
        (workspace_id,)
    ).fetchone()
    conn.close()
    if row:
        result = dict(row)
        if isinstance(result.get('rules'), str):
            result['rules'] = json.loads(result['rules'])
        return result
    return None


def get_policy_version(workspace_id, version):
    """Get a specific policy version."""
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM policy_profile WHERE workspace_id = ? AND version = ?",
        (workspace_id, version)
    ).fetchone()
    conn.close()
    if row:
        result = dict(row)
        if isinstance(result.get('rules'), str):
            result['rules'] = json.loads(result['rules'])
        return result
    return None


def list_policy_versions(workspace_id, limit=20):
    """List all policy versions for a workspace."""
    conn = get_db()
    rows = conn.execute(
        "SELECT profile_id, workspace_id, version, active, created_by, created_at FROM policy_profile WHERE workspace_id = ? ORDER BY version DESC LIMIT ?",
        (workspace_id, limit)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def create_policy_version(workspace_id, rules, created_by=None):
    """Create a new policy version, deactivating the previous one. Returns the new profile."""
    with transaction() as conn:
        row = conn.execute(
            "SELECT COALESCE(MAX(version), 0) + 1 as next_v FROM policy_profile WHERE workspace_id = ?",
            (workspace_id,)
        ).fetchone()
        next_version = row['next_v']

        # Deactivate current active profile
        conn.execute(
            "UPDATE policy_profile SET active = 0 WHERE workspace_id = ? AND active = 1",
            (workspace_id,)
        )

        # Insert new version
        profile_id = str(uuid.uuid4())
        now = now_iso()
        conn.execute(
            """INSERT INTO policy_profile (profile_id, workspace_id, version, rules, active, created_by, created_at)
               VALUES (?, ?, ?, ?, 1, ?, ?)""",
            (profile_id, workspace_id, next_version, json.dumps(rules), created_by, now)
        )

    return {
        'profile_id': profile_id,
        'workspace_id': workspace_id,
        'version': next_version,
        'rules': rules,
        'active': True,
        'created_by': created_by,
        'created_at': now,
    }


def delete_active_policy(workspace_id):
    """Deactivate the current policy (no policy = allow all)."""
    with transaction() as conn:
        conn.execute(
            "UPDATE policy_profile SET active = 0 WHERE workspace_id = ? AND active = 1",
            (workspace_id,)
        )


# --- Policy Decision Log (MVP 2) ---

def log_policy_decision(receipt_id, workspace_id, profile_version, decision, reasons):
    """Log a policy evaluation result."""
    log_id = str(uuid.uuid4())
    now = now_iso()
    with transaction() as conn:
        conn.execute(
            """INSERT INTO policy_decision_log (log_id, receipt_id, workspace_id, profile_version, decision, reasons, evaluated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (log_id, receipt_id, workspace_id, profile_version, decision, json.dumps(reasons), now)
        )
    return log_id


def list_policy_decisions(workspace_id, limit=50, decision_filter=None):
    """List policy decisions for a workspace."""
    conn = get_db()
    query = "SELECT * FROM policy_decision_log WHERE workspace_id = ?"
    params = [workspace_id]
    if decision_filter:
        query += " AND decision = ?"
        params.append(decision_filter)
    query += " ORDER BY evaluated_at DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    results = []
    for r in rows:
        d = dict(r)
        if isinstance(d.get('reasons'), str):
            d['reasons'] = json.loads(d['reasons'])
        results.append(d)
    return results


def count_policy_decisions(workspace_id, decision_filter=None, since=None):
    """Count policy decisions, optionally filtered."""
    conn = get_db()
    query = "SELECT COUNT(*) as cnt FROM policy_decision_log WHERE workspace_id = ?"
    params = [workspace_id]
    if decision_filter:
        query += " AND decision = ?"
        params.append(decision_filter)
    if since:
        query += " AND evaluated_at > ?"
        params.append(since)
    row = conn.execute(query, params).fetchone()
    conn.close()
    return row['cnt']


# --- Providers (MVP 3) ---

def create_provider(name, terms_url_prefix, contact_email, api_key_raw, webhook_url=None):
    """Register a new provider. Returns provider dict + raw API key."""
    provider_id = "prov_" + str(uuid.uuid4()).replace('-', '')[:16]
    key_hash = hashlib.sha256(api_key_raw.encode()).hexdigest()
    verification_token = "tok_" + secrets.token_urlsafe(24)
    now = now_iso()
    with transaction() as conn:
        conn.execute(
            """INSERT INTO provider (provider_id, name, terms_url_prefix, webhook_url,
               contact_email, api_key_hash, verified, verification_token, created_at)
               VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)""",
            (provider_id, name, terms_url_prefix, webhook_url,
             contact_email, key_hash, verification_token, now))
    return {
        'provider_id': provider_id,
        'name': name,
        'terms_url_prefix': terms_url_prefix,
        'webhook_url': webhook_url,
        'contact_email': contact_email,
        'verified': False,
        'verification_token': verification_token,
        'created_at': now,
    }


def verify_provider_key(api_key_raw):
    """Look up a provider by API key. Returns provider dict or None."""
    key_hash = hashlib.sha256(api_key_raw.encode()).hexdigest()
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM provider WHERE api_key_hash = ?", (key_hash,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_provider(provider_id):
    """Get a provider by ID."""
    conn = get_db()
    row = conn.execute("SELECT * FROM provider WHERE provider_id = ?", (provider_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def verify_provider(provider_id):
    """Mark a provider as verified."""
    with transaction() as conn:
        conn.execute("UPDATE provider SET verified = 1 WHERE provider_id = ?", (provider_id,))


def update_provider_webhook(provider_id, webhook_url):
    """Update provider webhook URL."""
    with transaction() as conn:
        conn.execute("UPDATE provider SET webhook_url = ? WHERE provider_id = ?",
                     (webhook_url, provider_id))


def find_providers_for_terms_url(terms_url):
    """Find all providers whose terms_url_prefix matches the given terms_url."""
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM provider WHERE verified = 1 AND webhook_url IS NOT NULL"
    ).fetchall()
    conn.close()
    matches = []
    for row in rows:
        d = dict(row)
        if terms_url.startswith(d['terms_url_prefix']):
            matches.append(d)
    return matches


def list_receipts_for_provider(terms_url_prefix, limit=50, date_from=None, date_to=None):
    """List receipts whose terms_url starts with the given prefix."""
    conn = get_db()
    query = "SELECT * FROM receipt WHERE terms_url LIKE ?"
    params = [terms_url_prefix + '%']
    if date_from:
        query += " AND created_at >= ?"
        params.append(date_from)
    if date_to:
        query += " AND created_at < ?"
        params.append(date_to)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    results = [dict(r) for r in rows]
    for r in results:
        if r.get('action_context'):
            try: r['action_context'] = json.loads(r['action_context'])
            except: pass
    return results


def count_receipts_for_provider(terms_url_prefix, since=None):
    """Count receipts for a provider's terms_url_prefix."""
    conn = get_db()
    query = "SELECT COUNT(*) as cnt FROM receipt WHERE terms_url LIKE ?"
    params = [terms_url_prefix + '%']
    if since:
        query += " AND created_at >= ?"
        params.append(since)
    row = conn.execute(query, params).fetchone()
    conn.close()
    return row['cnt']


def unique_agents_for_provider(terms_url_prefix):
    """Get unique agent IDs that have receipts for this provider."""
    conn = get_db()
    rows = conn.execute(
        "SELECT DISTINCT agent_id FROM receipt WHERE terms_url LIKE ?",
        (terms_url_prefix + '%',)
    ).fetchall()
    conn.close()
    return [row['agent_id'] for row in rows]


def action_type_breakdown_for_provider(terms_url_prefix):
    """Get action type counts for a provider."""
    conn = get_db()
    rows = conn.execute(
        "SELECT action_type, COUNT(*) as cnt FROM receipt WHERE terms_url LIKE ? GROUP BY action_type",
        (terms_url_prefix + '%',)
    ).fetchall()
    conn.close()
    return {row['action_type']: row['cnt'] for row in rows}


# --- Webhook Log (MVP 3) ---

def log_webhook(provider_id, event_type, receipt_id, payload, status_code=None, delivered_at=None):
    """Log a webhook delivery attempt."""
    now = now_iso()
    with transaction() as conn:
        conn.execute(
            """INSERT INTO webhook_log (provider_id, event_type, receipt_id, payload,
               status_code, attempts, delivered_at, created_at)
               VALUES (?, ?, ?, ?, ?, 1, ?, ?)""",
            (provider_id, event_type, receipt_id, json.dumps(payload),
             status_code, delivered_at, now))


def list_webhook_logs(provider_id, limit=50):
    """List webhook delivery logs for a provider."""
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM webhook_log WHERE provider_id = ? ORDER BY created_at DESC LIMIT ?",
        (provider_id, limit)
    ).fetchall()
    conn.close()
    results = []
    for r in rows:
        d = dict(r)
        if isinstance(d.get('payload'), str):
            try: d['payload'] = json.loads(d['payload'])
            except: pass
        results.append(d)
    return results
