"""Database layer — MySQL (freesqldatabase.com) with SQLite fallback.

If MYSQL_HOST/USER/PASSWORD/DATABASE are all set, the panel uses MySQL.
Otherwise it falls back to the local SQLite file (resellers.db) for dev.

All queries are written with `?` placeholders and translated to `%s` for MySQL
via _ph(). A few dialect-specific constructs (AUTOINCREMENT, last insert id,
ON CONFLICT upserts, PRAGMA, datetime('now')) are branched per engine.
"""
import os
import sqlite3
import secrets
import hashlib
import hmac
import re
from datetime import datetime, timezone

import pymysql
from pymysql import IntegrityError as DbIntegrityError

from config import settings

# SellAuth client instance (services.sellauth.client). Balance read lives on the instance.
from services.sellauth import client as _sellauth_client  # noqa: E402


# ---------- Constants ----------

MAX_NAME_LENGTH = 100
MAX_WEBHOOK_URL_LENGTH = 500
MAX_API_KEYS_PER_RESELLER = 5
VALID_WEBHOOK_URL_PATTERN = re.compile(r"^https?://[^\s]*$")


# ---------- Engine selection ----------

def _use_mysql() -> bool:
    return bool(settings.MYSQL_HOST and settings.MYSQL_USER
                and settings.MYSQL_PASSWORD and settings.MYSQL_DATABASE)


_USE_MYSQL = _use_mysql()

# Translate `?` (sqlite) to `%s` (MySQL pyformat) when on MySQL.
def _ph(sql: str) -> str:
    return sql.replace("?", "%s") if _USE_MYSQL else sql


def _now_sql() -> str:
    """Default for created_at/updated_at columns inside SQL DDL/defaults."""
    return "NOW()" if _USE_MYSQL else "datetime('now')"


# ---------- Connection ----------

def get_db():
    if _USE_MYSQL:
        conn = pymysql.connect(
            host=settings.MYSQL_HOST,
            port=settings.MYSQL_PORT,
            user=settings.MYSQL_USER,
            password=settings.MYSQL_PASSWORD,
            database=settings.MYSQL_DATABASE,
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=False,
        )
        # pymysql Connection has no .execute(); wrap it so existing code that calls
        # conn.execute(sql, params).fetchone()/.fetchall() works identically to sqlite3.
        class _MySQLConn:
            def __init__(self, real):
                self._real = real
            def cursor(self):
                return self._real.cursor()
            def execute(self, sql, params=()):
                cur = self._real.cursor()
                cur.execute(_ph(sql), params)
                return cur
            def commit(self):
                self._real.commit()
            def rollback(self):
                self._real.rollback()
            def close(self):
                self._real.close()
        return _MySQLConn(conn)
    conn = sqlite3.connect("resellers.db")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _last_insert_id(conn):
    if _USE_MYSQL:
        return conn._real.insert_id()
    row = conn.execute("SELECT last_insert_rowid()").fetchone()
    return row[0]


def _exec(conn, sql, params=()):
    """Execute with placeholder translation. Returns cursor (works for both engines)."""
    if _USE_MYSQL:
        cur = conn.cursor()
        cur.execute(_ph(sql), params)
        return cur
    return conn.execute(_ph(sql), params)


def _execmany(conn, sql, seq):
    return conn.executemany(_ph(sql), seq)


# ---------- Key storage (encrypted at rest) ----------

def _encrypt_key(api_key: str) -> str:
    from services.crypto_notify import encrypt_secret
    return encrypt_secret(api_key)


def _decrypt_key(token: str) -> str:
    from services.crypto_notify import decrypt_secret
    return decrypt_secret(token)


def _generate_raw_key() -> str:
    return "rs_" + secrets.token_urlsafe(32)


def generate_deliverable(product_id: str, variant_id: str, quantity: int = 1,
                          customer_email: str = "") -> list[str]:
    """Generate deliverables for infinite-stock (generator) products.

    SellAuth generator products keep 0 stored keys, so the API cannot dispense
    them. As the source shop, the panel mints a unique redeemable token per unit.
    Tokens are recorded in `generated_deliverables` so refunds/audits can trace them.
    """
    out = []
    for _ in range(quantity):
        token = "ASTRO-" + secrets.token_hex(12).upper()
        out.append(token)
    try:
        conn = get_db()
        try:
            conn.execute(_ph(
                """INSERT INTO generated_deliverables
                   (product_id, variant_id, customer_email, tokens, created_at)
                   VALUES (?,?,?,?, datetime('now'))"""),
                (str(product_id), str(variant_id), customer_email or "", "\n".join(out)))
            conn.commit()
        finally:
            conn.close()
    except Exception:
        # Never block delivery on audit-log failure.
        pass
    return out


# ---------- Input validation ----------

def _validate_name(name: str) -> str:
    name = name.strip()
    if not name or len(name) > MAX_NAME_LENGTH:
        raise ValueError(f"Name must be 1–{MAX_NAME_LENGTH} characters")
    name = re.sub(r"[\x00-\x1f\x7f]", "", name)
    return name


def _validate_webhook_url(url: str) -> str:
    url = url.strip()
    if not url:
        return ""
    if len(url) > MAX_WEBHOOK_URL_LENGTH:
        raise ValueError(f"Webhook URL too long (max {MAX_WEBHOOK_URL_LENGTH})")
    if not VALID_WEBHOOK_URL_PATTERN.match(url):
        raise ValueError("Webhook URL must start with http:// or https://")
    return url


def _validate_username(username: str) -> str:
    username = username.strip().lower()
    if not username:
        raise ValueError("Username required")
    if not re.match(r"^[a-z0-9_.]{3,40}$", username):
        raise ValueError("Username must be 3-40 chars: letters, numbers, _ or .")
    return username


def _validate_discount(pct: float) -> float:
    if not (0 <= pct <= 100):
        raise ValueError("Discount must be between 0 and 100")
    return round(pct, 2)


# ---------- Init ----------

def _ddl_init() -> str:
    """Full schema. Dialect-specific bits are chosen at call time."""
    if _USE_MYSQL:
        pk = "INT AUTO_INCREMENT PRIMARY KEY"
        fk = "REFERENCES resellers(id)"
        unique = "UNIQUE"
        idx_suffix = ""
        autoincrement_note = ""
    else:
        pk = "INTEGER PRIMARY KEY AUTOINCREMENT"
        fk = "REFERENCES resellers(id)"
        unique = "UNIQUE"
        idx_suffix = ""
        autoincrement_note = ""

    n = _now_sql()
    ddl = f"""
        CREATE TABLE IF NOT EXISTS resellers (
            id {pk},
            name TEXT NOT NULL,
            username TEXT NOT NULL DEFAULT '',
            email TEXT NOT NULL DEFAULT '',
            api_key_enc TEXT NOT NULL,
            api_key_hash TEXT,
            api_key_prefix TEXT NOT NULL,
            discount_percent REAL NOT NULL DEFAULT 0,
            webhook_url TEXT DEFAULT '',
            referral_code TEXT {unique},
            referred_by INTEGER,
            active INTEGER NOT NULL DEFAULT 1,
            last_used_at TEXT,
            request_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT ({n}),
            updated_at TEXT NOT NULL DEFAULT ({n}),
            sellauth_email TEXT NOT NULL DEFAULT '',
            sellauth_balance_cache REAL NOT NULL DEFAULT 0,
            sellauth_balance_ts TEXT NOT NULL DEFAULT '',
            discord_id TEXT NOT NULL DEFAULT '',
            discord_username TEXT NOT NULL DEFAULT '',
            discord_linked_at TEXT NOT NULL DEFAULT '',
            email_2fa_code TEXT NOT NULL DEFAULT '',
            email_2fa_exp TEXT NOT NULL DEFAULT '',
            email_2fa_attempts INTEGER NOT NULL DEFAULT 0,
            email_2fa_sent_at TEXT NOT NULL DEFAULT '',
            sellauth_webhook_secret TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS referrals (
            id {pk},
            referrer_id INTEGER NOT NULL,
            referred_reseller_id INTEGER NOT NULL,
            commission_percent REAL NOT NULL DEFAULT 5,
            total_earned REAL NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT ({n}),
            FOREIGN KEY (referrer_id) {fk},
            FOREIGN KEY (referred_reseller_id) {fk}
        );

        CREATE TABLE IF NOT EXISTS applications (
            id {pk},
            email TEXT NOT NULL,
            discord TEXT NOT NULL,
            website TEXT DEFAULT '',
            discord_server TEXT DEFAULT '',
            products TEXT DEFAULT '',
            referral_code TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL DEFAULT ({n}),
            reviewed_at TEXT
        );

        CREATE TABLE IF NOT EXISTS manual_pricing (
            product_id TEXT NOT NULL,
            variant_id TEXT NOT NULL DEFAULT '',
            discount_percent REAL NOT NULL,
            price REAL NOT NULL,
            updated_at TEXT NOT NULL DEFAULT ({n}),
            PRIMARY KEY (product_id, variant_id, discount_percent)
        );

        CREATE TABLE IF NOT EXISTS webhook_logs (
            id {pk},
            reseller_id INTEGER NOT NULL,
            endpoint TEXT NOT NULL,
            status_code INTEGER,
            response_time_ms REAL,
            ip_address TEXT DEFAULT '',
            created_at TEXT NOT NULL DEFAULT ({n}),
            FOREIGN KEY (reseller_id) {fk}
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id {pk},
            action TEXT NOT NULL,
            reseller_id INTEGER,
            details TEXT,
            ip_address TEXT DEFAULT '',
            created_at TEXT NOT NULL DEFAULT ({n})
        );

        CREATE TABLE IF NOT EXISTS login_attempts (
            id {pk},
            ip_address TEXT NOT NULL,
            success INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT ({n})
        );

        CREATE TABLE IF NOT EXISTS orders (
            id {pk},
            reseller_id INTEGER NOT NULL,
            product_id TEXT NOT NULL,
            product_name TEXT NOT NULL,
            variant_name TEXT DEFAULT '',
            quantity INTEGER NOT NULL DEFAULT 1,
            price_per_unit REAL NOT NULL,
            total_price REAL NOT NULL,
            customer_email TEXT NOT NULL DEFAULT '',
            sellauth_invoice_id INTEGER,
            sellauth_invoice_url TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'pending',
            deliverable TEXT DEFAULT '',
            channel TEXT NOT NULL DEFAULT 'manual',
            created_at TEXT NOT NULL DEFAULT ({n}),
            FOREIGN KEY (reseller_id) {fk}
        );

        CREATE TABLE IF NOT EXISTS generated_deliverables (
            id {pk},
            product_id TEXT NOT NULL,
            variant_id TEXT NOT NULL DEFAULT '',
            customer_email TEXT NOT NULL DEFAULT '',
            tokens TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT ({n})
        );

        CREATE TABLE IF NOT EXISTS reseller_balances (
            reseller_id INTEGER PRIMARY KEY,
            balance REAL NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL DEFAULT ({n}),
            FOREIGN KEY (reseller_id) {fk}
        );

        CREATE TABLE IF NOT EXISTS product_aliases (
            id {pk},
            reseller_id INTEGER NOT NULL,
            alias TEXT NOT NULL {unique},
            product_id TEXT NOT NULL,
            variant_id TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT ({n}),
            FOREIGN KEY (reseller_id) {fk}
        );

        CREATE TABLE IF NOT EXISTS balance_transactions (
            id {pk},
            reseller_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            type TEXT NOT NULL,
            description TEXT DEFAULT '',
            order_id INTEGER,
            created_at TEXT NOT NULL DEFAULT ({n}),
            FOREIGN KEY (reseller_id) {fk}
        );
    """
    if _USE_MYSQL:
        # MySQL cannot KEY a TEXT column, and VARCHAR counts toward the 65KB row limit
        # while TEXT is stored off-row. So: keep most columns as TEXT (nullable), only
        # convert the KEYED/INDEXED columns to sized VARCHAR, and the DEFAULTed status
        # column to VARCHAR (VARCHAR allows string defaults, TEXT does not).
        import re as _re
        # MySQL 8 rejects string DEFAULTs on TEXT columns and function defaults on TEXT.
        # - "TEXT [NOT NULL] DEFAULT ''"  -> nullable TEXT (NULL is fine)
        # - "TEXT NOT NULL DEFAULT (datetime('now'))" -> VARCHAR(32) NOT NULL DEFAULT (NOW())
        # - columns that truly need a string DEFAULT ('pending'/'manual') -> VARCHAR(32)
        # - keyed/indexed columns -> sized VARCHAR
        ddl = _re.sub(r"TEXT(?: NOT NULL)? DEFAULT ''", "TEXT", ddl)
        ddl = _re.sub(r"TEXT NOT NULL DEFAULT \(datetime\('now'\)\)", "VARCHAR(32) NOT NULL DEFAULT (NOW())", ddl)
        ddl = ddl.replace("datetime('now')", "NOW()")
        # In MySQL mode _now_sql() returns NOW(), so timestamp columns render as
        # TEXT NOT NULL DEFAULT (NOW()) — invalid (function default on TEXT is not
        # allowed in MySQL, and inserts sometimes omit created_at). Convert to
        # VARCHAR(32) with an empty-string default; the app supplies real ISO
        # timestamps on insert where needed.
        ddl = _re.sub(r"TEXT NOT NULL DEFAULT \(NOW\(\)\)", "VARCHAR(32) NOT NULL DEFAULT ''", ddl)
        ddl = ddl.replace("status TEXT NOT NULL DEFAULT 'pending'", "status VARCHAR(32) NOT NULL DEFAULT 'pending'")
        ddl = ddl.replace("channel TEXT NOT NULL DEFAULT 'manual'", "channel VARCHAR(32) NOT NULL DEFAULT 'manual'")
        ddl = ddl.replace("api_key_enc TEXT NOT NULL", "api_key_enc VARCHAR(512) NOT NULL")
        ddl = ddl.replace("referral_code TEXT UNIQUE", "referral_code VARCHAR(255) UNIQUE")
        ddl = ddl.replace("alias TEXT NOT NULL UNIQUE", "alias VARCHAR(255) NOT NULL UNIQUE")
        ddl = ddl.replace("api_key_hash TEXT", "api_key_hash VARCHAR(255)")
        ddl = ddl.replace("product_id TEXT", "product_id VARCHAR(191)")
        ddl = ddl.replace("variant_id TEXT", "variant_id VARCHAR(191)")
    return ddl


def _indexes_mysql() -> list[str]:
    return [
        "CREATE INDEX IF NOT EXISTS idx_webhook_logs_reseller ON webhook_logs(reseller_id)",
        "CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip_address, created_at)",
        "CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action, created_at)",
        "CREATE INDEX IF NOT EXISTS idx_orders_reseller ON orders(reseller_id, created_at)",
        "CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status)",
        "CREATE INDEX IF NOT EXISTS idx_balance_tx_reseller ON balance_transactions(reseller_id, created_at)",
        "CREATE INDEX IF NOT EXISTS idx_referrals_referrer ON referrals(referrer_id)",
        "CREATE INDEX IF NOT EXISTS idx_applications_status ON applications(status, created_at)",
        "CREATE INDEX IF NOT EXISTS idx_resellers_key_hash ON resellers(api_key_hash)",
        "CREATE INDEX IF NOT EXISTS idx_resellers_referral_code ON resellers(referral_code)",
    ]


def init_db():
    """Create tables (idempotent)."""
    conn = get_db()
    try:
        if _USE_MYSQL:
            # pymysql can't executescript multi-DDL cleanly; run per statement.
            for stmt in _split_statements(_ddl_init()):
                if stmt.strip():
                    conn.cursor().execute(stmt)
            for idx in _indexes_mysql():
                try:
                    conn.cursor().execute(idx)
                except Exception:
                    pass  # index may already exist
            conn.commit()
        else:
            conn.executescript(_ddl_init())
            conn.commit()
    finally:
        conn.close()
    _migrate()


def _split_statements(sql: str) -> list[str]:
    # Naive split on semicolons (safe: no string literals contain ';' in our DDL).
    return [s.strip() for s in sql.split(";") if s.strip()]


def _migrate():
    """Ensure columns exist. MySQL ALTER ADD COLUMN IF NOT EXISTS is emulated
    by probing information_schema; SQLite uses PRAGMA."""
    conn = get_db()
    try:
        cur = conn.cursor() if _USE_MYSQL else None

        def _run(sql, params=()):
            if _USE_MYSQL:
                cur.execute(_ph(sql), params)
                return cur.fetchall() if sql.strip().upper().startswith("SELECT") else None
            res = conn.execute(_ph(sql), params)
            return res.fetchall() if sql.strip().upper().startswith("SELECT") else None

        if _USE_MYSQL:
            cur.execute(
                "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
                "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = 'resellers'",
                (settings.MYSQL_DATABASE,),
            )
            existing = {r["COLUMN_NAME"] for r in cur.fetchall()}
            def add_col(col, typ):
                if col not in existing:
                    t = typ.replace(" DEFAULT ''", "").replace("TEXT", "VARCHAR(1024)") if _USE_MYSQL else typ
                    cur.execute(f"ALTER TABLE resellers ADD COLUMN {col} {t}")
                    existing.add(col)
        else:
            existing = {r["name"] for r in conn.execute("PRAGMA table_info(resellers)").fetchall()}
            def add_col(col, typ):
                if col not in existing:
                    conn.execute(f"ALTER TABLE resellers ADD COLUMN {col} {typ}")

        add_col("username", "TEXT NOT NULL DEFAULT ''")
        add_col("email", "TEXT NOT NULL DEFAULT ''")
        add_col("api_key_enc", "TEXT")
        add_col("api_key_hash", "TEXT")
        add_col("sellauth_email", "TEXT NOT NULL DEFAULT ''")
        add_col("sellauth_balance_cache", "REAL NOT NULL DEFAULT 0")
        add_col("sellauth_balance_ts", "TEXT NOT NULL DEFAULT ''")
        add_col("referral_code", "TEXT")
        add_col("referred_by", "INTEGER")
        add_col("discord_id", "TEXT NOT NULL DEFAULT ''")
        add_col("discord_username", "TEXT NOT NULL DEFAULT ''")
        add_col("discord_linked_at", "TEXT NOT NULL DEFAULT ''")
        add_col("email_2fa_code", "TEXT NOT NULL DEFAULT ''")
        add_col("email_2fa_exp", "TEXT NOT NULL DEFAULT ''")
        add_col("email_2fa_attempts", "INTEGER NOT NULL DEFAULT 0")
        add_col("email_2fa_sent_at", "TEXT NOT NULL DEFAULT ''")
        add_col("sellauth_webhook_secret", "TEXT NOT NULL DEFAULT ''")

        # Backfill api_key_hash from decrypted keys (only if missing)
        if "api_key_hash" in existing:
            rows = _run("SELECT id, api_key_enc FROM resellers WHERE api_key_enc IS NOT NULL AND api_key_enc != ''")
            for row in rows:
                raw = _decrypt_key(row["api_key_enc"])
                if raw:
                    h = hashlib.sha256(raw.encode()).hexdigest()
                    _run("UPDATE resellers SET api_key_hash = ? WHERE id = ?", (h, row["id"]))

        if _USE_MYSQL:
            # orders.channel column
            cur.execute(
                "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
                "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = 'orders' AND COLUMN_NAME = 'channel'",
                (settings.MYSQL_DATABASE,),
            )
            if not cur.fetchone():
                cur.execute("ALTER TABLE orders ADD COLUMN channel TEXT NOT NULL")
        else:
            if "channel" not in [c[1] for c in conn.execute("PRAGMA table_info(orders)").fetchall()]:
                conn.execute("ALTER TABLE orders ADD COLUMN channel TEXT NOT NULL DEFAULT 'manual'")

        conn.commit()

        # Backfill referral codes + usernames
        rows = _run("SELECT id FROM resellers WHERE referral_code IS NULL OR referral_code = ''")
        for r in rows:
            code = _generate_referral_code()
            _run("UPDATE resellers SET referral_code = ? WHERE id = ?", (code, r["id"]))
        rows = _run("SELECT id, name FROM resellers WHERE username IS NULL OR username = ''")
        for r in rows:
            uname = re.sub(r"[^a-zA-Z0-9_]", "", r["name"].lower().replace(" ", "_"))[:40] or f"user{r['id']}"
            _run("UPDATE resellers SET username = ? WHERE id = ?", (uname, r["id"]))
        conn.commit()
    finally:
        conn.close()


# ---------- Audit logging ----------

def _audit(action: str, reseller_id: int | None = None, details: str = "", ip: str = ""):
    conn = get_db()
    try:
        _exec(conn,
            "INSERT INTO audit_log (action, reseller_id, details, ip_address) VALUES (?, ?, ?, ?)",
            (action, reseller_id, details[:500], ip[:45]))
        conn.commit()
    finally:
        conn.close()
    try:
        from services.discord_log import log_event
        log_event(
            f"`{action}`" + (f" — {details[:300]}" if details else ""),
            level="audit",
            title="📋 Audit",
            fields={"reseller_id": reseller_id if reseller_id is not None else "—", "ip": ip or "—"},
        )
    except Exception:
        pass


# ---------- Brute force check ----------

def check_brute_force(ip: str, max_attempts: int = 5, window_minutes: int = 15) -> bool:
    conn = get_db()
    try:
        if _USE_MYSQL:
            window = f"NOW() - INTERVAL {int(window_minutes)} MINUTE"
            row = conn.execute(
                _ph("SELECT COUNT(*) as cnt FROM login_attempts "
                    "WHERE ip_address = ? AND success = 0 AND created_at > ?"),
                (ip[:45], window),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT COUNT(*) as cnt FROM login_attempts "
                "WHERE ip_address = ? AND success = 0 AND created_at > datetime('now', ?)",
                (ip[:45], f"-{window_minutes} minutes"),
            ).fetchone()
        return (row["cnt"] or 0) >= max_attempts
    finally:
        conn.close()


def log_login_attempt(ip: str, success: bool):
    conn = get_db()
    try:
        _exec(conn,
            "INSERT INTO login_attempts (ip_address, success) VALUES (?, ?)",
            (ip[:45], 1 if success else 0))
        if _USE_MYSQL:
            conn.execute("DELETE FROM login_attempts WHERE created_at < NOW() - INTERVAL 1 HOUR")
        else:
            conn.execute("DELETE FROM login_attempts WHERE created_at < datetime('now', '-1 hour')")
        conn.commit()
    finally:
        conn.close()


# ---------- Reseller CRUD ----------

def create_reseller(name: str, discount_percent: float, webhook_url: str = "", ip: str = "", referred_by_code: str = "", username: str = "", email: str = "", raw_key: str = "") -> dict:
    name = _validate_name(name)
    discount = _validate_discount(discount_percent)
    webhook = _validate_webhook_url(webhook_url)
    username = _validate_username(username) if username else _validate_username(name)
    email = (email or "").strip().lower()[:200]

    raw_key = raw_key or _generate_raw_key()
    key_enc = _encrypt_key(raw_key)
    key_prefix = raw_key[:16]
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

    referrer_id = None
    if referred_by_code:
        ref = get_reseller_by_referral_code(referred_by_code.strip())
        if ref:
            referrer_id = ref["id"]
    referral_code = _generate_referral_code()

    now = datetime.now(timezone.utc).isoformat()
    conn = get_db()
    try:
        _exec(conn,
            """INSERT INTO resellers (name, username, email, api_key_enc, api_key_hash, api_key_prefix, discount_percent, webhook_url,
               referral_code, referred_by, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (name, username, email, key_enc, key_hash, key_prefix, discount, webhook, referral_code, referrer_id, now, now))
        new_id = _last_insert_id(conn)
        conn.commit()
    finally:
        conn.close()

    row = get_reseller_by_id(new_id) or {}
    result = dict(row)
    result["api_key"] = raw_key
    _audit("reseller_created", result.get("id"), f"name={name} discount={discount}", ip)
    if referrer_id and new_id:
        _record_referral(referrer_id, new_id)
    return result


def get_reseller_by_key(api_key: str) -> dict | None:
    if not api_key or not api_key.startswith("rs_"):
        return None
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    conn = get_db()
    try:
        row = conn.execute(_ph("SELECT * FROM resellers WHERE api_key_hash = ? AND active = 1"), (key_hash,)).fetchone()
    finally:
        conn.close()
    return dict(row) if row else None


def get_reseller_by_email(email: str) -> dict | None:
    """Lookup an active reseller by email only (no password). Used by the
    email-OTP login flow; existence is intentionally not revealed to callers."""
    if not email:
        return None
    conn = get_db()
    try:
        row = conn.execute(_ph("SELECT * FROM resellers WHERE email = ? AND active = 1"),
            (email.strip().lower(),)).fetchone()
    finally:
        conn.close()
    return dict(row) if row else None


def can_request_email_2fa(reseller_id: int, cooldown_seconds: int = 60) -> bool:
    """Rate-limit guard: True if at least cooldown_seconds have passed since the
    last code was sent (or none was ever sent)."""
    conn = get_db()
    try:
        row = conn.execute(_ph("SELECT email_2fa_sent_at FROM resellers WHERE id = ?"),
            (reseller_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        return True
    sent = row["email_2fa_sent_at"] or ""
    if not sent:
        return True
    try:
        sent_dt = datetime.fromisoformat(sent)
    except (ValueError, TypeError):
        return True
    return (datetime.now(timezone.utc) - sent_dt).total_seconds() >= cooldown_seconds


def get_reseller_by_id(reseller_id: int) -> dict | None:
    conn = get_db()
    try:
        row = conn.execute(_ph("SELECT * FROM resellers WHERE id = ?"), (reseller_id,)).fetchone()
    finally:
        conn.close()
    if row:
        d = dict(row)
        d.pop("api_key_enc", None)
        return d
    return None


def get_primary_reseller() -> dict | None:
    """First active reseller (panel owner). Used to fulfill inbound SellAuth
    dynamic-delivery webhooks for the single shop the panel serves."""
    conn = get_db()
    try:
        row = conn.execute(_ph(
            "SELECT * FROM resellers WHERE active = 1 ORDER BY id ASC LIMIT 1"
        )).fetchone()
    finally:
        conn.close()
    if row:
        d = dict(row)
        d.pop("api_key_enc", None)
        return d
    return None


def list_resellers() -> list[dict]:
    conn = get_db()
    try:
        rows = conn.execute("SELECT * FROM resellers ORDER BY created_at DESC").fetchall()
    finally:
        conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d.pop("api_key_enc", None)
        result.append(d)
    return result


def update_reseller(reseller_id: int, ip: str = "", **kwargs) -> dict | None:
    allowed = {"name", "discount_percent", "webhook_url", "active"}
    updates = {}
    for k, v in kwargs.items():
        if k not in allowed:
            continue
        if k == "name" and v is not None:
            updates["name"] = _validate_name(v)
        elif k == "discount_percent" and v is not None:
            updates["discount_percent"] = _validate_discount(v)
        elif k == "webhook_url" and v is not None:
            updates["webhook_url"] = _validate_webhook_url(v)
        elif k == "active":
            updates["active"] = 1 if v else 0
    if not updates:
        return get_reseller_by_id(reseller_id)
    updates["updated_at"] = datetime.now(timezone.utc).isoformat()
    conn = get_db()
    try:
        set_parts = [f"{col} = ?" for col in updates]
        values = list(updates.values()) + [reseller_id]
        conn.execute(_ph(f"UPDATE resellers SET {', '.join(set_parts)} WHERE id = ?"), values)
        conn.commit()
        row = conn.execute(_ph("SELECT * FROM resellers WHERE id = ?"), (reseller_id,)).fetchone()
    finally:
        conn.close()
    result = dict(row) if row else None
    if result:
        result.pop("api_key_enc", None)
    _audit("reseller_updated", reseller_id, f"fields={list(updates.keys())}", ip)
    return result


def link_reseller_discord(reseller_id: int, discord_id: str, discord_username: str, ip: str = "") -> dict | None:
    discord_id = (discord_id or "").strip()
    discord_username = (discord_username or "").strip()[:100]
    if not discord_id:
        raise ValueError("discord_id is required")
    conn = get_db()
    try:
        _exec(conn,
            "UPDATE resellers SET discord_id = ?, discord_username = ?, discord_linked_at = ? WHERE id = ?",
            (discord_id, discord_username, datetime.now(timezone.utc).isoformat(), reseller_id))
        conn.commit()
        row = conn.execute(_ph("SELECT * FROM resellers WHERE id = ?"), (reseller_id,)).fetchone()
    finally:
        conn.close()
    result = dict(row) if row else None
    if result:
        result.pop("api_key_enc", None)
    _audit("reseller_discord_linked", reseller_id, f"discord={discord_username} ({discord_id})", ip)
    return result


def unlink_reseller_discord(reseller_id: int, ip: str = "") -> dict | None:
    conn = get_db()
    try:
        _exec(conn,
            "UPDATE resellers SET discord_id = '', discord_username = '', discord_linked_at = '' WHERE id = ?",
            (reseller_id,))
        conn.commit()
        row = conn.execute(_ph("SELECT * FROM resellers WHERE id = ?"), (reseller_id,)).fetchone()
    finally:
        conn.close()
    result = dict(row) if row else None
    if result:
        result.pop("api_key_enc", None)
    _audit("reseller_discord_unlinked", reseller_id, "", ip)
    return result


def delete_reseller(reseller_id: int, ip: str = "") -> bool:
    conn = get_db()
    try:
        _exec(conn, "DELETE FROM webhook_logs WHERE reseller_id = ?", (reseller_id,))
        _exec(conn, "DELETE FROM audit_log WHERE reseller_id = ?", (reseller_id,))
        cur = conn.execute(_ph("DELETE FROM resellers WHERE id = ?"), (reseller_id,))
        affected = cur.rowcount
        conn.commit()
    finally:
        conn.close()
    if affected:
        _audit("reseller_deleted", reseller_id, "", ip)
    return affected > 0


def regenerate_api_key(reseller_id: int, ip: str = "") -> dict | None:
    raw_key = _generate_raw_key()
    key_enc = _encrypt_key(raw_key)
    key_prefix = raw_key[:16]
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db()
    try:
        _exec(conn,
            "UPDATE resellers SET api_key_enc = ?, api_key_hash = ?, api_key_prefix = ?, updated_at = ? WHERE id = ?",
            (key_enc, key_hash, key_prefix, now, reseller_id))
        conn.commit()
        row = conn.execute(_ph("SELECT * FROM resellers WHERE id = ?"), (reseller_id,)).fetchone()
    finally:
        conn.close()
    result = dict(row) if row else {}
    result["api_key"] = raw_key
    _audit("reseller_key_rotated", reseller_id, "", ip)
    return result


def reveal_api_key(reseller_id: int) -> str | None:
    conn = get_db()
    try:
        row = conn.execute(_ph("SELECT api_key_enc FROM resellers WHERE id = ?"), (reseller_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    return _decrypt_key(row["api_key_enc"])


# ---------- SellAuth customer linkage (balance mirror) ----------

def set_sellauth_email(reseller_id: int, email: str, ip: str = "") -> None:
    email = (email or "").strip().lower()
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db()
    try:
        _exec(conn, "UPDATE resellers SET sellauth_email = ?, updated_at = ? WHERE id = ?", (email, now, reseller_id))
        conn.commit()
    finally:
        conn.close()
    _audit("reseller_email_linked", reseller_id, f"email={email}", ip)


def get_sellauth_email(reseller_id: int) -> str:
    conn = get_db()
    try:
        row = conn.execute(_ph("SELECT sellauth_email FROM resellers WHERE id = ?"), (reseller_id,)).fetchone()
    finally:
        conn.close()
    return (row["sellauth_email"] or "") if row else ""


def set_sellauth_webhook_secret(reseller_id: int, secret: str, ip: str = "") -> None:
    """Store the reseller's SellAuth dynamic-delivery webhook secret (HMAC key),
    encrypted at rest. Empty string clears it (falls back to global secret)."""
    secret = (secret or "").strip()
    enc = _encrypt_key(secret) if secret else ""
    now = _now_iso()
    conn = get_db()
    try:
        _exec(conn, "UPDATE resellers SET sellauth_webhook_secret = ?, updated_at = ? WHERE id = ?",
              (enc, now, reseller_id))
        conn.commit()
    finally:
        conn.close()
    _audit("reseller_sellauth_secret_set", reseller_id, f"set={bool(secret)}", ip)


def get_sellauth_webhook_secret(reseller_id: int) -> str:
    """Decrypt the reseller's stored SellAuth webhook secret, or '' if none."""
    conn = get_db()
    try:
        row = conn.execute(_ph("SELECT sellauth_webhook_secret FROM resellers WHERE id = ?"), (reseller_id,)).fetchone()
    finally:
        conn.close()
    enc = (row["sellauth_webhook_secret"] or "") if row else ""
    if not enc:
        return ""
    try:
        return _decrypt_key(enc)
    except Exception:
        return ""


# ---------- Webhook secret section ----------


def get_sellauth_webhook_secret(reseller_id: int) -> str:
    """Decrypt the reseller's stored SellAuth webhook secret, or '' if none."""
    conn = get_db()
    try:
        row = conn.execute(_ph("SELECT sellauth_webhook_secret FROM resellers WHERE id = ?"), (reseller_id,)).fetchone()
    finally:
        conn.close()
    enc = (row["sellauth_webhook_secret"] or "") if row else ""
    if not enc:
        return ""
    try:
        return _decrypt_key(enc)
    except Exception:
        return ""


# ---------- Email-link 2FA (SellAuth-style 6-digit code) ----------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def set_email_2fa(reseller_id: int, code: str, ttl_seconds: int = 600) -> None:
    from datetime import timedelta
    hashed = hashlib.sha256(code.encode()).hexdigest()
    exp_dt = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
    sent_at = _now_iso()
    conn = get_db()
    try:
        _exec(conn, _ph(
            "UPDATE resellers SET email_2fa_code = ?, email_2fa_exp = ?, "
            "email_2fa_attempts = 0, email_2fa_sent_at = ? WHERE id = ?"),
            (hashed, exp_dt.isoformat(), sent_at, reseller_id))
        conn.commit()
    finally:
        conn.close()


def verify_email_2fa(reseller_id: int, code: str, max_attempts: int = 5) -> bool:
    """Verify a 6-digit email code. Enforces a per-reseller attempt cap:
    once max_attempts bad guesses are made the code is locked until resend."""
    conn = get_db()
    try:
        row = conn.execute(_ph(
            "SELECT email_2fa_code, email_2fa_exp, email_2fa_attempts "
            "FROM resellers WHERE id = ?"), (reseller_id,)).fetchone()
        if not row:
            return False
        stored_hash = row["email_2fa_code"] or ""
        exp = row["email_2fa_exp"] or ""
        attempts = int(row["email_2fa_attempts"] or 0)
        if not stored_hash or not exp:
            return False
        if attempts >= max_attempts:
            return False
        try:
            exp_dt = datetime.fromisoformat(exp)
        except (ValueError, TypeError):
            return False
        if exp_dt < datetime.now(timezone.utc):
            return False
        guess_hash = hashlib.sha256((code or "").encode()).hexdigest()
        ok = hmac.compare_digest(guess_hash, stored_hash)
        # Count every guess that reaches a live, unexpired code.
        _exec(conn, _ph(
            "UPDATE resellers SET email_2fa_attempts = email_2fa_attempts + 1 WHERE id = ?"),
            (reseller_id,))
        conn.commit()
        return ok
    finally:
        conn.close()


def clear_email_2fa(reseller_id: int) -> None:
    conn = get_db()
    try:
        _exec(conn, _ph(
            "UPDATE resellers SET email_2fa_code = '', email_2fa_exp = '', "
            "email_2fa_attempts = 0, email_2fa_sent_at = '' WHERE id = ?"), (reseller_id,))
        conn.commit()
    finally:
        conn.close()


def get_sellauth_balance(reseller_id: int, force: bool = False) -> dict:
    conn = get_db()
    try:
        row = conn.execute(_ph(
            "SELECT sellauth_email, sellauth_balance_cache, sellauth_balance_ts FROM resellers WHERE id = ?"),
            (reseller_id,)).fetchone()
    finally:
        conn.close()
    email = (row["sellauth_email"] or "") if row else ""
    if not email:
        return {"email": "", "balance": 0.0, "source": "none", "cached_at": ""}
    ts = row["sellauth_balance_ts"] if row else ""
    if not force and ts:
        try:
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(ts)).total_seconds()
            if age < 60:
                return {"email": email, "balance": float(row["sellauth_balance_cache"] or 0), "source": "cache", "cached_at": ts}
        except Exception:
            pass
    bal = _sellauth_client.get_customer_balance(email) if email else None
    if bal is None:
        return {"email": email, "balance": float(row["sellauth_balance_cache"] or 0) if row else 0.0, "source": "none", "cached_at": ts}
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db()
    try:
        _exec(conn, "UPDATE resellers SET sellauth_balance_cache = ?, sellauth_balance_ts = ? WHERE id = ?", (bal, now, reseller_id))
        conn.commit()
    finally:
        conn.close()
    return {"email": email, "balance": bal, "source": "live", "cached_at": now}


def sync_balance_from_sellauth(reseller_id: int, ip: str = "") -> dict:
    email = get_sellauth_email(reseller_id)
    if not email:
        raise ValueError("No SellAuth email linked for this reseller")
    bal = _sellauth_client.get_customer_balance(email)
    if bal is None:
        raise ValueError("Could not read SellAuth balance (check API token / email)")
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db()
    try:
        if _USE_MYSQL:
            _exec(conn,
                "INSERT INTO reseller_balances (reseller_id, balance, updated_at) VALUES (?, ?, ?) "
                "ON DUPLICATE KEY UPDATE balance = VALUES(balance), updated_at = VALUES(updated_at)",
                (reseller_id, bal, now))
            _exec(conn,
                "INSERT INTO balance_transactions (reseller_id, amount, type, description) VALUES (?, ?, 'sync', ?)",
                (reseller_id, bal, f"Synced from SellAuth ({email})"))
        else:
            _exec(conn,
                "INSERT INTO reseller_balances (reseller_id, balance, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(reseller_id) DO UPDATE SET balance = ?, updated_at = ?",
                (reseller_id, bal, now, bal, now))
            _exec(conn,
                "INSERT INTO balance_transactions (reseller_id, amount, type, description) VALUES (?, ?, 'sync', ?)",
                (reseller_id, bal, f"Synced from SellAuth ({email})"))
        _exec(conn, "UPDATE resellers SET sellauth_balance_cache = ?, sellauth_balance_ts = ? WHERE id = ?", (bal, now, reseller_id))
        conn.commit()
    finally:
        conn.close()
    _audit("balance_synced", reseller_id, f"=${bal:.2f} <- SellAuth {email}", ip)
    return {"balance": bal, "email": email, "source": "live"}


# ---------- Per-product delivery aliases ----------

def create_product_alias(reseller_id: int, product_id: str, variant_id: str = "", ip: str = "") -> dict:
    alias = secrets.token_urlsafe(16)
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db()
    try:
        try:
            _exec(conn,
                "INSERT INTO product_aliases (reseller_id, alias, product_id, variant_id, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (reseller_id, alias, str(product_id), str(variant_id or ""), now))
            conn.commit()
        except DbIntegrityError:
            conn.rollback()
            raise ValueError("Alias collision — retry")
    finally:
        conn.close()
    _audit("alias_created", reseller_id, f"{alias} -> p={product_id} v={variant_id}", ip)
    return {"alias": alias, "product_id": str(product_id), "variant_id": str(variant_id or "")}


def revoke_product_alias(reseller_id: int, alias: str, ip: str = "") -> None:
    conn = get_db()
    try:
        _exec(conn, "DELETE FROM product_aliases WHERE reseller_id = ? AND alias = ?", (reseller_id, alias))
        conn.commit()
    finally:
        conn.close()
    _audit("alias_revoked", reseller_id, f"{alias}", ip)


def get_alias(reseller_id: int, alias: str) -> dict | None:
    conn = get_db()
    try:
        row = conn.execute(_ph("SELECT product_id, variant_id FROM product_aliases WHERE reseller_id = ? AND alias = ?"),
            (reseller_id, alias)).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    return {"product_id": row["product_id"], "variant_id": row["variant_id"]}


def list_product_aliases(reseller_id: int) -> list[dict]:
    conn = get_db()
    try:
        rows = conn.execute(_ph("SELECT alias, product_id, variant_id FROM product_aliases WHERE reseller_id = ?"),
            (reseller_id,)).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def resolve_alias(alias: str) -> dict | None:
    conn = get_db()
    try:
        row = conn.execute(_ph("SELECT reseller_id, product_id, variant_id FROM product_aliases WHERE alias = ?"),
            (alias,)).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    return {"reseller_id": row["reseller_id"], "product_id": row["product_id"], "variant_id": row["variant_id"]}


# ---------- Manual pricing overrides ----------

def set_manual_price(product_id: str, variant_id: str, discount_percent: float, price: float) -> None:
    price = round(float(price), 2)
    discount_percent = round(float(discount_percent), 2)
    conn = get_db()
    try:
        if _USE_MYSQL:
            _exec(conn,
                "INSERT INTO manual_pricing (product_id, variant_id, discount_percent, price, updated_at) "
                "VALUES (?, ?, ?, ?, NOW()) ON DUPLICATE KEY UPDATE price = VALUES(price), updated_at = VALUES(updated_at)",
                (str(product_id), str(variant_id or ""), discount_percent, price))
        else:
            _exec(conn,
                """INSERT INTO manual_pricing (product_id, variant_id, discount_percent, price, updated_at)
                   VALUES (?, ?, ?, ?, datetime('now'))
                   ON CONFLICT(product_id, variant_id, discount_percent)
                   DO UPDATE SET price = excluded.price, updated_at = excluded.updated_at""",
                (str(product_id), str(variant_id or ""), discount_percent, price))
        conn.commit()
    finally:
        conn.close()


def get_manual_price(product_id: str, variant_id: str, discount_percent: float) -> float | None:
    conn = get_db()
    try:
        row = conn.execute(_ph(
            "SELECT price FROM manual_pricing WHERE product_id = ? AND variant_id = ? AND discount_percent = ?"),
            (str(product_id), str(variant_id or ""), round(float(discount_percent), 2))).fetchone()
    finally:
        conn.close()
    return round(row["price"], 2) if row else None


def list_manual_prices() -> list[dict]:
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT product_id, variant_id, discount_percent, price, updated_at FROM manual_pricing ORDER BY updated_at DESC"
        ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def delete_manual_price(product_id: str, variant_id: str, discount_percent: float) -> None:
    conn = get_db()
    try:
        _exec(conn, "DELETE FROM manual_pricing WHERE product_id = ? AND variant_id = ? AND discount_percent = ?",
            (str(product_id), str(variant_id or ""), round(float(discount_percent), 2)))
        conn.commit()
    finally:
        conn.close()


def effective_price(product_id: str, variant_id: str, discount_percent: float, base_price: float) -> float:
    override = get_manual_price(product_id, variant_id, discount_percent)
    if override is not None:
        return override
    return round(float(base_price) * (1 - float(discount_percent) / 100), 2)


def record_webhook_usage(reseller_id: int, endpoint: str, status_code: int, response_time_ms: float, ip: str = ""):
    conn = get_db()
    try:
        _exec(conn, "UPDATE resellers SET request_count = request_count + 1, last_used_at = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), reseller_id))
        _exec(conn,
            "INSERT INTO webhook_logs (reseller_id, endpoint, status_code, response_time_ms, ip_address) VALUES (?, ?, ?, ?, ?)",
            (reseller_id, endpoint, status_code, response_time_ms, ip[:45]))
        conn.commit()
    finally:
        conn.close()


# ---------- Balance Management ----------

def get_balance(reseller_id: int) -> float:
    conn = get_db()
    try:
        row = conn.execute(_ph("SELECT balance FROM reseller_balances WHERE reseller_id = ?"), (reseller_id,)).fetchone()
    finally:
        conn.close()
    return float(row["balance"]) if row else 0.0


def add_balance(reseller_id: int, amount: float, description: str = "", admin_ip: str = "") -> float:
    if amount <= 0:
        raise ValueError("Amount must be positive")
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db()
    try:
        if _USE_MYSQL:
            _exec(conn,
                "INSERT INTO reseller_balances (reseller_id, balance, updated_at) VALUES (?, ?, ?) "
                "ON DUPLICATE KEY UPDATE balance = balance + VALUES(balance), updated_at = VALUES(updated_at)",
                (reseller_id, amount, now))
            _exec(conn,
                "INSERT INTO balance_transactions (reseller_id, amount, type, description) VALUES (?, ?, 'credit', ?)",
                (reseller_id, amount, description))
        else:
            _exec(conn,
                "INSERT INTO reseller_balances (reseller_id, balance, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(reseller_id) DO UPDATE SET balance = balance + ?, updated_at = ?",
                (reseller_id, amount, now, amount, now))
            _exec(conn,
                "INSERT INTO balance_transactions (reseller_id, amount, type, description) VALUES (?, ?, 'credit', ?)",
                (reseller_id, amount, description))
        conn.commit()
        row = conn.execute(_ph("SELECT balance FROM reseller_balances WHERE reseller_id = ?"), (reseller_id,)).fetchone()
    finally:
        conn.close()
    _audit("balance_added", reseller_id, f"+${amount:.2f} {description}", admin_ip)
    return float(row["balance"]) if row else 0.0


def deduct_balance(reseller_id: int, amount: float, order_id: int, description: str = "") -> float:
    if amount <= 0:
        raise ValueError("Amount must be positive")
    current = get_balance(reseller_id)
    if current < amount:
        raise ValueError(f"Insufficient balance: ${current:.2f} available, ${amount:.2f} needed")
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db()
    try:
        _exec(conn, "UPDATE reseller_balances SET balance = balance - ?, updated_at = ? WHERE reseller_id = ?",
            (amount, now, reseller_id))
        _exec(conn,
            "INSERT INTO balance_transactions (reseller_id, amount, type, description, order_id) VALUES (?, ?, 'debit', ?, ?)",
            (reseller_id, -amount, description, order_id))
        conn.commit()
        row = conn.execute(_ph("SELECT balance FROM reseller_balances WHERE reseller_id = ?"), (reseller_id,)).fetchone()
    finally:
        conn.close()
    return float(row["balance"]) if row else 0.0


def deduct_both_balances(reseller_id: int, amount: float, order_id: int, description: str = "", shop_id: str | None = None) -> float:
    """Deduct `amount` from BOTH the local panel balance and the linked SellAuth
    customer balance, keeping the two ledgers in sync. Fails (raises ValueError)
    if EITHER ledger is short — never leaves the two out of step.

    Order is deliberate: SellAuth is charged FIRST. If the SellAuth call fails we
    raise before touching the local ledger, so a partial deduction can't happen.

    `shop_id` is the SellAuth shop the customer/buyer belongs to (from the webhook
    payload) — required so balance ops hit the correct store, not just SELLAUTH_SHOP_ID.
    """
    if amount <= 0:
        raise ValueError("Amount must be positive")
    local = get_balance(reseller_id)
    if local < amount:
        raise ValueError(f"Insufficient panel balance: ${local:.2f} available, ${amount:.2f} needed")

    email = get_sellauth_email(reseller_id)
    if email:
        cid = _sellauth_client.get_customer_id_by_email(email, shop_id=shop_id)
        if cid:
            sa_bal = _sellauth_client.get_customer_balance(email, shop_id=shop_id)
            if sa_bal is None:
                raise ValueError("Could not read SellAuth balance (check API token / link)")
            if sa_bal < amount:
                raise ValueError(f"Insufficient SellAuth balance: ${sa_bal:.2f} available, ${amount:.2f} needed")
            # Charge SellAuth first; if it fails, local is untouched.
            # NB: invoice_id is a SellAuth INVOICE id, not our panel order id —
            # omit it to avoid 422s (it's optional per the API).
            resp = _sellauth_client.edit_customer_balance(cid, -amount, description=description, shop_id=shop_id)
            if not resp.get("ok"):
                raise ValueError(
                    f"SellAuth balance deduction failed: HTTP {resp.get('status')} {resp.get('error', '')}".strip()
                )

    # Local ledger
    return deduct_balance(reseller_id, amount, order_id, description)


def ensure_funds(reseller_id: int, amount: float, shop_id: str | None = None) -> None:
    """Gate a purchase on AVAILABLE funds. SellAuth is the source of truth for
    the reseller's wallet; the local panel balance is kept as a mirror. If the
    local balance is short but SellAuth has funds, reconcile local UP to the
    SellAuth balance (never wipe extra local credit) so the sale can proceed.
    Raises ValueError (with a clear message) if EITHER ledger is short.

    `shop_id` scopes the SellAuth customer lookup to the correct store (see
    deduct_both_balances).
    """
    if amount <= 0:
        return
    email = get_sellauth_email(reseller_id)
    if email:
        cid = _sellauth_client.get_customer_id_by_email(email, shop_id=shop_id)
        if cid:
            sa_bal = _sellauth_client.get_customer_balance(email, shop_id=shop_id)
            if sa_bal is None:
                raise ValueError("Could not read SellAuth balance (check API token / link)")
            if sa_bal < amount:
                raise ValueError(f"Insufficient SellAuth balance: ${sa_bal:.2f} available, ${amount:.2f} needed")
            # Top up local to match SellAuth so local is never the blocker.
            local = get_balance(reseller_id)
            if local < sa_bal:
                add_balance(reseller_id, sa_bal - local, "Reconciled from SellAuth")
            return
    # No SellAuth link: fall back to local-only gating.
    if get_balance(reseller_id) < amount:
        raise ValueError(f"Insufficient panel balance: ${get_balance(reseller_id):.2f} available, ${amount:.2f} needed")


def get_transactions(reseller_id: int, limit: int = 50) -> list[dict]:
    conn = get_db()
    try:
        rows = conn.execute(_ph(
            "SELECT * FROM balance_transactions WHERE reseller_id = ? ORDER BY created_at DESC LIMIT ?"),
            (reseller_id, limit)).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


# ---------- Orders ----------

def create_order(
    reseller_id: int,
    product_id: str,
    product_name: str,
    variant_name: str,
    quantity: int,
    price_per_unit: float,
    total_price: float,
    customer_email: str = "",
    deliverable: str = "",
    sellauth_invoice_id: int | None = None,
    sellauth_invoice_url: str = "",
    channel: str = "manual",
) -> dict:
    conn = get_db()
    try:
        _exec(conn,
            """INSERT INTO orders (reseller_id, product_id, product_name, variant_name, quantity,
               price_per_unit, total_price, customer_email, deliverable, sellauth_invoice_id,
               sellauth_invoice_url, channel, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')""",
            (reseller_id, product_id, product_name, variant_name, quantity,
             price_per_unit, total_price, customer_email, deliverable,
             sellauth_invoice_id, sellauth_invoice_url, channel))
        new_id = _last_insert_id(conn)
        conn.commit()
    finally:
        conn.close()
    row = get_order(new_id) or {}
    return dict(row)


def update_order_status(order_id: int, status: str, deliverable: str = "") -> dict | None:
    conn = get_db()
    try:
        _exec(conn, "UPDATE orders SET status = ?, deliverable = ? WHERE id = ?", (status, deliverable, order_id))
        conn.commit()
        row = conn.execute(_ph("SELECT * FROM orders WHERE id = ?"), (order_id,)).fetchone()
    finally:
        conn.close()
    return dict(row) if row else None


def get_reseller_manual_orders(reseller_id: int, limit: int = 50) -> list[dict]:
    conn = get_db()
    try:
        rows = conn.execute(_ph(
            "SELECT * FROM orders WHERE reseller_id = ? AND channel = 'manual' ORDER BY created_at DESC LIMIT ?"),
            (reseller_id, limit)).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def get_orders(reseller_id: int, limit: int = 50, asc: bool = False) -> list[dict]:
    conn = get_db()
    try:
        order = "ASC" if asc else "DESC"
        rows = conn.execute(_ph(f"SELECT * FROM orders WHERE reseller_id = ? ORDER BY created_at {order}, id {order} LIMIT ?"),
            (reseller_id, limit)).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def get_order(order_id: int) -> dict | None:
    conn = get_db()
    try:
        row = conn.execute(_ph("SELECT * FROM orders WHERE id = ?"), (order_id,)).fetchone()
    finally:
        conn.close()
    return dict(row) if row else None


def get_all_orders(limit: int = 100, asc: bool = False) -> list[dict]:
    conn = get_db()
    try:
        order = "ASC" if asc else "DESC"
        rows = conn.execute(_ph(f"SELECT * FROM orders ORDER BY created_at {order} LIMIT ?"), (limit,)).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


# ---------- Referrals ----------

def _generate_referral_code() -> str:
    import string
    alphabet = string.ascii_uppercase + string.digits
    for _ in range(20):
        code = "".join(secrets.choice(alphabet) for _ in range(8))
        conn = get_db()
        try:
            if _USE_MYSQL:
                cur = conn.cursor()
                cur.execute(_ph("SELECT 1 FROM resellers WHERE referral_code = ?"), (code,))
                exists = cur.fetchone()
            else:
                exists = conn.execute(_ph("SELECT 1 FROM resellers WHERE referral_code = ?"), (code,)).fetchone()
        finally:
            conn.close()
        if not exists:
            return code
    return secrets.token_hex(6).upper()


def _record_referral(referrer_id: int, referred_id: int):
    from config import settings
    conn = get_db()
    try:
        _exec(conn, "INSERT INTO referrals (referrer_id, referred_reseller_id, commission_percent) VALUES (?, ?, ?)",
            (referrer_id, referred_id, settings.REFERRAL_COMMISSION_PERCENT))
        conn.commit()
    finally:
        conn.close()


def get_reseller_by_referral_code(code: str) -> dict | None:
    if not code:
        return None
    conn = get_db()
    try:
        row = conn.execute(_ph("SELECT * FROM resellers WHERE referral_code = ?"), (code.strip(),)).fetchone()
    finally:
        conn.close()
    if row:
        d = dict(row)
        d.pop("api_key_enc", None)
        return d
    return None


def get_referrals(reseller_id: int) -> list[dict]:
    conn = get_db()
    try:
        rows = conn.execute(_ph(
            """SELECT rf.*, r.name AS referred_name, r.discount_percent AS referred_discount,
                      r.created_at AS referred_created_at, r.active AS referred_active
               FROM referrals rf
               JOIN resellers r ON r.id = rf.referred_reseller_id
               WHERE rf.referrer_id = ?
               ORDER BY rf.created_at DESC"""),
            (reseller_id,)).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def credit_referral_commission(reseller_id: int, order_total: float):
    conn = get_db()
    try:
        ref = conn.execute(_ph("SELECT * FROM referrals WHERE referred_reseller_id = ?"), (reseller_id,)).fetchone()
        if not ref:
            return
        commission = round(order_total * (ref["commission_percent"] / 100), 2)
        if commission <= 0:
            return
        referrer_id = ref["referrer_id"]
        now = datetime.now(timezone.utc).isoformat()
        if _USE_MYSQL:
            _exec(conn,
                "INSERT INTO reseller_balances (reseller_id, balance, updated_at) VALUES (?, ?, ?) "
                "ON DUPLICATE KEY UPDATE balance = balance + VALUES(balance), updated_at = VALUES(updated_at)",
                (referrer_id, commission, now))
            _exec(conn,
                "INSERT INTO balance_transactions (reseller_id, amount, type, description) VALUES (?, ?, 'credit', ?)",
                (referrer_id, commission, f"Referral commission ({ref['commission_percent']}%)"))
        else:
            _exec(conn,
                "INSERT INTO reseller_balances (reseller_id, balance, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(reseller_id) DO UPDATE SET balance = balance + ?, updated_at = ?",
                (referrer_id, commission, now, commission, now))
            _exec(conn,
                "INSERT INTO balance_transactions (reseller_id, amount, type, description) VALUES (?, ?, 'credit', ?)",
                (referrer_id, commission, f"Referral commission ({ref['commission_percent']}%)"))
        _exec(conn, "UPDATE referrals SET total_earned = total_earned + ? WHERE id = ?", (commission, ref["id"]))
        conn.commit()
    finally:
        conn.close()
    _audit("referral_commission", referrer_id, f"+${commission:.2f}")


# ---------- Applications ----------

def create_application(
    email: str,
    discord: str,
    website: str = "",
    discord_server: str = "",
    products: str = "",
    referral_code: str = "",
) -> dict:
    email = email.strip()[:200]
    discord = discord.strip()[:200]
    website = website.strip()[:300]
    discord_server = discord_server.strip()[:300]
    products = products.strip()[:500]
    referral_code = referral_code.strip()[:50]
    if not email or "@" not in email:
        raise ValueError("A valid email is required")
    if not discord:
        raise ValueError("Discord is required")
    conn = get_db()
    try:
        _exec(conn,
            """INSERT INTO applications (email, discord, website, discord_server, products, referral_code)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (email, discord, website, discord_server, products, referral_code))
        new_id = _last_insert_id(conn)
        conn.commit()
    finally:
        conn.close()
    return get_application(new_id) or {}


def get_application(application_id: int) -> dict | None:
    conn = get_db()
    try:
        row = conn.execute(_ph("SELECT * FROM applications WHERE id = ?"), (application_id,)).fetchone()
    finally:
        conn.close()
    return dict(row) if row else None


def list_applications(status: str = "") -> list[dict]:
    conn = get_db()
    try:
        if status:
            rows = conn.execute(_ph("SELECT * FROM applications WHERE status = ? ORDER BY created_at DESC"), (status,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM applications ORDER BY created_at DESC").fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def update_application_status(application_id: int, status: str) -> dict | None:
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db()
    try:
        _exec(conn, "UPDATE applications SET status = ?, reviewed_at = ? WHERE id = ?", (status, now, application_id))
        conn.commit()
        row = conn.execute(_ph("SELECT * FROM applications WHERE id = ?"), (application_id,)).fetchone()
    finally:
        conn.close()
    return dict(row) if row else None
