"""SQLite database — reseller storage with hashed API keys."""
import sqlite3
import secrets
import hashlib
import hmac
import re
from datetime import datetime, timezone

# SellAuth client instance (services.sellauth.client). Balance read lives on the instance.
from services.sellauth import client as _sellauth_client  # noqa: E402


# ---------- Constants ----------

MAX_NAME_LENGTH = 100
MAX_WEBHOOK_URL_LENGTH = 500
MAX_API_KEYS_PER_RESELLER = 5
VALID_WEBHOOK_URL_PATTERN = re.compile(r"^https?://[^\s]*$")


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect("resellers.db")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# ---------- Key storage (encrypted at rest) ----------

def _encrypt_key(api_key: str) -> str:
    """Encrypt API key for storage. Returns token string."""
    from services.crypto_notify import encrypt_secret
    return encrypt_secret(api_key)


def _decrypt_key(token: str) -> str:
    """Decrypt a stored key token. Returns '' on failure."""
    from services.crypto_notify import decrypt_secret
    return decrypt_secret(token)


def _generate_raw_key() -> str:
    """Generate a cryptographically secure API key."""
    return "rs_" + secrets.token_urlsafe(32)


# ---------- Input validation ----------

def _validate_name(name: str) -> str:
    name = name.strip()
    if not name or len(name) > MAX_NAME_LENGTH:
        raise ValueError(f"Name must be 1–{MAX_NAME_LENGTH} characters")
    # Strip control characters and HTML
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
    # Allow letters, numbers, underscore, dot
    if not re.match(r"^[a-z0-9_.]{3,40}$", username):
        raise ValueError("Username must be 3-40 chars: letters, numbers, _ or .")
    return username


def _validate_discount(pct: float) -> float:
    if not (0 <= pct <= 100):
        raise ValueError("Discount must be between 0 and 100")
    return round(pct, 2)


# ---------- Init ----------

def init_db():
    """Create tables."""
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS resellers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            username TEXT NOT NULL DEFAULT '',
            email TEXT NOT NULL DEFAULT '',
            api_key_enc TEXT NOT NULL,
            api_key_hash TEXT,
            api_key_prefix TEXT NOT NULL,
            discount_percent REAL NOT NULL DEFAULT 0,
            webhook_url TEXT DEFAULT '',
            referral_code TEXT UNIQUE,
            referred_by INTEGER,
            active INTEGER NOT NULL DEFAULT 1,
            last_used_at TEXT,
            request_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            email_2fa_code TEXT NOT NULL DEFAULT '',
            email_2fa_exp TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS referrals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            referrer_id INTEGER NOT NULL,
            referred_reseller_id INTEGER NOT NULL,
            commission_percent REAL NOT NULL DEFAULT 5,
            total_earned REAL NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (referrer_id) REFERENCES resellers(id),
            FOREIGN KEY (referred_reseller_id) REFERENCES resellers(id)
        );

        CREATE TABLE IF NOT EXISTS applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            discord TEXT NOT NULL,
            website TEXT DEFAULT '',
            discord_server TEXT DEFAULT '',
            products TEXT DEFAULT '',
            referral_code TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            reviewed_at TEXT
        );

        CREATE TABLE IF NOT EXISTS manual_pricing (
            product_id TEXT NOT NULL,
            variant_id TEXT NOT NULL DEFAULT '',
            discount_percent REAL NOT NULL,
            price REAL NOT NULL,
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (product_id, variant_id, discount_percent)
        );

        CREATE TABLE IF NOT EXISTS webhook_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reseller_id INTEGER NOT NULL,
            endpoint TEXT NOT NULL,
            status_code INTEGER,
            response_time_ms REAL,
            ip_address TEXT DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (reseller_id) REFERENCES resellers(id)
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            reseller_id INTEGER,
            details TEXT,
            ip_address TEXT DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            success INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (reseller_id) REFERENCES resellers(id)
        );

        CREATE TABLE IF NOT EXISTS reseller_balances (
            reseller_id INTEGER PRIMARY KEY,
            balance REAL NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (reseller_id) REFERENCES resellers(id)
        );

        CREATE TABLE IF NOT EXISTS product_aliases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reseller_id INTEGER NOT NULL,
            alias TEXT NOT NULL UNIQUE,
            product_id TEXT NOT NULL,
            variant_id TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (reseller_id) REFERENCES resellers(id)
        );

        CREATE TABLE IF NOT EXISTS balance_transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reseller_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            type TEXT NOT NULL,
            description TEXT DEFAULT '',
            order_id INTEGER,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (reseller_id) REFERENCES resellers(id)
        );

        CREATE INDEX IF NOT EXISTS idx_webhook_logs_reseller ON webhook_logs(reseller_id);
        CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip_address, created_at);
        CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action, created_at);
        CREATE INDEX IF NOT EXISTS idx_orders_reseller ON orders(reseller_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status);
        CREATE INDEX IF NOT EXISTS idx_balance_tx_reseller ON balance_transactions(reseller_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_referrals_referrer ON referrals(referrer_id);
        CREATE INDEX IF NOT EXISTS idx_applications_status ON applications(status, created_at);
        CREATE INDEX IF NOT EXISTS idx_resellers_key_hash ON resellers(api_key_hash);
    """)
    conn.commit()
    conn.close()

    _migrate()


def _migrate():
    """Add columns that may be missing on pre-existing databases."""
    conn = get_db()
    existing = {r["name"] for r in conn.execute("PRAGMA table_info(resellers)").fetchall()}
    if "username" not in existing:
        conn.execute("ALTER TABLE resellers ADD COLUMN username TEXT NOT NULL DEFAULT ''")
    if "email" not in existing:
        conn.execute("ALTER TABLE resellers ADD COLUMN email TEXT NOT NULL DEFAULT ''")
    if "api_key_enc" not in existing and "api_key_hash" in existing:
        # Add encrypted column, copy nothing (old hashed keys are unrecoverable).
        conn.execute("ALTER TABLE resellers ADD COLUMN api_key_enc TEXT")
        conn.execute("UPDATE resellers SET api_key_enc = '' WHERE api_key_enc IS NULL")
    if "api_key_hash" not in existing:
        # Fast lookup column: SHA-256 of the raw API key. Lets /api/deliver and
        # login authenticate in O(1) without decrypting every reseller's key.
        conn.execute("ALTER TABLE resellers ADD COLUMN api_key_hash TEXT")
        # Backfill from the encrypted (decryptable) keys we already hold.
        rows = conn.execute("SELECT id, api_key_enc FROM resellers WHERE api_key_enc IS NOT NULL AND api_key_enc != ''").fetchall()
        for row in rows:
            try:
                raw = _decrypt_key(row["api_key_enc"])
            except Exception:
                raw = ""
            if raw:
                h = hashlib.sha256(raw.encode()).hexdigest()
                conn.execute("UPDATE resellers SET api_key_hash = ? WHERE id = ?", (h, row["id"]))
    if "sellauth_email" not in existing:
        conn.execute("ALTER TABLE resellers ADD COLUMN sellauth_email TEXT NOT NULL DEFAULT ''")
    if "sellauth_balance_cache" not in existing:
        conn.execute("ALTER TABLE resellers ADD COLUMN sellauth_balance_cache REAL NOT NULL DEFAULT 0")
    if "sellauth_balance_ts" not in existing:
        conn.execute("ALTER TABLE resellers ADD COLUMN sellauth_balance_ts TEXT NOT NULL DEFAULT ''")
    if "referral_code" not in existing:
        conn.execute("ALTER TABLE resellers ADD COLUMN referral_code TEXT")
    if "referred_by" not in existing:
        conn.execute("ALTER TABLE resellers ADD COLUMN referred_by INTEGER")
    if "discord_id" not in existing:
        # Linked Discord account id (from OAuth) for 2FA / delivery DMs
        conn.execute("ALTER TABLE resellers ADD COLUMN discord_id TEXT NOT NULL DEFAULT ''")
    if "discord_username" not in existing:
        conn.execute("ALTER TABLE resellers ADD COLUMN discord_username TEXT NOT NULL DEFAULT ''")
    if "discord_linked_at" not in existing:
        conn.execute("ALTER TABLE resellers ADD COLUMN discord_linked_at TEXT NOT NULL DEFAULT ''")
    if "email_2fa_code" not in existing:
        conn.execute("ALTER TABLE resellers ADD COLUMN email_2fa_code TEXT NOT NULL DEFAULT ''")
    if "email_2fa_exp" not in existing:
        conn.execute("ALTER TABLE resellers ADD COLUMN email_2fa_exp TEXT NOT NULL DEFAULT ''")
    if "channel" not in [c[1] for c in conn.execute("PRAGMA table_info(orders)").fetchall()]:
        conn.execute("ALTER TABLE orders ADD COLUMN channel TEXT NOT NULL DEFAULT 'manual'")
    conn.commit()
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_resellers_referral_code ON resellers(referral_code)")
    conn.commit()
    # Backfill referral codes for any resellers missing one
    rows = conn.execute("SELECT id FROM resellers WHERE referral_code IS NULL OR referral_code = ''").fetchall()
    for r in rows:
        code = _generate_referral_code()
        conn.execute("UPDATE resellers SET referral_code = ? WHERE id = ?", (code, r["id"]))
    # Backfill username from name if empty
    rows = conn.execute("SELECT id, name FROM resellers WHERE username IS NULL OR username = ''").fetchall()
    for r in rows:
        uname = re.sub(r"[^a-zA-Z0-9_]", "", r["name"].lower().replace(" ", "_"))[:40] or f"user{r['id']}"
        conn.execute("UPDATE resellers SET username = ? WHERE id = ?", (uname, r["id"]))
    conn.commit()
    conn.close()


# ---------- Audit logging ----------

def _audit(action: str, reseller_id: int | None = None, details: str = "", ip: str = ""):
    conn = get_db()
    conn.execute(
        "INSERT INTO audit_log (action, reseller_id, details, ip_address) VALUES (?, ?, ?, ?)",
        (action, reseller_id, details[:500], ip[:45]),
    )
    conn.commit()
    conn.close()
    # Mirror to Discord (best-effort, non-blocking)
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
    """Returns True if this IP is rate-limited (too many recent failures)."""
    conn = get_db()
    row = conn.execute(
        """SELECT COUNT(*) as cnt FROM login_attempts
           WHERE ip_address = ? AND success = 0
           AND created_at > datetime('now', ?)""",
        (ip[:45], f"-{window_minutes} minutes"),
    ).fetchone()
    conn.close()
    return (row["cnt"] or 0) >= max_attempts


def log_login_attempt(ip: str, success: bool):
    conn = get_db()
    conn.execute(
        "INSERT INTO login_attempts (ip_address, success) VALUES (?, ?)",
        (ip[:45], 1 if success else 0),
    )
    # Purge old entries
    conn.execute("DELETE FROM login_attempts WHERE created_at < datetime('now', '-1 hour')")
    conn.commit()
    conn.close()


# ---------- Reseller CRUD ----------

def create_reseller(name: str, discount_percent: float, webhook_url: str = "", ip: str = "", referred_by_code: str = "", username: str = "", email: str = "", raw_key: str = "") -> dict:
    """Create a reseller. Returns the RAW API KEY once — stored encrypted, revealable later.
    If raw_key is provided, it is used as the reseller password (e.g. test accounts)."""
    name = _validate_name(name)
    discount = _validate_discount(discount_percent)
    webhook = _validate_webhook_url(webhook_url)
    username = _validate_username(username) if username else _validate_username(name)
    email = (email or "").strip().lower()[:200]

    raw_key = raw_key or _generate_raw_key()
    key_enc = _encrypt_key(raw_key)
    key_prefix = raw_key[:16]
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()  # for display only

    # Resolve referrer (if any) and generate a referral code
    referrer_id = None
    if referred_by_code:
        ref = get_reseller_by_referral_code(referred_by_code.strip())
        if ref:
            referrer_id = ref["id"]
    referral_code = _generate_referral_code()

    now = datetime.now(timezone.utc).isoformat()
    conn = get_db()
    conn.execute(
        """INSERT INTO resellers (name, username, email, api_key_enc, api_key_hash, api_key_prefix, discount_percent, webhook_url,
           referral_code, referred_by, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (name, username, email, key_enc, key_hash, key_prefix, discount, webhook, referral_code, referrer_id, now, now),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM resellers WHERE username = ?", (username,)).fetchone()
    new_id = row["id"] if row else None
    conn.close()

    result = dict(row) if row else {}
    result["api_key"] = raw_key  # ONLY time the raw key is returned

    _audit("reseller_created", result.get("id"), f"name={name} discount={discount}", ip)

    # Record referral relationship
    if referrer_id and new_id:
        _record_referral(referrer_id, new_id)

    return result


def get_reseller_by_key(api_key: str) -> dict | None:
    """Lookup reseller by raw API key (password). O(1) via SHA-256 hash — no decrypt loop."""
    if not api_key or not api_key.startswith("rs_"):
        return None
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM resellers WHERE api_key_hash = ? AND active = 1", (key_hash,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_reseller_by_username_password(username: str, password: str) -> dict | None:
    """Login: username + password (password == API key). Hashed compare, O(1)."""
    if not username or not password:
        return None
    key_hash = hashlib.sha256(password.encode()).hexdigest()
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM resellers WHERE username = ? AND api_key_hash = ? AND active = 1",
        (username.strip(), key_hash),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_reseller_by_email_password(email: str, password: str) -> dict | None:
    """Login: email + password (password == API key). Hashed compare, O(1)."""
    if not email or not password:
        return None
    key_hash = hashlib.sha256(password.encode()).hexdigest()
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM resellers WHERE email = ? AND api_key_hash = ? AND active = 1",
        (email.strip().lower(), key_hash),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_reseller_by_id(reseller_id: int) -> dict | None:
    """Get reseller by ID. NEVER returns the raw API key — only prefix."""
    conn = get_db()
    row = conn.execute("SELECT * FROM resellers WHERE id = ?", (reseller_id,)).fetchone()
    conn.close()
    if row:
        d = dict(row)
        d.pop("api_key_enc", None)
        return d
    return None


def list_resellers() -> list[dict]:
    """List all resellers. NEVER returns raw API keys — only prefixes."""
    conn = get_db()
    rows = conn.execute("SELECT * FROM resellers ORDER BY created_at DESC").fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d.pop("api_key_enc", None)
        result.append(d)
    return result


def update_reseller(reseller_id: int, ip: str = "", **kwargs) -> dict | None:
    """Update reseller fields. Only allowed fields can be changed."""
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
    set_parts = [f"{col} = ?" for col in updates]
    values = list(updates.values()) + [reseller_id]
    conn.execute(f"UPDATE resellers SET {', '.join(set_parts)} WHERE id = ?", values)
    conn.commit()
    row = conn.execute("SELECT * FROM resellers WHERE id = ?", (reseller_id,)).fetchone()
    conn.close()

    result = dict(row) if row else None
    if result:
        result.pop("api_key_enc", None)
    _audit("reseller_updated", reseller_id, f"fields={list(updates.keys())}", ip)
    return result


def link_reseller_discord(reseller_id: int, discord_id: str, discord_username: str, ip: str = "") -> dict | None:
    """Store a verified Discord account link (from OAuth) on the reseller."""
    discord_id = (discord_id or "").strip()
    discord_username = (discord_username or "").strip()[:100]
    if not discord_id:
        raise ValueError("discord_id is required")
    conn = get_db()
    conn.execute(
        "UPDATE resellers SET discord_id = ?, discord_username = ?, "
        "discord_linked_at = ? WHERE id = ?",
        (discord_id, discord_username, datetime.now(timezone.utc).isoformat(), reseller_id),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM resellers WHERE id = ?", (reseller_id,)).fetchone()
    conn.close()
    result = dict(row) if row else None
    if result:
        result.pop("api_key_enc", None)
    _audit("reseller_discord_linked", reseller_id, f"discord={discord_username} ({discord_id})", ip)
    return result


def unlink_reseller_discord(reseller_id: int, ip: str = "") -> dict | None:
    """Remove the reseller's Discord link (e.g. before re-linking)."""
    conn = get_db()
    conn.execute(
        "UPDATE resellers SET discord_id = '', discord_username = '', discord_linked_at = '' WHERE id = ?",
        (reseller_id,),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM resellers WHERE id = ?", (reseller_id,)).fetchone()
    conn.close()
    result = dict(row) if row else None
    if result:
        result.pop("api_key_enc", None)
    _audit("reseller_discord_unlinked", reseller_id, "", ip)
    return result


def delete_reseller(reseller_id: int, ip: str = "") -> bool:
    conn = get_db()
    # Delete child records first
    conn.execute("DELETE FROM webhook_logs WHERE reseller_id = ?", (reseller_id,))
    conn.execute("DELETE FROM audit_log WHERE reseller_id = ?", (reseller_id,))
    conn.execute("DELETE FROM resellers WHERE id = ?", (reseller_id,))
    conn.commit()
    affected = conn.total_changes
    conn.close()

    if affected:
        _audit("reseller_deleted", reseller_id, "", ip)
    return affected > 0


def regenerate_api_key(reseller_id: int, ip: str = "") -> dict | None:
    """Regenerate API key. Returns the NEW raw key once. Old key is overwritten."""
    raw_key = _generate_raw_key()
    key_enc = _encrypt_key(raw_key)
    key_prefix = raw_key[:16]
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    now = datetime.now(timezone.utc).isoformat()

    conn = get_db()
    conn.execute(
        "UPDATE resellers SET api_key_enc = ?, api_key_hash = ?, api_key_prefix = ?, updated_at = ? WHERE id = ?",
        (key_enc, key_hash, key_prefix, now, reseller_id),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM resellers WHERE id = ?", (reseller_id,)).fetchone()
    conn.close()

    result = dict(row) if row else {}
    result["api_key"] = raw_key  # Only time the new raw key is exposed

    _audit("reseller_key_rotated", reseller_id, "", ip)
    return result


def reveal_api_key(reseller_id: int) -> str | None:
    """Decrypt and return the raw API key for admin reveal. Returns None if not found."""
    conn = get_db()
    row = conn.execute("SELECT api_key_enc FROM resellers WHERE id = ?", (reseller_id,)).fetchone()
    conn.close()
    if not row:
        return None
    return _decrypt_key(row["api_key_enc"])


# ---------- SellAuth customer linkage (balance mirror) ----------

def set_sellauth_email(reseller_id: int, email: str, ip: str = "") -> None:
    email = (email or "").strip().lower()
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db()
    conn.execute(
        "UPDATE resellers SET sellauth_email = ?, updated_at = ? WHERE id = ?",
        (email, now, reseller_id),
    )
    conn.commit()
    conn.close()
    _audit("reseller_email_linked", reseller_id, f"email={email}", ip)


def get_sellauth_email(reseller_id: int) -> str:
    conn = get_db()
    row = conn.execute("SELECT sellauth_email FROM resellers WHERE id = ?", (reseller_id,)).fetchone()
    conn.close()
    return (row["sellauth_email"] or "") if row else ""


# ---------- Email-link 2FA (SellAuth-style 6-digit code) ----------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def set_email_2fa(reseller_id: int, code: str, ttl_seconds: int = 600) -> None:
    """Store a hashed 2FA code with an expiry timestamp. Code is hashed (never plaintext)."""
    from datetime import timedelta
    hashed = hashlib.sha256(code.encode()).hexdigest()
    exp_dt = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
    conn = get_db()
    conn.execute(
        "UPDATE resellers SET email_2fa_code = ?, email_2fa_exp = ? WHERE id = ?",
        (hashed, exp_dt.isoformat(), reseller_id),
    )
    conn.commit()
    conn.close()


def verify_email_2fa(reseller_id: int, code: str) -> bool:
    """Constant-time verify of the 2FA code. Returns True if valid + unexpired."""
    conn = get_db()
    row = conn.execute(
        "SELECT email_2fa_code, email_2fa_exp FROM resellers WHERE id = ?", (reseller_id,)
    ).fetchone()
    conn.close()
    if not row:
        return False
    stored_hash = row["email_2fa_code"] or ""
    exp = row["email_2fa_exp"] or ""
    if not stored_hash or not exp:
        return False
    try:
        exp_dt = datetime.fromisoformat(exp)
    except (ValueError, TypeError):
        return False
    if exp_dt < datetime.now(timezone.utc):
        return False
    guess_hash = hashlib.sha256((code or "").encode()).hexdigest()
    return hmac.compare_digest(guess_hash, stored_hash)


def clear_email_2fa(reseller_id: int) -> None:
    conn = get_db()
    conn.execute(
        "UPDATE resellers SET email_2fa_code = '', email_2fa_exp = '' WHERE id = ?",
        (reseller_id,),
    )
    conn.commit()
    conn.close()


def get_sellauth_balance(reseller_id: int, force: bool = False) -> dict:
    """Return the reseller's SellAuth store balance.

    Cached 60s unless force=True. Returns
    {"email":..., "balance": float, "source": "live"|"cache"|"none", "cached_at":...}
    """
    conn = get_db()
    row = conn.execute(
        "SELECT sellauth_email, sellauth_balance_cache, sellauth_balance_ts FROM resellers WHERE id = ?",
        (reseller_id,),
    ).fetchone()
    conn.close()
    email = (row["sellauth_email"] or "") if row else ""
    if not email:
        return {"email": "", "balance": 0.0, "source": "none", "cached_at": ""}

    # Serve cache if fresh and not forced
    ts = row["sellauth_balance_ts"] if row else ""
    if not force and ts:
        try:
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(ts)).total_seconds()
            if age < 60:
                return {"email": email, "balance": float(row["sellauth_balance_cache"] or 0), "source": "cache", "cached_at": ts}
        except Exception:
            pass

    # Live fetch
    bal = _sellauth_client.get_customer_balance(email) if email else None
    if bal is None:
        # keep last cache if fetch failed
        return {"email": email, "balance": float(row["sellauth_balance_cache"] or 0) if row else 0.0, "source": "none", "cached_at": ts}
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db()
    conn.execute(
        "UPDATE resellers SET sellauth_balance_cache = ?, sellauth_balance_ts = ? WHERE id = ?",
        (bal, now, reseller_id),
    )
    conn.commit()
    conn.close()
    return {"email": email, "balance": bal, "source": "live", "cached_at": now}


def sync_balance_from_sellauth(reseller_id: int, ip: str = "") -> dict:
    """Pull the linked SellAuth customer balance and OVERWRITE the panel's
    spendable balance with it. Returns {'balance': float, 'email': str, 'source': str}."""
    email = get_sellauth_email(reseller_id)
    if not email:
        raise ValueError("No SellAuth email linked for this reseller")
    bal = _sellauth_client.get_customer_balance(email)
    if bal is None:
        raise ValueError("Could not read SellAuth balance (check API token / email)")
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db()
    conn.execute(
        "INSERT INTO reseller_balances (reseller_id, balance, updated_at) VALUES (?, ?, ?) "
        "ON CONFLICT(reseller_id) DO UPDATE SET balance = ?, updated_at = ?",
        (reseller_id, bal, now, bal, now),
    )
    conn.execute(
        "INSERT INTO balance_transactions (reseller_id, amount, type, description) VALUES (?, ?, 'sync', ?)",
        (reseller_id, bal, f"Synced from SellAuth ({email})"),
    )
    conn.execute(
        "UPDATE resellers SET sellauth_balance_cache = ?, sellauth_balance_ts = ? WHERE id = ?",
        (bal, now, reseller_id),
    )
    conn.commit()
    conn.close()
    _audit("balance_synced", reseller_id, f"=${bal:.2f} <- SellAuth {email}", ip)
    return {"balance": bal, "email": email, "source": "live"}


# ---------- Per-product delivery aliases (blank until generated, revocable) ----------

def create_product_alias(reseller_id: int, product_id: str, variant_id: str = "", ip: str = "") -> dict:
    """Generate a reseller-unique random alias token for a (product, variant).
    Returns {'alias': str, 'url': str} or raises ValueError on dup race (retry)."""
    alias = secrets.token_urlsafe(16)
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO product_aliases (reseller_id, alias, product_id, variant_id, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (reseller_id, alias, str(product_id), str(variant_id or ""), now),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise ValueError("Alias collision — retry")
    conn.close()
    _audit("alias_created", reseller_id, f"{alias} -> p={product_id} v={variant_id}", ip)
    return {"alias": alias, "product_id": str(product_id), "variant_id": str(variant_id or "")}


def revoke_product_alias(reseller_id: int, alias: str, ip: str = "") -> None:
    conn = get_db()
    conn.execute(
        "DELETE FROM product_aliases WHERE reseller_id = ? AND alias = ?",
        (reseller_id, alias),
    )
    conn.commit()
    conn.close()
    _audit("alias_revoked", reseller_id, f"{alias}", ip)


def get_alias(reseller_id: int, alias: str) -> dict | None:
    """Look up one alias owned by this reseller. Returns {product_id, variant_id} or None."""
    conn = get_db()
    row = conn.execute(
        "SELECT product_id, variant_id FROM product_aliases WHERE reseller_id = ? AND alias = ?",
        (reseller_id, alias),
    ).fetchone()
    conn.close()
    if not row:
        return None
    return {"product_id": row["product_id"], "variant_id": row["variant_id"]}


def list_product_aliases(reseller_id: int) -> list[dict]:
    """All aliases owned by this reseller: [{alias, product_id, variant_id}]."""
    conn = get_db()
    rows = conn.execute(
        "SELECT alias, product_id, variant_id FROM product_aliases WHERE reseller_id = ?",
        (reseller_id,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def resolve_alias(alias: str) -> dict | None:
    """Public lookup by alias token only (no reseller_id needed) -> {reseller_id, product_id, variant_id}."""
    conn = get_db()
    row = conn.execute(
        "SELECT reseller_id, product_id, variant_id FROM product_aliases WHERE alias = ?",
        (alias,),
    ).fetchone()
    conn.close()
    if not row:
        return None
    return {"reseller_id": row["reseller_id"], "product_id": row["product_id"], "variant_id": row["variant_id"]}


# ---------- Manual pricing overrides ----------
# Lets the owner hand-set a price for any product/variant at any specific discount level.
# Key: (product_id, variant_id, discount_percent) -> fixed price (overrides computed discount price).

def set_manual_price(product_id: str, variant_id: str, discount_percent: float, price: float) -> None:
    """Upsert a manual price override for a product/variant at a given discount level."""
    price = round(float(price), 2)
    discount_percent = round(float(discount_percent), 2)
    conn = get_db()
    conn.execute(
        """INSERT INTO manual_pricing (product_id, variant_id, discount_percent, price, updated_at)
           VALUES (?, ?, ?, ?, datetime('now'))
           ON CONFLICT(product_id, variant_id, discount_percent)
           DO UPDATE SET price = excluded.price, updated_at = excluded.updated_at""",
        (str(product_id), str(variant_id or ""), discount_percent, price),
    )
    conn.commit()
    conn.close()


def get_manual_price(product_id: str, variant_id: str, discount_percent: float) -> float | None:
    """Return the manual override price if one exists, else None."""
    conn = get_db()
    row = conn.execute(
        "SELECT price FROM manual_pricing WHERE product_id = ? AND variant_id = ? AND discount_percent = ?",
        (str(product_id), str(variant_id or ""), round(float(discount_percent), 2)),
    ).fetchone()
    conn.close()
    return round(row["price"], 2) if row else None


def list_manual_prices() -> list[dict]:
    """All manual price overrides, newest first."""
    conn = get_db()
    rows = conn.execute(
        "SELECT product_id, variant_id, discount_percent, price, updated_at FROM manual_pricing ORDER BY updated_at DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def delete_manual_price(product_id: str, variant_id: str, discount_percent: float) -> None:
    conn = get_db()
    conn.execute(
        "DELETE FROM manual_pricing WHERE product_id = ? AND variant_id = ? AND discount_percent = ?",
        (str(product_id), str(variant_id or ""), round(float(discount_percent), 2)),
    )
    conn.commit()
    conn.close()


def effective_price(product_id: str, variant_id: str, discount_percent: float, base_price: float) -> float:
    """Return the override price if set for (product, variant, discount), else base_price*(1-discount/100)."""
    override = get_manual_price(product_id, variant_id, discount_percent)
    if override is not None:
        return override
    return round(float(base_price) * (1 - float(discount_percent) / 100), 2)



def record_webhook_usage(reseller_id: int, endpoint: str, status_code: int, response_time_ms: float, ip: str = ""):
    conn = get_db()
    conn.execute(
        "UPDATE resellers SET request_count = request_count + 1, last_used_at = ? WHERE id = ?",
        (datetime.now(timezone.utc).isoformat(), reseller_id),
    )
    conn.execute(
        "INSERT INTO webhook_logs (reseller_id, endpoint, status_code, response_time_ms, ip_address) VALUES (?, ?, ?, ?, ?)",
        (reseller_id, endpoint, status_code, response_time_ms, ip[:45]),
    )
    conn.commit()
    conn.close()


# ---------- Balance Management ----------

def get_balance(reseller_id: int) -> float:
    conn = get_db()
    row = conn.execute("SELECT balance FROM reseller_balances WHERE reseller_id = ?", (reseller_id,)).fetchone()
    conn.close()
    return float(row["balance"]) if row else 0.0


def add_balance(reseller_id: int, amount: float, description: str = "", admin_ip: str = "") -> float:
    """Add funds to a reseller's balance. Returns new balance."""
    if amount <= 0:
        raise ValueError("Amount must be positive")
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db()
    conn.execute(
        "INSERT INTO reseller_balances (reseller_id, balance, updated_at) VALUES (?, ?, ?) "
        "ON CONFLICT(reseller_id) DO UPDATE SET balance = balance + ?, updated_at = ?",
        (reseller_id, amount, now, amount, now),
    )
    conn.execute(
        "INSERT INTO balance_transactions (reseller_id, amount, type, description) VALUES (?, ?, 'credit', ?)",
        (reseller_id, amount, description),
    )
    conn.commit()
    new_balance = conn.execute("SELECT balance FROM reseller_balances WHERE reseller_id = ?", (reseller_id,)).fetchone()
    conn.close()
    _audit("balance_added", reseller_id, f"+${amount:.2f} {description}", admin_ip)
    return float(new_balance["balance"]) if new_balance else 0.0


def deduct_balance(reseller_id: int, amount: float, order_id: int, description: str = "") -> float:
    """Deduct from reseller balance for an order. Returns new balance, raises if insufficient."""
    if amount <= 0:
        raise ValueError("Amount must be positive")
    current = get_balance(reseller_id)
    if current < amount:
        raise ValueError(f"Insufficient balance: ${current:.2f} available, ${amount:.2f} needed")
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db()
    conn.execute(
        "UPDATE reseller_balances SET balance = balance - ?, updated_at = ? WHERE reseller_id = ?",
        (amount, now, reseller_id),
    )
    conn.execute(
        "INSERT INTO balance_transactions (reseller_id, amount, type, description, order_id) VALUES (?, ?, 'debit', ?, ?)",
        (reseller_id, -amount, description, order_id),
    )
    conn.commit()
    new_balance = conn.execute("SELECT balance FROM reseller_balances WHERE reseller_id = ?", (reseller_id,)).fetchone()
    conn.close()
    return float(new_balance["balance"]) if new_balance else 0.0


def get_transactions(reseller_id: int, limit: int = 50) -> list[dict]:
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM balance_transactions WHERE reseller_id = ? ORDER BY created_at DESC LIMIT ?",
        (reseller_id, limit),
    ).fetchall()
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
    conn.execute(
        """INSERT INTO orders (reseller_id, product_id, product_name, variant_name, quantity,
           price_per_unit, total_price, customer_email, deliverable, sellauth_invoice_id,
           sellauth_invoice_url, channel, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')""",
        (reseller_id, product_id, product_name, variant_name, quantity,
         price_per_unit, total_price, customer_email, deliverable,
         sellauth_invoice_id, sellauth_invoice_url, channel),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM orders WHERE rowid = last_insert_rowid()").fetchone()
    conn.close()
    return dict(row) if row else {}


def update_order_status(order_id: int, status: str, deliverable: str = "") -> dict | None:
    conn = get_db()
    conn.execute(
        "UPDATE orders SET status = ?, deliverable = ? WHERE id = ?",
        (status, deliverable, order_id),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_reseller_manual_orders(reseller_id: int, limit: int = 50) -> list[dict]:
    """Manual (panel Buy Keys / catalog) orders only — webhook deliveries excluded, since those
    push the key to the reseller's own webhook and have no in-panel deliverable to show."""
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM orders WHERE reseller_id = ? AND channel = 'manual' "
        "ORDER BY created_at DESC LIMIT ?",
        (reseller_id, limit),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_orders(reseller_id: int, limit: int = 50) -> list[dict]:
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM orders WHERE reseller_id = ? ORDER BY created_at DESC LIMIT ?",
        (reseller_id, limit),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_order(order_id: int) -> dict | None:
    conn = get_db()
    row = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_orders(limit: int = 100) -> list[dict]:
    conn = get_db()
    rows = conn.execute("SELECT * FROM orders ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------- Referrals ----------

def _generate_referral_code() -> str:
    """Generate a short, unique referral code (e.g. 'XK4F9T2Q')."""
    import string
    alphabet = string.ascii_uppercase + string.digits
    for _ in range(20):
        code = "".join(secrets.choice(alphabet) for _ in range(8))
        conn = get_db()
        exists = conn.execute("SELECT 1 FROM resellers WHERE referral_code = ?", (code,)).fetchone()
        conn.close()
        if not exists:
            return code
    # Extremely unlikely fallback
    return secrets.token_hex(6).upper()


def _record_referral(referrer_id: int, referred_id: int):
    """Create a referral relationship with the configured commission %."""
    from config import settings
    conn = get_db()
    conn.execute(
        "INSERT INTO referrals (referrer_id, referred_reseller_id, commission_percent) VALUES (?, ?, ?)",
        (referrer_id, referred_id, settings.REFERRAL_COMMISSION_PERCENT),
    )
    conn.commit()
    conn.close()


def get_reseller_by_referral_code(code: str) -> dict | None:
    """Lookup a reseller by referral code."""
    if not code:
        return None
    conn = get_db()
    row = conn.execute("SELECT * FROM resellers WHERE referral_code = ?", (code.strip(),)).fetchone()
    conn.close()
    if row:
        d = dict(row)
        d.pop("api_key_enc", None)
        return d
    return None


def get_referrals(reseller_id: int) -> list[dict]:
    """Get all resellers referred by this reseller, with earned totals."""
    conn = get_db()
    rows = conn.execute(
        """SELECT rf.*, r.name AS referred_name, r.discount_percent AS referred_discount,
                  r.created_at AS referred_created_at, r.active AS referred_active
           FROM referrals rf
           JOIN resellers r ON r.id = rf.referred_reseller_id
           WHERE rf.referrer_id = ?
           ORDER BY rf.created_at DESC""",
        (reseller_id,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def credit_referral_commission(reseller_id: int, order_total: float):
    """If this reseller was referred, credit the referrer their commission on an order."""
    conn = get_db()
    ref = conn.execute(
        "SELECT * FROM referrals WHERE referred_reseller_id = ?", (reseller_id,)
    ).fetchone()
    if not ref:
        conn.close()
        return
    commission = round(order_total * (ref["commission_percent"] / 100), 2)
    if commission <= 0:
        conn.close()
        return
    referrer_id = ref["referrer_id"]
    # Credit to referrer's balance
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO reseller_balances (reseller_id, balance, updated_at) VALUES (?, ?, ?) "
        "ON CONFLICT(reseller_id) DO UPDATE SET balance = balance + ?, updated_at = ?",
        (referrer_id, commission, now, commission, now),
    )
    conn.execute(
        "INSERT INTO balance_transactions (reseller_id, amount, type, description) VALUES (?, ?, 'credit', ?)",
        (referrer_id, commission, f"Referral commission ({ref['commission_percent']}%)"),
    )
    conn.execute(
        "UPDATE referrals SET total_earned = total_earned + ? WHERE id = ?",
        (commission, ref["id"]),
    )
    conn.commit()
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
    conn.execute(
        """INSERT INTO applications (email, discord, website, discord_server, products, referral_code)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (email, discord, website, discord_server, products, referral_code),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM applications WHERE rowid = last_insert_rowid()").fetchone()
    conn.close()
    return dict(row) if row else {}


def list_applications(status: str = "") -> list[dict]:
    conn = get_db()
    if status:
        rows = conn.execute(
            "SELECT * FROM applications WHERE status = ? ORDER BY created_at DESC", (status,)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM applications ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_application_status(application_id: int, status: str) -> dict | None:
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db()
    conn.execute(
        "UPDATE applications SET status = ?, reviewed_at = ? WHERE id = ?",
        (status, now, application_id),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM applications WHERE id = ?", (application_id,)).fetchone()
    conn.close()
    return dict(row) if row else None
