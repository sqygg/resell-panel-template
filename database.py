"""SQLite database — reseller storage with hashed API keys."""
import sqlite3
import secrets
import hashlib
import hmac
import re
from datetime import datetime, timezone


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


# ---------- Key hashing ----------

def _hash_key(api_key: str) -> str:
    """SHA-256 hash of the API key. We never store plaintext."""
    return hashlib.sha256(api_key.encode()).hexdigest()


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
            api_key_hash TEXT NOT NULL UNIQUE,
            api_key_prefix TEXT NOT NULL,
            discount_percent REAL NOT NULL DEFAULT 0,
            webhook_url TEXT DEFAULT '',
            referral_code TEXT UNIQUE,
            referred_by INTEGER,
            active INTEGER NOT NULL DEFAULT 1,
            last_used_at TEXT,
            request_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
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

        CREATE INDEX IF NOT EXISTS idx_resellers_hash ON resellers(api_key_hash);
        CREATE INDEX IF NOT EXISTS idx_webhook_logs_reseller ON webhook_logs(reseller_id);
        CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip_address, created_at);
        CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action, created_at);
        CREATE INDEX IF NOT EXISTS idx_orders_reseller ON orders(reseller_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status);
        CREATE INDEX IF NOT EXISTS idx_balance_tx_reseller ON balance_transactions(reseller_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_referrals_referrer ON referrals(referrer_id);
        CREATE INDEX IF NOT EXISTS idx_applications_status ON applications(status, created_at);
    """)
    conn.commit()
    conn.close()

    _migrate()


def _migrate():
    """Add columns that may be missing on pre-existing databases."""
    conn = get_db()
    existing = {r["name"] for r in conn.execute("PRAGMA table_info(resellers)").fetchall()}
    if "referral_code" not in existing:
        conn.execute("ALTER TABLE resellers ADD COLUMN referral_code TEXT")
    if "referred_by" not in existing:
        conn.execute("ALTER TABLE resellers ADD COLUMN referred_by INTEGER")
    conn.commit()
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_resellers_referral_code ON resellers(referral_code)")
    conn.commit()
    # Backfill referral codes for any resellers missing one
    rows = conn.execute("SELECT id FROM resellers WHERE referral_code IS NULL OR referral_code = ''").fetchall()
    for r in rows:
        code = _generate_referral_code()
        conn.execute("UPDATE resellers SET referral_code = ? WHERE id = ?", (code, r["id"]))
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

def create_reseller(name: str, discount_percent: float, webhook_url: str = "", ip: str = "", referred_by_code: str = "") -> dict:
    """Create a reseller. Returns the RAW API KEY once — never stored, never retrievable again."""
    name = _validate_name(name)
    discount = _validate_discount(discount_percent)
    webhook = _validate_webhook_url(webhook_url)

    raw_key = _generate_raw_key()
    key_hash = _hash_key(raw_key)
    key_prefix = raw_key[:16]  # for display only

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
        """INSERT INTO resellers (name, api_key_hash, api_key_prefix, discount_percent, webhook_url,
           referral_code, referred_by, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (name, key_hash, key_prefix, discount, webhook, referral_code, referrer_id, now, now),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM resellers WHERE api_key_hash = ?", (key_hash,)).fetchone()
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
    """Lookup reseller by raw API key. Hash it, search by hash."""
    if not api_key or not api_key.startswith("rs_"):
        return None
    key_hash = _hash_key(api_key)
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM resellers WHERE api_key_hash = ? AND active = 1", (key_hash,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_reseller_by_id(reseller_id: int) -> dict | None:
    """Get reseller by ID. NEVER returns the raw API key or hash."""
    conn = get_db()
    row = conn.execute("SELECT * FROM resellers WHERE id = ?", (reseller_id,)).fetchone()
    conn.close()
    if row:
        d = dict(row)
        d.pop("api_key_hash", None)
        return d
    return None


def list_resellers() -> list[dict]:
    """List all resellers. NEVER returns raw API keys or hashes — only prefixes."""
    conn = get_db()
    rows = conn.execute("SELECT * FROM resellers ORDER BY created_at DESC").fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        # Strip sensitive fields
        d.pop("api_key_hash", None)
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
        result.pop("api_key_hash", None)
    _audit("reseller_updated", reseller_id, f"fields={list(updates.keys())}", ip)
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
    """Regenerate API key. Returns the NEW raw key once. Old hash is overwritten."""
    raw_key = _generate_raw_key()
    key_hash = _hash_key(raw_key)
    key_prefix = raw_key[:16]
    now = datetime.now(timezone.utc).isoformat()

    conn = get_db()
    conn.execute(
        "UPDATE resellers SET api_key_hash = ?, api_key_prefix = ?, updated_at = ? WHERE id = ?",
        (key_hash, key_prefix, now, reseller_id),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM resellers WHERE id = ?", (reseller_id,)).fetchone()
    conn.close()

    result = dict(row) if row else {}
    result["api_key"] = raw_key  # Only time the new raw key is exposed

    _audit("reseller_key_rotated", reseller_id, "", ip)
    return result


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
    sellauth_invoice_id: int | None = None,
    sellauth_invoice_url: str = "",
) -> dict:
    conn = get_db()
    conn.execute(
        """INSERT INTO orders (reseller_id, product_id, product_name, variant_name, quantity,
           price_per_unit, total_price, customer_email, sellauth_invoice_id,
           sellauth_invoice_url, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')""",
        (reseller_id, product_id, product_name, variant_name, quantity,
         price_per_unit, total_price, customer_email,
         sellauth_invoice_id, sellauth_invoice_url),
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
        d.pop("api_key_hash", None)
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
