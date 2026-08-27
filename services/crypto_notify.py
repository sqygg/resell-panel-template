"""Encryption for API keys at rest (stdlib-only, no 'cryptography' package) + notifications."""
import base64
import hashlib
import hmac
import secrets
from config import settings

_SALT = b"reseller-panel-v1-static-salt"


def _key() -> bytes:
    """Derive a 32-byte key from SESSION_SECRET via PBKDF2."""
    secret = (settings.SESSION_SECRET or "insecure-default-change-me").encode()
    return hashlib.pbkdf2_hmac("sha256", secret, _SALT, 100_000)


def _keystream(key: bytes, nonce: bytes):
    """Yield a SHA-256 keystream keyed by (key, nonce, counter)."""
    ctr = 0
    while True:
        yield hashlib.sha256(key + nonce + ctr.to_bytes(8, "big")).digest()
        ctr += 1


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a secret (API key) for storage. Returns a b64 token string."""
    key = _key()
    nonce = secrets.token_bytes(16)
    data = plaintext.encode()
    out = bytearray()
    gen = _keystream(key, nonce)
    for i in range(len(data)):
        block = next(gen)
        out.append(data[i] ^ block[i % 32])
    mac = hmac.new(key, nonce + bytes(out), hashlib.sha256).digest()
    return base64.b64encode(nonce + mac + bytes(out)).decode()


def decrypt_secret(token: str) -> str:
    """Decrypt a stored token back to plaintext. Returns '' on failure/tamper."""
    try:
        raw = base64.b64decode(token)
        if len(raw) < 48:
            return ""
        nonce, mac, ct = raw[:16], raw[16:48], raw[48:]
        key = _key()
        if hmac.new(key, nonce + ct, hashlib.sha256).digest() != mac:
            return ""
        gen = _keystream(key, nonce)
        out = bytearray()
        for i in range(len(ct)):
            block = next(gen)
            out.append(ct[i] ^ block[i % 32])
        return bytes(out).decode()
    except Exception:
        return ""


# ---------- Notifications (Discord only; ntfy dropped per user) ----------

def notify_new_application(app: dict) -> None:
    """Send a Discord webhook notification about a new reseller application."""
    if not settings.DISCORD_WEBHOOK_URL:
        return
    name = (app.get("name") or app.get("email") or "Someone")
    lines = [
        "📥 **New reseller application**",
        f"**Email:** {app.get('email', '?')}",
        f"**Discord:** {app.get('discord', '?')}",
        f"**Website:** {app.get('website') or '—'}",
        f"**Products:** {app.get('products') or '—'}",
    ]
    text = "\n".join(lines)
    try:
        import httpx
        httpx.post(settings.DISCORD_WEBHOOK_URL, json={"content": text}, timeout=8)
    except Exception:
        pass
