"""Encryption for API keys at rest + notification delivery (Discord/ntfy)."""
import base64
import os
import httpx
from cryptography.fernet import Fernet
from config import settings


# ---------- Encryption ----------

def _fernet_key() -> bytes:
    """Derive a Fernet key from SESSION_SECRET (32 url-safe bytes)."""
    raw = (settings.SESSION_SECRET or "insecure-default-change-me").encode()
    return base64.urlsafe_b64encode(raw.ljust(32, b"0")[:32])


_fernet = Fernet(_fernet_key())


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a secret (API key) for storage. Returns b64 token string."""
    return _fernet.encrypt(plaintext.encode()).decode()


def decrypt_secret(token: str) -> str:
    """Decrypt a stored token back to plaintext. Returns '' on failure."""
    try:
        return _fernet.decrypt(token.encode()).decode()
    except Exception:
        return ""


# ---------- Notifications ----------

def notify_new_application(app: dict) -> None:
    """Send a notification about a new reseller application to Discord + ntfy."""
    name = (app.get("name") or app.get("email") or "Someone")
    lines = [
        f"📥 **New reseller application**",
        f"**Email:** {app.get('email', '?')}",
        f"**Discord:** {app.get('discord', '?')}",
        f"**Website:** {app.get('website') or '—'}",
        f"**Products:** {app.get('products') or '—'}",
    ]
    text = "\n".join(lines)

    # Discord
    if settings.DISCORD_WEBHOOK_URL:
        try:
            httpx.post(settings.DISCORD_WEBHOOK_URL, json={"content": text}, timeout=8)
        except Exception:
            pass

    # ntfy
    if settings.NTFY_TOPIC:
        try:
            url = f"{settings.NTFY_SERVER.rstrip('/')}/{settings.NTFY_TOPIC}"
            httpx.post(url, data=text.encode(), timeout=8,
                       headers={"Title": "New reseller application", "Priority": "default"})
        except Exception:
            pass
