"""Discord activity/audit logging — mirror every audited action + errors to a Discord channel.

Fire-and-forget: failures are swallowed (never break the request). Uses the
DISCORD_LOG_WEBHOOK_URL env var, falling back to DISCORD_WEBHOOK_URL.
"""
import os
import httpx
from config import settings

_LOG_URL = os.getenv("DISCORD_LOG_WEBHOOK_URL") or settings.DISCORD_WEBHOOK_URL

# Color codes for embed side-bars (decimal, Discord format)
_COLORS = {
    "info": 0x5865F2,      # blurple
    "success": 0x57F287,   # green
    "warn": 0xFEE75C,      # yellow
    "error": 0xED4245,     # red
    "audit": 0x9B59B6,     # purple
}


def _level_color(level: str) -> int:
    return _COLORS.get(level, _COLORS["info"])


def log_event(message: str, *, level: str = "info", title: str = "Reseller Panel", fields: dict | None = None):
    """Send a message to the Discord log webhook. Non-blocking, best-effort."""
    if not _LOG_URL:
        return
    # Keep secrets out of logs
    if any(s in message for s in ("api_key", "token", "password", "secret")):
        message = "[redacted] " + message[:120]
    embed = {
        "title": title,
        "description": message[:1900],
        "color": _level_color(level),
    }
    if fields:
        embed["fields"] = [
            {"name": k[:256], "value": str(v)[:1024], "inline": True}
            for k, v in list(fields.items())[:10]
        ]
    try:
        httpx.post(_LOG_URL, json={"embeds": [embed]}, timeout=8)
    except Exception:
        pass


def log_error(exc: Exception, *, path: str = "", level: str = "error"):
    """Log an unhandled exception to Discord."""
    name = type(exc).__name__
    detail = str(exc)[:800]
    log_event(
        f"**{name}** on `{path}`\n```\n{detail}\n```",
        level=level,
        title="⚠️ Unhandled Error",
    )
