"""Transactional email (2FA codes, alerts).

Primary transport is the Brevo HTTPS email API (api.brevo.com/v3/smtp/email)
on port 443 — Railway permits outbound 443, whereas it blocks mail ports
(587/465/2525), which made the old SMTP path time out.

If BREVO_API_KEY is set we use the API. Otherwise we fall back to the legacy
SMTP transport (only useful off-Railway). SMTP_* env vars remain supported
for that fallback.
"""
import logging
import smtplib
import ssl
from email.message import EmailMessage

import httpx
from config import settings

logger = logging.getLogger("reseller-panel")

_BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"


# ---------- Brevo API (preferred) ----------

def _brevo_configured() -> bool:
    return bool(settings.BREVO_API_KEY and settings.SMTP_FROM)


def send_email_brevo(to: str, subject: str, body: str) -> bool:
    """Send via Brevo HTTPS API (port 443). Returns True on success."""
    if not _brevo_configured():
        return False
    payload = {
        "sender": {"email": settings.SMTP_FROM},
        "to": [{"email": to}],
        "subject": subject,
        "textContent": body,
    }
    try:
        r = httpx.post(
            _BREVO_API_URL,
            headers={"api-key": settings.BREVO_API_KEY, "Content-Type": "application/json"},
            json=payload,
            timeout=15,
        )
        if r.status_code >= 400:
            logger.error(f"[mailer] Brevo API rejected send to {to}: {r.status_code} {r.text[:300]}")
            return False
        logger.info(f"[mailer] Brevo API sent '{subject}' to {to}")
        return True
    except Exception as e:
        logger.error(f"[mailer] Brevo API send failed to {to}: {type(e).__name__}: {e}")
        return False


# ---------- Legacy SMTP fallback (off-Railway only) ----------

def smtp_configured() -> bool:
    return bool(settings.SMTP_HOST and settings.SMTP_USER and settings.SMTP_FROM)


def send_email_smtp(to: str, subject: str, body: str) -> bool:
    """Send a plaintext email over SMTP. Returns True on success, False if
    misconfigured/unreachable. NOTE: Railway blocks mail ports, so this only
    works outside Railway."""
    if not smtp_configured():
        logger.warning(f"[mailer] SMTP not configured — cannot send to {to}: {subject}")
        return False
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.SMTP_FROM
    msg["To"] = to
    msg.set_content(body)

    try:
        port = settings.SMTP_PORT
        if port == 465:
            with smtplib.SMTP_SSL(settings.SMTP_HOST, port, timeout=15) as s:
                s.login(settings.SMTP_USER, settings.SMTP_PASS)
                s.send_message(msg)
        else:
            with smtplib.SMTP(settings.SMTP_HOST, port, timeout=15) as s:
                s.ehlo()
                if port != 25:
                    s.starttls(context=ssl.create_default_context())
                s.login(settings.SMTP_USER, settings.SMTP_PASS)
                s.send_message(msg)
        logger.info(f"[mailer] sent '{subject}' to {to}")
        return True
    except Exception as e:
        logger.error(f"[mailer] failed to send to {to}: {type(e).__name__}: {e}")
        return False


# ---------- Unified dispatch ----------

def send_email(to: str, subject: str, body: str) -> bool:
    """Send using Brevo API when configured, else SMTP fallback."""
    if _brevo_configured():
        return send_email_brevo(to, subject, body)
    return send_email_smtp(to, subject, body)


def send_2fa_code(to: str, code: str) -> bool:
    """Email a 2FA code for linking an email address."""
    subject = "Your Astro Panel email verification code"
    body = (
        "You requested to link this email address to your Astro Panel reseller account.\n\n"
        f"Your verification code is: {code}\n\n"
        "This code expires in 10 minutes. If you did not request this, you can ignore the email.\n\n"
        "— Astro Panel"
    )
    return send_email(to, subject, body)
