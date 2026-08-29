"""SMTP transactional email (2FA codes, alerts).

Credentials come from config (SMTP_HOST/PORT/USER/PASS/FROM).
If SMTP is not configured, send() returns False and callers should
degrade gracefully (e.g. log) rather than crash the request.
"""
import logging
import smtplib
import ssl
from email.message import EmailMessage

from config import settings

logger = logging.getLogger("reseller-panel")


def smtp_configured() -> bool:
    return bool(settings.SMTP_HOST and settings.SMTP_USER and settings.SMTP_FROM)


def send_email(to: str, subject: str, body: str) -> bool:
    """Send a plaintext email. Returns True on success, False if misconfigured/unreachable."""
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
