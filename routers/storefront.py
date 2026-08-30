"""Astro Reseller Panel — storefront: /auth, /apply, /reseller (dashboard + catalog + orders + balance + referrals)."""
import os
import uuid
import time
import httpx
from fastapi import APIRouter, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
import database as db
from security import get_client_ip
from services.sellauth import client as sellauth
from config import settings
import services.mailer as mailer
from services.crypto_notify import notify_new_application

router = APIRouter(tags=["store"])
templates = Jinja2Templates(directory="templates")

_store_sessions: dict[str, dict] = {}
_STORE_SESSION_TTL = 86400


def _sweep_store_sessions():
    """Drop expired reseller sessions (in-memory store). Called on each lookup."""
    now = time.time()
    expired = [sid for sid, s in _store_sessions.items() if not s.get("exp") or now > s["exp"]]
    for sid in expired:
        _store_sessions.pop(sid, None)


def _brand_ctx(**extra) -> dict:
    ctx = {
        "brand_name": "ASTRO",
        "brand_tagline": "Your reliable partner in gaming solutions.",
        "public_url": settings.PUBLIC_URL,
        "deploy_sha": os.getenv("RAILWAY_GIT_COMMIT_SHA", ""),
    }
    ctx.update(extra)
    return ctx


def get_store_reseller(request: Request) -> dict | None:
    _sweep_store_sessions()
    sid = request.cookies.get("store_session", "")
    return _store_sessions.get(sid)


def require_reseller(request: Request):
    r = get_store_reseller(request)
    if not r:
        raise HTTPException(status_code=401, detail="Please login at /auth")
    return r


# ---------- Auth ----------

@router.get("/auth", response_class=HTMLResponse)
def auth_page(request: Request, error: str = "", email: str = ""):
    r = get_store_reseller(request)
    if r:
        return RedirectResponse(url="/reseller", status_code=303)
    return templates.TemplateResponse("auth.html", _brand_ctx(request=request, error=error, email=email))


@router.post("/auth")
def auth_action(request: Request, email: str = Form(...)):
    """Email-OTP step 1: look up the reseller by email, mint a 6-digit code,
    store it hashed with a 10-min TTL, and email it. Existence is not revealed:
    an unknown email gets the same generic 'check your inbox' response."""
    email = (email or "").strip().lower()
    import re
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return templates.TemplateResponse("auth.html", _brand_ctx(
            request=request, error="Enter a valid email address.", email=email))
    r = db.get_reseller_by_email(email)
    ip = get_client_ip(request)
    if r:
        rid = r["id"]
        # Rate-limit: one code per 60s per reseller.
        if not db.can_request_email_2fa(rid, cooldown_seconds=60):
            return templates.TemplateResponse("auth.html", _brand_ctx(
                request=request, error="A code was just sent. Wait 60s before requesting another.",
                email=email, stage="verify"))
        code = f"{_secrets.randbelow(1000000):06d}"
        db.set_email_2fa(rid, code, ttl_seconds=600)
        sent = mailer.send_2fa_code(email, code)
        db._audit("reseller_login_code_sent", rid, f"sent={sent}", ip)
        if not sent:
            return templates.TemplateResponse("auth.html", _brand_ctx(
                request=request,
                error="Could not send the verification code (SMTP not configured). Contact the store owner.",
                email=email))
    # Always show the verify stage; never disclose whether the email exists.
    return templates.TemplateResponse("auth.html", _brand_ctx(
        request=request, stage="verify", email=email))


@router.post("/auth/verify")
def auth_verify(request: Request, email: str = Form(...), code: str = Form(...)):
    """Email-OTP step 2: verify the code, then issue the session cookie."""
    email = (email or "").strip().lower()
    code = (code or "").strip()
    r = db.get_reseller_by_email(email)
    ip = get_client_ip(request)
    if not r or not db.verify_email_2fa(r["id"], code):
        db._audit("reseller_login_failed", r["id"] if r else None, "bad_code", ip)
        return templates.TemplateResponse("auth.html", _brand_ctx(
            request=request, stage="verify", email=email,
            error="Invalid or expired code. Request a new one."))
    db.clear_email_2fa(r["id"])
    db._audit("reseller_login_ok", r["id"], "", ip)
    sid = uuid.uuid4().hex
    _store_sessions[sid] = {
        "id": r["id"],
        "name": r["name"],
        "email": r.get("email", ""),
        "discount": r["discount_percent"],
        "referral_code": r.get("referral_code", ""),
        "exp": time.time() + _STORE_SESSION_TTL,
    }
    resp = RedirectResponse(url="/reseller", status_code=303)
    resp.set_cookie("store_session", sid, httponly=True, samesite="strict", max_age=86400)
    return resp


@router.post("/auth/resend")
def auth_resend(request: Request, email: str = Form(...)):
    """Re-issue a code for the verify stage (respects the 60s cooldown)."""
    email = (email or "").strip().lower()
    r = db.get_reseller_by_email(email)
    ip = get_client_ip(request)
    if r and db.can_request_email_2fa(r["id"], cooldown_seconds=60):
        code = f"{_secrets.randbelow(1000000):06d}"
        db.set_email_2fa(r["id"], code, ttl_seconds=600)
        mailer.send_2fa_code(email, code)
        db._audit("reseller_login_code_sent", r["id"], "resent", ip)
    return templates.TemplateResponse("auth.html", _brand_ctx(
        request=request, stage="verify", email=email, resent="1"))


@router.get("/logout")
def auth_logout():
    resp = RedirectResponse(url="/auth", status_code=303)
    resp.delete_cookie("store_session")
    return resp


# ---------- Apply ----------

@router.get("/apply", response_class=HTMLResponse)
def apply_page(request: Request, done: str = ""):
    ref = request.query_params.get("ref", "")
    return templates.TemplateResponse("apply.html", _brand_ctx(request=request, ref=ref, done=done == "1"))


@router.post("/apply")
def apply_submit(
    request: Request,
    email: str = Form(...),
    discord: str = Form(...),
    website: str = Form(""),
    discord_server: str = Form(""),
    products: str = Form(""),
    referral_code: str = Form(""),
):
    email = email.strip()
    discord = discord.strip()
    website = website.strip()
    if not discord:
        return templates.TemplateResponse("apply.html", _brand_ctx(request=request, error="Discord is required.", ref=referral_code))
    if not website:
        return templates.TemplateResponse("apply.html", _brand_ctx(request=request, error="Website is required.", ref=referral_code))
    try:
        app = db.create_application(
            email=email, discord=discord, website=website,
            discord_server=discord_server, products=products, referral_code=referral_code,
        )
        notify_new_application(dict(app))
    except ValueError as e:
        return templates.TemplateResponse("apply.html", _brand_ctx(request=request, error=str(e), ref=referral_code))
    return RedirectResponse(url="/apply?done=1", status_code=303)


# ---------- Reseller dashboard ----------

@router.get("/reseller", response_class=HTMLResponse)
def reseller_dashboard(request: Request):
    r = require_reseller(request)
    balance_info = db.get_sellauth_balance(r["id"])
    all_orders = db.get_orders(r["id"], limit=1000)
    orders = all_orders[:10]
    referrals = db.get_referrals(r["id"])
    total_spent = sum(o["total_price"] for o in all_orders)
    total_orders = len(all_orders)
    referral_earned = sum(x["total_earned"] for x in referrals)

    # --- Chart data: 7-day spend series + order status breakdown ---
    from collections import defaultdict
    import datetime as _dt
    today = _dt.date.today()
    spend_by_day = defaultdict(float)
    status_counts = defaultdict(int)
    for o in all_orders:
        status_counts[o.get("status", "pending")] += 1
        try:
            d = _dt.datetime.strptime(o["created_at"][:10], "%Y-%m-%d").date()
        except (ValueError, KeyError, TypeError):
            continue
        spend_by_day[d.isoformat()] += float(o.get("total_price", 0) or 0)
    spend_series = []
    for i in range(6, -1, -1):
        day = (today - _dt.timedelta(days=i)).isoformat()
        spend_series.append({"day": day[5:], "total": round(spend_by_day.get(day, 0.0), 2)})

    return templates.TemplateResponse("reseller_dashboard.html", _brand_ctx(
        request=request, reseller=r, balance=balance_info["balance"], balance_source=balance_info["source"],
        sellauth_email=balance_info["email"], orders=orders,
        referrals=referrals, total_spent=total_spent, total_orders=total_orders,
        referral_earned=referral_earned, referral_count=len(referrals),
        spend_series=spend_series,
        status_counts={"pending": status_counts.get("pending", 0), "completed": status_counts.get("completed", 0),
                       "failed": status_counts.get("failed", 0)},
    ))


@router.get("/reseller/catalog", response_class=HTMLResponse)
def reseller_catalog(request: Request):
    r = require_reseller(request)
    products = sellauth.get_products_for_webhook()
    balance_info = db.get_sellauth_balance(r["id"])
    aliases = db.list_product_aliases(r["id"])
    alias_map = {(a["product_id"], a["variant_id"]): a["alias"] for a in aliases}
    df = 1 - (r["discount"] / 100)
    api_key = db.reveal_api_key(r["id"]) or ""
    base = settings.PUBLIC_URL.rstrip("/") if settings.PUBLIC_URL else str(request.base_url).rstrip("/")
    for p in products:
        p["reseller_price"] = db.effective_price(str(p["id"]), "", r["discount"], p["price"])
        for v in p.get("variants", []):
            v["reseller_price"] = db.effective_price(str(p["id"]), str(v.get("variant_id", "")), r["discount"], v["price"])
            # Always build the per-product delivery URL from the API key — no prefix
            # required, no legacy alias. This is the format resellers paste into their
            # own store (one Dynamic Delivery URL per product/variant).
            v["delivery_url"] = (
                f"{base}/api/deliver/{api_key}/product/{p['id']}?variant_id={v['variant_id']}"
                if api_key else ""
            )
    return templates.TemplateResponse("reseller_catalog.html", _brand_ctx(
        request=request, reseller=r, products=products, balance=balance_info["balance"],
        balance_source=balance_info["source"], sellauth_email=balance_info["email"]))


@router.get("/reseller/catalog.json")
def reseller_catalog_json(request: Request):
    """Machine-readable catalog for resellers: every product + variant with its
    ready-to-paste SellAuth Dynamic Delivery URL. Powers 'Connect your store'-style
    bulk import and one-click copy."""
    r = require_reseller(request)
    products = sellauth.get_products_for_webhook()
    base = settings.PUBLIC_URL.rstrip("/") if settings.PUBLIC_URL else str(request.base_url).rstrip("/")
    api_key = db.reveal_api_key(r["id"])
    out = []
    for p in products:
        variants = []
        for v in p.get("variants", []) or []:
            vid = v.get("variant_id") or v.get("id")
            variants.append({
                "variant_id": vid,
                "name": v.get("name", "Default"),
                "price": v.get("price"),
                "stock": v.get("stock"),
                "delivery_url": f"{base}/api/deliver/{api_key}/product/{p['id']}?variant_id={vid}",
            })
        if not variants:
            variants.append({
                "variant_id": None,
                "name": "Default",
                "price": p.get("price"),
                "stock": p.get("stock"),
                "delivery_url": f"{base}/api/deliver/{api_key}/product/{p['id']}",
            })
        out.append({
            "product_id": p["id"],
            "name": p.get("name", "Unknown"),
            "price": p.get("price"),
            "currency": p.get("currency", "USD"),
            "variants": variants,
        })
    return JSONResponse(content={
        "shop": base,
        "reseller": r.get("email"),
        "products": out,
    })


@router.get("/reseller/catalog/export")
def reseller_catalog_export(request: Request):
    """One-click bulk export: plain-text list of product/variant -> delivery URL,
    ready to paste into SellAuth (one Dynamic URL per line)."""
    r = require_reseller(request)
    products = sellauth.get_products_for_webhook()
    base = settings.PUBLIC_URL.rstrip("/") if settings.PUBLIC_URL else str(request.base_url).rstrip("/")
    api_key = db.reveal_api_key(r["id"])
    lines = []
    for p in products:
        for v in (p.get("variants", []) or []):
            vid = v.get("variant_id") or v.get("id")
            url = f"{base}/api/deliver/{api_key}/product/{p['id']}?variant_id={vid}"
            lines.append(f"{p.get('name','?')} | {v.get('name','Default')} | {url}")
        if not p.get("variants"):
            url = f"{base}/api/deliver/{api_key}/product/{p['id']}"
            lines.append(f"{p.get('name','?')} | Default | {url}")
    return PlainTextResponse("\n".join(lines), media_type="text/plain")


@router.post("/reseller/alias/{product_id}")
def reseller_alias_create(request: Request, product_id: str, variant_id: str = Form("")):
    r = require_reseller(request)
    try:
        db.create_product_alias(r["id"], product_id, variant_id, ip=get_client_ip(request))
    except ValueError as e:
        return HTMLResponse(f"<script>alert('{e}');window.location='/reseller/catalog';</script>")
    return RedirectResponse(url="/reseller/catalog", status_code=303)


@router.post("/reseller/alias/{product_id}/revoke")
def reseller_alias_revoke(request: Request, product_id: str, variant_id: str = Form("")):
    r = require_reseller(request)
    aliases = db.list_product_aliases(r["id"])
    for a in aliases:
        if a["product_id"] == product_id and a["variant_id"] == variant_id:
            db.revoke_product_alias(r["id"], a["alias"], ip=get_client_ip(request))
    return RedirectResponse(url="/reseller/catalog", status_code=303)


@router.get("/reseller/api", response_class=HTMLResponse)
def reseller_api_page(request: Request):
    r = require_reseller(request)
    balance_info = db.get_sellauth_balance(r["id"])
    # Never send the raw key to the frontend — only a masked prefix for display.
    masked = (r.get("api_key_prefix") or "") + "…"
    return templates.TemplateResponse("reseller_api.html", _brand_ctx(
        request=request, reseller=r, api_key_mask=masked,
        balance=balance_info["balance"], balance_source=balance_info["source"],
        sellauth_email=balance_info["email"],
        has_sellauth_secret=bool(db.get_sellauth_webhook_secret(r["id"])),
        code=request.query_params.get("code", ""),
        resent=request.query_params.get("resent", ""),
        secret_set=request.query_params.get("secret_set", "")))


@router.get("/reseller/api/key", response_class=JSONResponse)
def reseller_api_key(request: Request):
    """Return the reseller's API key. Only when authenticated — keeps the key
    out of the initial page HTML (no key in DOM until explicitly revealed)."""
    r = require_reseller(request)
    key = db.reveal_api_key(r["id"]) or ""
    return JSONResponse({"api_key": key})


@router.post("/reseller/api/sellauth-secret")
def reseller_set_sellauth_secret(request: Request, secret: str = Form("")):
    """Save or clear the reseller's own SellAuth dynamic-delivery webhook secret.
    Stored encrypted at rest; used to verify inbound webhook HMAC signatures."""
    r = require_reseller(request)
    secret = (secret or "").strip()
    if secret and len(secret) > 200:
        return HTMLResponse("<script>alert('Secret too long (max 200 chars).');window.location='/reseller/api';</script>")
    db.set_sellauth_webhook_secret(r["id"], secret, ip=get_client_ip(request))
    return RedirectResponse(url="/reseller/api?secret_set=1", status_code=303)


@router.post("/reseller/api/sync")
def reseller_sync_balance(request: Request):
    r = require_reseller(request)
    try:
        info = db.sync_balance_from_sellauth(r["id"], ip=get_client_ip(request))
    except ValueError as e:
        return HTMLResponse(f"<script>alert('{e}');window.location='/reseller/api';</script>")
    return RedirectResponse(url="/reseller/api?synced=1", status_code=303)


@router.get("/reseller/api/regen", response_class=HTMLResponse)
def reseller_api_regen(request: Request):
    r = require_reseller(request)
    result = db.regenerate_api_key(r["id"])
    new_key = result.get("api_key", "") if result else ""
    # Key is shown once on the regen page only; never stored in the session.
    return templates.TemplateResponse("reseller_api_regen.html", _brand_ctx(
        request=request, reseller=r, new_key=new_key))


@router.post("/reseller/api/link-sellauth")
def reseller_link_sellauth(request: Request, email: str = Form("")):
    r = require_reseller(request)
    email = (email or "").strip().lower()
    import re
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return HTMLResponse("<script>alert('Enter a valid email address.');window.location='/reseller/api';</script>")
    # Generate a SellAuth-style 6-digit 2FA code, store hashed, email it.
    code = f"{_secrets.randbelow(1000000):06d}"  # 000000-999999
    db.set_email_2fa(r["id"], code, ttl_seconds=600)
    from services.mailer import send_2fa_code
    sent = send_2fa_code(email, code)
    ip = get_client_ip(request)
    db._audit("reseller_email_2fa_sent", r["id"], f"email={email} sent={sent}", ip)
    if not sent:
        return HTMLResponse("<script>alert('Could not send the verification code (SMTP not configured). Contact the store owner.');window.location='/reseller/api';</script>")
    # Stash the pending email in session so step 2 knows the target.
    sid = request.cookies.get("store_session", "")
    if sid in _store_sessions:
        _store_sessions[sid]["pending_email"] = email
    return RedirectResponse(url="/reseller/api?code=1", status_code=303)


@router.post("/reseller/api/link-sellauth/verify")
def reseller_link_sellauth_verify(request: Request, code: str = Form("")):
    r = require_reseller(request)
    code = (code or "").strip()
    if not db.verify_email_2fa(r["id"], code):
        return HTMLResponse("<script>alert('Invalid or expired code. Request a new one.');window.location='/reseller/api?code=1';</script>")
    sid = request.cookies.get("store_session", "")
    pending = _store_sessions.get(sid, {}).get("pending_email", "")
    if not pending:
        return HTMLResponse("<script>alert('Session expired. Start over.');window.location='/reseller/api';</script>")
    db.set_sellauth_email(r["id"], pending, ip=get_client_ip(request))
    db.clear_email_2fa(r["id"])
    if sid in _store_sessions:
        _store_sessions[sid].pop("pending_email", None)
    return RedirectResponse(url="/reseller/api?linked=1", status_code=303)


@router.post("/reseller/api/link-sellauth/resend")
def reseller_link_sellauth_resend(request: Request):
    r = require_reseller(request)
    sid = request.cookies.get("store_session", "")
    pending = _store_sessions.get(sid, {}).get("pending_email", "")
    if not pending:
        return HTMLResponse("<script>alert('No pending link. Enter your email again.');window.location='/reseller/api';</script>")
    code = f"{_secrets.randbelow(1000000):06d}"
    db.set_email_2fa(r["id"], code, ttl_seconds=600)
    from services.mailer import send_2fa_code
    sent = send_2fa_code(pending, code)
    if not sent:
        return HTMLResponse("<script>alert('Could not resend (SMTP not configured).');window.location='/reseller/api?code=1';</script>")
    return RedirectResponse(url="/reseller/api?code=1&resent=1", status_code=303)


# ---------- Reseller Discord account linking (OAuth) ----------
import secrets as _secrets
import urllib.parse as _urlparse
_DISCORD_OAUTH_SCOPE = "identify"


@router.get("/reseller/discord")
def reseller_discord_page(request: Request):
    """Settings widget showing Discord link status + link button."""
    r = require_reseller(request)
    linked = bool(r.get("discord_id"))
    discord_cfg_ok = bool(settings.DISCORD_CLIENT_ID and settings.DISCORD_OAUTH_REDIRECT_URI)
    return templates.TemplateResponse("reseller_discord.html", _brand_ctx(
        request=request, reseller=r, linked=linked,
        discord_username=r.get("discord_username", ""),
        discord_cfg_ok=discord_cfg_ok,
    ))


@router.get("/reseller/discord/start")
def reseller_discord_start(request: Request):
    """Begin OAuth: issue state cookie, redirect to Discord authorize URL."""
    r = require_reseller(request)
    if not (settings.DISCORD_CLIENT_ID and settings.DISCORD_OAUTH_REDIRECT_URI):
        return HTMLResponse("<script>alert('Discord linking is not configured.');window.location='/reseller/discord';</script>")
    state = _secrets.token_urlsafe(24)
    # stash reseller id bound to state to prevent CSRF / link hijack
    resp = RedirectResponse(
        "https://discord.com/api/oauth2/authorize?" + _urlparse.urlencode({
            "client_id": settings.DISCORD_CLIENT_ID,
            "redirect_uri": settings.DISCORD_OAUTH_REDIRECT_URI,
            "response_type": "code",
            "scope": _DISCORD_OAUTH_SCOPE,
            "state": state,
            "prompt": "consent",
        }),
        status_code=303,
    )
    resp.set_cookie("discord_oauth_state", state, httponly=True, samesite="strict", max_age=600)
    return resp


@router.get("/reseller/discord/callback")
def reseller_discord_callback(request: Request, code: str = "", state: str = ""):
    """Exchange code for a user token, read identity, store the link."""
    r = require_reseller(request)
    # verify state
    expected = request.cookies.get("discord_oauth_state", "")
    if not code or not state or not expected or not _compare_state(state, expected):
        resp = HTMLResponse("<script>alert('Link failed: invalid state.');window.location='/reseller/discord';</script>")
        resp.delete_cookie("discord_oauth_state")
        return resp
    if not (settings.DISCORD_CLIENT_ID and settings.DISCORD_CLIENT_SECRET and settings.DISCORD_OAUTH_REDIRECT_URI):
        return HTMLResponse("<script>alert('Discord linking is not configured.');window.location='/reseller/discord';</script>")
    try:
        token = _exchange_discord_code(code)
        identity = _discord_identify(token)
    except Exception as e:
        safe = str(e).replace("\\", "").replace("'", "").replace('"', "")[:200]
        return HTMLResponse(f"<script>alert('Discord error: {safe}');window.location='/reseller/discord';</script>")
    db.link_reseller_discord(r["id"], str(identity["id"]), identity.get("username", ""), ip=get_client_ip(request))
    resp = RedirectResponse(url="/reseller/discord?linked=1", status_code=303)
    resp.delete_cookie("discord_oauth_state")
    return resp


@router.post("/reseller/discord/unlink")
def reseller_discord_unlink(request: Request):
    r = require_reseller(request)
    db.unlink_reseller_discord(r["id"], ip=get_client_ip(request))
    return RedirectResponse(url="/reseller/discord?unlinked=1", status_code=303)


def _compare_state(a: str, b: str) -> bool:
    import hmac
    return hmac.compare_digest(a, b)


def _exchange_discord_code(code: str) -> str:
    """Exchange authorization code for a user access token. Returns the token."""
    data = {
        "client_id": settings.DISCORD_CLIENT_ID,
        "client_secret": settings.DISCORD_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.DISCORD_OAUTH_REDIRECT_URI,
    }
    resp = httpx.post("https://discord.com/api/oauth2/token", data=data,
                      headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=15)
    resp.raise_for_status()
    return resp.json()["access_token"]


def _discord_identify(token: str) -> dict:
    """GET /users/@me using the user token. Returns id + username."""
    resp = httpx.get("https://discord.com/api/users/@me",
                     headers={"Authorization": f"Bearer {token}"}, timeout=15)
    resp.raise_for_status()
    u = resp.json()
    if not u.get("id"):
        raise ValueError("No Discord user id returned")
    return u


@router.get("/reseller/buy", response_class=HTMLResponse)
def reseller_buy_page(request: Request):
    r = require_reseller(request)
    products = sellauth.get_products_for_webhook()
    balance_info = db.get_sellauth_balance(r["id"])
    df = 1 - (r["discount"] / 100)
    base = settings.PUBLIC_URL.rstrip("/") if settings.PUBLIC_URL else str(request.base_url).rstrip("/")
    for p in products:
        p["reseller_price"] = db.effective_price(str(p["id"]), "", r["discount"], p["price"])
        for v in p.get("variants", []):
            v["reseller_price"] = db.effective_price(str(p["id"]), str(v.get("variant_id", "")), r["discount"], v["price"])
    return templates.TemplateResponse("reseller_buy.html", _brand_ctx(
        request=request, reseller=r, products=products, balance=balance_info["balance"],
        balance_source=balance_info["source"], sellauth_email=balance_info["email"],
        base=base))


@router.post("/reseller/buy/submit", response_class=HTMLResponse)
def reseller_buy_submit(request: Request, product_id: str = Form(...), variant_id: str = Form(""), quantity: int = Form(1)):
    r = require_reseller(request)
    api_key = db.reveal_api_key(r["id"]) or ""
    if not api_key:
        return HTMLResponse("<script>alert('No API key set — contact store owner');window.location='/reseller/buy';</script>")
    # Reuse the exact same delivery core as the API (balance gate, stock dispense, deduct)
    try:
        from routers.api_delivery import _do_deliver
        result = _do_deliver(api_key, product_id, variant_id or None, quantity, "", None, request)
    except HTTPException as e:
        msg = e.detail if isinstance(e.detail, str) else str(e.detail)
        return HTMLResponse(f"<script>alert('{msg}');window.location='/reseller/buy';</script>")
    # result is a dict on success
    keys = result.get("keys", [])
    new_bal = db.get_balance(r["id"])
    return templates.TemplateResponse("reseller_buy_done.html", _brand_ctx(
        request=request, reseller=r, product_id=product_id, variant_id=variant_id,
        quantity=quantity, total=result.get("total_charged", 0), keys=keys,
        new_balance=new_bal, order_id=result.get("order_id")))


@router.get("/reseller/balance", response_class=HTMLResponse)
def reseller_balance(request: Request):
    r = require_reseller(request)
    balance_info = db.get_sellauth_balance(r["id"], force=True)
    transactions = db.get_transactions(r["id"])
    return templates.TemplateResponse("reseller_balance.html", _brand_ctx(
        request=request, reseller=r, balance=balance_info["balance"],
        balance_source=balance_info["source"], sellauth_email=balance_info["email"],
        transactions=transactions))


@router.get("/reseller/referrals", response_class=HTMLResponse)
def reseller_referrals(request: Request):
    r = require_reseller(request)
    referrals = db.get_referrals(r["id"])
    referral_earned = sum(x["total_earned"] for x in referrals)
    code = r.get("referral_code", "")
    base = settings.PUBLIC_URL.rstrip("/") if settings.PUBLIC_URL else ""
    link = f"{base}/apply?ref={code}" if code else ""
    return templates.TemplateResponse("reseller_referrals.html", _brand_ctx(
        request=request, reseller=r, referrals=referrals, referral_earned=referral_earned,
        referral_code=code, referral_link=link, commission_percent=settings.REFERRAL_COMMISSION_PERCENT,
        balance=db.get_balance(r["id"])))


@router.get("/reseller/orders", response_class=HTMLResponse)
def reseller_orders_page(request: Request):
    r = require_reseller(request)
    sort = request.query_params.get("sort", "latest")
    orders = db.get_orders(r["id"], asc=(sort == "oldest"))
    return templates.TemplateResponse("reseller_orders.html", _brand_ctx(
        request=request, reseller=r, orders=orders, sort=sort))


# NOTE: legacy POST /reseller/order/{product_id} "Dispense" flow removed; buy via /reseller/buy.