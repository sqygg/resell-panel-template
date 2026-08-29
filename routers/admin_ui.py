"""Admin UI — web dashboard with brute-force protection and secure cookies."""
import os
import re
import time
import logging
import uuid
from fastapi import APIRouter, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
import database as db
from security import get_client_ip
from services.sellauth import client as sellauth

router = APIRouter(prefix="", tags=["ui"])
templates = Jinja2Templates(directory="templates")
templates.context_processors.append(lambda request: {"deploy_sha": os.getenv("RAILWAY_GIT_COMMIT_SHA", "")})

# In-memory session store (valid sessions)
_active_sessions: dict[str, str] = {}  # session_id -> admin_token
_session_expiry: dict[str, float] = {}  # session_id -> expiry epoch
SESSION_COOKIE = "session_id"
SESSION_MAX_AGE = 86400  # 24 hours


def _sweep_admin_sessions():
    now = time.time()
    expired = [sid for sid, exp in _session_expiry.items() if not exp or now > exp]
    for sid in expired:
        _active_sessions.pop(sid, None)
        _session_expiry.pop(sid, None)


def get_admin_token(request: Request) -> str:
    """Extract session token from cookie."""
    from config import settings
    _sweep_admin_sessions()
    sid = request.cookies.get(SESSION_COOKIE, "")
    return _active_sessions.get(sid, "")


def check_ui_auth(request: Request) -> bool:
    """Validate session cookie."""
    token = get_admin_token(request)
    from config import settings
    return hmac_compare(token, settings.ADMIN_PASSWORD)


def hmac_compare(a: str, b: str) -> bool:
    """Constant-time string comparison."""
    import hmac
    return hmac.compare_digest(a.encode() if isinstance(a, str) else a,
                                b.encode() if isinstance(b, str) else b)


def set_session_cookie(response, admin_token: str):
    """Set a secure session cookie."""
    sid = uuid.uuid4().hex
    _active_sessions[sid] = admin_token
    _session_expiry[sid] = time.time() + SESSION_MAX_AGE
    response.set_cookie(
        key=SESSION_COOKIE,
        value=sid,
        httponly=True,
        samesite="strict",
        secure=True,  # HTTPS only (Railway terminates TLS)
        max_age=SESSION_MAX_AGE,
    )


def clear_session(request: Request):
    """Remove session from store."""
    sid = request.cookies.get(SESSION_COOKIE, "")
    _active_sessions.pop(sid, None)


# ---------- Auth pages ----------

@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@router.post("/login")
def login_action(request: Request, password: str = Form(...)):
    from config import settings
    ip = get_client_ip(request)

    # Brute force check — 5 failed attempts per hour per IP (strict on admin password)
    if db.check_brute_force(ip, max_attempts=5, window_minutes=60):
        resp = RedirectResponse(url="/login?error=rate_limited", status_code=303)
        return resp

    if hmac_compare(password, settings.ADMIN_PASSWORD):
        db.log_login_attempt(ip, True)
        resp = RedirectResponse(url="/admin", status_code=303)
        set_session_cookie(resp, settings.ADMIN_PASSWORD)
        return resp

    db.log_login_attempt(ip, False)
    try:
        from services.discord_log import log_event
        log_event(f"**Failed admin login** from `{ip}`", level="warn", title="🔐 Admin Auth")
    except Exception:
        pass
    return RedirectResponse(url="/login?error=1", status_code=303)


@router.get("/logout")
def logout(request: Request):
    clear_session(request)
    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE)
    return resp


# ---------- Dashboard ----------

@router.get("/admin", response_class=HTMLResponse)
def dashboard(request: Request):
    if not check_ui_auth(request):
        return RedirectResponse(url="/login")
    products = sellauth.get_products_for_webhook()
    resellers = db.list_resellers()
    # Top products by stock for the chart
    stock_series = sorted(
        [{"name": p["name"], "stock": p.get("stock", 0)} for p in products],
        key=lambda x: x["stock"], reverse=True,
    )[:6]
    reseller_split = {
        "active": sum(1 for r in resellers if r["active"]),
        "inactive": sum(1 for r in resellers if not r["active"]),
    }
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "products": products,
        "resellers": resellers,
        "active_resellers": reseller_split["active"],
        "total_products": len(products),
        "total_stock": sum(p.get("stock", 0) for p in products),
        "stock_series": stock_series,
        "reseller_split": reseller_split,
    })


# ---------- Resellers ----------

@router.get("/resellers", response_class=HTMLResponse)
def resellers_page(request: Request):
    if not check_ui_auth(request):
        return RedirectResponse(url="/login")
    resellers = db.list_resellers()
    # Attach balances
    for r in resellers:
        r["balance"] = db.get_balance(r["id"])
    return templates.TemplateResponse("resellers.html", {
        "request": request,
        "resellers": resellers,
    })


@router.post("/resellers/create")
def reseller_create(
    request: Request,
    name: str = Form(..., max_length=100),
    discount_percent: float = Form(0),
    webhook_url: str = Form("", max_length=500),
    referred_by_code: str = Form("", max_length=50),
):
    if not check_ui_auth(request):
        return RedirectResponse(url="/login")
    ip = get_client_ip(request)
    try:
        result = db.create_reseller(
            name=name.strip(),
            discount_percent=discount_percent,
            webhook_url=webhook_url.strip(),
            ip=ip,
            referred_by_code=referred_by_code.strip(),
        )
    except ValueError as e:
        return HTMLResponse(f"<script>alert('{str(e)}');window.location='/resellers';</script>", status_code=400)

    # Show the API key once via flash in the redirect
    key_html = f"<script>alert('Reseller created!\\n\\nAPI Key (copy now — never shown again):\\n{result['api_key']}');window.location='/resellers';</script>"
    return HTMLResponse(key_html)


@router.post("/resellers/create-test")
def reseller_create_test(request: Request):
    """Create a fixed test reseller (email=Test, password=Test). No caller IP logged."""
    if not check_ui_auth(request):
        return RedirectResponse(url="/login")
    try:
        db.create_reseller(
            name="Test",
            discount_percent=0,
            ip="",  # do NOT log the admin's IP for test accounts
            username="test",
            email="test@email.com",
            raw_key="Test",
        )
    except ValueError as e:
        return HTMLResponse(f"<script>alert('{str(e)}');window.location='/resellers';</script>", status_code=400)
    return RedirectResponse(url="/resellers", status_code=303)


@router.post("/resellers/{reseller_id}/update")
def reseller_update(
    request: Request,
    reseller_id: int,
    name: str = Form(..., max_length=100),
    discount_percent: float = Form(0),
    webhook_url: str = Form("", max_length=500),
    active: str = Form("1"),
    sellauth_email: str = Form("", max_length=200),
):
    if not check_ui_auth(request):
        return RedirectResponse(url="/login")
    ip = get_client_ip(request)
    try:
        db.update_reseller(
            reseller_id,
            ip=ip,
            name=name.strip(),
            discount_percent=discount_percent,
            webhook_url=webhook_url.strip(),
            active=active == "1",
        )
    except ValueError:
        pass  # Silently ignore — don't expose validation errors to UI
    db.set_sellauth_email(reseller_id, sellauth_email, ip=ip)
    return RedirectResponse(url="/resellers", status_code=303)


@router.post("/resellers/{reseller_id}/sync")
def reseller_sync(request: Request, reseller_id: int):
    if not check_ui_auth(request):
        return RedirectResponse(url="/login")
    ip = get_client_ip(request)
    try:
        db.sync_balance_from_sellauth(reseller_id, ip=ip)
    except ValueError as e:
        return HTMLResponse(f"<script>alert('{str(e)}');window.location='/resellers';</script>")
    return RedirectResponse(url="/resellers?synced=1", status_code=303)


@router.get("/resellers/{reseller_id}/delete")
def reseller_delete(request: Request, reseller_id: int):
    if not check_ui_auth(request):
        return RedirectResponse(url="/login")
    ip = get_client_ip(request)
    db.delete_reseller(reseller_id, ip=ip)
    return RedirectResponse(url="/resellers", status_code=303)


@router.post("/resellers/{reseller_id}/regenerate")
def reseller_regenerate(request: Request, reseller_id: int):
    if not check_ui_auth(request):
        return RedirectResponse(url="/login")
    ip = get_client_ip(request)
    result = db.regenerate_api_key(reseller_id, ip=ip)
    if not result:
        return RedirectResponse(url="/resellers", status_code=303)
    key_html = f"<script>alert('New API Key (copy now — never shown again):\\n{result['api_key']}');window.location='/resellers';</script>"
    return HTMLResponse(key_html)


# ---------- Stock ----------

@router.get("/stock", response_class=HTMLResponse)
def stock_page(request: Request):
    if not check_ui_auth(request):
        return RedirectResponse(url="/login")
    products = sellauth.get_products_for_webhook()
    return templates.TemplateResponse("stock.html", {
        "request": request,
        "products": products,
    })


# ---------- Admin: Balance & Orders ----------

@router.get("/admin/orders", response_class=HTMLResponse)
def admin_orders(request: Request):
    if not check_ui_auth(request):
        return RedirectResponse(url="/login")
    orders = db.get_all_orders(100)
    return templates.TemplateResponse("admin_orders.html", {
        "request": request,
        "orders": orders,
    })


@router.post("/admin/resellers/{reseller_id}/add-balance")
def admin_add_balance(
    request: Request,
    reseller_id: int,
    amount: float = Form(...),
    description: str = Form("Manual deposit"),
):
    if not check_ui_auth(request):
        return RedirectResponse(url="/login")
    ip = get_client_ip(request)
    try:
        db.add_balance(reseller_id, amount, description, ip)
    except ValueError:
        pass
    return RedirectResponse(url="/resellers", status_code=303)


# ---------- Admin: Applications ----------

@router.get("/admin/applications", response_class=HTMLResponse)
def admin_applications(request: Request):
    if not check_ui_auth(request):
        return RedirectResponse(url="/login")
    apps = db.list_applications()
    return templates.TemplateResponse("applications.html", {
        "request": request,
        "applications": apps,
    })


@router.post("/admin/applications/{app_id}/approve")
def admin_approve_application(
    request: Request,
    app_id: int,
    name: str = Form(...),
    discount_percent: float = Form(30),
):
    if not check_ui_auth(request):
        return RedirectResponse(url="/login")
    ip = get_client_ip(request)
    app = db.update_application_status(app_id, "approved")
    if not app:
        return RedirectResponse(url="/admin/applications", status_code=303)
    try:
        uname = re.sub(r"[^a-zA-Z0-9_]", "", (app.get("email") or app.get("discord") or f"reseller{app_id}").lower().replace(" ", "_"))[:40]
        if not uname:
            uname = f"reseller{app_id}"
        db.create_reseller(
            name=name.strip(),
            username=uname,
            email=app.get("email", ""),
            discount_percent=discount_percent,
            ip=ip,
            referred_by_code=app.get("referral_code", ""),
        )
    except Exception as e:  # noqa: BLE001 - surface a safe message to admin
        logger = logging.getLogger("reseller-panel")
        logger.error(f"Approval failed for app {app_id}: {e}")
        return HTMLResponse(
            "<h2>Approval failed</h2><p>The application was approved but reseller creation errored. "
            "Check the logs or retry. <a href='/admin/applications'>Back</a></p>",
            status_code=200,
        )
    return RedirectResponse(url="/admin/applications", status_code=303)


@router.post("/admin/applications/{app_id}/reject")
def admin_reject_application(request: Request, app_id: int):
    if not check_ui_auth(request):
        return RedirectResponse(url="/login")
    db.update_application_status(app_id, "rejected")
    return RedirectResponse(url="/admin/applications", status_code=303)


# ---------- Manual Pricing ----------
# Owner can hand-set a fixed price for any product/variant at any discount level.
# Override key: (product_id, variant_id, discount_percent). Applied in api_delivery,
# catalog and buy pricing via db.effective_price().

@router.get("/admin/pricing", response_class=HTMLResponse)
def admin_pricing(request: Request):
    if not check_ui_auth(request):
        return RedirectResponse(url="/login")
    products = sellauth.get_products_for_webhook()
    overrides = db.list_manual_prices()
    # Build a lookup keyed by (product_id, variant_id, discount) for the table display
    ov_map = {(o["product_id"], o["variant_id"], o["discount_percent"]): o for o in overrides}
    return templates.TemplateResponse("manual_pricing.html", {
        "request": request,
        "products": products,
        "overrides": overrides,
        "ov_map": ov_map,
    })


@router.post("/admin/pricing/save")
def admin_pricing_save(request: Request,
                        product_id: str = Form(...),
                        variant_id: str = Form(""),
                        discount_percent: float = Form(...),
                        price: float = Form(...)):
    if not check_ui_auth(request):
        return JSONResponse({"ok": False, "error": "Unauthorized"}, status_code=401)
    if not product_id:
        return JSONResponse({"ok": False, "error": "Product required"}, status_code=400)
    if price < 0:
        return JSONResponse({"ok": False, "error": "Price must be >= 0"}, status_code=400)
    db.set_manual_price(product_id, variant_id or "", discount_percent, price)
    return JSONResponse({"ok": True, "price": round(price, 2)})


@router.post("/admin/pricing/delete")
def admin_pricing_delete(request: Request,
                          product_id: str = Form(...),
                          variant_id: str = Form(""),
                          discount_percent: float = Form(...)):
    if not check_ui_auth(request):
        return JSONResponse({"ok": False, "error": "Unauthorized"}, status_code=401)
    db.delete_manual_price(product_id, variant_id or "", discount_percent)
    return JSONResponse({"ok": True})


# ---------- API key retrieval (post-creation) ----------
# NOTE: removed GET /api/admin/key/{reseller_id} — it returned a reseller's raw
# decrypted API key on a Bearer password, an unnecessary key-exposure surface.
# The UI reveal (resellers.html) is sufficient and gated by admin session cookie.
