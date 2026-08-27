"""Astro Reseller Panel — storefront: /auth, /apply, /reseller (dashboard + catalog + orders + balance + referrals)."""
import os
import uuid
import httpx
from fastapi import APIRouter, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
import database as db
from security import get_client_ip
from services.sellauth import client as sellauth
from config import settings
from services.crypto_notify import notify_new_application

router = APIRouter(tags=["store"])
templates = Jinja2Templates(directory="templates")

_store_sessions: dict[str, dict] = {}


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
def auth_action(request: Request, email: str = Form(...), password: str = Form(...)):
    reseller = db.get_reseller_by_email_password(email.strip(), password) or \
        db.get_reseller_by_username_password(email.strip(), password)
    if not reseller:
        return templates.TemplateResponse("auth.html", _brand_ctx(
            request=request, error="Invalid email or password", email=email))
    sid = uuid.uuid4().hex
    _store_sessions[sid] = {
        "id": reseller["id"],
        "name": reseller["name"],
        "email": reseller.get("email", ""),
        "discount": reseller["discount_percent"],
        "api_key": db.reveal_api_key(reseller["id"]) or "",
        "referral_code": reseller.get("referral_code", ""),
    }
    resp = RedirectResponse(url="/reseller", status_code=303)
    resp.set_cookie("store_session", sid, httponly=True, samesite="strict", max_age=86400)
    return resp


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
    balance = db.get_balance(r["id"])
    orders = db.get_orders(r["id"], limit=10)
    referrals = db.get_referrals(r["id"])
    total_spent = sum(o["total_price"] for o in db.get_orders(r["id"], limit=1000))
    total_orders = len(db.get_orders(r["id"], limit=1000))
    referral_earned = sum(x["total_earned"] for x in referrals)
    return templates.TemplateResponse("reseller_dashboard.html", _brand_ctx(
        request=request, reseller=r, balance=balance, orders=orders,
        referrals=referrals, total_spent=total_spent, total_orders=total_orders,
        referral_earned=referral_earned, referral_count=len(referrals),
    ))


@router.get("/reseller/catalog", response_class=HTMLResponse)
def reseller_catalog(request: Request):
    r = require_reseller(request)
    products = sellauth.get_products_for_webhook()
    balance = db.get_balance(r["id"])
    df = 1 - (r["discount"] / 100)
    for p in products:
        p["reseller_price"] = round(p["price"] * df, 2)
        for v in p.get("variants", []):
            v["reseller_price"] = round(v["price"] * df, 2)
            v["delivery_url"] = f"{settings.PUBLIC_URL.rstrip('/') if settings.PUBLIC_URL else str(request.base_url).rstrip('/')}/api/deliver/{r['api_key']}?product_id={p['id']}&variant_id={v['id']}" if r.get("api_key") else ""
    return templates.TemplateResponse("reseller_catalog.html", _brand_ctx(
        request=request, reseller=r, products=products, balance=balance))


@router.get("/reseller/api", response_class=HTMLResponse)
def reseller_api_page(request: Request):
    r = require_reseller(request)
    return templates.TemplateResponse("reseller_api.html", _brand_ctx(
        request=request, reseller=r, api_key=r.get("api_key", "")))


@router.get("/reseller/api/regen", response_class=HTMLResponse)
def reseller_api_regen(request: Request):
    r = require_reseller(request)
    result = db.regenerate_api_key(r["id"])
    new_key = result.get("api_key", "") if result else ""
    # update session key
    sid = request.cookies.get("store_session", "")
    if sid in _store_sessions:
        _store_sessions[sid]["api_key"] = new_key
    return templates.TemplateResponse("reseller_api_regen.html", _brand_ctx(
        request=request, reseller=r, new_key=new_key))


@router.get("/reseller/orders", response_class=HTMLResponse)
def reseller_orders(request: Request):
    r = require_reseller(request)
    orders = db.get_orders(r["id"])
    return templates.TemplateResponse("reseller_orders.html", _brand_ctx(
        request=request, reseller=r, orders=orders, balance=db.get_balance(r["id"])))


@router.get("/reseller/balance", response_class=HTMLResponse)
def reseller_balance(request: Request):
    r = require_reseller(request)
    transactions = db.get_transactions(r["id"])
    return templates.TemplateResponse("reseller_balance.html", _brand_ctx(
        request=request, reseller=r, balance=db.get_balance(r["id"]), transactions=transactions))


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


# ---------- Place Order (dispense key from SellAuth stock) ----------

@router.post("/reseller/order/{product_id}")
def reseller_order_submit(
    request: Request, product_id: str,
    variant_id: str = Form(""), quantity: int = Form(1), customer_email: str = Form(""),
):
    r = require_reseller(request)
    product = sellauth.get_product(product_id)
    if not product:
        return HTMLResponse("<script>alert('Product not found');window.location='/reseller/catalog';</script>")
    df = 1 - (r["discount"] / 100)
    variant_name = "Default"
    unit_price = float(product.get("price", 0))
    variant_sellauth_id = None
    for v in product.get("variants", []):
        if str(v.get("id")) == variant_id or not variant_id:
            variant_sellauth_id = v.get("id")
            variant_name = v.get("name", "Default")
            unit_price = float(v.get("price", 0))
            break
    reseller_price = round(unit_price * df, 2)
    total = round(reseller_price * quantity, 2)
    if total <= 0:
        return HTMLResponse("<script>alert('Invalid order total');window.location='/reseller/catalog';</script>")
    balance = db.get_balance(r["id"])
    if balance < total:
        return HTMLResponse(f"<script>alert('Insufficient balance. Need ${total:.2f}, have ${balance:.2f}');window.location='/reseller/catalog';</script>")
    # Dispense a real key from SellAuth stock (only charge if we actually got one)
    delivered = ""
    try:
        delivered = sellauth.dispense_one(product_id, variant_sellauth_id or product.get("variants", [{}])[0].get("id"))
    except Exception:
        delivered = ""
    if not delivered:
        return HTMLResponse("<script>alert('Out of stock — key could not be dispensed');window.location='/reseller/catalog';</script>")
    order = db.create_order(
        reseller_id=r["id"], product_id=product_id, product_name=product.get("name", "Unknown"),
        variant_name=variant_name, quantity=quantity, price_per_unit=reseller_price,
        total_price=total, customer_email=customer_email, deliverable=delivered,
    )
    db.deduct_balance(r["id"], total, order["id"], f"Order #{order['id']}: {product.get('name')} x{quantity}")
    db.credit_referral_commission(r["id"], total)
    return templates.TemplateResponse("reseller_order_done.html", _brand_ctx(
        request=request, reseller=r, order=order, deliverable=delivered,
        new_balance=db.get_balance(r["id"])))
