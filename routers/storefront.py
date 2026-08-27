"""Reseller storefront — dashboard, catalog, order placement, order history, balance, referrals.
Resellers authenticate with their API key (cookie-based session for the web UI)."""
import uuid
import httpx
from fastapi import APIRouter, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
import database as db
from security import get_client_ip
from services.sellauth import client as sellauth
from config import settings

router = APIRouter(prefix="/store", tags=["store"])
templates = Jinja2Templates(directory="templates")

# Reseller session store (API key → reseller_id)
_store_sessions: dict[str, dict] = {}

# Brand context injected into every template
def _brand_ctx(**extra) -> dict:
    ctx = {
        "brand_name": settings.BRAND_NAME,
        "brand_tagline": settings.BRAND_TAGLINE,
        "public_url": settings.PUBLIC_URL,
    }
    ctx.update(extra)
    return ctx


def get_store_reseller(request: Request) -> dict | None:
    """Get the authenticated reseller from their session cookie."""
    sid = request.cookies.get("store_session", "")
    return _store_sessions.get(sid)


def require_reseller(request: Request):
    """Require authenticated reseller. Returns their session record or redirects to login."""
    r = get_store_reseller(request)
    if not r:
        raise HTTPException(status_code=401, detail="Please login at /store/login")
    return r


# ---------- Auth ----------

@router.get("/login", response_class=HTMLResponse)
def store_login_page(request: Request):
    return templates.TemplateResponse("store_login.html", _brand_ctx(request=request))


@router.post("/login")
def store_login_action(request: Request, username: str = Form(...), password: str = Form(...)):
    reseller = db.get_reseller_by_username_password(username.strip(), password)
    if not reseller:
        return HTMLResponse(
            "<script>alert('Invalid username or password');window.location='/store/login';</script>"
        )

    sid = uuid.uuid4().hex
    _store_sessions[sid] = {
        "id": reseller["id"],
        "name": reseller["name"],
        "discount": reseller["discount_percent"],
        "api_key": db.reveal_api_key(reseller["id"]) or "",
        "referral_code": reseller.get("referral_code", ""),
    }
    resp = RedirectResponse(url="/store", status_code=303)
    resp.set_cookie("store_session", sid, httponly=True, samesite="strict", max_age=86400)
    return resp


@router.get("/logout")
def store_logout():
    resp = RedirectResponse(url="/store/login", status_code=303)
    resp.delete_cookie("store_session")
    return resp


# ---------- Dashboard ----------

@router.get("/", response_class=HTMLResponse)
def store_dashboard(request: Request):
    r = require_reseller(request)
    balance = db.get_balance(r["id"])
    orders = db.get_orders(r["id"], limit=10)
    transactions = db.get_transactions(r["id"], limit=10)
    referrals = db.get_referrals(r["id"])

    total_spent = sum(o["total_price"] for o in db.get_orders(r["id"], limit=1000))
    total_orders = len(db.get_orders(r["id"], limit=1000))
    referral_earned = sum(x["total_earned"] for x in referrals)

    return templates.TemplateResponse("store_dashboard.html", _brand_ctx(
        request=request,
        reseller=r,
        balance=balance,
        orders=orders,
        transactions=transactions,
        referrals=referrals,
        total_spent=total_spent,
        total_orders=total_orders,
        referral_earned=referral_earned,
        referral_count=len(referrals),
    ))


# ---------- Products / Catalog ----------

@router.get("/products", response_class=HTMLResponse)
def store_catalog(request: Request):
    r = require_reseller(request)
    products = sellauth.get_products_for_webhook()
    balance = db.get_balance(r["id"])

    # Apply reseller discount to prices
    df = 1 - (r["discount"] / 100)
    for p in products:
        p["reseller_price"] = round(p["price"] * df, 2)
        for v in p.get("variants", []):
            v["reseller_price"] = round(v["price"] * df, 2)

    return templates.TemplateResponse("store_catalog.html", _brand_ctx(
        request=request,
        reseller=r,
        products=products,
        balance=balance,
    ))


# ---------- Place Order ----------

@router.get("/order/{product_id}", response_class=HTMLResponse)
def store_order_page(request: Request, product_id: str):
    r = require_reseller(request)
    product = sellauth.get_product(product_id)
    if not product:
        return HTMLResponse("<script>alert('Product not found');window.location='/store/products';</script>")

    df = 1 - (r["discount"] / 100)
    price = float(product.get("price", 0))
    product["reseller_price"] = round(price * df, 2)
    for v in product.get("variants", []):
        v["reseller_price"] = round(float(v.get("price", 0)) * df, 2)

    balance = db.get_balance(r["id"])

    return templates.TemplateResponse("store_order.html", _brand_ctx(
        request=request,
        reseller=r,
        product=product,
        balance=balance,
    ))


@router.post("/order/{product_id}")
def store_order_submit(
    request: Request,
    product_id: str,
    variant_id: str = Form(""),
    quantity: int = Form(1),
    customer_email: str = Form(""),
):
    r = require_reseller(request)
    ip = get_client_ip(request)

    # Get product details
    product = sellauth.get_product(product_id)
    if not product:
        return HTMLResponse("<script>alert('Product not found');window.location='/store/products';</script>")

    df = 1 - (r["discount"] / 100)

    # Find variant price
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
        return HTMLResponse("<script>alert('Invalid order total');window.location='/store/products';</script>")

    # Check balance
    balance = db.get_balance(r["id"])
    if balance < total:
        return HTMLResponse(f"<script>alert('Insufficient balance. Need ${total:.2f}, have ${balance:.2f}');window.location='/store/products';</script>")

    # Create SellAuth checkout session for the customer
    invoice_url = ""
    invoice_id = None
    try:
        checkout_data = {
            "cart": [{"productId": int(product_id), "variantId": variant_sellauth_id or 1, "quantity": quantity}],
            "email": customer_email or None,
        }
        result = sellauth._request("POST", f"/shops/{settings.SELLAUTH_SHOP_ID}/checkout", json=checkout_data)
        if result and result.get("success"):
            invoice_id = result.get("invoice_id")
            invoice_url = result.get("url", "")
    except Exception:
        pass  # Order still goes through even if SellAuth checkout fails

    # Create order record
    order = db.create_order(
        reseller_id=r["id"],
        product_id=product_id,
        product_name=product.get("name", "Unknown"),
        variant_name=variant_name,
        quantity=quantity,
        price_per_unit=reseller_price,
        total_price=total,
        customer_email=customer_email,
        sellauth_invoice_id=invoice_id,
        sellauth_invoice_url=invoice_url,
    )

    # Deduct balance
    try:
        db.deduct_balance(r["id"], total, order["id"], f"Order #{order['id']}: {product.get('name')} x{quantity}")
    except ValueError as e:
        return HTMLResponse(f"<script>alert('{e}');window.location='/store/products';</script>")

    # Credit referral commission to the referrer (if this reseller was referred)
    db.credit_referral_commission(r["id"], total)

    return templates.TemplateResponse("store_order_done.html", _brand_ctx(
        request=request,
        reseller=r,
        order=order,
        invoice_url=invoice_url,
        new_balance=db.get_balance(r["id"]),
    ))


# ---------- Order History ----------

@router.get("/orders", response_class=HTMLResponse)
def store_orders(request: Request):
    r = require_reseller(request)
    orders = db.get_orders(r["id"])
    return templates.TemplateResponse("store_orders.html", _brand_ctx(
        request=request,
        reseller=r,
        orders=orders,
        balance=db.get_balance(r["id"]),
    ))


# ---------- Balance ----------

@router.get("/balance", response_class=HTMLResponse)
def store_balance(request: Request):
    r = require_reseller(request)
    balance = db.get_balance(r["id"])
    transactions = db.get_transactions(r["id"])
    return templates.TemplateResponse("store_balance.html", _brand_ctx(
        request=request,
        reseller=r,
        balance=balance,
        transactions=transactions,
    ))


# ---------- Referrals ----------

@router.get("/referrals", response_class=HTMLResponse)
def store_referrals(request: Request):
    r = require_reseller(request)
    referrals = db.get_referrals(r["id"])
    referral_earned = sum(x["total_earned"] for x in referrals)

    # Build the referral link
    code = r.get("referral_code", "")
    link = ""
    if code:
        base = settings.PUBLIC_URL.rstrip("/") if settings.PUBLIC_URL else str(request.base_url).rstrip("/")
        link = f"{base}/apply?ref={code}"

    return templates.TemplateResponse("store_referrals.html", _brand_ctx(
        request=request,
        reseller=r,
        referrals=referrals,
        referral_earned=referral_earned,
        referral_code=code,
        referral_link=link,
        commission_percent=settings.REFERRAL_COMMISSION_PERCENT,
        balance=db.get_balance(r["id"]),
    ))


# ---------- Public: Apply to become a reseller ----------

@router.get("/apply", response_class=HTMLResponse)
def store_apply_page(request: Request):
    ref = request.query_params.get("ref", "")
    return templates.TemplateResponse("store_apply.html", _brand_ctx(
        request=request,
        ref=ref,
    ))


@router.post("/apply")
def store_apply_submit(
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
            email=email,
            discord=discord,
            website=website,
            discord_server=discord_server,
            products=products,
            referral_code=referral_code,
        )
        from services.crypto_notify import notify_new_application
        notify_new_application(dict(app))
    except ValueError as e:
        return HTMLResponse(f"<script>alert('{e}');history.back();</script>")
    return RedirectResponse(url="/store/apply?done=1", status_code=303)
