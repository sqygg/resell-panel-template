"""Reseller API delivery — dispense real keys from SellAuth stock, charged against prepaid balance.

GET  /api/deliver/{api_key}?product_id=&variant_id=&quantity=&customer_email=&order_id=
POST /api/deliver/{api_key}  json: {product_id, variant_id?, quantity?, customer_email?, order_id?}

Flow: authenticate -> price by VARIANT -> check balance -> check stock -> dispense -> deduct balance
      -> record order -> credit referral -> fire reseller webhook (if set).
"""
import time
import json
import httpx
from fastapi import APIRouter, HTTPException, Request, Query
from pydantic import BaseModel
import database as db
from security import get_client_ip
from config import settings
from services.sellauth import client as sellauth

router = APIRouter(prefix="/api/deliver", tags=["delivery"])

RESERVED = {"health", "docs", "openapi.json", "redoc", "dynamic"}


# ---------------------------------------------------------------------------
# SellAuth dynamic-delivery webhook
# SellAuth POSTs one request per invoice item with a nested `item` object and
# signs the raw body via the X-Signature header (HMAC-SHA256). It expects the
# response BODY to be newline-delimited deliverables (each line = one key) on
# HTTP 200, NOT a JSON document.
#
# The reseller is identified by their API key in the path:
#   POST /api/deliver/dynamic/{reseller_api_key}
# so each reseller can supply their OWN SellAuth webhook secret. Falls back to
# the global SELLAUTH_WEBHOOK_SECRET if the reseller hasn't set one.
# ---------------------------------------------------------------------------
@router.post("/dynamic/{api_key}")
async def deliver_dynamic(api_key: str, request: Request):
    import hmac as _hmac
    import hashlib as _hashlib

    reseller = db.get_reseller_by_key(api_key)
    if not reseller:
        return _plain(401, "Unauthorized")

    raw = await request.body()
    secret = db.get_sellauth_webhook_secret(reseller["id"]) or settings.SELLAUTH_WEBHOOK_SECRET
    if secret:
        sig = request.headers.get("X-Signature", "")
        expected = _hmac.new(secret.encode(), raw, _hashlib.sha256).hexdigest()
        if not _hmac.compare_digest(sig, expected):
            return _plain(401, "Invalid signature")

    try:
        payload = json.loads(raw) if raw else {}
    except Exception:
        return _plain(400, "Invalid JSON body")

    item = payload.get("item") or {}
    product_id = str(item.get("product_id", "")).strip()
    shop_id = str(payload.get("shop_id", "")).strip() or settings.SELLAUTH_SHOP_ID
    variant_id_raw = item.get("variant_id")
    variant_id = str(variant_id_raw).strip() if variant_id_raw not in (None, "") else None
    try:
        quantity = int(item.get("quantity", 1) or 1)
    except (TypeError, ValueError):
        quantity = 1
    customer_email = payload.get("email", "") or ""

    if not product_id:
        return _plain(400, "Missing item.product_id")

    try:
        result = _do_deliver(
            api_key, product_id, variant_id, quantity, customer_email,
            str(payload.get("unique_id", "")), request,
            shop_id=shop_id,
        )
    except HTTPException as e:
        # Non-2xx/429/5xx => SellAuth marks item failed (shows this text)
        return _plain(e.status_code, str(e.detail))
    except Exception as e:  # noqa: BLE001
        return _plain(500, f"Delivery error: {e}")

    keys = result.get("keys", [])
    return _plain(200, "\n".join(keys))


def _plain(status_code: int, text: str):
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(content=text, status_code=status_code)


def _deliver_plain(api_key, product_id, variant_id, quantity, customer_email, order_id, request, **kw):
    """Run a delivery and return the SellAuth-compatible plain-text body
    (newline-delimited keys), exactly like the /dynamic/ webhook path."""
    try:
        result = _do_deliver(api_key, product_id, variant_id, quantity,
                             customer_email, order_id, request, **kw)
    except HTTPException as e:
        return _plain(e.status_code, str(e.detail))
    except Exception as e:  # noqa: BLE001
        return _plain(500, f"Delivery error: {e}")
    keys = result.get("keys", [])
    return _plain(200, "\n".join(keys))


class DeliveryRequest(BaseModel):
    product_id: str | None = None
    variant_id: str | int | None = None
    item: dict | None = None  # SellAuth nests product_id/variant_id here

    def resolved(self) -> tuple[str | None, str | None, int, str]:
        pid = self.product_id
        vid = self.variant_id
        qty = self.quantity
        email = self.customer_email
        if not pid and self.item:
            pid = self.item.get("product_id")
            vid = vid if vid is not None else self.item.get("variant_id")
            try:
                qty = int(self.item.get("quantity", qty) or qty)
            except (TypeError, ValueError):
                pass
            email = email or (self.item.get("email") or "")
        return (str(pid).strip() if pid not in (None, "") else None,
                str(vid).strip() if vid not in (None, "") else None,
                qty, email)
    quantity: int = 1
    customer_email: str = ""
    order_id: str | None = None


def _resolve_variant(product_id: str, variant_id, product: dict) -> str:
    if variant_id is not None:
        return str(variant_id)
    variants = product.get("variants") or []
    if variants:
        return str(variants[0]["id"])
    return str(product_id)


def _variant_price(product: dict, variant_id: str) -> float:
    for v in product.get("variants") or []:
        if str(v.get("id")) == variant_id:
            return _safe_float(v.get("price"))
    return _safe_float(product.get("price"))


def _safe_float(val, default=0.0) -> float:
    """SellAuth sometimes returns price as None/string. Never crash on it."""
    try:
        if val is None or val == "":
            return default
        return float(val)
    except (TypeError, ValueError):
        return default


def _do_deliver(
    api_key: str,
    product_id,
    variant_id,
    quantity: int,
    customer_email: str,
    order_id,
    request: Request,
    alias_owner: int | None = None,
    shop_id: str | None = None,
):
    start = time.time()
    ip = get_client_ip(request)

    if api_key and api_key.lower() in RESERVED:
        raise HTTPException(status_code=404, detail="Not found")

    # Authenticate: alias mode uses the alias owner; key mode looks up by key
    if alias_owner is not None:
        reseller = db.get_reseller_by_id(alias_owner)
        if not reseller or not reseller.get("active"):
            raise HTTPException(status_code=401, detail="Unauthorized")
    else:
        if not api_key:
            raise HTTPException(status_code=401, detail="Unauthorized")
        reseller = db.get_reseller_by_key(api_key)
        if not reseller:
            raise HTTPException(status_code=401, detail="Unauthorized")

    if not (1 <= quantity <= 50):
        raise HTTPException(status_code=400, detail="Quantity must be 1-50")

    product = sellauth.get_product(product_id, shop_id=shop_id)
    if not product.get("ok"):
        detail = (f"SellAuth product {product_id} lookup failed"
                  f" (shop {product.get('shop_id')}): HTTP {product.get('status')} {product.get('error', '')}").strip()
        raise HTTPException(status_code=404, detail=detail)
    product = product.get("data", {})

    variant_id = _resolve_variant(product_id, variant_id, product)
    vname = "Default"
    for v in product.get("variants") or []:
        if str(v.get("id")) == variant_id:
            vname = v.get("name", "Default")
            break

    # Price by VARIANT (not product-level) with reseller discount applied
    unit = db.effective_price(product_id, variant_id, reseller["discount_percent"], _variant_price(product, variant_id))
    total = round(unit * quantity, 2)

    # Funds gate: SellAuth is source of truth; local is reconciled up to match
    # so a $0 local mirror never blocks a purchase the reseller CAN afford.
    # Raises ValueError (402) if EITHER ledger is genuinely short.
    try:
        db.ensure_funds(reseller["id"], total, shop_id=shop_id)
    except ValueError as e:
        elapsed = (time.time() - start) * 1000
        db.record_webhook_usage(reseller["id"], "/api/deliver", 402, elapsed, ip)
        raise HTTPException(status_code=402, detail=str(e))

    # Dispense — two paths:
    #  • Finite stock: pull real keys from SellAuth stock (atomic).
    #  • Infinite stock (-1, dynamic/generator product): SellAuth holds 0 stored
    #    keys. The real deliverable comes from the developer webhook URL set on the
    #    SellAuth variant (dynamic_url) — exactly what SellAuth POSTs to at checkout.
    #    We call it directly: no reseller program, no balance, no paid plan needed.
    is_infinite = False
    dynamic_url = ""
    for v in product.get("variants") or []:
        if str(v.get("id")) == variant_id:
            is_infinite = (int(v.get("stock", 0) or 0) == -1)
            dynamic_url = v.get("dynamic_url") or product.get("dynamic_url") or ""
            break
    if is_infinite:
        if dynamic_url:
            # Source-shop products are signed by SellAuth with the SHOP webhook secret
            # (Storefront > Configure > Miscellaneous), not the per-reseller card (which
            # is for inbound verification). Use the source shop secret for outbound signing.
            secret = settings.SELLAUTH_WEBHOOK_SECRET or ""
            if not secret:
                elapsed = (time.time() - start) * 1000
                db.record_webhook_usage(reseller["id"], "/api/deliver", 409, elapsed, ip)
                raise HTTPException(
                    status_code=409,
                    detail="Set SELLAUTH_WEBHOOK_SECRET to your shop's webhook secret "
                           "(Storefront > Configure > Miscellaneous) to sign dynamic delivery.")
            rdel = sellauth.dynamic_deliver(
                dynamic_url, product_id, variant_id, quantity,
                customer_email or "", shop_id=shop_id, webhook_secret=secret)
            if not rdel.get("ok"):
                elapsed = (time.time() - start) * 1000
                db.record_webhook_usage(reseller["id"], "/api/deliver", 409, elapsed, ip)
                raise HTTPException(
                    status_code=409,
                    detail=f"Dynamic delivery failed: HTTP {rdel.get('status')} {rdel.get('error', '')}".strip())
            keys = rdel.get("keys") or []
        else:
            # No developer webhook set on the variant → try SellAuth Reseller Dynamic
            # Delivery as a fallback (requires a reseller token). Optional path.
            token = db.get_sellauth_reseller_token(reseller["id"]) or settings.SELLAUTH_RESELLER_TOKEN
            if not token:
                elapsed = (time.time() - start) * 1000
                db.record_webhook_usage(reseller["id"], "/api/deliver", 409, elapsed, ip)
                raise HTTPException(
                    status_code=409,
                    detail="Infinite-stock product has no dynamic delivery URL set on the variant. "
                           "Set the developer webhook URL in your SellAuth product, or configure a "
                           "SellAuth reseller token.")
            rdel = sellauth.reseller_deliver(token, product_id, variant_id, quantity)
            if not rdel.get("ok"):
                elapsed = (time.time() - start) * 1000
                db.record_webhook_usage(reseller["id"], "/api/deliver", 409, elapsed, ip)
                raise HTTPException(
                    status_code=409,
                    detail=f"Source delivery failed: HTTP {rdel.get('status')} {rdel.get('error', '')}".strip())
            keys = rdel.get("keys") or []
    else:
        keys = sellauth.dispense_bulk(product_id, variant_id, quantity, shop_id=shop_id)
    if keys is None:
        elapsed = (time.time() - start) * 1000
        db.record_webhook_usage(reseller["id"], "/api/deliver", 409, elapsed, ip)
        raise HTTPException(status_code=409, detail="Out of stock or upstream error")
    if not keys:
        elapsed = (time.time() - start) * 1000
        db.record_webhook_usage(reseller["id"], "/api/deliver", 409, elapsed, ip)
        raise HTTPException(status_code=409, detail="Insufficient stock for requested quantity")

    # Create order (pending) then charge — links the balance transaction to the order
    order = db.create_order(
        reseller_id=reseller["id"],
        product_id=str(product_id),
        product_name=product.get("name", "Unknown"),
        variant_name=vname,
        quantity=len(keys),
        price_per_unit=unit,
        total_price=total,
        customer_email=customer_email or "",
        channel="webhook",
    )
    try:
        db.deduct_both_balances(
            reseller["id"], total, order["id"],
            f"API delivery {product.get('name', '?')} x{quantity}",
            shop_id=shop_id,
        )
    except ValueError as e:
            # Roll back the partial order state if balance deduction fails
            db.update_order_status(order["id"], "failed")
            elapsed = (time.time() - start) * 1000
            db.record_webhook_usage(reseller["id"], "/api/deliver", 402, elapsed, ip)
            raise HTTPException(status_code=402, detail=str(e))
    db.update_order_status(order["id"], "delivered", deliverable="\n".join(keys))
    db.credit_referral_commission(reseller["id"], total)

    # Fire reseller webhook if configured
    webhook_status = None
    if reseller.get("webhook_url"):
        payload = {
            "event": "delivery",
            "order_id": order["id"],
            "reseller_order_ref": order_id,
            "product_id": str(product_id),
            "variant_id": str(variant_id),
            "quantity": len(keys),
            "keys": keys,
            "customer_email": customer_email,
        }
        try:
            with httpx.Client(timeout=10) as c:
                r = c.post(reseller["webhook_url"], json=payload)
                webhook_status = r.status_code
        except Exception:
            webhook_status = 0

    elapsed = (time.time() - start) * 1000
    db.record_webhook_usage(reseller["id"], "/api/deliver", 200, elapsed, ip)

    return {
        "success": True,
        "order_id": order["id"],
        "product_id": str(product_id),
        "variant_id": str(variant_id),
        "quantity": len(keys),
        "unit_price": unit,
        "total_charged": total,
        "keys": keys,
        "webhook_status": webhook_status,
    }


@router.post("/{api_key}")
def deliver_post(api_key: str, body: DeliveryRequest, request: Request):
    pid, vid, qty, email = body.resolved()
    if not pid:
        raise HTTPException(status_code=400, detail="Missing product_id (top-level or item.product_id)")
    return _deliver_plain(api_key, pid, vid, qty, email, body.order_id, request)


@router.get("/{api_key}")
def deliver_get(
    api_key: str,
    request: Request,
    product_id: str = Query(None),
    variant_id: str | int | None = Query(None),
    quantity: int = Query(1),
    customer_email: str = Query(""),
    order_id: str | None = Query(None),
):
    # Alias mode: /api/deliver/{alias}  (product/variant come from the alias, not query)
    resolved = db.resolve_alias(api_key)
    if resolved:
        return _deliver_plain(
            None, resolved["product_id"], resolved["variant_id"], quantity,
            customer_email, order_id, request, alias_owner=resolved["reseller_id"],
        )
    # Not an alias: must be a real API key with product_id
    if not product_id:
        raise HTTPException(status_code=401, detail="Unauthorized or missing product_id")
    return _deliver_plain(api_key, product_id, variant_id, quantity, customer_email, order_id, request)


@router.post("/{api_key}/product/{product_id}")
def deliver_post_product(api_key: str, product_id: str, body: DeliveryRequest, request: Request):
    return _deliver_plain(
        api_key, product_id, body.variant_id, body.quantity,
        body.customer_email, body.order_id, request,
    )


@router.get("/{api_key}/product/{product_id}")
def deliver_get_product(
    api_key: str,
    product_id: str,
    request: Request,
    variant_id: str | int | None = Query(None),
    quantity: int = Query(1),
    customer_email: str = Query(""),
    order_id: str | None = Query(None),
):
    return _deliver_plain(api_key, product_id, variant_id, quantity, customer_email, order_id, request)

