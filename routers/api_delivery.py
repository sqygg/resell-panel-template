"""Reseller API delivery — dispense real keys from SellAuth stock, charged against prepaid balance.

GET  /api/deliver/{api_key}?product_id=&variant_id=&quantity=&customer_email=&order_id=
POST /api/deliver/{api_key}  json: {product_id, variant_id?, quantity?, customer_email?, order_id?}

Flow: authenticate -> price by VARIANT -> check balance -> check stock -> dispense -> deduct balance
      -> record order -> credit referral -> fire reseller webhook (if set).
"""
import time
import httpx
from fastapi import APIRouter, HTTPException, Request, Query
from pydantic import BaseModel
import database as db
from security import get_client_ip
from services.sellauth import client as sellauth

router = APIRouter(prefix="/api/deliver", tags=["delivery"])

RESERVED = {"health", "docs", "openapi.json", "redoc"}


class DeliveryRequest(BaseModel):
    product_id: str
    variant_id: str | int | None = None
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
            return float(v.get("price", 0))
    return float(product.get("price", 0))


def _do_deliver(
    api_key: str,
    product_id,
    variant_id,
    quantity: int,
    customer_email: str,
    order_id,
    request: Request,
):
    start = time.time()
    ip = get_client_ip(request)

    if api_key.lower() in RESERVED:
        raise HTTPException(status_code=404, detail="Not found")

    reseller = db.get_reseller_by_key(api_key)
    if not reseller:
        raise HTTPException(status_code=401, detail="Unauthorized")

    if not (1 <= quantity <= 50):
        raise HTTPException(status_code=400, detail="Quantity must be 1-50")

    product = sellauth.get_product(product_id)
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    variant_id = _resolve_variant(product_id, variant_id, product)
    vname = "Default"
    for v in product.get("variants") or []:
        if str(v.get("id")) == variant_id:
            vname = v.get("name", "Default")
            break

    # Price by VARIANT (not product-level) with reseller discount applied
    unit = round(_variant_price(product, variant_id) * (1 - reseller["discount_percent"] / 100), 2)
    total = round(unit * quantity, 2)

    # Balance check BEFORE dispensing (never charge for nothing)
    balance = db.get_balance(reseller["id"])
    if balance < total:
        elapsed = (time.time() - start) * 1000
        db.record_webhook_usage(reseller["id"], "/api/deliver", 402, elapsed, ip)
        raise HTTPException(
            status_code=402,
            detail=f"Insufficient balance: ${balance:.2f} available, ${total:.2f} needed",
        )

    # Dispense (atomic bulk; returns [] without consuming if stock insufficient)
    keys = sellauth.dispense_bulk(product_id, variant_id, quantity)
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
    )
    try:
        db.deduct_balance(
            reseller["id"], total, order["id"],
            f"API delivery {product.get('name', '?')} x{quantity}",
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
    return _do_deliver(
        api_key, body.product_id, body.variant_id, body.quantity,
        body.customer_email, body.order_id, request,
    )


@router.get("/{api_key}")
def deliver_get(
    api_key: str,
    request: Request,
    product_id: str = Query(...),
    variant_id: str | int | None = Query(None),
    quantity: int = Query(1),
    customer_email: str = Query(""),
    order_id: str | None = Query(None),
):
    return _do_deliver(
        api_key, product_id, variant_id, quantity, customer_email, order_id, request,
    )
