"""Reseller API delivery — dispense a real key/serial from SellAuth stock.

POST /api/deliver/{api_key}  body: {product_id, variant_id?, quantity?, customer_email?, order_id?}
  -> authenticates reseller, dispenses N keys from SellAuth, records the order,
     and fires the reseller's webhook_url with the delivered keys (if set).
"""
import time
import httpx
from fastapi import APIRouter, HTTPException, Request
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
    order_id: str | None = None  # reseller's own reference


def _resolve_variant(product_id: str, variant_id, reseller: dict):
    """Pick a variant id: explicit else first variant else product id."""
    if variant_id is not None:
        return str(variant_id)
    prod = sellauth.get_product(product_id)
    if prod and prod.get("variants"):
        return str(prod["variants"][0]["id"])
    return str(product_id)


@router.post("/{api_key}")
def deliver(api_key: str, body: DeliveryRequest, request: Request):
    start = time.time()
    ip = get_client_ip(request)

    if api_key.lower() in RESERVED:
        raise HTTPException(status_code=404, detail="Not found")

    reseller = db.get_reseller_by_key(api_key)
    if not reseller:
        raise HTTPException(status_code=401, detail="Unauthorized")

    if not (1 <= body.quantity <= 50):
        raise HTTPException(status_code=400, detail="Quantity must be 1-50")

    variant_id = _resolve_variant(body.product_id, body.variant_id, reseller)

    # Dispense keys one by one (each reads/overwrites SellAuth stock atomically)
    keys = []
    for _ in range(body.quantity):
        k = sellauth.dispense_one(body.product_id, variant_id)
        if k is None:
            # Out of stock or upstream error — stop, refund the ones we took? We only took what we return.
            break
        keys.append(k)

    if not keys:
        elapsed = (time.time() - start) * 1000
        db.record_webhook_usage(reseller["id"], "/api/deliver", 409, elapsed, ip)
        raise HTTPException(status_code=409, detail="Out of stock or upstream error")

    # Discount factor for price record (informational)
    df = 1 - (reseller["discount_percent"] / 100)
    prod = sellauth.get_product(body.product_id) or {}
    unit = float(prod.get("price", 0)) * df
    total = round(unit * len(keys), 2)
    pname = prod.get("name", "Unknown")
    vname = "Default"
    try:
        for v in prod.get("variants", []):
            if str(v.get("id")) == str(variant_id):
                vname = v.get("name", "Default")
                break
    except Exception:
        pass

    order = db.create_order(
        reseller_id=reseller["id"],
        product_id=str(body.product_id),
        product_name=pname,
        variant_name=vname,
        quantity=len(keys),
        price_per_unit=round(unit, 2),
        total_price=total,
        customer_email=body.customer_email or "",
        sellauth_invoice_id=None,
        sellauth_invoice_url="",
    )
    db.update_order_status(order["id"], "delivered", deliverable="\n".join(keys))
    db.credit_referral_commission(reseller["id"], total)

    # Fire reseller webhook if configured
    webhook_status = None
    if reseller.get("webhook_url"):
        payload = {
            "event": "delivery",
            "order_id": order["id"],
            "reseller_order_ref": body.order_id,
            "product_id": str(body.product_id),
            "variant_id": str(variant_id),
            "quantity": len(keys),
            "keys": keys,
            "customer_email": body.customer_email,
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
        "product_id": str(body.product_id),
        "variant_id": str(variant_id),
        "quantity": len(keys),
        "keys": keys,
        "webhook_status": webhook_status,
    }
