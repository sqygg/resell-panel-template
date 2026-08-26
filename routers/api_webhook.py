"""Dynamic webhook endpoint — resellers query stock with their discount applied."""
import time
from fastapi import APIRouter, HTTPException, Query, Request
import database as db
from security import get_client_ip
from services.sellauth import client as sellauth

router = APIRouter(prefix="/api/webhook", tags=["webhook"])

# Reserved paths that aren't API keys
RESERVED = {"health", "docs", "openapi.json", "redoc", "product"}


@router.get("/{api_key}")
def webhook_delivery(
    api_key: str,
    request: Request,
    type: str | None = Query(None, description="Filter by product type"),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
):
    """
    Products with reseller's discount applied.
    API key is never logged or stored — validated via hash only.
    """
    start = time.time()
    ip = get_client_ip(request)

    # Reject reserved words as keys
    if api_key.lower() in RESERVED:
        raise HTTPException(status_code=404, detail="Not found")

    # Validate reseller (key is hashed, compared to stored hash)
    reseller = db.get_reseller_by_key(api_key)
    if not reseller:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Fetch products from SellAuth
    try:
        products = sellauth.get_products_for_webhook()
    except Exception as e:
        raise HTTPException(status_code=502, detail="Upstream service unavailable")

    # Apply reseller discount
    discount_factor = 1 - (reseller["discount_percent"] / 100)
    for p in products:
        p["original_price"] = p["price"]
        p["price"] = round(p["price"] * discount_factor, 2)
        p["discount_percent"] = reseller["discount_percent"]
        for v in p.get("variants", []):
            v["original_price"] = v["price"]
            v["price"] = round(v["price"] * discount_factor, 2)

    # Filter by type
    if type and type in ("service", "file"):
        products = [p for p in products if p.get("type") == type]

    # Paginate
    total = len(products)
    start_idx = (page - 1) * per_page
    page_items = products[start_idx : start_idx + per_page]

    elapsed_ms = (time.time() - start) * 1000
    db.record_webhook_usage(reseller["id"], "/api/webhook", 200, elapsed_ms, ip)

    return {
        "success": True,
        "reseller": {
            "name": reseller["name"],
            "discount_percent": reseller["discount_percent"],
        },
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "total_pages": max(1, (total + per_page - 1) // per_page),
        },
        "products": page_items,
    }


@router.get("/{api_key}/product/{product_id}")
def webhook_product_detail(api_key: str, product_id: str, request: Request):
    """Single product with discount applied."""
    start = time.time()
    ip = get_client_ip(request)

    if api_key.lower() in RESERVED:
        raise HTTPException(status_code=404, detail="Not found")

    reseller = db.get_reseller_by_key(api_key)
    if not reseller:
        raise HTTPException(status_code=401, detail="Unauthorized")

    try:
        product = sellauth.get_product(product_id)
    except Exception:
        raise HTTPException(status_code=502, detail="Upstream service unavailable")

    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    discount_factor = 1 - (reseller["discount_percent"] / 100)
    product["original_price"] = float(product.get("price", 0))
    product["price"] = round(product["original_price"] * discount_factor, 2)
    product["discount_percent"] = reseller["discount_percent"]

    elapsed_ms = (time.time() - start) * 1000
    db.record_webhook_usage(reseller["id"], f"/product/{product_id}", 200, elapsed_ms, ip)

    return {
        "success": True,
        "reseller": {"name": reseller["name"], "discount_percent": reseller["discount_percent"]},
        "product": product,
    }


@router.get("/{api_key}/health")
def webhook_health(api_key: str, request: Request):
    """Validate API key — minimal info exposure."""
    if api_key.lower() in RESERVED:
        raise HTTPException(status_code=404, detail="Not found")

    reseller = db.get_reseller_by_key(api_key)
    if not reseller:
        raise HTTPException(status_code=401, detail="Unauthorized")

    ip = get_client_ip(request)
    db.record_webhook_usage(reseller["id"], "/health", 200, 0, ip)

    return {
        "success": True,
        "reseller": {
            "name": reseller["name"],
            "discount_percent": reseller["discount_percent"],
        },
    }
