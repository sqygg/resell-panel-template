"""Admin API — manage resellers. Bearer-token auth, audit-logged."""
import hmac
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
import database as db
from security import get_client_ip

router = APIRouter(prefix="/api/admin", tags=["admin"])


# ---------- Schemas ----------

class ResellerCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    discount_percent: float = Field(default=0, ge=0, le=100)
    webhook_url: str = Field(default="", max_length=500)


class ResellerUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=100)
    discount_percent: float | None = Field(default=None, ge=0, le=100)
    webhook_url: str | None = Field(default=None, max_length=500)
    active: bool | None = None


# ---------- Auth ----------

def check_admin(request: Request):
    """Constant-time comparison to prevent timing attacks on the admin password."""
    from config import settings
    auth = request.headers.get("Authorization", "")
    expected = f"Bearer {settings.ADMIN_PASSWORD}"
    if not hmac.compare_digest(auth, expected):
        raise HTTPException(status_code=401, detail="Unauthorized")


# ---------- Routes ----------

@router.get("/resellers")
def list_resellers(request: Request):
    check_admin(request)
    resellers = db.list_resellers()
    # Strip sensitive fields before returning
    safe = []
    for r in resellers:
        safe.append({
            "id": r["id"],
            "name": r["name"],
            "api_key_prefix": r.get("api_key_prefix", ""),
            "discount_percent": r["discount_percent"],
            "webhook_url": r.get("webhook_url", ""),
            "active": bool(r["active"]),
            "request_count": r.get("request_count", 0),
            "last_used_at": r.get("last_used_at"),
            "created_at": r.get("created_at"),
            "updated_at": r.get("updated_at"),
        })
    return safe


@router.post("/resellers")
def create_reseller(body: ResellerCreate, request: Request):
    check_admin(request)
    ip = get_client_ip(request)
    try:
        reseller = db.create_reseller(
            name=body.name.strip(),
            discount_percent=body.discount_percent,
            webhook_url=body.webhook_url.strip(),
            ip=ip,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Return with the ONE-TIME raw key
    return {
        "id": reseller["id"],
        "name": reseller["name"],
        "api_key": reseller["api_key"],  # ONLY returned here — never again
        "api_key_prefix": reseller.get("api_key_prefix", ""),
        "discount_percent": reseller["discount_percent"],
        "webhook_url": reseller.get("webhook_url", ""),
        "active": bool(reseller["active"]),
        "created_at": reseller.get("created_at"),
        "message": "⚠️ Save the api_key now — it will never be shown again.",
    }


@router.get("/resellers/{reseller_id}")
def get_reseller(reseller_id: int, request: Request):
    check_admin(request)
    r = db.get_reseller_by_id(reseller_id)
    if not r:
        raise HTTPException(status_code=404, detail="Not found")
    return {
        "id": r["id"],
        "name": r["name"],
        "api_key_prefix": r.get("api_key_prefix", ""),
        "discount_percent": r["discount_percent"],
        "webhook_url": r.get("webhook_url", ""),
        "active": bool(r["active"]),
        "request_count": r.get("request_count", 0),
        "last_used_at": r.get("last_used_at"),
        "created_at": r.get("created_at"),
        "updated_at": r.get("updated_at"),
    }


@router.put("/resellers/{reseller_id}")
def update_reseller(reseller_id: int, body: ResellerUpdate, request: Request):
    check_admin(request)
    ip = get_client_ip(request)
    try:
        updates = {k: v for k, v in body.model_dump().items() if v is not None}
        r = db.update_reseller(reseller_id, ip=ip, **updates)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not r:
        raise HTTPException(status_code=404, detail="Not found")
    return {"id": r["id"], "updated": True}


@router.delete("/resellers/{reseller_id}")
def delete_reseller(reseller_id: int, request: Request):
    check_admin(request)
    ip = get_client_ip(request)
    ok = db.delete_reseller(reseller_id, ip=ip)
    if not ok:
        raise HTTPException(status_code=404, detail="Not found")
    return {"deleted": True}


@router.post("/resellers/{reseller_id}/regenerate-key")
def regenerate_key(reseller_id: int, request: Request):
    """Regenerate API key. Returns the NEW raw key ONCE. Old key stops immediately."""
    check_admin(request)
    ip = get_client_ip(request)
    r = db.regenerate_api_key(reseller_id, ip=ip)
    if not r:
        raise HTTPException(status_code=404, detail="Not found")
    return {
        "id": r["id"],
        "name": r["name"],
        "api_key": r["api_key"],  # ONLY returned here
        "api_key_prefix": r.get("api_key_prefix", ""),
        "message": "⚠️ Save the new api_key now — the old key is no longer valid.",
    }
