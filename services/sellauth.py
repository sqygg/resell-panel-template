"""SellAuth API client — fetch products and stock."""
import httpx
from config import settings


class SellAuthClient:
    def __init__(self):
        self.base = settings.sellauth_base_url
        self.headers = settings.sellauth_headers
        self.shop_id = settings.SELLAUTH_SHOP_ID

    def _request(self, method: str, path: str, **kwargs) -> dict | None:
        """Make an API request to SellAuth. Returns parsed JSON or None on failure."""
        url = f"{self.base}{path}"
        try:
            with httpx.Client(timeout=15) as client:
                resp = client.request(method, url, headers=self.headers, **kwargs)
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPStatusError as e:
            print(f"[SellAuth] HTTP {e.response.status_code}: {e.response.text[:300]}")
            return None
        except Exception as e:
            print(f"[SellAuth] Error: {e}")
            return None

    def get_products(self, page: int = 1, per_page: int = 50) -> list[dict]:
        """Fetch all products from the shop with their stock info."""
        data = self._request(
            "GET",
            f"/shops/{self.shop_id}/products",
            json={
                "page": page,
                "perPage": per_page,
                "orderColumn": "id",
                "orderDirection": "desc",
            },
        )
        if not data:
            return []
        # Response shape: {"data": [...], "meta": {"total": N, ...}}
        products = data.get("data", [])
        return products

    def get_product(self, product_id: str, shop_id: str | None = None) -> dict:
        """Fetch a single product by ID. Returns {"ok": True, "data": {...}} on
        success, or {"ok": False, "status": int, "error": str} on failure (so
        callers can surface the REAL SellAuth reason instead of 'Product not found').
        `shop_id` overrides the configured shop (used by webhooks that carry the
        real shop id in the payload)."""
        sid = shop_id or self.shop_id
        url = f"{self.base}/shops/{sid}/products/{product_id}"
        try:
            with httpx.Client(timeout=15) as client:
                resp = client.get(url, headers=self.headers)
                if resp.status_code == 200:
                    try:
                        return {"ok": True, "data": resp.json()}
                    except Exception:
                        return {"ok": True, "data": {}}
                return {"ok": False, "status": resp.status_code, "error": resp.text[:400], "shop_id": sid}
        except Exception as e:
            return {"ok": False, "status": 0, "error": str(e)[:400], "shop_id": sid}

    def update_stock(self, product_id: str, variant_id: str, quantity: int) -> bool:
        """Update stock quantity for a product variant."""
        result = self._request(
            "PUT",
            f"/shops/{self.shop_id}/products/{product_id}/stock/{variant_id}",
            json={"quantity": quantity},
        )
        return result is not None

    # ---------- Serial / key delivery ----------

    def get_deliverables(self, product_id: str, variant_id: str | int, shop_id: str | None = None) -> list[str] | None:
        """List serials/keys on a product variant. Returns list or None on failure."""
        sid = shop_id or self.shop_id
        result = self._request(
            "GET",
            f"/shops/{sid}/products/{product_id}/deliverables/{variant_id}",
        )
        if result is None:
            return None
        # API returns a list of strings, or {"deliverables": [...]} in some versions
        if isinstance(result, list):
            return result
        return result.get("deliverables", [])

    def append_deliverable(self, product_id: str, variant_id: str | int, key: str) -> bool:
        """Inject a single key back into stock (e.g. on refund/return)."""
        result = self._request(
            "PUT",
            f"/shops/{self.shop_id}/products/{product_id}/deliverables/append/{variant_id}",
            json={"deliverables": [key]},
        )
        return result is not None

    def reseller_deliver(self, token: str, product_id: str, variant_id: str | int,
                          quantity: int = 1, max_unit_price: float | None = None) -> dict:
        """Pull REAL deliverables for an infinite-stock (generator) product via
        SellAuth Reseller Dynamic Delivery.

        Generator products keep 0 stored keys, so the normal dispense path can't
        fulfil them. SellAuth only mints real keys through this endpoint, which
        charges the token owner's reseller balance and returns the actual
        deliverables. Returns {"ok": True, "keys": [...]} or {"ok": False, ...}.
        """
        if not token:
            return {"ok": False, "status": 0, "error": "No SellAuth reseller token configured"}
        params = {"product_id": product_id, "variant_id": variant_id, "quantity": quantity}
        if max_unit_price is not None:
            params["max_unit_price"] = max_unit_price
        url = f"{self.base}/reseller/dynamic/{token}"
        try:
            with httpx.Client(timeout=20) as client:
                resp = client.get(url, headers=self.headers, params=params)
                # Successful dynamic delivery returns plain-text deliverables, one per line.
                if resp.status_code == 200:
                    text = resp.text.strip()
                    keys = [k for k in text.splitlines() if k.strip()]
                    return {"ok": True, "keys": keys}
                return {"ok": False, "status": resp.status_code,
                        "error": resp.text[:400]}
        except Exception as e:
            return {"ok": False, "status": 0, "error": str(e)[:400]}


    def dispense_one(self, product_id: str, variant_id: str | int) -> str | None:
        """
        Atomically take ONE key from SellAuth stock and return it.
        Reads the current list, pops the first entry, overwrites with the rest.
        Returns the key string or None if out of stock / error.
        """
        keys = self.get_deliverables(product_id, variant_id)
        if keys is None:
            return None
        if not keys:
            return None
        remaining = keys[1:]
        result = self._request(
            "PUT",
            f"/shops/{self.shop_id}/products/{product_id}/deliverables/overwrite/{variant_id}",
            json={"deliverables": remaining, "confirm_empty": True},
        )
        if result is None:
            return None
        return keys[0]

    def dispense_bulk(self, product_id: str, variant_id: str | int, quantity: int, shop_id: str | None = None) -> list[str] | None:
        """Atomically take up to `quantity` keys from SellAuth stock.

        Returns the taken key list, or None on upstream failure.
        If fewer than `quantity` are in stock, returns [] WITHOUT consuming
        (caller should treat empty as out-of-stock).
        """
        keys = self.get_deliverables(product_id, variant_id, shop_id=shop_id)
        if keys is None:
            return None
        if len(keys) < quantity:
            return []
        take = keys[:quantity]
        remaining = keys[quantity:]
        sid = shop_id or self.shop_id
        result = self._request(
            "PUT",
            f"/shops/{sid}/products/{product_id}/deliverables/overwrite/{variant_id}",
            json={"deliverables": remaining, "confirm_empty": True},
        )
        if result is None:
            return None
        return take

    # ---------- Stock sync ----------

    def sync_stock_snapshot(self) -> dict:
        """
        Pull a full stock snapshot: {product_id: {variant_id: stock, price}}.
        Used by the dashboard to show live stock without per-render API hits.
        """
        raw = self.get_products()
        snap: dict = {}
        for p in raw:
            pid = str(p.get("id"))
            variants = {}
            for v in p.get("variants", []):
                variants[str(v.get("id"))] = {
                    "name": v.get("name", "Default"),
                    "stock": int(v.get("stock", 0) or 0),
                    "price": float(v.get("price", 0)),
                }
            snap[pid] = {
                "name": p.get("name", "Unknown"),
                "type": p.get("type", "service"),
                "currency": p.get("currency", "USD"),
                "variants": variants,
                "flat_stock": int(p.get("stock", 0) or 0),
            }
        return snap

    def get_products_for_webhook(self) -> list[dict]:
        """
        Fetch products formatted for webhook delivery.
        Returns a simplified list with: id, name, price, stock, variants.
        """
        raw = self.get_products()
        cleaned = []
        for p in raw:
            variants = []
            for v in p.get("variants", []):
                variants.append({
                    "variant_id": v.get("id"),
                    "name": v.get("name", "Default"),
                    "price": float(v.get("price") or 0),
                    "stock": int(v.get("stock", 0) or 0),
                })

            # Use the first variant's price/stock if no variants
            price = variants[0]["price"] if variants else float(p.get("price") or 0)
            stock = variants[0]["stock"] if variants else int(p.get("stock", 0) or 0)

            cleaned.append({
                "id": p.get("id"),
                "name": p.get("name", "Unknown"),
                "description": p.get("description", ""),
                "price": price,
                "stock": stock,
                "currency": p.get("currency", "USD"),
                "type": p.get("type", "service"),
                "variants": variants,
            })
        return cleaned


    # ---------- Customer (store balance mirror) ----------

    def get_customer_by_email(self, email: str, shop_id: str | None = None) -> dict | None:
        """Look up a SellAuth customer record by email. Returns {id, email, balance} or None.
        Scans all pages (the matching customer may not be on page 1)."""
        sid = shop_id or self.shop_id
        email = (email or "").lower()
        page = 1
        while True:
            data = self._request(
                "GET",
                f"/shops/{sid}/customers",
                json={"page": page, "perPage": 100, "email": email},
            )
            if not data:
                return None
            rows = data.get("data", []) if isinstance(data, dict) else data
            if not rows:
                return None
            for c in rows:
                if (c.get("email") or "").lower() == email:
                    return c
            meta = data.get("meta", {}) if isinstance(data, dict) else {}
            total = int(meta.get("total", 0) or 0)
            if total and page * 100 >= total:
                return None
            page += 1

    def get_customer_balance(self, email: str, shop_id: str | None = None) -> float | None:
        """Return a customer's store balance (USD) by email, or None if not found."""
        c = self.get_customer_by_email(email, shop_id=shop_id)
        if not c:
            return None
        try:
            return float(c.get("balance", 0) or 0)
        except (TypeError, ValueError):
            return 0.0

    def get_customer_id_by_email(self, email: str, shop_id: str | None = None) -> str | None:
        """Return a SellAuth customer's id by email, or None if not found."""
        c = self.get_customer_by_email(email, shop_id=shop_id)
        if not c:
            return None
        cid = c.get("id")
        return str(cid) if cid is not None else None

    def edit_customer_balance(
        self, customer_id: str, amount: float, description: str = "", invoice_id: int | None = None, shop_id: str | None = None
    ) -> dict:
        """Add (positive) or deduct (negative) balance for a SellAuth customer.
        Returns {"ok": True, ...} on success, or {"ok": False, "status": int,
        "error": str} on failure (so callers can surface the REAL reason instead
        of a generic 'API error'). amount must be within [-1000, 1000]."""
        sid = shop_id or self.shop_id
        payload: dict = {"amount": round(float(amount), 2), "description": description[:255]}
        if invoice_id is not None:
            payload["invoice_id"] = invoice_id
        url = f"{self.base}/shops/{sid}/customers/{customer_id}/balance"
        try:
            with httpx.Client(timeout=15) as client:
                resp = client.put(url, headers=self.headers, json=payload)
                if resp.status_code == 200:
                    try:
                        return {"ok": True, **resp.json()}
                    except Exception:
                        return {"ok": True}
                return {"ok": False, "status": resp.status_code, "error": resp.text[:400]}
        except Exception as e:
            return {"ok": False, "status": 0, "error": str(e)[:400]}


client = SellAuthClient()
