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

    def get_product(self, product_id: str) -> dict | None:
        """Fetch a single product by ID."""
        return self._request("GET", f"/shops/{self.shop_id}/products/{product_id}")

    def update_stock(self, product_id: str, variant_id: str, quantity: int) -> bool:
        """Update stock quantity for a product variant."""
        result = self._request(
            "PUT",
            f"/shops/{self.shop_id}/products/{product_id}/stock/{variant_id}",
            json={"quantity": quantity},
        )
        return result is not None

    # ---------- Serial / key delivery ----------

    def get_deliverables(self, product_id: str, variant_id: str | int) -> list[str] | None:
        """List serials/keys on a product variant. Returns list or None on failure."""
        result = self._request(
            "GET",
            f"/shops/{self.shop_id}/products/{product_id}/deliverables/{variant_id}",
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
                    "price": float(v.get("price", 0)),
                    "stock": int(v.get("stock", 0) or 0),
                })

            # Use the first variant's price/stock if no variants
            price = variants[0]["price"] if variants else float(p.get("price", 0))
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


client = SellAuthClient()
