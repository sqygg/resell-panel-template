"""Exodus.fun reseller API client — issue real keys via their native endpoint.

Endpoint (GET):
  {EXODUS_BASE_URL}/api/reseller/v1/keys/issue
    ?api_key=EXODUS_API_KEY&product_id=<exodus_api_name>&period=<1day|7days>&format=simple

Returns plain text, one key per line (no prefix). On success we split into a
list of keys. Network/HTTP errors raise so the caller can 409 with the real reason.
"""
import httpx
from config import settings


class ExodusClient:
    def validate_key(self) -> dict:
        """Call GET {base}/auth/validate?api_key=... Returns {'ok': bool, 'error': str}."""
        if not settings.EXODUS_API_KEY:
            return {"ok": False, "error": "EXODUS_API_KEY is not set"}
        url = f"{settings.EXODUS_BASE_URL.rstrip('/')}/api/reseller/v1/auth/validate"
        try:
            with httpx.Client(timeout=15) as client:
                resp = client.get(url, params={"api_key": settings.EXODUS_API_KEY})
        except Exception as e:
            return {"ok": False, "error": f"request failed: {e}"}
        try:
            data = resp.json()
        except Exception:
            return {"ok": False, "error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
        if data.get("success"):
            return {"ok": True, "error": ""}
        return {"ok": False, "error": data.get("error") or f"HTTP {resp.status_code}"}

    def issue_keys(self, product_id: str, period: str, quantity: int = 1) -> list[str]:
        """Fetch `quantity` keys for an exodus product/period.

        product_id = exodus `exodus_api_name` (e.g. "R6X External")
        period      = "1day" | "3days" | "7days" | "30days"
        Returns list of plain keys (verbatim, no prefix).
        Raises RuntimeError on HTTP/network failure with a useful message.
        """
        if not settings.EXODUS_API_KEY:
            raise RuntimeError("EXODUS_API_KEY is not set in environment")
        url = f"{settings.EXODUS_BASE_URL.rstrip('/')}/api/reseller/v1/keys/issue"
        params = {
            "api_key": settings.EXODUS_API_KEY,
            "product_id": product_id,
            "period": period,
            "format": "simple",
        }
        try:
            with httpx.Client(timeout=20) as client:
                resp = client.get(url, params=params)
        except Exception as e:
            raise RuntimeError(f"Exodus request failed: {e}") from e
        if resp.status_code != 200:
            raise RuntimeError(
                f"Exodus HTTP {resp.status_code}: {resp.text[:300]}")
        # Plain newline-delimited keys, strip blanks + trailing whitespace
        keys = [k.strip() for k in resp.text.splitlines() if k.strip()]
        if not keys:
            raise RuntimeError("Exodus returned no keys (empty body)")
        return keys


client = ExodusClient()
