"""Supplier-backed key fetching.

A supplier mapping points a SellAuth product_id at an *external* simple-issue
endpoint (exodus.fun-style) that returns the key(s) in plain text. When a delivery
webhook hits a mapped product, the panel fetches the key from the supplier instead
of dispensing from its own SellAuth stock — so it can resell across shops it has
no API access to.
"""
import httpx


def fetch_keys(supplier_url: str, quantity: int = 1, timeout: int = 15) -> list[str]:
    """Fetch `quantity` keys from a supplier's simple-issue URL.

    Supports two shapes:
      1. GET with query params (exodus.fun-style): the URL already embeds
         api_key + product_id + period etc. We just append/replace `&format=simple`
         and (if the supplier reads it) `&quantity=`.
      2. POST JSON (SellAuth-style dynamic endpoint): send the same body the
         upstream webhook gave us, get back newline keys.

    Returns a list of key strings. Raises RuntimeError with a clear message on
    any upstream failure (so the caller can surface it to SellAuth).
    """
    if not supplier_url:
        raise RuntimeError("No supplier URL configured for this product")

    # GET simple-issue form: ensure we ask for plain text. We do NOT append a
    # quantity param because most simple-issue endpoints dispense exactly one key
    # per request; we loop below to gather `quantity` keys.
    url = supplier_url
    sep = "&" if "?" in url else "?"
    if "format=" not in url:
        url += f"{sep}format=simple"

    keys: list[str] = []
    attempts = 0
    max_attempts = max(1, quantity) * 2  # allow the endpoint to return batches
    while len(keys) < quantity and attempts < max_attempts:
        attempts += 1
        try:
            with httpx.Client(timeout=timeout, follow_redirects=True) as client:
                resp = client.get(url, headers={"User-Agent": "AstroPanel/1.0"})
        except Exception as e:
            raise RuntimeError(f"Supplier request failed: {e}") from e
        if resp.status_code != 200:
            raise RuntimeError(
                f"Supplier returned HTTP {resp.status_code}: {resp.text[:300]}"
            )
        text = resp.text.strip()
        if not text:
            raise RuntimeError("Supplier returned an empty response (no keys)")
        # Split into individual keys: newline or comma separated, ignore blanks.
        batch = [k.strip() for k in text.replace("\r", "").split("\n") if k.strip()]
        if len(batch) == 1 and "," in batch[0]:
            batch = [k.strip() for k in batch[0].split(",") if k.strip()]
        if not batch:
            raise RuntimeError("Supplier response contained no parseable keys")
        keys.extend(batch)
        if quantity and quantity <= 1:
            break
    if quantity:
        keys = keys[:quantity]
    if not keys:
        raise RuntimeError("Supplier returned no keys")
    return keys
