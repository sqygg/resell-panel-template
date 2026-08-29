"""Security middleware — rate limiting, security headers, request validation."""
import time
import hashlib
from collections import defaultdict
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from config import settings


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Inject security headers on every response."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        # Allow embedding only from the SellAuth store (iframe on /blog).
        # frame-ancestors supersedes X-Frame-Options; we omit X-Frame-Options=DENY
        # so the panel can be framed by the approved origin.
        frame_ancestors = settings.FRAME_ANCESTORS or "'self'"
        response.headers["Content-Security-Policy"] = (
            f"default-src 'self'; "
            f"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            f"font-src 'self' https://fonts.gstatic.com; "
            f"script-src 'self' 'unsafe-inline'; "
            f"img-src 'self' data: https:; "
            f"frame-ancestors {frame_ancestors}"
        )
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cache-Control"] = "no-store, max-age=0"
        # Strip server header if present
        if "Server" in response.headers:
            del response.headers["Server"]
        return response


class RateLimiter:
    """In-memory rate limiter using sliding window."""

    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._windows: dict[str, list[float]] = defaultdict(list)

    def _clean(self, key: str, now: float):
        cutoff = now - self.window_seconds
        self._windows[key] = [t for t in self._windows[key] if t > cutoff]

    def is_allowed(self, key: str) -> bool:
        now = time.time()
        self._clean(key, now)
        if len(self._windows[key]) >= self.max_requests:
            return False
        self._windows[key].append(now)
        return True

    def remaining(self, key: str) -> int:
        self._clean(key, time.time())
        return max(0, self.max_requests - len(self._windows[key]))


# Rate limiter instances
global_limiter = RateLimiter(max_requests=60, window_seconds=60)       # 60 req/min per IP
webhook_limiter = RateLimiter(max_requests=30, window_seconds=60)      # 30 req/min per reseller
login_limiter = RateLimiter(max_requests=5, window_seconds=60)         # 5 login attempts/min per IP
admin_api_limiter = RateLimiter(max_requests=30, window_seconds=60)    # 30 admin API calls/min


def get_client_ip(request: Request) -> str:
    """Extract real client IP, respecting X-Forwarded-For."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    client = request.client
    return client.host if client else "unknown"


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Apply rate limiting based on path prefix."""

    async def dispatch(self, request: Request, call_next):
        ip = get_client_ip(request)
        path = request.url.path

        # Determine which limiter to use
        if path.startswith("/api/webhook/"):
            # Rate limit per reseller key (extract from path)
            parts = path.split("/")
            if len(parts) >= 4:
                key_hash = hashlib.sha256(parts[3].encode()).hexdigest()[:12]
                limiter_key = f"wh:{key_hash}"
            else:
                limiter_key = f"wh:{ip}"
            limiter = webhook_limiter
        elif path.startswith("/api/admin/"):
            limiter_key = f"admin:{ip}"
            limiter = admin_api_limiter
        elif path in ("/login", "/auth", "/apply") and request.method == "POST":
            # Auth/registration endpoints: strict per-IP limit to stop brute force
            limiter_key = f"login:{ip}"
            limiter = login_limiter
        else:
            limiter_key = f"global:{ip}"
            limiter = global_limiter

        if not limiter.is_allowed(limiter_key):
            retry_after = limiter.window_seconds
            raise HTTPException(
                status_code=429,
                detail="Too many requests",
                headers={"Retry-After": str(retry_after)},
            )

        response = await call_next(request)

        # Add rate limit headers
        remaining = limiter.remaining(limiter_key)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Limit"] = str(limiter.max_requests)

        return response


class SizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject oversized requests."""

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length", "0")
        max_size = settings.MAX_REQUEST_SIZE_BYTES
        if int(content_length) > max_size:
            raise HTTPException(status_code=413, detail="Request too large")
        return await call_next(request)
