"""Configuration — loaded from .env, validated at startup."""
import os
import sys
import secrets
from dotenv import load_dotenv

load_dotenv()


class Settings:
    # ---------- SellAuth ----------
    SELLAUTH_API_KEY: str = os.getenv("SELLAUTH_API_KEY", "")
    SELLAUTH_SHOP_ID: str = os.getenv("SELLAUTH_SHOP_ID", "")

    # ---------- Admin ----------
    ADMIN_PASSWORD: str = os.getenv("ADMIN_PASSWORD", "")
    # Session secret for cookie signing
    SESSION_SECRET: str = os.getenv("SESSION_SECRET", secrets.token_urlsafe(32))

    # ---------- Network ----------
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))
    # Comma-separated list of allowed origins (empty = same-origin only)
    ALLOWED_ORIGINS: str = os.getenv("ALLOWED_ORIGINS", "")

    # ---------- Security ----------
    # Maximum request body size (bytes)
    MAX_REQUEST_SIZE_BYTES: int = int(os.getenv("MAX_REQUEST_SIZE_BYTES", "65536"))  # 64KB
    # Rate limiting
    RATE_LIMIT_ENABLED: bool = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"

    # ---------- Discord ----------
    DISCORD_BOT_TOKEN: str = os.getenv("DISCORD_BOT_TOKEN", "")
    DISCORD_OWNER_ID: str = os.getenv("DISCORD_OWNER_ID", "")
    # OAuth app credentials (for reseller Discord account linking)
    DISCORD_CLIENT_ID: str = os.getenv("DISCORD_CLIENT_ID", "")
    DISCORD_CLIENT_SECRET: str = os.getenv("DISCORD_CLIENT_SECRET", "")
    # Redirect URI must be registered in the Discord dev portal. Derived from PUBLIC_URL.
    @property
    def DISCORD_OAUTH_REDIRECT_URI(self) -> str:
        base = self.PUBLIC_URL.rstrip("/")
        return f"{base}/reseller/discord/callback" if base else ""

    # ---------- Branding ----------
    # Origins allowed to embed the panel in an iframe (CSP frame-ancestors).
    # Set to your SellAuth store, e.g. "https://astr0.mysellauth.com"
    FRAME_ANCESTORS: str = os.getenv("FRAME_ANCESTORS", "'self'")
    BRAND_NAME: str = os.getenv("BRAND_NAME", "Astro Panel")
    BRAND_TAGLINE: str = os.getenv("BRAND_TAGLINE", "Your reliable partner in gaming solutions.")
    # Public base URL for referral links (e.g. https://panel.yourdomain.com)
    PUBLIC_URL: str = os.getenv("PUBLIC_URL", "")
    # Referrer earns this % of a referred reseller's order totals
    REFERRAL_COMMISSION_PERCENT: float = float(os.getenv("REFERRAL_COMMISSION_PERCENT", "5"))
    # Default discount % applied to an approved reseller application
    DEFAULT_APPLICATION_DISCOUNT: float = float(os.getenv("DEFAULT_APPLICATION_DISCOUNT", "30"))

    # ---------- Notifications (new applications) ----------
    DISCORD_WEBHOOK_URL: str = os.getenv("DISCORD_WEBHOOK_URL", "")
    # Dedicated channel for audit/error logging (falls back to DISCORD_WEBHOOK_URL if unset)
    DISCORD_LOG_WEBHOOK_URL: str = os.getenv("DISCORD_LOG_WEBHOOK_URL", "")
    NTFY_TOPIC: str = os.getenv("NTFY_TOPIC", "")
    NTFY_SERVER: str = os.getenv("NTFY_SERVER", "https://ntfy.angelatos.gr")

    # ---------- Production ----------
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "production")

    # ---------- Validation ----------

    def validate(self) -> list[str]:
        """Validate config at startup. Returns list of warnings (empty = all good)."""
        warnings = []

        if not self.SELLAUTH_API_KEY or self.SELLAUTH_API_KEY == "your_sellauth_api_key_here":
            warnings.append("SELLAUTH_API_KEY is not set — stock will not load")
        if not self.SELLAUTH_SHOP_ID or self.SELLAUTH_SHOP_ID == "your_shop_id_here":
            warnings.append("SELLAUTH_SHOP_ID is not set — stock will not load")
        if not self.ADMIN_PASSWORD or self.ADMIN_PASSWORD == "admin":
            warnings.append("ADMIN_PASSWORD is weak or default — change it in .env")
        if not self.DISCORD_CLIENT_ID or not self.DISCORD_CLIENT_SECRET:
            warnings.append("DISCORD_CLIENT_ID/SECRET not set — reseller Discord linking disabled")
        if not self.PUBLIC_URL:
            warnings.append("PUBLIC_URL not set — OAuth redirect URI cannot be built")
        if self.DEBUG:
            warnings.append("DEBUG is enabled — disable in production")

        return warnings

    # ---------- Derived ----------

    @property
    def sellauth_base_url(self) -> str:
        return "https://api.sellauth.com/v1"

    @property
    def sellauth_headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.SELLAUTH_API_KEY}",
            "Content-Type": "application/json",
        }

    @property
    def cors_origins(self) -> list[str]:
        if not self.ALLOWED_ORIGINS:
            return []
        return [o.strip() for o in self.ALLOWED_ORIGINS.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"

    def __repr__(self) -> str:
        """Safe repr — never leaks secrets."""
        return (
            f"Settings(SELLAUTH_SHOP_ID={self.SELLAUTH_SHOP_ID!r}, "
            f"ADMIN_PASSWORD={'***' if self.ADMIN_PASSWORD else 'not set'}, "
            f"HOST={self.HOST}, PORT={self.PORT}, "
            f"DEBUG={self.DEBUG}, ENVIRONMENT={self.ENVIRONMENT})"
        )


settings = Settings()
