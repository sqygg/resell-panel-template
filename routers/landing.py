"""Public landing / starter page — the site front (no auth)."""
import os
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from routers.storefront import get_store_reseller

from config import settings, DEPLOY_VERSION
router = APIRouter(tags=["site"])
templates = Jinja2Templates(directory="templates")
templates.context_processors.append(lambda request: {"deploy_sha": os.getenv("RAILWAY_GIT_COMMIT_SHA", ""), "deploy_version": DEPLOY_VERSION})

# Public pages crawlers may index; everything else (dashboards, api, admin) is disallowed.
ROBOTS_TXT = """\
User-agent: *
Allow: /$
Allow: /faq$
Allow: /privacy$
Allow: /apply$
Allow: /block$
Allow: /api-docs$
Disallow: /
"""


@router.get("/robots.txt", response_class=PlainTextResponse)
def robots_txt():
    return PlainTextResponse(ROBOTS_TXT)


@router.get("/privacy", response_class=HTMLResponse)
def privacy(request: Request):
    """Public privacy policy."""
    return templates.TemplateResponse("privacy.html", {"request": request})


@router.get("/", response_class=HTMLResponse)
def landing(request: Request):
    """Public starter page. Authenticated owner dashboard lives at /admin."""
    from config import settings
    return templates.TemplateResponse("landing.html", {
        "request": request,
        "brand_name": settings.BRAND_NAME,
        "brand_tagline": settings.BRAND_TAGLINE,
    })


@router.get("/api-docs", response_class=HTMLResponse)
def api_docs(request: Request):
    """Reseller API documentation."""
    return templates.TemplateResponse(
        "api_docs.html",
        {"request": request, "reseller": get_store_reseller(request)},
    )


@router.get("/block", response_class=HTMLResponse)
def block_landing(request: Request):
    """Alias of the main landing page, served at /block."""
    from config import settings
    return templates.TemplateResponse("landing.html", {
        "request": request,
        "brand_name": settings.BRAND_NAME,
        "brand_tagline": settings.BRAND_TAGLINE,
    })


@router.get("/faq", response_class=HTMLResponse)
def faq(request: Request):
    """Public FAQ page."""
    return templates.TemplateResponse("faq.html", {"request": request})
