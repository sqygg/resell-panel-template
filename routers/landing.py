"""Public landing / starter page — the site front (no auth)."""
import os
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter(tags=["site"])
templates = Jinja2Templates(directory="templates")
templates.context_processors.append(lambda request: {"deploy_sha": os.getenv("RAILWAY_GIT_COMMIT_SHA", "")})


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
    """Reseller API documentation (public)."""
    return templates.TemplateResponse("api_docs.html", {"request": request})


@router.get("/block", response_class=HTMLResponse)
def block_landing(request: Request):
    """Alias of the main landing page, served at /block."""
    from config import settings
    return templates.TemplateResponse("landing.html", {
        "request": request,
        "brand_name": settings.BRAND_NAME,
        "brand_tagline": settings.BRAND_TAGLINE,
    })
