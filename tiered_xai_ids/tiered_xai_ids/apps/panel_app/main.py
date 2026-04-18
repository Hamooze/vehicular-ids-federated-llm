from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from tiered_xai_ids.shared.config import PanelSettings, get_panel_settings
from tiered_xai_ids.shared.logging_config import configure_logging


def create_app() -> FastAPI:
    settings = get_panel_settings()
    configure_logging(service_name=settings.service_name, level=settings.log_level)
    app = FastAPI(title="Tiered IDS Live Panel", version="1.0.0")
    templates = Jinja2Templates(directory=str(Path(__file__).resolve().parents[2] / "templates"))

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"service": settings.service_name, "status": "ok"}

    @app.get("/", response_class=HTMLResponse)
    async def home(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(
            request=request,
            name="live_panel.html",
            context={
                "request": request,
                "title": "Tiered IDS Live Panel",
                "subtitle": "Dedicated UI app with live WebSocket updates",
                "orchestrator_url": settings.orchestrator_url.rstrip("/"),
                "global_model_url": settings.global_model_url.rstrip("/"),
            },
        )

    @app.get("/dashboard", response_class=HTMLResponse)
    async def dashboard(request: Request) -> HTMLResponse:
        return await home(request)

    @app.get("/api/config")
    async def config() -> dict[str, str]:
        return {
            "orchestrator_url": settings.orchestrator_url.rstrip("/"),
            "global_model_url": settings.global_model_url.rstrip("/"),
        }

    return app


app = create_app()
