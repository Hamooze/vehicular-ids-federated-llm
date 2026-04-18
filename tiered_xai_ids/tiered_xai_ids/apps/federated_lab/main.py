import asyncio
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from tiered_xai_ids.shared.config import FederatedLabSettings, get_federated_lab_settings
from tiered_xai_ids.shared.http_client import get_json, post_json
from tiered_xai_ids.shared.logging_config import configure_logging
from tiered_xai_ids.shared.schemas import (
    DetectionBranchConfig,
    FederatedLearningConfigPatch,
    FederatedRoundRunRequest,
    MasterAssistantRequest,
)


def create_app() -> FastAPI:
    settings = get_federated_lab_settings()
    configure_logging(service_name=settings.service_name, level=settings.log_level)
    app = FastAPI(title="Federated Learning Lab", version="1.0.0")
    templates = Jinja2Templates(directory=str(Path(__file__).resolve().parents[2] / "templates"))

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"service": settings.service_name, "status": "ok"}

    @app.get("/", response_class=HTMLResponse)
    async def home(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(
            request=request,
            name="federated_lab.html",
            context={
                "request": request,
                "title": "Federated Learning Lab",
                "subtitle": "Control and monitor lightweight federated training",
            },
        )

    @app.get("/dashboard", response_class=HTMLResponse)
    async def dashboard(request: Request) -> HTMLResponse:
        return await home(request)

    @app.get("/api/config")
    async def config() -> dict[str, str]:
        return {
            "global_model_url": settings.global_model_url.rstrip("/"),
            "orchestrator_url": settings.orchestrator_url.rstrip("/"),
        }

    @app.get("/api/state")
    async def state() -> dict[str, Any]:
        global_url = settings.global_model_url.rstrip("/")
        orch_url = settings.orchestrator_url.rstrip("/")
        learning_state_task = asyncio.create_task(
            _safe_get_json(f"{global_url}/v1/federated/learning/state", settings.request_timeout_seconds)
        )
        federated_state_task = asyncio.create_task(
            _safe_get_json(f"{global_url}/v1/federated/state", settings.request_timeout_seconds)
        )
        server_status_task = asyncio.create_task(
            _safe_get_json(f"{orch_url}/api/servers/status", settings.request_timeout_seconds)
        )
        branches_task = asyncio.create_task(
            _safe_get_json(f"{orch_url}/api/detection/branches", settings.request_timeout_seconds)
        )
        live_overview_task = asyncio.create_task(
            _safe_get_json(f"{orch_url}/api/live/overview", settings.request_timeout_seconds)
        )
        learning_state, federated_state, server_status, detection_branches, live_overview = await asyncio.gather(
            learning_state_task,
            federated_state_task,
            server_status_task,
            branches_task,
            live_overview_task,
        )
        return {
            "learning_state": learning_state,
            "federated_state": federated_state,
            "server_status": server_status,
            "detection_branches": detection_branches,
            "live_overview": live_overview,
        }

    @app.post("/api/learning/config")
    async def update_learning_config(payload: FederatedLearningConfigPatch) -> dict[str, Any]:
        global_url = settings.global_model_url.rstrip("/")
        return await _safe_post_json(
            f"{global_url}/v1/federated/learning/config",
            payload.model_dump(mode="json"),
            settings.request_timeout_seconds,
        )

    @app.post("/api/learning/round/run")
    async def run_learning_round(payload: FederatedRoundRunRequest) -> dict[str, Any]:
        global_url = settings.global_model_url.rstrip("/")
        return await _safe_post_json(
            f"{global_url}/v1/federated/learning/round/run",
            payload.model_dump(mode="json"),
            settings.request_timeout_seconds,
        )

    @app.post("/api/assistant/query")
    async def assistant_query(payload: MasterAssistantRequest) -> dict[str, Any]:
        global_url = settings.global_model_url.rstrip("/")
        return await _safe_post_json(
            f"{global_url}/v1/assistant/query",
            payload.model_dump(mode="json"),
            max(15.0, settings.request_timeout_seconds),
        )

    @app.get("/api/detection/branches")
    async def detection_branches() -> dict[str, Any]:
        orch_url = settings.orchestrator_url.rstrip("/")
        return await _safe_get_json(f"{orch_url}/api/detection/branches", settings.request_timeout_seconds)

    @app.post("/api/detection/branches")
    async def detection_branches_update(payload: DetectionBranchConfig) -> dict[str, Any]:
        orch_url = settings.orchestrator_url.rstrip("/")
        return await _safe_post_json(
            f"{orch_url}/api/detection/branches",
            payload.model_dump(mode="json"),
            settings.request_timeout_seconds,
        )

    return app


async def _safe_get_json(url: str, timeout_seconds: float) -> dict[str, Any]:
    try:
        return await get_json(url, timeout_seconds=timeout_seconds)
    except Exception as exc:
        return {"error": _safe_error_text(exc), "url": url}


async def _safe_post_json(url: str, payload: dict[str, Any], timeout_seconds: float) -> dict[str, Any]:
    try:
        _, data = await post_json(url, payload, timeout_seconds=timeout_seconds)
        return data
    except Exception as exc:
        return {"error": _safe_error_text(exc), "url": url}


def _safe_error_text(exc: Exception) -> str:
    text = str(exc).strip()
    return text if text else exc.__class__.__name__


app = create_app()
