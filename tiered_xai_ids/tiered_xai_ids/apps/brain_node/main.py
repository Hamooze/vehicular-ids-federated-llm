import asyncio
import logging
from collections import deque
from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, FastAPI

from tiered_xai_ids.shared.auth import require_internal_key
from tiered_xai_ids.shared.attack_utils import (
    build_local_update,
    infer_attack_type,
    pick_specialized_model,
)
from tiered_xai_ids.shared.config import BrainSettings, get_brain_settings
from tiered_xai_ids.shared.correlation import CorrelationIdMiddleware, get_correlation_id
from tiered_xai_ids.shared.federated_math import (
    apply_delta,
    build_feature_vector,
    compute_average_delta,
    default_attack_weights,
    predict_score,
    priority_to_score,
)
from tiered_xai_ids.shared.http_client import post_json
from tiered_xai_ids.shared.llm_schemas import BrainLLMOutput
from tiered_xai_ids.shared.logging_config import configure_logging
from tiered_xai_ids.shared.ollama_client import OllamaClient
from tiered_xai_ids.shared.prompts import render_prompt
from tiered_xai_ids.shared.schemas import (
    BrainReportResponse,
    CaseSummary,
    DetectionBranchConfig,
    DependencyHealth,
    EvidenceRow,
    FederatedGlobalModelState,
    HealthResponse,
    LightweightModelWeights,
    LocalModelSignal,
    NodeModelDelta,
    NodeModelUpdateRequest,
    NodeModelUpdateResponse,
    XAIReport,
)


logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    settings = get_brain_settings()
    configure_logging(service_name=settings.service_name, level=settings.log_level)
    app = FastAPI(title="Brain Node", version="1.0.0")
    app.add_middleware(CorrelationIdMiddleware)

    ollama_client = OllamaClient(
        base_url=settings.ollama_base_url,
        timeout_seconds=settings.request_timeout_seconds,
        max_retries=settings.max_model_retries,
    )
    federated_tasks: set[asyncio.Task[None]] = set()
    recent_reports: deque[dict[str, str]] = deque(maxlen=50)
    local_training_buffer: deque[dict[str, Any]] = deque(maxlen=400)
    local_model_state = FederatedGlobalModelState(
        revision=0,
        updated_at=datetime.now(timezone.utc),
        weights=default_attack_weights(),
    )

    @app.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        ollama_ok = await ollama_client.check_health()
        dependency = DependencyHealth(
            name="ollama",
            status="ok" if ollama_ok else "down",
            detail=settings.ollama_base_url,
        )
        return HealthResponse(
            service=settings.service_name,
            status="ok" if ollama_ok else "degraded",
            model=(
                f"default={settings.model_name},ddos={settings.ddos_model_name},"
                f"gps={settings.gps_model_name}"
            ),
            dependencies=[dependency],
        )

    @app.post("/v1/reports/from-case", response_model=BrainReportResponse)
    async def from_case(case_summary: CaseSummary) -> BrainReportResponse:
        attack_context = " ".join([*case_summary.attack_hypothesis, *case_summary.ioc_candidates])
        attack_type = _respect_branch_config(
            infer_attack_type("case_summary", attack_context),
            case_summary.detection,
        )
        training_bucket = _attack_bucket_for_training(
            attack_type,
            attack_context,
            case_summary.detection,
        )
        selected_model = pick_specialized_model(
            default_model=settings.model_name,
            ddos_model=settings.ddos_model_name,
            gps_model=settings.gps_model_name,
            attack_type=attack_type,
        )
        llm_output = await _build_report_with_fallback(
            settings,
            ollama_client,
            case_summary,
            selected_model=selected_model,
        )
        local_features = build_feature_vector(
            confidence=min(1.0, case_summary.risk_score / 100.0),
            anomaly_score=min(1.0, case_summary.risk_score / 100.0),
            priority_score=priority_to_score(_risk_to_priority(case_summary.risk_score)),
            context_score=min(1.0, len(case_summary.ioc_candidates) / 10.0),
        )
        if training_bucket is not None:
            local_score = predict_score(
                local_model_state.weights[training_bucket].model_dump(),
                local_features,
            )
            local_training_buffer.append(
                {
                    "attack_type": training_bucket,
                    "features": local_features,
                    "target": min(1.0, max(case_summary.risk_score / 100.0, local_score)),
                }
            )
        report = XAIReport(
            case_id=case_summary.case_id,
            executive_summary=llm_output.executive_summary,
            incident_narrative=llm_output.incident_narrative,
            evidence_table=[
                EvidenceRow(
                    indicator=item.indicator,
                    source=item.source,
                    relevance=item.relevance,
                )
                for item in llm_output.evidence_table
            ],
            risk_assessment=llm_output.risk_assessment,
            recommended_actions=llm_output.recommended_actions,
            uncertainties=llm_output.uncertainties,
            appendix=llm_output.appendix,
        )
        recent_reports.appendleft(
            {
                "case_id": report.case_id,
                "executive_summary": report.executive_summary[:220],
                "recommended_actions": ", ".join(report.recommended_actions[:3]),
                "uncertainties": ", ".join(report.uncertainties[:2]),
                "attack_type": attack_type,
            }
        )
        response = BrainReportResponse(correlation_id=get_correlation_id(), report=report)
        if attack_type in {"ddos", "gps_spoof"}:
            try:
                signal = LocalModelSignal(
                    attack_type=attack_type,
                    confidence=min(1.0, case_summary.risk_score / 100.0),
                    anomaly_score=min(1.0, case_summary.risk_score / 100.0),
                )
                update = build_local_update(
                    node_id=settings.service_name,
                    node_role="brain",
                    signal=signal,
                    metadata={"case_id": case_summary.case_id},
                )
                task = asyncio.create_task(
                    _report_local_update(
                        endpoint=f"{settings.global_model_url.rstrip('/')}/v1/federated/local-update",
                        update_payload=update.model_dump(mode="json"),
                        timeout_seconds=min(12.0, settings.request_timeout_seconds),
                    )
                )
                federated_tasks.add(task)
                task.add_done_callback(lambda done_task: federated_tasks.discard(done_task))
            except Exception as exc:
                logger.warning("brain_federated_enqueue_failed error=%s", _safe_error_text(exc))
        return response

    @app.get("/v1/reports/recent")
    async def recent() -> list[dict[str, str]]:
        return list(recent_reports)

    @app.post("/v1/reset", dependencies=[Depends(require_internal_key)])
    async def reset_node() -> dict[str, str]:
        recent_reports.clear()
        local_training_buffer.clear()
        return {"status": "ok"}

    @app.get("/v1/federated/model/state", dependencies=[Depends(require_internal_key)])
    async def model_state() -> dict[str, Any]:
        return {
            "node_id": settings.service_name,
            "revision": local_model_state.revision,
            "updated_at": local_model_state.updated_at.isoformat(),
            "buffer_size": len(local_training_buffer),
            "weights": local_model_state.model_dump(mode="json")["weights"],
        }

    @app.post("/v1/federated/model/sync", dependencies=[Depends(require_internal_key)])
    async def model_sync(payload: FederatedGlobalModelState) -> dict[str, Any]:
        applied = False
        if payload.revision >= local_model_state.revision:
            local_model_state.revision = payload.revision
            local_model_state.updated_at = payload.updated_at
            local_model_state.weights = payload.weights
            applied = True
        return {
            "node_id": settings.service_name,
            "applied": applied,
            "revision": local_model_state.revision,
        }

    @app.post("/v1/federated/model/update", response_model=NodeModelUpdateResponse, dependencies=[Depends(require_internal_key)])
    async def model_update(payload: NodeModelUpdateRequest) -> NodeModelUpdateResponse:
        selected_attacks = set(payload.attack_types)

        captured = list(local_training_buffer)
        local_training_buffer.clear()

        deltas: dict[str, NodeModelDelta] = {}
        sample_counts: dict[str, int] = {}
        local_weights: dict[str, LightweightModelWeights] = {}
        weighted_loss = 0.0
        total_samples = 0

        for attack in selected_attacks:
            deltas[attack] = NodeModelDelta()
            sample_counts[attack] = 0
            if attack in local_model_state.weights:
                local_weights[attack] = LightweightModelWeights(**local_model_state.weights[attack].model_dump())
            else:
                weight_keys = ("bias", "confidence", "anomaly_score", "priority_score", "context_score")
                local_weights[attack] = LightweightModelWeights(**{k: 0.0 for k in weight_keys})
            
            attack_samples = [row for row in captured if row.get("attack_type") == attack][-payload.max_samples :]
            if not attack_samples:
                continue
            current_weights = local_model_state.weights[attack].model_dump()
            delta_values, avg_loss = compute_average_delta(
                weights=current_weights,
                samples=attack_samples,
            )
            local_weights[attack] = LightweightModelWeights(
                **apply_delta(
                    current_weights,
                    delta_values,
                    learning_rate=0.15,
                )
            )
            deltas[attack] = NodeModelDelta(**delta_values)
            count = len(attack_samples)
            sample_counts[attack] = count
            total_samples += count
            weighted_loss += avg_loss * count

        averaged_loss = weighted_loss / max(1, total_samples)
        return NodeModelUpdateResponse(
            node_id=settings.service_name,
            round_id=payload.round_id,
            sample_count=total_samples,
            sample_counts=sample_counts,
            avg_loss=averaged_loss,
            weights=local_weights,
            deltas=deltas,
        )

    return app


async def _build_report_with_fallback(
    settings: BrainSettings,
    ollama_client: OllamaClient,
    case_summary: CaseSummary,
    selected_model: str,
) -> BrainLLMOutput:
    try:
        llm_timeout = min(30.0, settings.request_timeout_seconds)
        return await asyncio.wait_for(
            ollama_client.chat_json(
                model=selected_model,
                system_prompt=render_prompt("brain_system"),
                user_prompt=render_prompt(
                    "brain_user",
                    case_summary=case_summary.model_dump(mode="json"),
                ),
                response_model=BrainLLMOutput,
                temperature=0.1,
            ),
            timeout=llm_timeout,
        )
    except Exception as exc:
        logger.error("brain_llm_fallback error=%s", str(exc))
        return BrainLLMOutput(
            executive_summary=(
                f"Case {case_summary.case_id} requires immediate analyst review due to elevated risk."
            ),
            incident_narrative=(
                "Model inference path unavailable. Narrative built from deterministic correlation artifacts."
            ),
            evidence_table=[
                {
                    "indicator": indicator,
                    "source": "filter_node",
                    "relevance": "Mapped IOC from correlated summary",
                }
                for indicator in case_summary.ioc_candidates[:8]
            ],
            risk_assessment=f"Risk score from filter node: {case_summary.risk_score:.1f}/100.",
            recommended_actions=[
                "Isolate affected assets from external networks.",
                "Collect packet capture and endpoint telemetry for forensic triage.",
                "Rotate exposed credentials and revoke stale tokens.",
            ],
            uncertainties=[
                "No LLM narrative due to local model error.",
                "Attack chain stage cannot be fully confirmed without deeper packet context.",
            ],
            appendix=[f"Referenced events: {', '.join(case_summary.referenced_event_ids)}"],
        )


def _safe_error_text(exc: Exception) -> str:
    text = str(exc).strip()
    return text if text else exc.__class__.__name__


def _risk_to_priority(risk_score: float) -> str:
    if risk_score >= 85:
        return "critical"
    if risk_score >= 65:
        return "high"
    if risk_score >= 45:
        return "medium"
    return "low"


def _attack_bucket_for_training(
    attack_type: str,
    text: str,
    detection: DetectionBranchConfig,
) -> str | None:
    if attack_type in {
        "prompt_injection",
        "indirect_prompt_injection",
        "v2x_exploitation",
        "data_poisoning",
    }:
        return attack_type
    if attack_type in {"ddos", "gps_spoof"}:
        if attack_type == "ddos" and not detection.ddos_enabled:
            return None
        if attack_type == "gps_spoof" and not detection.gps_enabled:
            return None
        return attack_type
    lowered = text.lower()
    if "gps" in lowered or "spoof" in lowered or "gnss" in lowered:
        if not detection.gps_enabled:
            return None
        return "gps_spoof"
    if not detection.ddos_enabled:
        return None
    return "ddos"


def _respect_branch_config(attack_type: str, detection: DetectionBranchConfig) -> str:
    if attack_type == "ddos" and not detection.ddos_enabled:
        return "unknown"
    if attack_type == "gps_spoof" and not detection.gps_enabled:
        return "unknown"
    return attack_type


async def _report_local_update(endpoint: str, update_payload: dict[str, object], timeout_seconds: float) -> None:
    try:
        await post_json(endpoint, update_payload, timeout_seconds=timeout_seconds)
    except Exception as exc:
        logger.warning("brain_federated_report_failed error=%s", _safe_error_text(exc))


app = create_app()
