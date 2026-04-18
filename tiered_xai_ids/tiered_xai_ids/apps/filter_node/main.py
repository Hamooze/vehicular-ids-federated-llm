import asyncio
import logging
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from fastapi import Depends, FastAPI

from tiered_xai_ids.shared.auth import require_internal_key
from tiered_xai_ids.shared.attack_utils import (
    build_local_update,
    infer_attack_type,
    pick_specialized_model,
)
from tiered_xai_ids.shared.config import FilterSettings, get_filter_settings
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
from tiered_xai_ids.shared.llm_schemas import FilterLLMOutput
from tiered_xai_ids.shared.logging_config import configure_logging
from tiered_xai_ids.shared.ollama_client import OllamaClient
from tiered_xai_ids.shared.prompts import render_prompt
from tiered_xai_ids.shared.rule_engine import RuleEngine
from tiered_xai_ids.shared.schemas import (
    CaseSummary,
    DetectionBranchConfig,
    DependencyHealth,
    FederatedGlobalModelState,
    FilterCaseResponse,
    ForwardStatus,
    HealthResponse,
    LightweightModelWeights,
    LocalModelSignal,
    NodeModelDelta,
    NodeModelUpdateRequest,
    NodeModelUpdateResponse,
    SensorEvent,
)


logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    settings = get_filter_settings()
    configure_logging(service_name=settings.service_name, level=settings.log_level)
    app = FastAPI(title="Filter Node", version="1.0.0")
    app.add_middleware(CorrelationIdMiddleware)

    ollama_client = OllamaClient(
        base_url=settings.ollama_base_url,
        timeout_seconds=settings.request_timeout_seconds,
        max_retries=settings.max_model_retries,
    )
    rule_engine = RuleEngine()
    forward_tasks: set[asyncio.Task[None]] = set()
    federated_tasks: set[asyncio.Task[None]] = set()
    last_brain_forward_at = 0.0
    recent_cases: deque[dict[str, str | float | bool]] = deque(maxlen=50)
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

    @app.post("/v1/cases/from-sensor", response_model=FilterCaseResponse)
    async def from_sensor(event: SensorEvent) -> FilterCaseResponse:
        nonlocal last_brain_forward_at
        rule_assessment = rule_engine.evaluate_sensor_event(event)
        # Use log_type + evidence for attack inference; raw_excerpt is now a
        # SHA-256 hash from the sensor node and no longer contains raw content.
        attack_hint = " ".join([str(event.log_type), " ".join(event.evidence)])
        inferred_attack = _respect_branch_config(
            infer_attack_type(str(event.log_type), attack_hint),
            event.detection,
        )
        training_bucket = _attack_bucket_for_training(
            inferred_attack,
            attack_hint,
            event.detection,
        )
        selected_model = pick_specialized_model(
            default_model=settings.model_name,
            ddos_model=settings.ddos_model_name,
            gps_model=settings.gps_model_name,
            attack_type=inferred_attack,
        )
        llm_output = await _summarize_with_fallback(
            settings=settings,
            ollama_client=ollama_client,
            event=event,
            rule_assessment=rule_assessment,
            selected_model=selected_model,
        )
        base_risk_score = max(llm_output.risk_score, rule_assessment.anomaly_score * 100.0)
        local_features = build_feature_vector(
            confidence=min(1.0, base_risk_score / 100.0),
            anomaly_score=min(1.0, max(rule_assessment.anomaly_score, base_risk_score / 100.0)),
            priority_score=priority_to_score(_risk_to_priority(base_risk_score)),
            context_score=1.0 if event.classification.label != "benign" else 0.2,
        )
        risk_score = base_risk_score
        if training_bucket is not None:
            local_score = predict_score(
                local_model_state.weights[training_bucket].model_dump(),
                local_features,
            )
            risk_score = min(
                100.0,
                max(base_risk_score, ((base_risk_score / 100.0) * 0.85 + (local_score * 0.15)) * 100.0),
            )
            local_training_buffer.append(
                {
                    "attack_type": training_bucket,
                    "features": local_features,
                    "target": 1.0 if risk_score >= settings.min_risk_to_forward else 0.0,
                }
            )
        case_id = f"case-{uuid4()}"
        window_end = event.timestamp + timedelta(minutes=2)
        summary = CaseSummary(
            case_id=case_id,
            time_window=f"{event.timestamp.isoformat()} -> {window_end.isoformat()}",
            affected_assets=_dedup([event.source_device, *llm_output.affected_assets]),
            attack_hypothesis=_dedup(llm_output.attack_hypothesis),
            detection=event.detection,
            protocol_notes=llm_output.protocol_notes,
            ioc_candidates=_dedup([*llm_output.ioc_candidates, *rule_assessment.ioc_candidates]),
            timeline=_dedup([*llm_output.timeline, f"{event.timestamp.isoformat()} sensor_event:{event.event_id}"]),
            risk_score=min(100.0, risk_score),
            justification=_dedup([*event.evidence, *llm_output.justification]),
            referenced_event_ids=[event.event_id],
        )

        endpoint = f"{settings.brain_node_url.rstrip('/')}/v1/reports/from-case"
        should_forward = summary.risk_score >= settings.min_risk_to_forward
        forward_status = ForwardStatus(forwarded=False, endpoint=endpoint)
        if should_forward:
            try:
                now = time.time()
                if now - last_brain_forward_at >= 5.0:
                    task = asyncio.create_task(
                        _forward_to_brain(
                            endpoint=endpoint,
                            summary=summary,
                            timeout_seconds=settings.request_timeout_seconds,
                        )
                    )
                    forward_tasks.add(task)
                    task.add_done_callback(lambda done_task: forward_tasks.discard(done_task))
                    last_brain_forward_at = now
                    forward_status = ForwardStatus(forwarded=True, endpoint=endpoint, status_code=202)
                else:
                    forward_status = ForwardStatus(
                        forwarded=False,
                        endpoint=endpoint,
                        error="throttled_to_protect_brain",
                    )
            except Exception as exc:
                error_text = _safe_error_text(exc)
                logger.error("forward_to_brain_failed error=%s", error_text)
                forward_status = ForwardStatus(
                    forwarded=False,
                    endpoint=endpoint,
                    error=error_text,
                )

        response = FilterCaseResponse(
            correlation_id=get_correlation_id(),
            case_summary=summary,
            forward_status=forward_status,
        )
        recent_cases.appendleft(
            {
                "case_id": summary.case_id,
                "risk_score": round(summary.risk_score, 2),
                "affected_assets": ", ".join(summary.affected_assets[:3]),
                "attack_hypothesis": ", ".join(summary.attack_hypothesis[:2]),
                "attack_type": inferred_attack,
                "forwarded": forward_status.forwarded,
            }
        )
        signal_attack = _respect_branch_config(
            infer_attack_type(
                str(event.log_type),
                " ".join(summary.attack_hypothesis),
            ),
            event.detection,
        )
        if signal_attack in {"ddos", "gps_spoof"}:
            try:
                signal = LocalModelSignal(
                    attack_type=signal_attack,
                    confidence=min(1.0, summary.risk_score / 100.0),
                    anomaly_score=min(1.0, max(rule_assessment.anomaly_score, summary.risk_score / 100.0)),
                )
                update = build_local_update(
                    node_id=settings.service_name,
                    node_role="filter",
                    signal=signal,
                    metadata={"case_id": summary.case_id},
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
                logger.warning("filter_federated_enqueue_failed error=%s", _safe_error_text(exc))
        return response

    @app.get("/v1/cases/recent")
    async def recent() -> list[dict[str, str | float | bool]]:
        return list(recent_cases)

    @app.post("/v1/reset", dependencies=[Depends(require_internal_key)])
    async def reset_node() -> dict[str, str]:
        recent_cases.clear()
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


async def _summarize_with_fallback(
    settings: FilterSettings,
    ollama_client: OllamaClient,
    event: SensorEvent,
    rule_assessment,
    selected_model: str,
) -> FilterLLMOutput:
    try:
        return await ollama_client.chat_json(
            model=selected_model,
            system_prompt=render_prompt("filter_system"),
            user_prompt=render_prompt(
                "filter_user",
                sensor_event=event.model_dump(mode="json"),
                rule_assessment={
                    "suspicious": rule_assessment.suspicious,
                    "anomaly_score": rule_assessment.anomaly_score,
                    "priority": rule_assessment.priority,
                    "evidence": rule_assessment.evidence,
                    "ioc_candidates": rule_assessment.ioc_candidates,
                },
            ),
            response_model=FilterLLMOutput,
            temperature=0.1,
        )
    except Exception as exc:
        logger.error("filter_llm_fallback error=%s", str(exc))
        return FilterLLMOutput(
            affected_assets=[event.source_device],
            attack_hypothesis=[f"{event.log_type} anomaly requiring triage"],
            protocol_notes="LLM unavailable; protocol analysis downgraded to deterministic path.",
            ioc_candidates=rule_assessment.ioc_candidates,
            timeline=[f"{event.timestamp.isoformat()} event observed on sensor node"],
            risk_score=max(35.0, rule_assessment.anomaly_score * 100.0),
            justification=event.evidence or ["rule-only fallback used"],
        )


def _dedup(items: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        text = item.strip()
        if text and text not in seen:
            seen.add(text)
            ordered.append(text)
    return ordered[:40]


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


def _safe_error_text(exc: Exception) -> str:
    text = str(exc).strip()
    return text if text else exc.__class__.__name__


async def _forward_to_brain(endpoint: str, summary: CaseSummary, timeout_seconds: float) -> None:
    try:
        await post_json(
            endpoint,
            summary.model_dump(mode="json"),
            timeout_seconds=timeout_seconds,
        )
    except Exception as exc:
        logger.error("async_forward_to_brain_failed error=%s", _safe_error_text(exc))


async def _report_local_update(endpoint: str, update_payload: dict[str, object], timeout_seconds: float) -> None:
    try:
        await post_json(endpoint, update_payload, timeout_seconds=timeout_seconds)
    except Exception as exc:
        logger.warning("filter_federated_report_failed error=%s", _safe_error_text(exc))


app = create_app()
