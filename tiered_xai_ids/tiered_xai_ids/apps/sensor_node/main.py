import asyncio
import hashlib
import logging
from collections import deque
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import Depends, FastAPI

from tiered_xai_ids.shared.attack_utils import (
    build_local_update,
    infer_attack_type,
    pick_specialized_model,
)
from tiered_xai_ids.shared.auth import require_internal_key
from tiered_xai_ids.shared.config import SensorSettings, get_sensor_settings
from tiered_xai_ids.shared.correlation import CorrelationIdMiddleware, get_correlation_id
from tiered_xai_ids.shared.sanitize import sanitize_for_llm
from tiered_xai_ids.shared.federated_math import (
    apply_delta,
    build_feature_vector,
    compute_average_delta,
    default_attack_weights,
    predict_score,
    priority_to_score,
)
from tiered_xai_ids.shared.http_client import post_json
from tiered_xai_ids.shared.llm_schemas import SensorLLMOutput
from tiered_xai_ids.shared.logging_config import configure_logging
from tiered_xai_ids.shared.ollama_client import OllamaClient
from tiered_xai_ids.shared.prompts import render_prompt
from tiered_xai_ids.shared.rule_engine import RuleAssessment, RuleEngine
from tiered_xai_ids.shared.schemas import (
    Classification,
    DetectionBranchConfig,
    DependencyHealth,
    FederatedGlobalModelState,
    ForwardStatus,
    HealthResponse,
    LightweightModelWeights,
    LocalModelSignal,
    NodeModelDelta,
    NodeModelUpdateRequest,
    NodeModelUpdateResponse,
    RawLogInput,
    SensorEvent,
    SensorIngestResponse,
)


logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    settings = get_sensor_settings()
    configure_logging(service_name=settings.service_name, level=settings.log_level)
    app = FastAPI(title="Sensor Node", version="1.0.0")
    app.add_middleware(CorrelationIdMiddleware)

    rule_engine = RuleEngine()
    ollama_client = OllamaClient(
        base_url=settings.ollama_base_url,
        timeout_seconds=settings.request_timeout_seconds,
        max_retries=settings.max_model_retries,
    )
    forward_tasks: set[asyncio.Task[None]] = set()
    federated_tasks: set[asyncio.Task[None]] = set()
    recent_events: deque[dict[str, str | float | bool]] = deque(maxlen=50)
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

    @app.post("/v1/ingest/log", response_model=SensorIngestResponse)
    async def ingest_log(payload: RawLogInput) -> SensorIngestResponse:
        # Always enforce server-side detection config; ignore caller-supplied flags.
        payload = payload.model_copy(update={"detection": DetectionBranchConfig()})
        rule_assessment = rule_engine.evaluate_raw_log(payload.log_type, payload.raw_log)
        inferred_attack = infer_attack_type(str(payload.log_type), payload.raw_log)
        attack_type = _respect_branch_config(inferred_attack, payload.detection)
        training_bucket = _attack_bucket_for_training(
            attack_type=attack_type,
            log_type=str(payload.log_type),
            raw_text=payload.raw_log,
            detection=payload.detection,
        )
        selected_model = pick_specialized_model(
            default_model=settings.model_name,
            ddos_model=settings.ddos_model_name,
            gps_model=settings.gps_model_name,
            attack_type=attack_type,
        )
        llm_output = await _classify_with_fallback(
            settings,
            ollama_client,
            payload,
            rule_assessment,
            selected_model=selected_model,
        )
        classification = _merge_classification(rule_assessment, llm_output)
        event_priority = _max_priority(rule_assessment.priority, llm_output.priority)
        local_features = build_feature_vector(
            confidence=classification.confidence,
            anomaly_score=classification.anomaly_score,
            priority_score=priority_to_score(event_priority),
            context_score=1.0 if classification.label != "benign" else 0.15,
        )
        if training_bucket is not None:
            local_score = predict_score(
                local_model_state.weights[training_bucket].model_dump(),
                local_features,
            )
            classification = _blend_with_local_model(classification, local_score)
            local_training_buffer.append(
                {
                    "attack_type": training_bucket,
                    "features": local_features,
                    "target": 1.0 if classification.label != "benign" else 0.0,
                }
            )

        event = SensorEvent(
            event_id=f"evt-{uuid4()}",
            timestamp=payload.timestamp,
            source_device=payload.source_device,
            log_type=payload.log_type,
            detection=payload.detection,
            classification=classification,
            evidence=_combine_evidence(rule_assessment.evidence, llm_output.evidence),
            priority=event_priority,
            raw_excerpt=f"sha256:{hashlib.sha256(payload.raw_log.encode()).hexdigest()}",
        )
        suspicious = (
            event.classification.label != "benign"
            or event.classification.anomaly_score >= settings.suspicious_threshold
        )

        endpoint = f"{settings.filter_node_url.rstrip('/')}/v1/cases/from-sensor"
        forward_status = ForwardStatus(forwarded=False, endpoint=endpoint)
        if suspicious:
            try:
                task = asyncio.create_task(
                    _forward_to_filter(
                        endpoint=endpoint,
                        event=event,
                        timeout_seconds=settings.request_timeout_seconds,
                    )
                )
                forward_tasks.add(task)
                task.add_done_callback(lambda done_task: forward_tasks.discard(done_task))
                forward_status = ForwardStatus(forwarded=True, endpoint=endpoint, status_code=202)
            except Exception as exc:
                error_text = _safe_error_text(exc)
                logger.error("forward_to_filter_failed error=%s", error_text)
                forward_status = ForwardStatus(
                    forwarded=False,
                    endpoint=endpoint,
                    error=error_text,
                )

        response = SensorIngestResponse(
            correlation_id=get_correlation_id(),
            suspicious=suspicious,
            event=event,
            forward_status=forward_status,
        )
        recent_events.appendleft(
            {
                "event_id": event.event_id,
                "source_device": event.source_device,
                "label": event.classification.label,
                "attack_type": attack_type,
                "confidence": round(event.classification.confidence, 2),
                "anomaly_score": round(event.classification.anomaly_score, 2),
                "priority": event.priority,
                "forwarded": forward_status.forwarded,
            }
        )
        if attack_type in {"ddos", "gps_spoof"}:
            try:
                federated_payload = build_local_update(
                    node_id=settings.service_name,
                    node_role="sensor",
                    signal=LocalModelSignal(
                        attack_type=attack_type,
                        confidence=classification.confidence,
                        anomaly_score=classification.anomaly_score,
                    ),
                    metadata={"source_device": payload.source_device},
                )
                task = asyncio.create_task(
                    _report_local_update(
                        endpoint=f"{settings.global_model_url.rstrip('/')}/v1/federated/local-update",
                        update_payload=federated_payload.model_dump(mode="json"),
                        timeout_seconds=min(12.0, settings.request_timeout_seconds),
                    )
                )
                federated_tasks.add(task)
                task.add_done_callback(lambda done_task: federated_tasks.discard(done_task))
            except Exception as exc:
                logger.warning("sensor_federated_enqueue_failed error=%s", _safe_error_text(exc))
        return response

    @app.get("/v1/events/recent")
    async def recent() -> list[dict[str, str | float | bool]]:
        return list(recent_events)

    @app.post("/v1/reset", dependencies=[Depends(require_internal_key)])
    async def reset_node() -> dict[str, str]:
        recent_events.clear()
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


async def _classify_with_fallback(
    settings: SensorSettings,
    ollama_client: OllamaClient,
    payload: RawLogInput,
    rule_assessment: RuleAssessment,
    selected_model: str,
) -> SensorLLMOutput:
    try:
        return await ollama_client.chat_json(
            model=selected_model,
            system_prompt=render_prompt("sensor_system"),
            user_prompt=render_prompt(
                "sensor_user",
                source_device=payload.source_device,
                log_type=payload.log_type,
                timestamp=payload.timestamp.isoformat(),
                raw_log=sanitize_for_llm(payload.raw_log),
                rule_assessment={
                    "suspicious": rule_assessment.suspicious,
                    "anomaly_score": rule_assessment.anomaly_score,
                    "priority": rule_assessment.priority,
                    "evidence": rule_assessment.evidence,
                    "ioc_candidates": rule_assessment.ioc_candidates,
                },
            ),
            response_model=SensorLLMOutput,
            temperature=0.0,
        )
    except Exception as exc:
        logger.error("sensor_llm_fallback error=%s", str(exc))
        fallback_label = "suspicious" if rule_assessment.suspicious else "benign"
        fallback_confidence = 0.70 if rule_assessment.suspicious else 0.55
        return SensorLLMOutput(
            label=fallback_label,
            confidence=fallback_confidence,
            anomaly_score=rule_assessment.anomaly_score,
            evidence=rule_assessment.evidence or ["rule-only classification used"],
            priority=rule_assessment.priority,
        )


def _merge_classification(rule_assessment: RuleAssessment, llm_output: SensorLLMOutput) -> Classification:
    anomaly_score = max(rule_assessment.anomaly_score, llm_output.anomaly_score)
    confidence = min(1.0, max(llm_output.confidence, anomaly_score))
    if llm_output.label == "malicious" or anomaly_score >= 0.85:
        label = "malicious"
    elif llm_output.label == "suspicious" or rule_assessment.suspicious or anomaly_score >= 0.55:
        label = "suspicious"
    else:
        label = "benign"
    return Classification(label=label, confidence=confidence, anomaly_score=anomaly_score)


def _blend_with_local_model(classification: Classification, model_score: float) -> Classification:
    blended = min(1.0, max(0.0, (classification.anomaly_score * 0.85) + (model_score * 0.15)))
    boosted_confidence = min(1.0, max(classification.confidence, blended))
    return Classification(
        label=classification.label,
        confidence=boosted_confidence,
        anomaly_score=blended,
    )


def _attack_bucket_for_training(
    attack_type: str,
    log_type: str,
    raw_text: str,
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
    combined = f"{log_type} {raw_text}".lower()
    if "gps" in combined or "gnss" in combined or "spoof" in combined:
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


def _combine_evidence(rule_evidence: list[str], llm_evidence: list[str]) -> list[str]:
    seen: set[str] = set()
    merged: list[str] = []
    for item in [*rule_evidence, *llm_evidence]:
        normalized = item.strip()
        if normalized and normalized not in seen:
            seen.add(normalized)
            merged.append(normalized)
    return merged[:20]


def _max_priority(first: str, second: str) -> str:
    rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    return first if rank.get(first, 1) >= rank.get(second, 1) else second


def _safe_error_text(exc: Exception) -> str:
    text = str(exc).strip()
    return text if text else exc.__class__.__name__


async def _forward_to_filter(endpoint: str, event: SensorEvent, timeout_seconds: float) -> None:
    try:
        await post_json(
            endpoint,
            event.model_dump(mode="json"),
            timeout_seconds=timeout_seconds,
        )
    except Exception as exc:
        logger.error("async_forward_to_filter_failed error=%s", _safe_error_text(exc))


async def _report_local_update(endpoint: str, update_payload: dict[str, object], timeout_seconds: float) -> None:
    try:
        await post_json(endpoint, update_payload, timeout_seconds=timeout_seconds)
    except Exception as exc:
        logger.warning("sensor_federated_report_failed error=%s", _safe_error_text(exc))


app = create_app()
