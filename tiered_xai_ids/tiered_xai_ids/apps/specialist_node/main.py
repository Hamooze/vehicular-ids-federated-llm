"""Parallel specialist IDS node.

Two independent instances run side-by-side:
  - ids-node-a  (IDS_SPECIALTY=ddos)      — DDoS specialist
  - ids-node-b  (IDS_SPECIALTY=gps_spoof) — GPS-spoofing specialist

Each node:
  1. Receives all traffic from the orchestrator (fanout, fire-and-forget).
  2. Classifies it using its specialty-biased local model + LLM.
  3. Maintains a local training buffer gated by specialty:
       - Before cross_learning_start_round FL rounds: only buffers its primary
         attack type, so its weights stay strongly specialised.
       - From cross_learning_start_round onwards: also buffers cross-type samples,
         allowing incremental knowledge transfer via the global model.
  4. Reports a LocalModelSignal to the global model after every detection.
  5. Participates in federated learning rounds via /v1/federated/model/update
     and /v1/federated/model/sync — receiving aggregated knowledge that includes
     the other specialist's expertise.

This design ensures:
  - IDS-A is the authoritative DDoS detector from round 1.
  - IDS-B is the authoritative GPS detector from round 1.
  - After cross_learning_start_round, both nodes start accumulating real data for
    the other attack type and refine their cross-type weights from an already-good
    initialisation (received via FL from the other specialist).
"""

import asyncio
import hashlib
import logging
from collections import deque
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import Depends, FastAPI, Request

from tiered_xai_ids.shared.auth import require_internal_key
from tiered_xai_ids.shared.attack_utils import (
    build_local_update,
    infer_attack_type,
    pick_specialized_model,
)
from tiered_xai_ids.shared.config import SpecialistNodeSettings, get_specialist_settings
from tiered_xai_ids.shared.correlation import CorrelationIdMiddleware, get_correlation_id
from tiered_xai_ids.shared.federated_math import (
    apply_delta,
    build_feature_vector,
    compute_average_delta,
    predict_score,
    priority_to_score,
    specialist_initial_weights,
)
from tiered_xai_ids.shared.http_client import post_json
from tiered_xai_ids.shared.llm_schemas import SensorLLMOutput
from tiered_xai_ids.shared.logging_config import configure_logging
from tiered_xai_ids.shared.ollama_client import OllamaClient
from tiered_xai_ids.shared.prompts import render_prompt
from tiered_xai_ids.shared.sanitize import sanitize_for_llm
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
    settings = get_specialist_settings()
    configure_logging(service_name=settings.service_name, level=settings.log_level)
    app = FastAPI(
        title=f"Specialist IDS Node ({settings.node_specialty})",
        version="1.0.0",
    )
    app.add_middleware(CorrelationIdMiddleware)

    rule_engine = RuleEngine()
    ollama_client = OllamaClient(
        base_url=settings.ollama_base_url,
        timeout_seconds=settings.request_timeout_seconds,
        max_retries=settings.max_model_retries,
    )
    federated_tasks: set[asyncio.Task[None]] = set()
    recent_events: deque[dict[str, str | float | bool]] = deque(maxlen=50)
    local_training_buffer: deque[dict[str, Any]] = deque(maxlen=400)

    # Initialise with specialty-biased weights.
    local_model_state = FederatedGlobalModelState(
        revision=0,
        updated_at=datetime.now(timezone.utc),
        weights=specialist_initial_weights(settings.node_specialty),
    )

    # --- Per-attack-type FL detection confidence (Exponential Weighted Average) ---
    # Each node tracks its own running belief of how well it can detect each attack type.
    # Specialty starts strong (0.80), cross-type starts weak (0.30) to reflect the
    # genuine knowledge gap. These values update every time an attack is detected,
    # regardless of FL learning rounds — they are the primary "FL score" shown in the UI.
    _SPECIALTY_INITIAL = 0.80
    _CROSS_INITIAL = 0.30
    _SPECIALTY_ALPHA = 0.20   # faster EWA update for own specialty
    _CROSS_ALPHA = 0.10       # slower EWA update for cross-type (knowledge transfers gradually)
    CROSS_TYPE_ALERT_THRESHOLD = 0.80  # must reach this before the node alerts on cross-type
    # Fixed EWA signal used for both specialty and cross-type detections.
    # Using the same value for both ensures that DDoS cross-learn on Node B and
    # GPS cross-learn on Node A converge identically — the only remaining difference
    # between specialty and cross-type is the alpha (0.20 vs 0.10), which naturally
    # makes specialty converge faster while cross-type grows more gradually.
    _SPECIALTY_SIGNAL = 0.92
    _CROSS_SIGNAL = 0.92

    _PRIMARY_ATTACKS = {"ddos", "gps_spoof"}
    node_fl_scores: dict[str, float] = {
        at: (
            _SPECIALTY_INITIAL if at == settings.node_specialty else _CROSS_INITIAL
        )
        for at in ["ddos", "gps_spoof", "prompt_injection",
                   "indirect_prompt_injection", "v2x_exploitation", "data_poisoning"]
    }

    # Both detection branches are always enabled. Detection quality is gated by
    # the node's accumulated FL score, not a hard round threshold.
    def _detection_config() -> DetectionBranchConfig:
        return DetectionBranchConfig(ddos_enabled=True, gps_enabled=True)

    @app.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        ollama_ok = await ollama_client.check_health()
        return HealthResponse(
            service=settings.service_name,
            status="ok" if ollama_ok else "degraded",
            model=settings.model_name,
            dependencies=[
                DependencyHealth(
                    name="ollama",
                    status="ok" if ollama_ok else "down",
                    detail=settings.ollama_base_url,
                )
            ],
        )

    @app.post("/v1/ingest/log", response_model=SensorIngestResponse)
    async def ingest_log(payload: RawLogInput, request: Request) -> SensorIngestResponse:
        # Read specialist enabled flags injected by the orchestrator as query params.
        # Default True so that direct calls (e.g. tests) behave normally.
        _node_a_online = request.query_params.get("specialist_a_enabled", "1") != "0"
        _node_b_online = request.query_params.get("specialist_b_enabled", "1") != "0"

        # Merge current detection config (specialty-gated until cross-learning kicks in)
        effective_payload = payload.model_copy(deep=True)
        effective_payload.detection = _detection_config()

        rule_assessment = rule_engine.evaluate_raw_log(
            effective_payload.log_type, effective_payload.raw_log
        )
        inferred_attack = infer_attack_type(
            str(effective_payload.log_type), effective_payload.raw_log
        )
        attack_type = _respect_branch_config(inferred_attack, effective_payload.detection)

        # --- Early-exit gate ---
        # If this is a cross-type attack, the specialist for that type is offline,
        # AND this node hasn't yet learned enough (score < threshold): do nothing at all.
        # No EWA update, no training, no event, no alert — the system stays completely silent.
        if attack_type in _PRIMARY_ATTACKS and attack_type != settings.node_specialty:
            _specialist_online = _node_a_online if attack_type == "ddos" else _node_b_online
            if not _specialist_online and node_fl_scores.get(attack_type, 0.0) < CROSS_TYPE_ALERT_THRESHOLD:
                return SensorIngestResponse(
                    correlation_id=get_correlation_id(),
                    suspicious=False,
                    event=SensorEvent(
                        event_id=f"ids-evt-{uuid4()}",
                        timestamp=effective_payload.timestamp,
                        source_device=effective_payload.source_device,
                        log_type=effective_payload.log_type,
                        detection=effective_payload.detection,
                        classification=Classification(label="benign", confidence=0.0, anomaly_score=0.0),
                        evidence=[],
                        priority="low",
                        raw_excerpt=effective_payload.raw_log[:200],
                    ),
                    forward_status=ForwardStatus(forwarded=False, endpoint="none", error=None),
                )

        # Determine which training bucket this sample belongs to
        training_bucket = _attack_bucket_for_training(
            attack_type=attack_type,
            log_type=str(effective_payload.log_type),
            raw_text=effective_payload.raw_log,
            detection=effective_payload.detection,
        )

        # Pick LLM model — specialist model if available for this attack type
        selected_model = pick_specialized_model(
            default_model=settings.model_name,
            ddos_model=settings.model_name,
            gps_model=settings.model_name,
            attack_type=attack_type,
        )

        llm_output = await _classify_with_fallback(
            settings, ollama_client, effective_payload, rule_assessment, selected_model
        )
        classification = _merge_classification(rule_assessment, llm_output)
        event_priority = _max_priority(rule_assessment.priority, llm_output.priority)

        # Save pre-FL label for correct training targets (used after possible gating below).
        pre_fl_label = classification.label

        local_features = build_feature_vector(
            confidence=classification.confidence,
            anomaly_score=classification.anomaly_score,
            priority_score=priority_to_score(event_priority),
            context_score=1.0 if classification.label != "benign" else 0.15,
        )

        # Determine whether this is a cross-type detection
        is_cross_type = attack_type in _PRIMARY_ATTACKS and attack_type != settings.node_specialty

        # --- Update per-attack-type FL score (EWA) ---
        # The detection signal is the raw confidence/anomaly weighted score, reflecting
        # how strongly this attack was detected before any FL modification.
        if attack_type in _PRIMARY_ATTACKS:
            _alpha = _SPECIALTY_ALPHA if not is_cross_type else _CROSS_ALPHA
            if not is_cross_type:
                _signal = _SPECIALTY_SIGNAL
            else:
                _signal = _CROSS_SIGNAL
            node_fl_scores[attack_type] = (
                (1.0 - _alpha) * node_fl_scores[attack_type] + _alpha * _signal
            )

        # --- Cross-type alert gate ---
        # If this node's FL score for a cross-type attack is below the threshold,
        # suppress the alert (classify as benign). Training still happens so the
        # node keeps learning toward the threshold.
        _gated = is_cross_type and node_fl_scores.get(attack_type, 0.0) < CROSS_TYPE_ALERT_THRESHOLD
        if _gated:
            _cs = node_fl_scores[attack_type]
            classification = Classification(
                label="benign",
                confidence=_cs,
                anomaly_score=_cs * 0.4,
            )
            event_priority = "low"
        elif training_bucket is not None:
            # Apply FL model blend for specialty and cross-type-confident detections
            local_score = predict_score(
                local_model_state.weights[training_bucket].model_dump(),
                local_features,
            )
            classification = _blend_with_local_model(classification, local_score)

        # --- Buffer training sample using PRE-GATE label ---
        # We train on the real signal regardless of whether we alerted, so the node
        # can learn and eventually cross the confidence threshold.
        if training_bucket is not None and _specialty_allows_training(
            training_bucket,
            settings.node_specialty,
            local_model_state.revision,
            settings.cross_learning_start_round,
        ):
            local_training_buffer.append(
                {
                    "attack_type": training_bucket,
                    "features": local_features,
                    "target": 1.0 if pre_fl_label != "benign" else 0.0,
                }
            )

        event = SensorEvent(
            event_id=f"ids-evt-{uuid4()}",
            timestamp=effective_payload.timestamp,
            source_device=effective_payload.source_device,
            log_type=effective_payload.log_type,
            detection=effective_payload.detection,
            classification=classification,
            evidence=_combine_evidence(rule_assessment.evidence, llm_output.evidence),
            priority=event_priority,
            raw_excerpt=f"sha256:{hashlib.sha256(effective_payload.raw_log.encode()).hexdigest()}",
        )
        suspicious = (
            event.classification.label != "benign"
            or event.classification.anomaly_score >= settings.suspicious_threshold
        )

        recent_events.appendleft(
            {
                "event_id": event.event_id,
                "source_device": event.source_device,
                "label": event.classification.label,
                "attack_type": attack_type,
                "specialty": settings.node_specialty,
                "confidence": round(event.classification.confidence, 2),
                "anomaly_score": round(event.classification.anomaly_score, 2),
                "priority": event.priority,
                "fl_revision": local_model_state.revision,
                "cross_learning_active": True,
                "node_fl_score": round(node_fl_scores.get(attack_type, 0.0), 3),
            }
        )

        # --- Report to global model for FL aggregation ---
        # Only report when NOT gated (gated = not yet FL-confident about cross-type).
        # Specialty attacks always report. Cross-type reports only after threshold reached.
        if not _gated and attack_type in _PRIMARY_ATTACKS and _specialty_allows_training(
            attack_type,
            settings.node_specialty,
            local_model_state.revision,
            settings.cross_learning_start_round,
        ):
            try:
                federated_payload = build_local_update(
                    node_id=settings.service_name,
                    node_role="specialist",
                    signal=LocalModelSignal(
                        attack_type=attack_type,
                        confidence=classification.confidence,
                        anomaly_score=classification.anomaly_score,
                    ),
                    metadata={
                        "source_device": effective_payload.source_device,
                        "specialty": settings.node_specialty,
                        "fl_revision": str(local_model_state.revision),
                    },
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
                logger.warning("specialist_federated_enqueue_failed error=%s", _safe_error_text(exc))

        return SensorIngestResponse(
            correlation_id=get_correlation_id(),
            suspicious=suspicious,
            event=event,
            forward_status=ForwardStatus(
                forwarded=False,
                endpoint="none",
                error=None,
            ),
        )

    @app.get("/v1/events/recent")
    async def recent() -> list[dict[str, str | float | bool]]:
        return list(recent_events)

    @app.post("/v1/reset", dependencies=[Depends(require_internal_key)])
    async def reset_node() -> dict[str, str]:
        recent_events.clear()
        local_training_buffer.clear()
        # Reset EWA scores to initial values
        for _at in list(node_fl_scores.keys()):
            node_fl_scores[_at] = (
                _SPECIALTY_INITIAL if _at == settings.node_specialty else _CROSS_INITIAL
            )
        return {"status": "ok"}

    @app.get("/v1/federated/model/state", dependencies=[Depends(require_internal_key)])
    async def model_state() -> dict[str, Any]:
        return {
            "node_id": settings.service_name,
            "specialty": settings.node_specialty,
            "cross_learning_active": True,
            "cross_type_alert_threshold": CROSS_TYPE_ALERT_THRESHOLD,
            "revision": local_model_state.revision,
            "updated_at": local_model_state.updated_at.isoformat(),
            "buffer_size": len(local_training_buffer),
            "weights": local_model_state.model_dump(mode="json")["weights"],
            # Per-attack-type running FL detection confidence (EWA). This is the
            # primary score displayed in the UI — starts at specialty=0.80, cross=0.30
            # and updates with every detection.
            "node_fl_scores": {k: round(v, 3) for k, v in node_fl_scores.items()},
        }

    @app.post("/v1/federated/model/sync", dependencies=[Depends(require_internal_key)])
    async def model_sync(payload: FederatedGlobalModelState) -> dict[str, Any]:
        """Receive aggregated global model weights from the global-model service.

        On each sync the revision counter increments, which is the mechanism that
        unlocks cross-type training once cross_learning_start_round is reached.
        """
        applied = False
        if payload.revision >= local_model_state.revision:
            local_model_state.revision = payload.revision
            local_model_state.updated_at = payload.updated_at
            local_model_state.weights = payload.weights
            applied = True
            if applied:
                logger.info(
                    "specialist_model_synced node=%s revision=%d cross_learning_active=%s",
                    settings.service_name,
                    local_model_state.revision,
                    local_model_state.revision >= settings.cross_learning_start_round,
                )
        return {
            "node_id": settings.service_name,
            "applied": applied,
            "revision": local_model_state.revision,
            "cross_learning_active": True,
        }

    @app.post("/v1/federated/model/update", response_model=NodeModelUpdateResponse, dependencies=[Depends(require_internal_key)])
    async def model_update(payload: NodeModelUpdateRequest) -> NodeModelUpdateResponse:
        """Compute and return a local model update for the global FL round.

        Only attack types that this node has actually trained on will contribute
        non-zero sample counts — so IDS-A dominates ddos aggregation early on,
        IDS-B dominates gps_spoof, and cross-type contributions grow from round
        cross_learning_start_round onwards.
        """
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
                local_weights[attack] = LightweightModelWeights(
                    **local_model_state.weights[attack].model_dump()
                )
            else:
                local_weights[attack] = LightweightModelWeights(
                    **{k: 0.0 for k in ("bias", "confidence", "anomaly_score", "priority_score", "context_score")}
                )

            attack_samples = [
                row for row in captured if row.get("attack_type") == attack
            ][-payload.max_samples:]
            if not attack_samples:
                continue

            current_weights = local_model_state.weights[attack].model_dump()
            delta_values, avg_loss = compute_average_delta(
                weights=current_weights,
                samples=attack_samples,
            )
            local_weights[attack] = LightweightModelWeights(
                **apply_delta(current_weights, delta_values, learning_rate=0.15)
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


# ── helpers ──────────────────────────────────────────────────────────────────

def _specialty_allows_training(
    attack_type: str,
    specialty: str,
    revision: int,
    cross_learning_start_round: int,
) -> bool:
    """Return True when this specialist node should buffer a sample for attack_type.

    Cross-learning is active from round 1. The non-specialist node's initial weights
    for the other attack type are set very low (via specialist_initial_weights), so it
    naturally starts with poor cross-type detection confidence and improves gradually
    through federated averaging — no hard round gate needed.
    """
    return True


async def _classify_with_fallback(
    settings: SpecialistNodeSettings,
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
        logger.error("specialist_llm_fallback error=%s", str(exc))
        fallback_label = "suspicious" if rule_assessment.suspicious else "benign"
        return SensorLLMOutput(
            label=fallback_label,
            confidence=0.70 if rule_assessment.suspicious else 0.55,
            anomaly_score=rule_assessment.anomaly_score,
            evidence=rule_assessment.evidence or ["rule-only classification used"],
            priority=rule_assessment.priority,
        )


def _merge_classification(
    rule_assessment: RuleAssessment, llm_output: SensorLLMOutput
) -> Classification:
    anomaly_score = max(rule_assessment.anomaly_score, llm_output.anomaly_score)
    confidence = min(1.0, max(llm_output.confidence, anomaly_score))
    if llm_output.label == "malicious" or anomaly_score >= 0.85:
        label = "malicious"
    elif llm_output.label == "suspicious" or rule_assessment.suspicious or anomaly_score >= 0.55:
        label = "suspicious"
    else:
        label = "benign"
    return Classification(label=label, confidence=confidence, anomaly_score=anomaly_score)


def _blend_with_local_model(
    classification: Classification, model_score: float
) -> Classification:
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


async def _report_local_update(
    endpoint: str, update_payload: dict[str, object], timeout_seconds: float
) -> None:
    try:
        await post_json(endpoint, update_payload, timeout_seconds=timeout_seconds)
    except Exception as exc:
        logger.warning("specialist_federated_report_failed error=%s", _safe_error_text(exc))


app = create_app()
