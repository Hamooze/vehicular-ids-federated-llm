import asyncio
import logging
from collections import deque
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI

from tiered_xai_ids.shared.config import GlobalModelSettings, get_global_model_settings
from tiered_xai_ids.shared.correlation import CorrelationIdMiddleware
from tiered_xai_ids.shared.federated_math import default_attack_weights
from tiered_xai_ids.shared.http_client import post_json
from tiered_xai_ids.shared.llm_schemas import GlobalCoordinatorLLMOutput, MasterAssistantLLMOutput
from tiered_xai_ids.shared.logging_config import configure_logging
from tiered_xai_ids.shared.ollama_client import OllamaClient
from tiered_xai_ids.shared.prompts import render_prompt
from tiered_xai_ids.shared.schemas import (
    CoordinationPolicy,
    DependencyHealth,
    FederatedGlobalModelState,
    FederatedIngestResponse,
    FederatedLearningConfig,
    FederatedLearningConfigPatch,
    FederatedLearningStateResponse,
    FederatedRoundRunRequest,
    FederatedRoundRunResponse,
    FederatedRoundSnapshot,
    HealthResponse,
    LightweightModelWeights,
    LocalModelUpdate,
    MasterAssistantRequest,
    MasterAssistantResponse,
    NodeModelUpdateRequest,
    NodeModelUpdateResponse,
    NodeRoundResult,
)


logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    settings = get_global_model_settings()
    configure_logging(service_name=settings.service_name, level=settings.log_level)
    app = FastAPI(title="Tiered IDS Global Model", version="1.0.0")
    app.add_middleware(CorrelationIdMiddleware)

    ollama_client = OllamaClient(
        base_url=settings.ollama_base_url,
        timeout_seconds=settings.request_timeout_seconds,
        max_retries=settings.max_model_retries,
    )
    state_lock = asyncio.Lock()
    learning_round_lock = asyncio.Lock()
    auto_round_task: asyncio.Task[None] | None = None
    history: deque[FederatedRoundSnapshot] = deque(maxlen=max(1, settings.history_size))
    round_id = 1
    round_started_at = datetime.now(timezone.utc)
    updates: list[LocalModelUpdate] = []
    totals: dict[str, float] = {}
    counts: dict[str, int] = {}
    current_policy = CoordinationPolicy(
        round_id=round_id,
        strategy="bootstrap",
        recommendation="Collect initial detections to compute the first federated policy.",
        recommended_actions=["Send sensor/filter/brain local updates to this service."],
        weights={attack: 0.5 for attack in ["ddos", "gps_spoof", "prompt_injection", "indirect_prompt_injection", "v2x_exploitation", "data_poisoning"]},
        contributing_nodes=[],
    )
    learning_config = FederatedLearningConfig(
        enabled=settings.learning_enabled,
        auto_rounds=settings.auto_rounds,
        learning_rate=settings.learning_rate,
        min_samples_per_node=settings.min_samples_per_node,
        max_samples_per_node=settings.max_samples_per_node,
        auto_round_interval_seconds=settings.auto_round_interval_seconds,
    )
    global_model_state = FederatedGlobalModelState(
        revision=0,
        updated_at=datetime.now(timezone.utc),
        weights=default_attack_weights(),
    )
    latest_learning_round: FederatedRoundRunResponse | None = None
    # Only the specialist IDS nodes participate in FL rounds.
    # sensor-node / filter-node / brain-node are detection pipeline nodes
    # and do not implement the /v1/federated/model/update endpoint.
    node_urls = {
        "ids-node-a": settings.ids_a_url.rstrip("/"),
        "ids-node-b": settings.ids_b_url.rstrip("/"),
    }

    def _current_scores() -> dict[str, float]:
        # When no updates yet for a given attack in the current round, fall back to the
        # last closed round's score rather than resetting to 0.5.
        last_scores = dict(history[0].scores) if history else {}
        attacks = ["ddos", "gps_spoof", "prompt_injection", "indirect_prompt_injection", "v2x_exploitation", "data_poisoning"]
        scores = {}
        for attack in attacks:
            if counts.get(attack, 0) > 0:
                s = totals[attack] / counts[attack]
                scores[attack] = min(1.0, max(0.0, s))
            else:
                scores[attack] = last_scores.get(attack, 0.5)
        return scores


    def _current_snapshot() -> FederatedRoundSnapshot:
        scores = _current_scores()
        participants = sorted({item.node_id for item in updates})
        return FederatedRoundSnapshot(
            round_id=round_id,
            started_at=round_started_at,
            closed_at=None,
            update_count=len(updates),
            scores=scores,
            node_participants=participants,
            policy=current_policy,
        )

    async def _generate_policy(
        *,
        target_round: int,
        scores: dict[str, float],
        participants: list[str],
        update_count: int,
    ) -> CoordinationPolicy:
        try:
            llm = await ollama_client.chat_json(
                model=settings.model_name,
                system_prompt=render_prompt("global_system"),
                user_prompt=render_prompt(
                    "global_user",
                    round_id=target_round,
                    scores={k: round(v, 4) for k, v in scores.items()},
                    update_count=update_count,
                    participants=participants,
                ),
                response_model=GlobalCoordinatorLLMOutput,
                temperature=0.1,
            )
            return CoordinationPolicy(
                round_id=target_round,
                strategy=llm.strategy,
                recommendation=llm.recommendation,
                recommended_actions=llm.recommended_actions,
                weights=scores,
                contributing_nodes=participants,
            )
        except Exception as exc:
            logger.warning("global_policy_fallback error=%s", str(exc))
            dominant = max(scores, key=scores.get) if scores else "ddos"
            return CoordinationPolicy(
                round_id=target_round,
                strategy="weighted_fallback",
                recommendation=(
                    f"Prioritize {dominant} defenses based on current federated confidence."
                ),
                recommended_actions=[
                    "Tighten rate limits and verify network flow baselines.",
                    "Validate GNSS integrity and detect impossible location jumps.",
                    "Increase analyst sampling on events above 0.7 anomaly score.",
                ],
                weights=scores,
                contributing_nodes=participants,
            )

    async def _close_round(reason: str) -> FederatedRoundSnapshot:
        nonlocal round_id
        nonlocal round_started_at
        nonlocal updates
        nonlocal totals
        nonlocal counts
        nonlocal current_policy

        scores = _current_scores()
        participants = sorted({item.node_id for item in updates})
        target_round = round_id
        policy = await _generate_policy(
            target_round=target_round,
            scores=scores,
            participants=participants,
            update_count=len(updates),
        )
        current_policy = policy
        closed = datetime.now(timezone.utc)
        snapshot = FederatedRoundSnapshot(
            round_id=target_round,
            started_at=round_started_at,
            closed_at=closed,
            update_count=len(updates),
            scores=scores,
            node_participants=participants,
            policy=policy,
        )
        history.appendleft(snapshot)
        had_updates = len(updates) > 0
        logger.info(
            f"federated_round_closed round={target_round} reason={reason} updates={len(updates)} scores={scores}",
        )
        round_id = target_round + 1
        round_started_at = closed
        updates = []
        totals = {}
        counts = {}
        # Trigger a FL learning round immediately after each scoring round that had data.
        # This keeps specialist node weights up-to-date without waiting for the auto timer.
        if had_updates and learning_config.enabled:
            asyncio.create_task(
                _execute_learning_round(force=False, max_samples_override=None, trigger=f"post_round_{target_round}")
            )
        return snapshot

    async def _collect_node_update(
        node_id: str,
        base_url: str,
        payload: NodeModelUpdateRequest,
    ) -> tuple[str, NodeModelUpdateResponse | None, str | None]:
        endpoint = f"{base_url}/v1/federated/model/update"
        try:
            _, data = await post_json(
                endpoint,
                payload.model_dump(mode="json"),
                timeout_seconds=min(20.0, settings.request_timeout_seconds),
            )
            return node_id, NodeModelUpdateResponse.model_validate(data), None
        except Exception as exc:
            return node_id, None, _safe_error_text(exc)

    async def _sync_node_model(
        node_id: str,
        base_url: str,
        model_state: FederatedGlobalModelState,
    ) -> tuple[str, bool]:
        endpoint = f"{base_url}/v1/federated/model/sync"
        try:
            _, data = await post_json(
                endpoint,
                model_state.model_dump(mode="json"),
                timeout_seconds=min(20.0, settings.request_timeout_seconds),
            )
            applied = bool(data.get("applied", False)) if isinstance(data, dict) else False
            return node_id, applied
        except Exception as exc:
            logger.warning("federated_sync_failed node=%s error=%s", node_id, _safe_error_text(exc))
            return node_id, False

    async def _execute_learning_round(
        *,
        force: bool,
        max_samples_override: int | None,
        trigger: str,
    ) -> FederatedRoundRunResponse:
        nonlocal global_model_state
        nonlocal latest_learning_round
        async with learning_round_lock:
            async with state_lock:
                config_snapshot = learning_config.model_copy(deep=True)
                active_round = round_id
                model_snapshot = global_model_state.model_copy(deep=True)

            if not config_snapshot.enabled and not force:
                response = FederatedRoundRunResponse(
                    round_id=active_round,
                    applied=False,
                    reason="learning_disabled",
                    learning_config=config_snapshot,
                    model_state=model_snapshot,
                    node_results=[],
                    synced_nodes=[],
                )
                async with state_lock:
                    latest_learning_round = response
                return response

            max_samples = max_samples_override or config_snapshot.max_samples_per_node
            request_payload = NodeModelUpdateRequest(
                round_id=active_round,
                max_samples=max_samples,
                attack_types=["ddos", "gps_spoof", "prompt_injection", "indirect_prompt_injection", "v2x_exploitation", "data_poisoning"],
            )
            collection = await asyncio.gather(
                *[
                    _collect_node_update(node_id, node_base_url, request_payload)
                    for node_id, node_base_url in node_urls.items()
                ]
            )

            node_results: list[NodeRoundResult] = []
            eligible_updates: list[NodeModelUpdateResponse] = []
            for node_id, response, error in collection:
                if error or response is None:
                    node_results.append(
                        NodeRoundResult(
                            node_id=node_id,
                            status="error",
                            sample_counts={},
                            detail=error or "update_failed",
                        )
                    )
                    continue
                if response.sample_count < config_snapshot.min_samples_per_node:
                    node_results.append(
                        NodeRoundResult(
                            node_id=node_id,
                            status="skipped",
                            sample_count=response.sample_count,
                            sample_counts=response.sample_counts,
                            avg_loss=response.avg_loss,
                            detail=f"need>={config_snapshot.min_samples_per_node}",
                        )
                    )
                    continue
                node_results.append(
                    NodeRoundResult(
                        node_id=node_id,
                        status="ok",
                        sample_count=response.sample_count,
                        sample_counts=response.sample_counts,
                        avg_loss=response.avg_loss,
                        detail="accepted",
                    )
                )
                eligible_updates.append(response)

            if not eligible_updates:
                response = FederatedRoundRunResponse(
                    round_id=active_round,
                    applied=False,
                    reason="no_eligible_node_updates",
                    learning_config=config_snapshot,
                    model_state=model_snapshot,
                    node_results=node_results,
                    synced_nodes=[],
                )
                async with state_lock:
                    latest_learning_round = response
                return response

            weight_keys = tuple(LightweightModelWeights().model_dump().keys())
            aggregate: dict[str, dict[str, float]] = {}
            for attack in request_payload.attack_types:
                aggregate[attack] = {key: 0.0 for key in weight_keys}
            
            round_totals = {attack: 0 for attack in request_payload.attack_types}
            for update in eligible_updates:
                for attack in request_payload.attack_types:
                    bucket_count = int(update.sample_counts.get(attack, 0))
                    if bucket_count <= 0:
                        continue
                    weight_values = update.weights[attack].model_dump()
                    for key in weight_keys:
                        aggregate[attack][key] += float(weight_values.get(key, 0.0)) * bucket_count
                    round_totals[attack] += bucket_count

            new_weights: dict[str, LightweightModelWeights] = {}
            safe_lr = min(1.0, max(0.01, config_snapshot.learning_rate))
            for attack in request_payload.attack_types:
                current_weights = model_snapshot.weights.get(attack)
                current_weights_dict = current_weights.model_dump() if current_weights else {k:0.0 for k in weight_keys}
                if round_totals[attack] > 0:
                    averaged_weights = {
                        key: value / float(round_totals[attack]) for key, value in aggregate[attack].items()
                    }
                    # FedAvg-style aggregation: average local trained weights, then blend by LR.
                    learned = {
                        key: max(
                            -3.0,
                            min(
                                3.0,
                                ((1.0 - safe_lr) * float(current_weights_dict.get(key, 0.0)))
                                + (safe_lr * float(averaged_weights.get(key, 0.0))),
                            ),
                        )
                        for key in weight_keys
                    }
                else:
                    learned = current_weights_dict
                new_weights[attack] = LightweightModelWeights(**learned)

            updated_model = FederatedGlobalModelState(
                revision=model_snapshot.revision + 1,
                updated_at=datetime.now(timezone.utc),
                weights=new_weights,
            )
            sync_results = await asyncio.gather(
                *[
                    _sync_node_model(node_id, node_base_url, updated_model)
                    for node_id, node_base_url in node_urls.items()
                ]
            )
            synced_nodes = [node_id for node_id, applied in sync_results if applied]
            response = FederatedRoundRunResponse(
                round_id=active_round,
                applied=True,
                reason=f"learning_round_applied_{trigger}",
                learning_config=config_snapshot,
                model_state=updated_model,
                node_results=node_results,
                synced_nodes=synced_nodes,
            )
            async with state_lock:
                global_model_state = updated_model
                latest_learning_round = response
            return response

    async def _auto_round_worker() -> None:
        while True:
            try:
                async with state_lock:
                    interval = max(10, learning_config.auto_round_interval_seconds)
                    should_run = learning_config.enabled and learning_config.auto_rounds
                await asyncio.sleep(interval)
                if not should_run:
                    continue
                await _execute_learning_round(force=False, max_samples_override=None, trigger="auto")
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.warning("auto_learning_round_failed error=%s", _safe_error_text(exc))

    @app.on_event("startup")
    async def startup() -> None:
        nonlocal auto_round_task
        if auto_round_task is None:
            auto_round_task = asyncio.create_task(_auto_round_worker())

    @app.on_event("shutdown")
    async def shutdown() -> None:
        nonlocal auto_round_task
        if auto_round_task is not None:
            auto_round_task.cancel()
            try:
                await auto_round_task
            except asyncio.CancelledError:
                pass
            auto_round_task = None

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
            model=settings.model_name,
            dependencies=[dependency],
        )

    @app.post("/v1/federated/local-update", response_model=FederatedIngestResponse)
    async def local_update(payload: LocalModelUpdate) -> FederatedIngestResponse:
        nonlocal totals
        nonlocal counts
        async with state_lock:
            updates.append(payload)
            for signal in payload.signals:
                score = min(1.0, max(0.0, (signal.confidence * 0.65) + (signal.anomaly_score * 0.35)))
                weighted = score * signal.sample_count
                t = signal.attack_type
                if t not in totals:
                    totals[t] = 0.0
                    counts[t] = 0
                totals[t] += weighted
                counts[t] += signal.sample_count

            elapsed = (datetime.now(timezone.utc) - round_started_at).total_seconds()
            if elapsed >= max(5, settings.round_duration_seconds):
                snapshot = await _close_round("timer")
            else:
                snapshot = _current_snapshot()
            return FederatedIngestResponse(
                accepted=True,
                current_round=snapshot.round_id,
                snapshot=snapshot,
            )

    @app.post("/v1/federated/round/close", response_model=FederatedRoundSnapshot)
    async def force_close_round() -> FederatedRoundSnapshot:
        async with state_lock:
            return await _close_round("manual")

    @app.get("/v1/federated/policy", response_model=CoordinationPolicy)
    async def policy() -> CoordinationPolicy:
        async with state_lock:
            return current_policy

    @app.get("/v1/federated/round/current", response_model=FederatedRoundSnapshot)
    async def round_current() -> FederatedRoundSnapshot:
        async with state_lock:
            return _current_snapshot()

    @app.get("/v1/federated/history", response_model=list[FederatedRoundSnapshot])
    async def round_history() -> list[FederatedRoundSnapshot]:
        async with state_lock:
            return list(history)

    @app.post("/v1/reset")
    async def reset_node() -> dict[str, str]:
        async with state_lock:
            history.clear()
        return {"status": "ok"}

    @app.get("/v1/federated/model/global", response_model=FederatedGlobalModelState)
    async def model_global() -> FederatedGlobalModelState:
        async with state_lock:
            return global_model_state

    @app.get("/v1/federated/learning/state", response_model=FederatedLearningStateResponse)
    async def learning_state() -> FederatedLearningStateResponse:
        async with state_lock:
            return FederatedLearningStateResponse(
                service=settings.service_name,
                config=learning_config,
                model_state=global_model_state,
                current_round=_current_snapshot(),
                latest_round_result=latest_learning_round,
                history_size=len(history),
            )

    @app.post("/v1/federated/learning/config", response_model=FederatedLearningConfig)
    async def learning_config_update(payload: FederatedLearningConfigPatch) -> FederatedLearningConfig:
        nonlocal learning_config
        async with state_lock:
            changed = payload.model_dump(exclude_none=True)
            merged = learning_config.model_dump(mode="json")
            merged.update(changed)
            learning_config = FederatedLearningConfig(**merged)
            return learning_config

    @app.post("/v1/federated/learning/round/run", response_model=FederatedRoundRunResponse)
    async def learning_round_run(payload: FederatedRoundRunRequest | None = None) -> FederatedRoundRunResponse:
        request_payload = payload or FederatedRoundRunRequest()
        return await _execute_learning_round(
            force=request_payload.force,
            max_samples_override=request_payload.max_samples_per_node,
            trigger="manual",
        )

    @app.get("/v1/federated/state")
    async def federated_state() -> dict[str, Any]:
        async with state_lock:
            snapshot = _current_snapshot()
            return {
                "service": settings.service_name,
                "model": settings.model_name,
                "round_duration_seconds": settings.round_duration_seconds,
                "current_round": snapshot.model_dump(mode="json"),
                "history_size": len(history),
                "learning_config": learning_config.model_dump(mode="json"),
                "global_model_state": global_model_state.model_dump(mode="json"),
                "latest_learning_round": (
                    latest_learning_round.model_dump(mode="json") if latest_learning_round else None
                ),
            }

    @app.post("/v1/assistant/query", response_model=MasterAssistantResponse)
    async def assistant_query(payload: MasterAssistantRequest) -> MasterAssistantResponse:
        async with state_lock:
            snapshot = _current_snapshot()
            policy = current_policy
            recent_history = [item.model_dump(mode="json") for item in list(history)[:5]]
            model_state_view = global_model_state.model_dump(mode="json")
            learning_view = learning_config.model_dump(mode="json")

        telemetry = payload.telemetry_context or {}
        detected_attack = _resolve_attack_focus(
            telemetry_attack=(
                telemetry.get("current_attack_type")
                or telemetry.get("stats", {}).get("attack_type")
                or ""
            ),
            snapshot_scores=snapshot.scores,
        )
        operator_prompt = _build_recommended_operator_prompt(
            attack_type=detected_attack,
            snapshot=snapshot,
            policy=policy,
            question=payload.question,
        )

        llm_output: MasterAssistantLLMOutput | None = None
        try:
            assistant_timeout = min(8.0, settings.request_timeout_seconds)
            llm_output = await asyncio.wait_for(
                ollama_client.chat_json(
                    model=settings.model_name,
                    system_prompt=render_prompt("master_assistant_system"),
                    user_prompt=render_prompt(
                        "master_assistant_user",
                        question=payload.question,
                        detected_attack_type=detected_attack,
                        current_round=snapshot.model_dump(mode="json"),
                        policy=policy.model_dump(mode="json"),
                        recent_history=recent_history,
                        telemetry_context={
                            **payload.telemetry_context,
                            "learning_config": learning_view,
                            "model_state": model_state_view,
                        },
                    ),
                    response_model=MasterAssistantLLMOutput,
                    temperature=0.1,
                ),
                timeout=assistant_timeout,
            )
        except Exception as exc:
            logger.warning("master_assistant_fallback error=%s", str(exc))

        if llm_output is None:
            # Build a meaningful, attack-type-specific response without the LLM.
            fl_a = float(telemetry.get('fl_score_node_a_ddos', 0.5))
            fl_b = float(telemetry.get('fl_score_node_b_gps', 0.5))
            rev_a = int(telemetry.get('node_a_fl_revision', 0))
            rev_b = int(telemetry.get('node_b_fl_revision', 0))
            high_score = max(fl_a, fl_b, max(snapshot.scores.values()) if snapshot.scores else 0.0)
            alert_level = _derive_alert_level(high_score)
            attack_label = _attack_label(detected_attack)
            primary_score = float(snapshot.scores.get(detected_attack, high_score)) if detected_attack != "none" else high_score

            if detected_attack == 'ddos':
                summary = (
                    f"Current telemetry indicates an active DDoS campaign against the vehicular edge path. "
                    f"Federated confidence for DDoS is {fl_a:.2f} after {rev_a} round(s), with traffic signatures "
                    f"consistent with burst-amplification flood behavior."
                )
                actions = [
                    "Apply ingress rate limiting on all interfaces showing packet-rate anomalies above baseline.",
                    "Deploy stateful SYN flood mitigation and block source IPs with sustained burst behavior.",
                    "Reroute affected traffic through DDoS scrubbing infrastructure immediately.",
                ]
            elif detected_attack == 'gps_spoof':
                summary = (
                    f"Current telemetry indicates active GNSS coordinate manipulation across monitored vehicles. "
                    f"Federated confidence for GPS spoofing is {fl_b:.2f} after {rev_b} round(s), with impossible "
                    f"location deltas consistent with external signal injection."
                )
                actions = [
                    "Cross-validate all GNSS positions against inertial navigation and cellular triangulation data.",
                    "Flag and quarantine vehicles reporting coordinate deltas exceeding physically possible thresholds.",
                    "Activate GNSS anti-spoofing countermeasures and switch to authenticated signal sources where available.",
                ]
            elif detected_attack == "prompt_injection":
                summary = (
                    f"The system is observing prompt-injection behavior targeting instruction-following logic. "
                    f"Current confidence for this class is {primary_score:.2f}, indicating likely command hijack "
                    f"attempts through untrusted text inputs."
                )
                actions = [
                    "Isolate the affected input channel and enforce strict allow-list validation for command-like tokens.",
                    "Enable response hardening by stripping instruction-override phrases before model inference.",
                    "Require human approval for high-impact actions generated from externally sourced prompts.",
                ]
            elif detected_attack == "indirect_prompt_injection":
                summary = (
                    f"Telemetry indicates indirect prompt-injection risk through external content sources. "
                    f"Current confidence for this class is {primary_score:.2f}, suggesting hidden instructions may be "
                    f"embedded in third-party route or context data."
                )
                actions = [
                    "Treat all third-party navigation and context feeds as untrusted and sanitize content before ingestion.",
                    "Separate retrieval content from execution instructions using strict templating boundaries.",
                    "Quarantine upstream sources that repeatedly include instruction-like patterns in data payloads.",
                ]
            elif detected_attack == "v2x_exploitation":
                summary = (
                    f"The detection pipeline indicates V2X exploitation patterns in cooperative signaling traffic. "
                    f"Current confidence for this class is {primary_score:.2f}, consistent with deceptive BSM/CAM "
                    f"message behavior and trust-channel abuse."
                )
                actions = [
                    "Cross-verify V2X messages against local sensor evidence before applying cooperative maneuvers.",
                    "Enable replay/sybil detection on sender identity, timing, and trajectory consistency checks.",
                    "Temporarily down-rank unverified V2X advisories in safety-critical decision logic.",
                ]
            elif detected_attack == "data_poisoning":
                summary = (
                    f"The system is detecting indicators of potential data-poisoning pressure on learning workflows. "
                    f"Current confidence for this class is {primary_score:.2f}, suggesting malicious influence on "
                    f"training signals or model-update quality."
                )
                actions = [
                    "Pause ingestion of suspect training/update batches and isolate their source pipelines.",
                    "Run integrity checks against recent model deltas and compare against trusted baseline snapshots.",
                    "Rollback to the last verified-safe model revision if poisoning impact crosses policy thresholds.",
                ]
            else:
                summary = (
                    f"No active high-confidence attack signature is currently present. "
                    f"Federated learning is running at round {snapshot.round_id} with {snapshot.update_count} updates. "
                    f"Node A DDoS confidence is {fl_a:.2f} and Node B GPS confidence is {fl_b:.2f}."
                )
                actions = policy.recommended_actions or [
                    "Continue monitoring network baselines for anomalous traffic patterns.",
                    "Ensure federated learning updates are flowing from all specialist nodes.",
                    "Review recent event logs for low-confidence detections that may indicate early-stage threats.",
                ]

            details = [
                f"Round {snapshot.round_id} | {snapshot.update_count} updates | participants: {', '.join(snapshot.node_participants) or 'none yet'}",
                f"Node A (DDoS) FL score: {fl_a:.2f} (round {rev_a}) | Node B (GPS) FL score: {fl_b:.2f} (round {rev_b})",
                f"Policy: {policy.recommendation}",
            ]
            return MasterAssistantResponse(
                summary=summary,
                details=details,
                alert_level=alert_level,
                recommended_actions=actions,
                recommended_prompt=operator_prompt,
                policy=policy,
                current_round=snapshot,
            )

        high_score = max(snapshot.scores.values()) if snapshot.scores else 0.0
        normalized_level = _normalize_alert_level(llm_output.alert_level, high_score)
        return MasterAssistantResponse(
            summary=llm_output.summary,
            details=llm_output.details,
            alert_level=normalized_level,
            recommended_actions=llm_output.recommended_actions or policy.recommended_actions,
            recommended_prompt=(llm_output.recommended_prompt.strip() or operator_prompt),
            policy=policy,
            current_round=snapshot,
        )

    return app


def _safe_error_text(exc: Exception) -> str:
    text = str(exc).strip()
    return text if text else exc.__class__.__name__


def _attack_label(attack_type: str) -> str:
    labels = {
        "ddos": "DDoS",
        "gps_spoof": "GPS Spoofing",
        "prompt_injection": "Prompt Injection",
        "indirect_prompt_injection": "Indirect Prompt Injection",
        "v2x_exploitation": "V2X Exploitation",
        "data_poisoning": "Data Poisoning",
        "none": "No Active Attack",
    }
    return labels.get(attack_type, attack_type.replace("_", " ").title())


def _resolve_attack_focus(*, telemetry_attack: Any, snapshot_scores: dict[str, float]) -> str:
    known = {
        "ddos",
        "gps_spoof",
        "prompt_injection",
        "indirect_prompt_injection",
        "v2x_exploitation",
        "data_poisoning",
    }
    telemetry_value = str(telemetry_attack or "").strip().lower()
    if telemetry_value in known:
        return telemetry_value
    if not snapshot_scores:
        return "none"
    dominant = max(snapshot_scores, key=snapshot_scores.get)
    if float(snapshot_scores.get(dominant, 0.0)) >= 0.55:
        return dominant
    return "none"


def _build_recommended_operator_prompt(
    *,
    attack_type: str,
    snapshot: FederatedRoundSnapshot,
    policy: CoordinationPolicy,
    question: str,
) -> str:
    round_meta = (
        f"Use federated round {snapshot.round_id}, update_count={snapshot.update_count}, "
        f"participants={', '.join(snapshot.node_participants) or 'none'}."
    )
    score_view = ", ".join(
        f"{k}={float(v):.2f}" for k, v in sorted(snapshot.scores.items(), key=lambda item: item[1], reverse=True)
    )
    policy_line = policy.recommendation.strip() or "No policy recommendation is currently available."
    prefix = f"Original operator question: {question.strip()}"

    prompts = {
        "ddos": (
            f"{prefix} Investigate this as an active DDoS event. Build a concise incident brief with: "
            "probable flood pattern, likely ingress points, immediate containment sequence, and verification checks. "
            f"{round_meta} Federated scores: {score_view}. Policy: {policy_line}"
        ),
        "gps_spoof": (
            f"{prefix} Analyze this as a GPS spoofing incident. Provide: confidence rationale, impossible-jump evidence, "
            "cross-validation steps (INS/cellular), and immediate mitigation actions for affected vehicles. "
            f"{round_meta} Federated scores: {score_view}. Policy: {policy_line}"
        ),
        "prompt_injection": (
            f"{prefix} Treat this as prompt-injection risk. Summarize likely injection vectors, trust-boundary failures, "
            "required input-sanitization controls, and a rapid containment checklist. "
            f"{round_meta} Federated scores: {score_view}. Policy: {policy_line}"
        ),
        "indirect_prompt_injection": (
            f"{prefix} Treat this as indirect prompt-injection through external content. Provide a targeted response plan "
            "covering source isolation, retrieval sanitization, and safe instruction separation controls. "
            f"{round_meta} Federated scores: {score_view}. Policy: {policy_line}"
        ),
        "v2x_exploitation": (
            f"{prefix} Investigate potential V2X exploitation. Produce a professional response with replay/sybil checks, "
            "message-authentication validation, and operational fallback strategy for cooperative driving logic. "
            f"{round_meta} Federated scores: {score_view}. Policy: {policy_line}"
        ),
        "data_poisoning": (
            f"{prefix} Analyze potential data-poisoning impact on model updates. Provide: affected training channels, "
            "model-integrity verification steps, rollback criteria, and recovery workflow. "
            f"{round_meta} Federated scores: {score_view}. Policy: {policy_line}"
        ),
        "none": (
            f"{prefix} Provide a professional readiness report with top risks, monitoring priorities, and pre-emptive "
            f"hardening actions. {round_meta} Federated scores: {score_view}. Policy: {policy_line}"
        ),
    }
    return prompts.get(attack_type, prompts["none"])


def _derive_alert_level(high_score: float) -> str:
    highest = high_score
    if highest >= 0.80:
        return "critical"
    if highest >= 0.60:
        return "elevated"
    return "normal"


def _normalize_alert_level(level: str, high_score: float) -> str:
    normalized = (level or "").strip().lower()
    if normalized in {"normal", "elevated", "critical"}:
        return normalized
    return _derive_alert_level(high_score)


app = create_app()
