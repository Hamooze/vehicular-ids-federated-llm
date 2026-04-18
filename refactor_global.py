import re

file_path = r"/docker/tiered_xai_ids/tiered_xai_ids/apps/global_model/main.py"
with open(file_path, "r", encoding="utf-8") as f:
    code = f.read()

# 1. State vars
code = code.replace(
    """    updates: list[LocalModelUpdate] = []
    ddos_total = 0.0
    ddos_count = 0
    gps_total = 0.0
    gps_count = 0
    current_policy""",
    """    updates: list[LocalModelUpdate] = []
    totals: dict[str, float] = {}
    counts: dict[str, int] = {}
    current_policy"""
)

# 2. Policy weights
code = code.replace(
    """        ddos_weight=0.5,
        gps_weight=0.5,
        contributing_nodes=[],""",
    """        weights={"ddos": 0.5, "gps_spoof": 0.5},
        contributing_nodes=[],"""
)

# 3. _current_scores
code = code.replace(
    """    def _current_scores() -> tuple[float, float]:
        ddos_score = ddos_total / ddos_count if ddos_count > 0 else 0.5
        gps_score = gps_total / gps_count if gps_count > 0 else 0.5
        return min(1.0, max(0.0, ddos_score)), min(1.0, max(0.0, gps_score))""",
    """    def _current_scores() -> dict[str, float]:
        scores = {}
        for attack in totals:
            s = totals[attack] / (counts.get(attack) or 1) if counts.get(attack, 0) > 0 else 0.5
            scores[attack] = min(1.0, max(0.0, s))
        return scores"""
)

# 4. _current_snapshot returns
code = code.replace(
    """    def _current_snapshot() -> FederatedRoundSnapshot:
        ddos_score, gps_score = _current_scores()
        participants = sorted({item.node_id for item in updates})
        return FederatedRoundSnapshot(
            round_id=round_id,
            started_at=round_started_at,
            closed_at=None,
            update_count=len(updates),
            ddos_score=ddos_score,
            gps_score=gps_score,
            node_participants=participants,
            policy=current_policy,
        )""",
    """    def _current_snapshot() -> FederatedRoundSnapshot:
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
        )"""
)

# 5. _generate_policy signature
code = code.replace(
    """    async def _generate_policy(
        *,
        target_round: int,
        ddos_score: float,
        gps_score: float,
        participants: list[str],
        update_count: int,
    ) -> CoordinationPolicy:""",
    """    async def _generate_policy(
        *,
        target_round: int,
        scores: dict[str, float],
        participants: list[str],
        update_count: int,
    ) -> CoordinationPolicy:"""
)
code = re.sub(
    r'ddos_score=round\(ddos_score, 4\),\s*gps_score=round\(gps_score, 4\),',
    'scores={k: round(v, 4) for k, v in scores.items()},',
    code
)
code = code.replace(
    """                ddos_weight=ddos_score,
                gps_weight=gps_score,
                contributing_nodes=participants,""",
    """                weights=scores,
                contributing_nodes=participants,"""
)

# 6. Policy fallback logic
fallback_old = """        except Exception as exc:
            logger.warning("global_policy_fallback error=%s", str(exc))
            dominant = "ddos" if ddos_score >= gps_score else "gps_spoof"
            return CoordinationPolicy(
                round_id=target_round,
                strategy="weighted_fallback",
                recommendation=(
                    f"Prioritize {dominant} defenses based on current federated confidence "
                    f"(ddos={ddos_score:.2f}, gps={gps_score:.2f})."
                ),
                recommended_actions=[
                    "Tighten rate limits and verify network flow baselines.",
                    "Validate GNSS integrity and detect impossible location jumps.",
                    "Increase analyst sampling on events above 0.7 anomaly score.",
                ],
                ddos_weight=ddos_score,
                gps_weight=gps_score,"""
fallback_new = """        except Exception as exc:
            logger.warning("global_policy_fallback error=%s", str(exc))
            dominant = max(scores, key=scores.get) if scores else "unknown"
            return CoordinationPolicy(
                round_id=target_round,
                strategy="weighted_fallback",
                recommendation=(
                    f"Prioritize {dominant} defenses based on current federated confidence. "
                    f"Scores: {scores}"
                ),
                recommended_actions=[
                    "Tighten rate limits and verify network flow baselines.",
                    "Validate GNSS integrity and detect impossible location jumps.",
                    "Increase analyst sampling on events above 0.7 anomaly score.",
                ],
                weights=scores,"""

code = code.replace(fallback_old, fallback_new)

# 7. _close_round locals
code = code.replace(
    """    async def _close_round(reason: str) -> FederatedRoundSnapshot:
        nonlocal round_id
        nonlocal round_started_at
        nonlocal updates
        nonlocal ddos_total
        nonlocal ddos_count
        nonlocal gps_total
        nonlocal gps_count
        nonlocal current_policy

        ddos_score, gps_score = _current_scores()
        participants = sorted({item.node_id for item in updates})
        target_round = round_id
        policy = await _generate_policy(
            target_round=target_round,
            ddos_score=ddos_score,
            gps_score=gps_score,
            participants=participants,
            update_count=len(updates),
        )""",
    """    async def _close_round(reason: str) -> FederatedRoundSnapshot:
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
        )"""
)

# Snapshot creation
code = code.replace(
    """        snapshot = FederatedRoundSnapshot(
            round_id=target_round,
            started_at=round_started_at,
            closed_at=closed,
            update_count=len(updates),
            ddos_score=ddos_score,
            gps_score=gps_score,
            node_participants=participants,
            policy=policy,
        )
        history.appendleft(snapshot)
        logger.info(
            "federated_round_closed round=%s reason=%s updates=%s ddos=%.3f gps=%.3f",
            target_round,
            reason,
            len(updates),
            ddos_score,
            gps_score,
        )
        round_id = target_round + 1
        round_started_at = closed
        updates = []
        ddos_total = 0.0
        ddos_count = 0
        gps_total = 0.0
        gps_count = 0
        return snapshot""",
    """        snapshot = FederatedRoundSnapshot(
            round_id=target_round,
            started_at=round_started_at,
            closed_at=closed,
            update_count=len(updates),
            scores=scores,
            node_participants=participants,
            policy=policy,
        )
        history.appendleft(snapshot)
        logger.info(
            f"federated_round_closed round={target_round} reason={reason} updates={len(updates)} scores={scores}",
        )
        round_id = target_round + 1
        round_started_at = closed
        updates = []
        totals = {}
        counts = {}
        return snapshot"""
)

# 8. Learning round execution request payload
code = code.replace(
    """            request_payload = NodeModelUpdateRequest(
                round_id=active_round,
                max_samples=max_samples,
                attack_types=["ddos", "gps_spoof"],
            )""",
    """            request_payload = NodeModelUpdateRequest(
                round_id=active_round,
                max_samples=max_samples,
                attack_types=["ddos", "gps_spoof", "prompt_injection", "indirect_prompt_injection", "v2x_exploitation", "data_poisoning"],
            )"""
)

# 9. Collection node result empty counts
code = code.replace(
    """                    node_results.append(
                        NodeRoundResult(
                            node_id=node_id,
                            status="error",
                            sample_counts={"ddos": 0, "gps_spoof": 0},
                            detail=error or "update_failed",
                        )
                    )""",
    """                    node_results.append(
                        NodeRoundResult(
                            node_id=node_id,
                            status="error",
                            sample_counts={},
                            detail=error or "update_failed",
                        )
                    )"""
)

# 10. Aggregation loops
code = code.replace(
    """            aggregate: dict[str, dict[str, float]] = {
                "ddos": {key: 0.0 for key in weight_keys},
                "gps_spoof": {key: 0.0 for key in weight_keys},
            }
            totals = {"ddos": 0, "gps_spoof": 0}
            for update in eligible_updates:
                for attack in ("ddos", "gps_spoof"):
                    bucket_count = int(update.sample_counts.get(attack, 0))""",
    """            aggregate: dict[str, dict[str, float]] = {}
            for attack in request_payload.attack_types:
                aggregate[attack] = {key: 0.0 for key in weight_keys}
            
            round_totals = {attack: 0 for attack in request_payload.attack_types}
            for update in eligible_updates:
                for attack in request_payload.attack_types:
                    bucket_count = int(update.sample_counts.get(attack, 0))"""
)

code = code.replace(
    """                    for key in weight_keys:
                        aggregate[attack][key] += float(weight_values.get(key, 0.0)) * bucket_count
                    totals[attack] += bucket_count""",
    """                    for key in weight_keys:
                        aggregate[attack][key] += float(weight_values.get(key, 0.0)) * bucket_count
                    round_totals[attack] += bucket_count"""
)

# Weight application
code = code.replace(
    """            for attack in ("ddos", "gps_spoof"):
                current_weights = model_snapshot.weights[attack].model_dump()
                if totals[attack] > 0:
                    averaged_weights = {
                        key: value / float(totals[attack]) for key, value in aggregate[attack].items()
                    }""",
    """            for attack in request_payload.attack_types:
                current_weights = model_snapshot.weights.get(attack)
                current_weights_dict = current_weights.model_dump() if current_weights else {k:0.0 for k in weight_keys}
                if round_totals[attack] > 0:
                    averaged_weights = {
                        key: value / float(round_totals[attack]) for key, value in aggregate[attack].items()
                    }"""
)
code = code.replace(
    """                                ((1.0 - safe_lr) * float(current_weights.get(key, 0.0)))""",
    """                                ((1.0 - safe_lr) * float(current_weights_dict.get(key, 0.0)))"""
)
code = code.replace(
    """                else:
                    learned = current_weights""",
    """                else:
                    learned = current_weights_dict"""
)

code = code.replace(
    """            updated_model = FederatedGlobalModelState(
                revision=model_snapshot.revision + 1,
                updated_at=datetime.now(timezone.utc),
                weights={
                    "ddos": new_weights["ddos"],
                    "gps_spoof": new_weights["gps_spoof"],
                },
            )""",
    """            updated_model = FederatedGlobalModelState(
                revision=model_snapshot.revision + 1,
                updated_at=datetime.now(timezone.utc),
                weights=new_weights,
            )"""
)

# 11. Endpoint tracking
code = code.replace(
    """    @app.post("/v1/federated/local-update", response_model=FederatedIngestResponse)
    async def local_update(payload: LocalModelUpdate) -> FederatedIngestResponse:
        nonlocal ddos_total
        nonlocal ddos_count
        nonlocal gps_total
        nonlocal gps_count
        async with state_lock:
            updates.append(payload)
            for signal in payload.signals:
                score = min(1.0, max(0.0, (signal.confidence * 0.65) + (signal.anomaly_score * 0.35)))
                weighted = score * signal.sample_count
                if signal.attack_type == "ddos":
                    ddos_total += weighted
                    ddos_count += signal.sample_count
                elif signal.attack_type == "gps_spoof":
                    gps_total += weighted
                    gps_count += signal.sample_count""",
    """    @app.post("/v1/federated/local-update", response_model=FederatedIngestResponse)
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
                counts[t] += signal.sample_count"""
)

# 12. MasterAssistant responses
code = code.replace(
    """        if llm_output is None:
            alert_level = _derive_alert_level(snapshot.ddos_score, snapshot.gps_score)
            details = [
                f"Current round={snapshot.round_id} updates={snapshot.update_count}.",
                f"Federated confidence: ddos={snapshot.ddos_score:.2f}, gps={snapshot.gps_score:.2f}.",
                f"Contributing nodes: {', '.join(snapshot.node_participants) or 'none yet'}.",
                (
                    "Learning mode: "
                    f"enabled={learning_view['enabled']} auto_rounds={learning_view['auto_rounds']} "
                    f"global_revision={model_state_view['revision']}."
                ),
                f"Policy: {policy.recommendation}",
            ]""",
    """        if llm_output is None:
            high_score = max(snapshot.scores.values()) if snapshot.scores else 0.0
            alert_level = _derive_alert_level(high_score)
            details = [
                f"Current round={snapshot.round_id} updates={snapshot.update_count}.",
                f"Federated confidence: {snapshot.scores}",
                f"Contributing nodes: {', '.join(snapshot.node_participants) or 'none yet'}.",
                (
                    "Learning mode: "
                    f"enabled={learning_view['enabled']} auto_rounds={learning_view['auto_rounds']} "
                    f"global_revision={model_state_view['revision']}."
                ),
                f"Policy: {policy.recommendation}",
            ]"""
)
code = code.replace(
    """        normalized_level = _normalize_alert_level(llm_output.alert_level, snapshot.ddos_score, snapshot.gps_score)""",
    """        high_score = max(snapshot.scores.values()) if snapshot.scores else 0.0
        normalized_level = _normalize_alert_level(llm_output.alert_level, high_score)"""
)

code = code.replace(
    """def _derive_alert_level(ddos_score: float, gps_score: float) -> str:
    highest = max(ddos_score, gps_score)
    if highest >= 0.80:""",
    """def _derive_alert_level(high_score: float) -> str:
    highest = high_score
    if highest >= 0.80:"""
)

code = code.replace(
    """def _normalize_alert_level(level: str, ddos_score: float, gps_score: float) -> str:
    normalized = (level or "").strip().lower()
    if normalized in {"normal", "elevated", "critical"}:
        return normalized
    return _derive_alert_level(ddos_score, gps_score)""",
    """def _normalize_alert_level(level: str, high_score: float) -> str:
    normalized = (level or "").strip().lower()
    if normalized in {"normal", "elevated", "critical"}:
        return normalized
    return _derive_alert_level(high_score)"""
)


with open(file_path, "w", encoding="utf-8") as f:
    f.write(code)

print("Rewrite applied!")
