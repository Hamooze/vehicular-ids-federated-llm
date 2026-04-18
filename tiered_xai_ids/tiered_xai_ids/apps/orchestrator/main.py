import asyncio
import logging
import random
import time
from collections import deque
from typing import Any

import httpx
from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from tiered_xai_ids.shared.auth import require_internal_key
from tiered_xai_ids.shared.config import OrchestratorSettings, get_orchestrator_settings
from tiered_xai_ids.shared.correlation import CorrelationIdMiddleware, get_correlation_id
from tiered_xai_ids.shared.email_notifier import EmailNotifier
from tiered_xai_ids.shared.http_client import get_json, post_json
from tiered_xai_ids.shared.logging_config import configure_logging
from tiered_xai_ids.shared.schemas import (
    AttackCommandRequest,
    DetectionBranchConfig,
    DependencyHealth,
    HealthResponse,
    LegacyV2XTelemetry,
    OrchestratorIngestResponse,
    RawLogInput,
    SensorIngestResponse,
)


logger = logging.getLogger(__name__)
location_history: dict[str, list[float]] = {}


def create_app() -> FastAPI:
    settings = get_orchestrator_settings()
    configure_logging(service_name=settings.service_name, level=settings.log_level)
    app = FastAPI(title="Tiered IDS Orchestrator", version="1.0.0")
    app.add_middleware(CorrelationIdMiddleware)
    origins = [origin.strip() for origin in settings.allowed_origins.split(",") if origin.strip()]
    if not origins:
        origins = ["*"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    recent_requests: deque[dict[str, str | bool]] = deque(maxlen=200)
    attack_logs: deque[dict[str, str]] = deque(maxlen=250)
    attack_lock = asyncio.Lock()
    attack_task: asyncio.Task[None] | None = None
    alert_tasks: set[asyncio.Task[None]] = set()
    inflight_packets: set[asyncio.Task[Any]] = set()
    live_subscribers: set[asyncio.Queue[dict[str, Any]]] = set()
    detection_branches = DetectionBranchConfig(
        ddos_enabled=settings.ddos_enabled,
        gps_enabled=settings.gps_spoof_enabled,
    )
    # Per-specialist fanout flags — when False the orchestrator stops sending
    # traffic to that node, which realistically disables it from the FL process.
    specialist_nodes_enabled: dict[str, bool] = {"a": True, "b": True}
    email_notifier = EmailNotifier(
        admin_email=settings.admin_email,
        smtp_host=settings.smtp_host,
        smtp_port=settings.smtp_port,
        smtp_user=settings.smtp_user,
        smtp_password=settings.smtp_password.get_secret_value(),
        smtp_from=settings.smtp_from,
        smtp_use_tls=settings.smtp_use_tls,
        cooldown_seconds=settings.alert_cooldown_seconds,
    )
    attack_state: dict[str, Any] = {
        "is_attacking": False,
        "attack_type": None,
        "packet_sent": 0,
        "packets_delivered": 0,
        "packets_failed": 0,
        "start_time": None,
        "current_vehicle": None,
        "stop_requested": False,
        "last_error": None,
    }

    def append_attack_log(level: str, message: str) -> None:
        item = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "level": level,
            "message": message,
        }
        attack_logs.appendleft(item)
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(
                _publish_live_snapshot(
                    settings,
                    recent_requests,
                    attack_logs,
                    attack_state,
                    inflight_packets,
                    live_subscribers,
                    detection_branches,
                )
            )
        except RuntimeError:
            # No running loop during bootstrap/tests.
            pass

    def build_stats() -> dict[str, Any]:
        uptime_seconds = 0
        if attack_state["start_time"] is not None:
            uptime_seconds = max(0, int(time.time() - float(attack_state["start_time"])))
        return {
            "is_attacking": attack_state["is_attacking"],
            "attack_type": attack_state["attack_type"],
            "total_packets_sent": attack_state["packet_sent"],
            "packets_delivered": attack_state["packets_delivered"],
            "packets_failed": attack_state["packets_failed"],
            "inflight_packets": len(inflight_packets),
            "active_for_seconds": uptime_seconds,
            "current_vehicle": attack_state["current_vehicle"],
            "last_error": attack_state["last_error"],
        }

    def current_detection_config() -> DetectionBranchConfig:
        return DetectionBranchConfig(
            ddos_enabled=detection_branches.ddos_enabled,
            gps_enabled=detection_branches.gps_enabled,
        )

    def apply_detection_config(payload: RawLogInput) -> RawLogInput:
        merged = payload.model_copy(deep=True)
        merged.detection = current_detection_config()
        return merged

    def severity_rank(label: str) -> int:
        normalized = (label or "").strip().lower()
        if normalized == "malicious":
            return 2
        if normalized == "suspicious":
            return 1
        return 0

    async def notify_admin_if_needed(payload: RawLogInput, sensor_response: SensorIngestResponse) -> None:
        if not email_notifier.configured:
            return
        event = sensor_response.event
        effective_label = event.classification.label
        if effective_label == "benign" and sensor_response.suspicious:
            effective_label = "suspicious"
        threshold = (settings.alert_min_severity or "suspicious").strip().lower()
        threshold_rank = severity_rank("malicious" if threshold == "malicious" else "suspicious")
        if severity_rank(effective_label) < threshold_rank:
            return

        subject = (
            f"[Tiered IDS] {effective_label.upper()} detection "
            f"on {payload.source_device} ({payload.log_type})"
        )
        body = (
            "Tiered IDS detection alert\n\n"
            f"Timestamp: {event.timestamp.isoformat()}\n"
            f"Device: {payload.source_device}\n"
            f"Log type: {payload.log_type}\n"
            f"Classification: {event.classification.label}\n"
            f"Confidence: {event.classification.confidence:.3f}\n"
            f"Anomaly score: {event.classification.anomaly_score:.3f}\n"
            f"Priority: {event.priority}\n"
            f"Event ID: {event.event_id}\n"
            f"Correlation ID: {sensor_response.correlation_id}\n"
            f"DDoS branch enabled: {event.detection.ddos_enabled}\n"
            f"GPS branch enabled: {event.detection.gps_enabled}\n"
            f"Evidence: {', '.join(event.evidence[:8]) or 'n/a'}\n"
        )
        sent, detail = await email_notifier.send_alert(
            subject=subject,
            body=body,
            dedupe_key=f"event:{event.event_id}",
        )
        if sent:
            append_attack_log("info", f"admin_alert_sent event={event.event_id} to={email_notifier.admin_email}")
        else:
            logger.warning("admin_alert_not_sent event=%s reason=%s", event.event_id, detail)

    async def process_raw_log(payload: RawLogInput) -> OrchestratorIngestResponse:
        payload = apply_detection_config(payload)
        endpoint = f"{settings.sensor_node_url.rstrip('/')}/v1/ingest/log"
        try:
            _, data = await post_json(
                endpoint,
                payload.model_dump(mode="json"),
                timeout_seconds=settings.request_timeout_seconds,
            )
            sensor_response = SensorIngestResponse.model_validate(data)
        except Exception as exc:
            error_text = _safe_error_text(exc)
            logger.error("orchestrator_sensor_forward_failed error=%s", error_text)
            raise HTTPException(status_code=502, detail=f"Sensor node unreachable: {error_text}") from exc

        # Fan out to ENABLED specialist IDS nodes only (fire-and-forget).
        # Disabled nodes receive no traffic and therefore accumulate no training
        # samples — this is the correct way to model a node being "offline".
        # We encode the current enabled state of both specialists as query params so
        # each receiving node knows whether the other specialist is online and can
        # decide whether to update its cross-type EWA / training buffer.
        log_dump = payload.model_dump(mode="json")
        _a_flag = "1" if specialist_nodes_enabled["a"] else "0"
        _b_flag = "1" if specialist_nodes_enabled["b"] else "0"
        _node_state_qs = f"?specialist_a_enabled={_a_flag}&specialist_b_enabled={_b_flag}"
        fanout_urls: list[str] = []
        if specialist_nodes_enabled["a"]:
            fanout_urls.append(settings.ids_a_url.rstrip("/"))
        if specialist_nodes_enabled["b"]:
            fanout_urls.append(settings.ids_b_url.rstrip("/"))
        for ids_url in fanout_urls:
            task = asyncio.create_task(
                _fanout_to_specialist(
                    endpoint=f"{ids_url}/v1/ingest/log{_node_state_qs}",
                    payload=log_dump,
                    timeout_seconds=min(30.0, settings.request_timeout_seconds),
                )
            )
            inflight_packets.add(task)
            task.add_done_callback(lambda done_task: inflight_packets.discard(done_task))

        response = OrchestratorIngestResponse(
            correlation_id=get_correlation_id(),
            sensor_response=sensor_response,
        )
        recent_requests.appendleft(
            {
                "source_device": payload.source_device,
                "log_type": str(payload.log_type),
                "timestamp": payload.timestamp.isoformat(),
                "suspicious": sensor_response.suspicious,
                "event_id": sensor_response.event.event_id,
                "ddos_enabled": sensor_response.event.detection.ddos_enabled,
                "gps_enabled": sensor_response.event.detection.gps_enabled,
                # raw_excerpt intentionally omitted — contains a hash only,
                # not useful for the UI and avoids leaking payload content.
            }
        )
        if email_notifier.configured:
            task = asyncio.create_task(notify_admin_if_needed(payload, sensor_response))
            alert_tasks.add(task)
            task.add_done_callback(lambda done_task: alert_tasks.discard(done_task))
        await _publish_live_snapshot(
            settings,
            recent_requests,
            attack_logs,
            attack_state,
            inflight_packets,
            live_subscribers,
            detection_branches,
        )
        return response

    async def process_legacy_telemetry(telemetry: LegacyV2XTelemetry) -> OrchestratorIngestResponse:
        return await process_raw_log(_legacy_to_raw_log(telemetry))

    async def dispatch_attack_packet(telemetry: LegacyV2XTelemetry) -> None:
        try:
            await process_legacy_telemetry(telemetry)
            attack_state["packets_delivered"] += 1
        except Exception as exc:
            attack_state["packets_failed"] += 1
            attack_state["last_error"] = _safe_error_text(exc)
        finally:
            await _publish_live_snapshot(
                settings,
                recent_requests,
                attack_logs,
                attack_state,
                inflight_packets,
                live_subscribers,
                detection_branches,
            )

    async def run_attack(
        attack_type: str,
        vehicle_id: str,
        duration_seconds: int,
        packet_count: int,
    ) -> None:
        nonlocal attack_task
        append_attack_log("warning", f"attack_started type={attack_type} vehicle={vehicle_id}")
        started = time.time()
        sleep_seconds = 0.12 if attack_type == "ddos" else 0.45

        try:
            for _ in range(packet_count):
                if attack_state["stop_requested"] or (time.time() - started) >= duration_seconds:
                    break

                telemetry = _build_telemetry_for_attack(attack_type=attack_type, vehicle_id=vehicle_id)
                attack_state["packet_sent"] += 1
                packet_task = asyncio.create_task(dispatch_attack_packet(telemetry))
                inflight_packets.add(packet_task)
                packet_task.add_done_callback(lambda done_task: inflight_packets.discard(done_task))

                await asyncio.sleep(sleep_seconds)
        finally:
            attack_state["is_attacking"] = False
            attack_state["attack_type"] = None
            attack_state["stop_requested"] = False
            attack_state["start_time"] = None
            attack_state["current_vehicle"] = None
            attack_task = None
            append_attack_log("info", "attack_finished")
            await _publish_live_snapshot(
                settings,
                recent_requests,
                attack_logs,
                attack_state,
                inflight_packets,
                live_subscribers,
                detection_branches,
            )

    async def start_attack(kind: str, payload: AttackCommandRequest) -> dict[str, Any]:
        nonlocal attack_task
        async with attack_lock:
            if attack_task is not None and not attack_task.done():
                raise HTTPException(status_code=409, detail="Another attack simulation is already running")

            vehicle_id = payload.vehicle_id.strip() or "V001"
            attack_state["is_attacking"] = True
            attack_state["attack_type"] = kind
            attack_state["stop_requested"] = False
            attack_state["start_time"] = time.time()
            attack_state["current_vehicle"] = vehicle_id
            attack_state["last_error"] = None

            attack_task = asyncio.create_task(
                run_attack(
                    attack_type=kind,
                    vehicle_id=vehicle_id,
                    duration_seconds=payload.duration_seconds,
                    packet_count=payload.packet_count,
                )
            )

        response = {
            "status": "attack_started",
            "attack_type": kind,
            "vehicle_id": vehicle_id,
            "duration_seconds": payload.duration_seconds,
            "packet_count": payload.packet_count,
        }
        await _publish_live_snapshot(
            settings,
            recent_requests,
            attack_logs,
            attack_state,
            inflight_packets,
            live_subscribers,
            detection_branches,
        )
        return response

    @app.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        dependencies = await _collect_dependency_health(settings)
        degraded = any(dep.status != "ok" for dep in dependencies)
        return HealthResponse(
            service=settings.service_name,
            status="degraded" if degraded else "ok",
            model=None,
            dependencies=dependencies,
        )

    @app.get("/api/health")
    async def api_health() -> dict[str, Any]:
        health_response = await health()
        return health_response.model_dump(mode="json")

    @app.get("/api/servers/status")
    async def servers_status() -> dict[str, Any]:
        dependencies = await _collect_dependency_health(settings)
        server_map = {
            "sensor": _dep_to_legacy_status("sensor-node", dependencies),
            "filter": _dep_to_legacy_status("filter-node", dependencies),
            "brain": _dep_to_legacy_status("brain-node", dependencies),
            "global_model": _dep_to_legacy_status("global-model", dependencies),
            "ids_node_a": _dep_to_legacy_status("ids-node-a", dependencies),
            "ids_node_b": _dep_to_legacy_status("ids-node-b", dependencies),
        }
        return {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "servers": server_map,
        }

    @app.get("/api/detection/branches", response_model=DetectionBranchConfig)
    async def detection_branches_get() -> DetectionBranchConfig:
        return current_detection_config()

    @app.put("/api/detection/branches", response_model=DetectionBranchConfig)
    async def detection_branches_put(payload: DetectionBranchConfig) -> DetectionBranchConfig:
        detection_branches.ddos_enabled = payload.ddos_enabled
        detection_branches.gps_enabled = payload.gps_enabled
        await _publish_live_snapshot(
            settings,
            recent_requests,
            attack_logs,
            attack_state,
            inflight_packets,
            live_subscribers,
            detection_branches,
        )
        return current_detection_config()

    @app.post("/api/detection/branches", response_model=DetectionBranchConfig)
    async def detection_branches_post(payload: DetectionBranchConfig) -> DetectionBranchConfig:
        return await detection_branches_put(payload)

    @app.get("/api/specialist-nodes/state")
    async def specialist_nodes_state_get() -> dict[str, Any]:
        return {
            "ids_node_a": {"enabled": specialist_nodes_enabled["a"]},
            "ids_node_b": {"enabled": specialist_nodes_enabled["b"]},
        }

    @app.put("/api/specialist-nodes/toggle")
    async def specialist_nodes_toggle(payload: dict[str, Any]) -> dict[str, Any]:
        node = str(payload.get("node", "")).strip().upper()
        enabled = bool(payload.get("enabled", True))
        if node == "A":
            specialist_nodes_enabled["a"] = enabled
        elif node == "B":
            specialist_nodes_enabled["b"] = enabled
        else:
            raise HTTPException(status_code=400, detail="node must be A or B")
        logger.info("specialist_node_toggled node=%s enabled=%s", node, enabled)
        return {
            "ok": True,
            "node": node,
            "enabled": enabled,
            "ids_node_a": {"enabled": specialist_nodes_enabled["a"]},
            "ids_node_b": {"enabled": specialist_nodes_enabled["b"]},
        }

    @app.post("/api/alerts/test-email")
    async def alerts_test_email(payload: dict[str, str] | None = None) -> dict[str, Any]:
        if not email_notifier.configured:
            return {
                "ok": False,
                "status": "not_configured",
                "admin_email": email_notifier.admin_email,
            }
        body = payload or {}
        subject = body.get("subject", "Tiered IDS test email").strip() or "Tiered IDS test email"
        message = body.get(
            "message",
            (
                "This is a test alert from Tiered IDS orchestrator.\n\n"
                f"Timestamp: {time.strftime('%Y-%m-%dT%H:%M:%S')}\n"
                f"DDoS branch enabled: {detection_branches.ddos_enabled}\n"
                f"GPS branch enabled: {detection_branches.gps_enabled}\n"
            ),
        )
        sent, detail = await email_notifier.send_alert(
            subject=subject,
            body=message,
            dedupe_key=f"manual-test-{int(time.time())}",
        )
        return {
            "ok": sent,
            "status": detail,
            "admin_email": email_notifier.admin_email,
        }

    @app.post("/v1/pipeline/log", response_model=OrchestratorIngestResponse)
    async def pipeline_log(payload: RawLogInput) -> OrchestratorIngestResponse:
        return await process_raw_log(payload)

    @app.post("/v2x/telemetry", response_model=OrchestratorIngestResponse)
    async def ingest_legacy_telemetry(payload: LegacyV2XTelemetry) -> OrchestratorIngestResponse:
        return await process_legacy_telemetry(payload)

    @app.get("/v1/pipeline/recent")
    async def recent_pipeline() -> list[dict[str, str | bool]]:
        return list(recent_requests)

    @app.post("/api/send/normal-traffic")
    async def send_normal_traffic(payload: AttackCommandRequest) -> dict[str, Any]:
        vehicle_id = payload.vehicle_id.strip() or "V001"
        telemetry = _build_normal_telemetry(vehicle_id=vehicle_id)
        try:
            result = await process_legacy_telemetry(telemetry)
            append_attack_log("info", f"normal_traffic_sent vehicle={vehicle_id}")
            return {
                "status": "sent",
                "vehicle_id": vehicle_id,
                "telemetry": telemetry.model_dump(mode="json"),
                "result": result.model_dump(mode="json"),
            }
        except Exception as exc:
            error_text = _safe_error_text(exc)
            append_attack_log("error", f"normal_traffic_failed vehicle={vehicle_id} error={error_text}")
            raise HTTPException(status_code=502, detail=error_text) from exc
        finally:
            await _publish_live_snapshot(
                settings,
                recent_requests,
                attack_logs,
                attack_state,
                inflight_packets,
                live_subscribers,
                detection_branches,
            )

    @app.post("/api/attack/ddos")
    async def launch_ddos(payload: AttackCommandRequest) -> dict[str, Any]:
        return await start_attack("ddos", payload)

    @app.post("/api/attack/gps-spoof")
    async def launch_gps_spoof(payload: AttackCommandRequest) -> dict[str, Any]:
        return await start_attack("gps_spoof", payload)

    @app.post("/api/attack/stop")
    async def stop_attack() -> dict[str, Any]:
        nonlocal attack_task
        async with attack_lock:
            attack_state["stop_requested"] = True
            if attack_task is not None and not attack_task.done():
                attack_task.cancel()
        append_attack_log("warning", "attack_stop_requested")
        response = {
            "status": "stopped",
            **build_stats(),
        }
        await _publish_live_snapshot(
            settings,
            recent_requests,
            attack_logs,
            attack_state,
            inflight_packets,
            live_subscribers,
            detection_branches,
        )
        return response

    @app.get("/api/stats")
    async def stats() -> dict[str, Any]:
        return build_stats()

    @app.get("/api/live/overview")
    async def live_overview() -> dict[str, Any]:
        return await _build_live_payload(
            settings,
            recent_requests,
            attack_logs,
            attack_state,
            inflight_packets,
            detection_branches,
        )

    @app.websocket("/ws/live")
    async def live_stream(websocket: WebSocket) -> None:
        await websocket.accept()
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=8)
        live_subscribers.add(queue)
        try:
            await websocket.send_json(
                {
                    "event": "snapshot",
                    "data": await _build_live_payload(
                        settings,
                        recent_requests,
                        attack_logs,
                        attack_state,
                        inflight_packets,
                        detection_branches,
                    ),
                }
            )
            while True:
                try:
                    payload = await asyncio.wait_for(
                        queue.get(),
                        timeout=max(2.0, settings.websocket_heartbeat_seconds),
                    )
                    await websocket.send_json(payload)
                except asyncio.TimeoutError:
                    snapshot = await _build_live_payload(
                        settings,
                        recent_requests,
                        attack_logs,
                        attack_state,
                        inflight_packets,
                        detection_branches,
                    )
                    await websocket.send_json(
                        {
                            "event": "update",
                            "data": snapshot,
                        }
                    )
        except WebSocketDisconnect:
            live_subscribers.discard(queue)
        except Exception:
            live_subscribers.discard(queue)

    @app.post("/api/reset", dependencies=[Depends(require_internal_key)])
    async def reset_all() -> dict[str, Any]:
        recent_requests.clear()
        attack_logs.clear()
        location_history.clear()
        inflight_packets.clear()
        attack_state.update({
            "is_attacking": False, 
            "attack_type": None, 
            "packet_sent": 0, 
            "packets_delivered": 0, 
            "packets_failed": 0, 
            "start_time": None,
            "current_vehicle": None,
            "stop_requested": False,
            "last_error": None
        })
        
        urls = [
            f"{settings.sensor_node_url}/v1/reset",
            f"{settings.filter_node_url}/v1/reset",
            f"{settings.brain_node_url}/v1/reset",
            f"{settings.global_model_url}/v1/reset",
            f"{settings.ids_a_url}/v1/reset",
            f"{settings.ids_b_url}/v1/reset",
            "http://simulator:9000/api/reset",
        ]
        
        async def safe_post(url: str) -> None:
            try:
                await post_json(url, {})
            except Exception as e:
                logger.error(f"Reset failed on {url}: {e}")
                
        await asyncio.gather(*(safe_post(u) for u in urls))
        
        append_attack_log("INFO", "System fully reset by user.")
        return {"status": "ok"}

    return app


def _dep_to_legacy_status(name: str, dependencies: list[DependencyHealth]) -> dict[str, str]:
    for dep in dependencies:
        if dep.name == name:
            if dep.status == "ok":
                mapped = "online"
            elif dep.status == "degraded":
                mapped = "degraded"
            else:
                mapped = "offline"
            return {
                "status": mapped,
                "detail": dep.detail,
            }
    return {"status": "offline", "detail": "unknown"}


def _legacy_to_raw_log(payload: LegacyV2XTelemetry) -> RawLogInput:
    normalized_msg = payload.message_type.strip().upper()
    if "DDOS" in normalized_msg:
        log_type = "netflow"
        hint = "ddos flood syn burst packet storm abnormal traffic amplification"
    elif "DATA" in normalized_msg and "POISON" in normalized_msg:
        log_type = "telemetry"
        hint = "data poisoning poisoned training label skew backdoor trigger model poisoning federated gradient"
    elif "INDIRECT" in normalized_msg and "PROMPT" in normalized_msg:
        log_type = "http"
        hint = "indirect prompt hidden instruction untrusted content navigation feed malicious route description"
    elif "PROMPT" in normalized_msg and "INJECTION" in normalized_msg:
        log_type = "http"
        hint = "prompt injection jailbreak ignore previous override instruction system prompt instruction hijack"
    elif "V2X" in normalized_msg and ("EXPLOIT" in normalized_msg or "DECEPTION" in normalized_msg):
        log_type = "telemetry"
        hint = "v2x bsm forgery cam replay phantom vehicle sybil platoon inconsistency inter-vehicle deception"
    elif "GPS" in normalized_msg and "SPOOF" in normalized_msg:
        log_type = "gps"
        hint = "gps spoof impossible location jump tampered coordinates trajectory anomaly"
    else:
        log_type = "telemetry"
        hint = "normal telemetry bsm driving status"

    x, y = payload.location[0], payload.location[1]
    if x >= 500 and y < 500: area = 1
    elif x >= 500 and y >= 500: area = 2
    elif x < 500 and y >= 500: area = 3
    else: area = 4

    raw_log = (
        f"vehicle_id={payload.vehicle_id} message_type={normalized_msg} "
        f"speed={payload.speed:.2f} heading={payload.heading:.2f} "
        f"location=Area {area} ({x:.6f},{y:.6f}) "
    )
    
    prev_loc = location_history.get(payload.vehicle_id)
    if prev_loc:
        raw_log += f"previous_location=({prev_loc[0]:.6f},{prev_loc[1]:.6f}) "
        import math
        dist = math.hypot(x - prev_loc[0], y - prev_loc[1])
        is_jump = False
        if abs(x) > 180 or abs(y) > 180:
            if dist > 35: is_jump = True
        else:
            if dist > 0.0005: is_jump = True

        if is_jump:
            hint += " gps spoof impossible location jump tampered coordinates trajectory anomaly"
            log_type = "gps"
        
    location_history[payload.vehicle_id] = payload.location
    raw_log += f"{hint}"
    return RawLogInput(
        source_device=payload.vehicle_id,
        log_type=log_type,
        raw_log=raw_log[:12000],
        timestamp=payload.timestamp,
    )


def _build_normal_telemetry(vehicle_id: str) -> LegacyV2XTelemetry:
    return LegacyV2XTelemetry(
        vehicle_id=vehicle_id,
        speed=round(random.uniform(45, 90), 2),
        location=[round(25.2048 + random.uniform(-0.005, 0.005), 6), round(55.2708 + random.uniform(-0.005, 0.005), 6)],
        heading=round(random.uniform(0, 359.0), 2),
        message_type="BSM",
    )


def _build_telemetry_for_attack(attack_type: str, vehicle_id: str) -> LegacyV2XTelemetry:
    if attack_type == "ddos":
        return LegacyV2XTelemetry(
            vehicle_id=vehicle_id,
            speed=round(random.uniform(80, 170), 2),
            location=[round(25.2 + random.uniform(-0.12, 0.12), 6), round(55.2 + random.uniform(-0.12, 0.12), 6)],
            heading=round(random.uniform(0, 359.0), 2),
            message_type="ATTACK_DDOS",
        )
    if attack_type == "gps_spoof":
        return LegacyV2XTelemetry(
            vehicle_id=vehicle_id,
            speed=round(random.uniform(40, 90), 2),
            location=[round(25.0 + random.uniform(-1.0, 1.0), 6), round(55.0 + random.uniform(-1.0, 1.0), 6)],
            heading=round(random.uniform(0, 359.0), 2),
            message_type="ATTACK_GPS_SPOOF",
        )
    if attack_type == "prompt_injection":
        return LegacyV2XTelemetry(
            vehicle_id=vehicle_id,
            speed=round(random.uniform(45, 95), 2),
            location=[round(25.2048 + random.uniform(-0.01, 0.01), 6), round(55.2708 + random.uniform(-0.01, 0.01), 6)],
            heading=round(random.uniform(0, 359.0), 2),
            message_type="ATTACK_PROMPT_INJECTION",
        )
    if attack_type == "indirect_prompt_injection":
        return LegacyV2XTelemetry(
            vehicle_id=vehicle_id,
            speed=round(random.uniform(40, 90), 2),
            location=[round(25.2048 + random.uniform(-0.02, 0.02), 6), round(55.2708 + random.uniform(-0.02, 0.02), 6)],
            heading=round(random.uniform(0, 359.0), 2),
            message_type="ATTACK_INDIRECT_PROMPT",
        )
    if attack_type == "v2x_exploitation":
        return LegacyV2XTelemetry(
            vehicle_id=vehicle_id,
            speed=round(random.uniform(70, 140), 2),
            location=[round(25.2048 + random.uniform(-0.08, 0.08), 6), round(55.2708 + random.uniform(-0.08, 0.08), 6)],
            heading=round(random.uniform(0, 359.0), 2),
            message_type="ATTACK_V2X_EXPLOITATION",
        )
    if attack_type == "data_poisoning":
        return LegacyV2XTelemetry(
            vehicle_id=vehicle_id,
            speed=round(random.uniform(35, 95), 2),
            location=[round(25.2048 + random.uniform(-0.03, 0.03), 6), round(55.2708 + random.uniform(-0.03, 0.03), 6)],
            heading=round(random.uniform(0, 359.0), 2),
            message_type="ATTACK_DATA_POISONING",
        )
    return LegacyV2XTelemetry(
        vehicle_id=vehicle_id,
        speed=round(random.uniform(40, 90), 2),
        location=[round(25.0 + random.uniform(-1.0, 1.0), 6), round(55.0 + random.uniform(-1.0, 1.0), 6)],
        heading=round(random.uniform(0, 359.0), 2),
        message_type="ATTACK_GPS_SPOOF",
    )


async def _fanout_to_specialist(endpoint: str, payload: dict, timeout_seconds: float) -> None:
    """Forward a log payload to a specialist IDS node.  Errors are logged and swallowed
    so that a slow or unavailable specialist never blocks the main pipeline."""
    try:
        await post_json(endpoint, payload, timeout_seconds=timeout_seconds)
    except Exception as exc:
        logger.warning("specialist_fanout_failed endpoint=%s error=%s", endpoint, _safe_error_text(exc))


async def _collect_dependency_health(settings: OrchestratorSettings) -> list[DependencyHealth]:
    checks = [
        ("sensor-node", f"{settings.sensor_node_url.rstrip('/')}/health"),
        ("filter-node", f"{settings.filter_node_url.rstrip('/')}/health"),
        ("brain-node", f"{settings.brain_node_url.rstrip('/')}/health"),
        ("global-model", f"{settings.global_model_url.rstrip('/')}/health"),
        ("ids-node-a", f"{settings.ids_a_url.rstrip('/')}/health"),
        ("ids-node-b", f"{settings.ids_b_url.rstrip('/')}/health"),
    ]
    coroutines = [_check_dependency(name, url, settings.request_timeout_seconds) for name, url in checks]
    return list(await asyncio.gather(*coroutines))


async def _check_dependency(name: str, url: str, timeout_seconds: float) -> DependencyHealth:
    try:
        payload = await get_json(url, timeout_seconds=timeout_seconds)
        remote_status = str(payload.get("status", "ok"))
        if remote_status not in {"ok", "degraded", "down"}:
            remote_status = "degraded"
        return DependencyHealth(name=name, status=remote_status, detail=url)
    except Exception as exc:
        return DependencyHealth(name=name, status="down", detail=f"{url} ({_safe_error_text(exc)})")


async def _fetch_list(url: str, timeout_seconds: float) -> list[dict[str, Any]]:
    try:
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()
        if isinstance(data, dict) and isinstance(data.get("value"), list):
            return [item for item in data["value"] if isinstance(item, dict)]
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
    except Exception:
        return []
    return []


async def _fetch_dict(url: str, timeout_seconds: float) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()
            if isinstance(data, dict):
                return data
    except Exception:
        return {}
    return {}


async def _build_live_payload(
    settings: OrchestratorSettings,
    recent_requests: deque[dict[str, str | bool]],
    attack_logs: deque[dict[str, str]],
    attack_state: dict[str, Any],
    inflight_packets: set[asyncio.Task[Any]],
    detection_branches: DetectionBranchConfig,
) -> dict[str, Any]:
    timeout_seconds = min(8.0, settings.request_timeout_seconds)
    (
        sensor_events,
        filter_cases,
        brain_reports,
        ids_a_events,
        ids_b_events,
        global_policy,
        federated_learning,
    ) = await asyncio.gather(
        _fetch_list(f"{settings.sensor_node_url.rstrip('/')}/v1/events/recent", timeout_seconds),
        _fetch_list(f"{settings.filter_node_url.rstrip('/')}/v1/cases/recent", timeout_seconds),
        _fetch_list(f"{settings.brain_node_url.rstrip('/')}/v1/reports/recent", timeout_seconds),
        _fetch_list(f"{settings.ids_a_url.rstrip('/')}/v1/events/recent", timeout_seconds),
        _fetch_list(f"{settings.ids_b_url.rstrip('/')}/v1/events/recent", timeout_seconds),
        _fetch_dict(f"{settings.global_model_url.rstrip('/')}/v1/federated/policy", timeout_seconds),
        _fetch_dict(f"{settings.global_model_url.rstrip('/')}/v1/federated/learning/state", timeout_seconds),
    )
    return {
        "schema_version": "LiveOverviewV1",
        "pipeline": list(recent_requests)[:50],
        "sensor_events": sensor_events,
        "filter_cases": filter_cases,
        "brain_reports": brain_reports,
        "ids_node_a_events": ids_a_events,
        "ids_node_b_events": ids_b_events,
        "attack_logs": list(attack_logs)[:80],
        "stats": {
            "is_attacking": attack_state["is_attacking"],
            "attack_type": attack_state["attack_type"],
            "total_packets_sent": attack_state["packet_sent"],
            "packets_delivered": attack_state["packets_delivered"],
            "packets_failed": attack_state["packets_failed"],
            "inflight_packets": len(inflight_packets),
            "current_vehicle": attack_state["current_vehicle"],
            "last_error": attack_state["last_error"],
        },
        "detection_branches": detection_branches.model_dump(mode="json"),
        "federated_learning": federated_learning,
        "global_policy": global_policy,
    }


async def _publish_live_snapshot(
    settings: OrchestratorSettings,
    recent_requests: deque[dict[str, str | bool]],
    attack_logs: deque[dict[str, str]],
    attack_state: dict[str, Any],
    inflight_packets: set[asyncio.Task[Any]],
    live_subscribers: set[asyncio.Queue[dict[str, Any]]],
    detection_branches: DetectionBranchConfig,
) -> None:
    if not live_subscribers:
        return
    payload = await _build_live_payload(
        settings,
        recent_requests,
        attack_logs,
        attack_state,
        inflight_packets,
        detection_branches,
    )
    dead_queues: list[asyncio.Queue[dict[str, Any]]] = []
    for queue in live_subscribers:
        if queue.full():
            try:
                queue.get_nowait()
            except Exception:
                dead_queues.append(queue)
                continue
        try:
            queue.put_nowait({"event": "update", "data": payload})
        except Exception:
            dead_queues.append(queue)
    for queue in dead_queues:
        live_subscribers.discard(queue)


def _safe_error_text(exc: Exception) -> str:
    text = str(exc).strip()
    return text if text else exc.__class__.__name__


app = create_app()
