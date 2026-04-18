"""
Compatibility IDS Server B (GPS spoof) proxy.

This legacy endpoint now forwards telemetry into the new tiered pipeline.
"""

from flask import Flask, jsonify, request
import os
import threading
import time
from typing import Any

import requests

app = Flask(__name__)

NODE_ID = os.getenv("NODE_ID", "IDS-B")
ZONE = os.getenv("ZONE", "B")
SPECIALTY = os.getenv("SPECIALTY", "gps_spoof")
IDS_B_PORT = int(os.getenv("IDS_B_PORT", "8002"))
ORCHESTRATOR_URL = os.getenv("ORCHESTRATOR_URL", "http://localhost:8100").rstrip("/")
GLOBAL_MODEL_URL = os.getenv("GLOBAL_MODEL_URL", "http://localhost:8104").rstrip("/")

stats = {
    "total_packets_analyzed": 0,
    "total_attacks_detected": 0,
    "packets_by_type": {},
    "server_start_time": time.time(),
    "last_sync_payload": {},
}


@app.route("/", methods=["GET"])
def health_check():
    uptime = time.time() - stats["server_start_time"]
    return jsonify(
        {
            "status": "online",
            "service": "Compatibility IDS Server B",
            "node_id": NODE_ID,
            "zone": ZONE,
            "specialty": SPECIALTY,
            "upstream_orchestrator": ORCHESTRATOR_URL,
            "upstream_global_model": GLOBAL_MODEL_URL,
            "uptime_seconds": uptime,
            "statistics": stats,
        }
    )


@app.route("/v2x/telemetry", methods=["POST"])
def analyze_telemetry():
    payload = request.get_json() or {}
    if not payload:
        return jsonify({"error": "No data provided"}), 400

    vehicle_id = str(payload.get("vehicle_id", "unknown"))
    message_type = str(payload.get("message_type", "BSM"))
    stats["total_packets_analyzed"] += 1
    stats["packets_by_type"][message_type] = stats["packets_by_type"].get(message_type, 0) + 1

    try:
        upstream = requests.post(
            f"{ORCHESTRATOR_URL}/v2x/telemetry",
            json=payload,
            timeout=15,
        )
        upstream.raise_for_status()
        upstream_data = upstream.json()
        sensor = upstream_data.get("sensor_response", {})
        event = sensor.get("event", {})
        classification = event.get("classification", {})
        detected = bool(sensor.get("suspicious", False))
        confidence = float(classification.get("confidence", 0.0))
        if detected:
            stats["total_attacks_detected"] += 1

        response_data = {
            "vehicle_id": vehicle_id,
            "node_id": NODE_ID,
            "zone": ZONE,
            "message_type": message_type,
            "timestamp": time.time(),
            "analysis": {
                "attack_type": SPECIALTY,
                "detected": detected,
                "confidence": confidence,
                "reasoning": "Forwarded through tiered orchestrator pipeline",
                "category": classification.get("label", "unknown"),
            },
            "server_info": {
                "is_specialist": True,
                "specialty": SPECIALTY,
                "mode": "compatibility_proxy",
            },
            "upstream": upstream_data,
        }

        threading.Thread(
            target=_report_to_global,
            args=(vehicle_id, detected, confidence),
            daemon=True,
        ).start()
        return jsonify(response_data), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 502


def _report_to_global(vehicle_id: str, detected: bool, confidence: float) -> None:
    try:
        signal_confidence = confidence if detected else max(0.05, confidence * 0.35)
        update_payload: dict[str, Any] = {
            "node_id": NODE_ID,
            "node_role": "legacy-ids-b",
            "correlation_id": f"legacy-{int(time.time() * 1000)}",
            "signals": [
                {
                    "attack_type": "gps_spoof",
                    "confidence": min(1.0, max(0.0, signal_confidence)),
                    "anomaly_score": min(1.0, max(0.0, signal_confidence)),
                    "sample_count": 1,
                }
            ],
            "metadata": {"vehicle_id": vehicle_id, "source": "compatibility_proxy"},
        }
        requests.post(
            f"{GLOBAL_MODEL_URL}/v1/federated/local-update",
            json=update_payload,
            timeout=8,
        )
    except Exception:
        pass


@app.route("/federated-learning/sync", methods=["POST"])
def sync_knowledge():
    sync_payload = request.get_json() or {}
    stats["last_sync_payload"] = sync_payload
    return jsonify(
        {
            "status": "synced",
            "node_id": NODE_ID,
            "mode": "compatibility_proxy",
            "received_keys": list(sync_payload.keys()),
        }
    ), 200


@app.route("/stats", methods=["GET"])
def get_stats():
    return jsonify(
        {
            "node_id": NODE_ID,
            "zone": ZONE,
            "specialty": SPECIALTY,
            "statistics": stats,
            "mode": "compatibility_proxy",
        }
    )


@app.route("/shutdown", methods=["POST"])
def shutdown():
    return jsonify({"status": "shutting_down"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=IDS_B_PORT, debug=False, threaded=True)
