"""
Compatibility Master Coordinator proxy.

Legacy distributed endpoints are preserved, but federated coordination is now
delegated to the new global-model service in tiered_xai_ids.
"""

from flask import Flask, jsonify, request
import os
import time
from typing import Any

import requests

app = Flask(__name__)

COORDINATOR_PORT = int(os.getenv("MASTER_COORDINATOR_PORT", "9090"))
COORDINATOR_HOST = os.getenv("MASTER_COORDINATOR_HOST", "0.0.0.0")
GLOBAL_MODEL_URL = os.getenv("GLOBAL_MODEL_URL", "http://localhost:8104").rstrip("/")
IDS_A_URL = os.getenv("IDS_A_URL", "http://localhost:8001").rstrip("/")
IDS_B_URL = os.getenv("IDS_B_URL", "http://localhost:8002").rstrip("/")

state = {
    "start_time": time.time(),
    "reports_received": 0,
    "last_report": {},
}


@app.route("/", methods=["GET"])
def health_check():
    uptime = time.time() - state["start_time"]
    return jsonify(
        {
            "status": "online",
            "service": "Compatibility Master Coordinator",
            "mode": "proxy_to_global_model",
            "global_model_url": GLOBAL_MODEL_URL,
            "uptime_seconds": uptime,
            "reports_received": state["reports_received"],
        }
    )


@app.route("/federated-learning/report", methods=["POST"])
def receive_report():
    report = request.get_json() or {}
    if not report:
        return jsonify({"error": "No report data provided"}), 400

    state["reports_received"] += 1
    state["last_report"] = report

    analysis = report.get("analysis_result", {}) if isinstance(report, dict) else {}
    specialty = str(report.get("specialty", "unknown"))
    confidence = float(analysis.get("confidence", 0.0))
    detected = bool(analysis.get("detected", False))
    normalized = confidence if detected else max(0.05, confidence * 0.35)
    attack_type = "gps_spoof" if "gps" in specialty.lower() else "ddos"

    update_payload: dict[str, Any] = {
        "node_id": str(report.get("node_id", "legacy-node")),
        "node_role": "legacy-coordinator-report",
        "correlation_id": f"legacy-{int(time.time() * 1000)}",
        "signals": [
            {
                "attack_type": attack_type,
                "confidence": min(1.0, max(0.0, normalized)),
                "anomaly_score": min(1.0, max(0.0, normalized)),
                "sample_count": 1,
            }
        ],
        "metadata": {
            "vehicle_id": str(report.get("vehicle_id", "unknown")),
            "zone": str(report.get("zone", "unknown")),
        },
    }

    try:
        upstream = requests.post(
            f"{GLOBAL_MODEL_URL}/v1/federated/local-update",
            json=update_payload,
            timeout=10,
        )
        upstream.raise_for_status()
        upstream_json = upstream.json()
        return jsonify(
            {
                "status": "received",
                "mode": "proxy_to_global_model",
                "global_response": upstream_json,
            }
        ), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 502


@app.route("/federated-learning/stats", methods=["GET"])
def get_federated_stats():
    try:
        state_response = requests.get(f"{GLOBAL_MODEL_URL}/v1/federated/state", timeout=8)
        state_response.raise_for_status()
        global_state = state_response.json()
    except Exception as exc:
        global_state = {"error": str(exc)}

    return jsonify(
        {
            "mode": "proxy_to_global_model",
            "reports_received": state["reports_received"],
            "last_report": state["last_report"],
            "global_state": global_state,
        }
    )


@app.route("/servers/status", methods=["GET"])
def get_servers_status():
    status_report: dict[str, Any] = {
        "coordinator": "online",
        "mode": "proxy_to_global_model",
        "timestamp": time.time(),
        "servers": {},
    }
    for name, url in {"A": IDS_A_URL, "B": IDS_B_URL}.items():
        try:
            resp = requests.get(url, timeout=5)
            status_report["servers"][name] = {
                "status": "online" if resp.status_code == 200 else "error",
                "status_code": resp.status_code,
                "details": resp.json() if resp.status_code == 200 else {},
            }
        except Exception as exc:
            status_report["servers"][name] = {"status": "offline", "error": str(exc)}
    try:
        global_resp = requests.get(f"{GLOBAL_MODEL_URL}/health", timeout=5)
        status_report["global_model"] = {
            "status": "online" if global_resp.status_code == 200 else "error",
            "status_code": global_resp.status_code,
            "details": global_resp.json() if global_resp.status_code == 200 else {},
        }
    except Exception as exc:
        status_report["global_model"] = {"status": "offline", "error": str(exc)}
    return jsonify(status_report)


@app.route("/config", methods=["GET"])
def get_config():
    return jsonify(
        {
            "coordinator_port": COORDINATOR_PORT,
            "coordinator_host": COORDINATOR_HOST,
            "global_model_url": GLOBAL_MODEL_URL,
            "ids_a_url": IDS_A_URL,
            "ids_b_url": IDS_B_URL,
            "mode": "proxy_to_global_model",
        }
    )


if __name__ == "__main__":
    app.run(host=COORDINATOR_HOST, port=COORDINATOR_PORT, debug=False, threaded=True)
