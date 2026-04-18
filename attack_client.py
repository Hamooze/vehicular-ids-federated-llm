"""
Attack Generation Client
Separate service that sends traffic and attack payloads to IDS servers
Hosts web interface for attack control
"""

from flask import Flask, render_template, jsonify, request
import math
import requests
import datetime
import random
import threading
import time
import os
import json
from typing import Any
from colorama import Fore, init

try:
    import docker
except Exception:
    docker = None

init(autoreset=True)

app = Flask(__name__)

# Configuration - Read from environment variables
# Defaults now point to the new orchestrator bridge so legacy UI works out-of-the-box.
ORCHESTRATOR_URL = os.getenv('ORCHESTRATOR_URL', 'http://localhost:8100')
IDS_A_URL = os.getenv('IDS_A_URL', ORCHESTRATOR_URL)
IDS_B_URL = os.getenv('IDS_B_URL', ORCHESTRATOR_URL)
# Direct URLs to specialist nodes (for FL state queries).
IDS_A_DIRECT_URL = os.getenv('IDS_A_DIRECT_URL', 'http://ids-node-a:8001')
IDS_B_DIRECT_URL = os.getenv('IDS_B_DIRECT_URL', 'http://ids-node-b:8002')
MASTER_COORDINATOR_URL = os.getenv('MASTER_COORDINATOR_URL', ORCHESTRATOR_URL)
GLOBAL_MODEL_URL = os.getenv('GLOBAL_MODEL_URL', '')
ATTACK_CLIENT_PORT = int(os.getenv('ATTACK_CLIENT_PORT', '7000'))
ATTACK_DOCKER_CONTROL_ENABLED = os.getenv('ATTACK_DOCKER_CONTROL_ENABLED', 'true').strip().lower() in {'1', 'true', 'yes', 'on'}

if not GLOBAL_MODEL_URL:
    if ":8100" in ORCHESTRATOR_URL:
        GLOBAL_MODEL_URL = ORCHESTRATOR_URL.replace(":8100", ":8104")
    else:
        GLOBAL_MODEL_URL = MASTER_COORDINATOR_URL

NODE_PROFILES = {
    'A': {
        'display_name': 'IDS Node A',
        'role': 'DDoS Specialist · ids-node-a',
        'specialty': 'ddos',
    },
    'B': {
        'display_name': 'IDS Node B',
        'role': 'GPS Spoof Specialist · ids-node-b',
        'specialty': 'gps_spoof',
    },
    'master': {
        'display_name': 'Global Model',
        'role': 'Federated learning coordinator · global-model',
    },
    'orchestrator': {
        'display_name': 'Orchestrator',
        'role': 'Pipeline router and live stream · orchestrator',
    },
}

EDGE_NODE_SERVICE_MAP = {
    'A': 'ids-node-a',
    'B': 'ids-node-b',
}

ATTACK_PROFILES: dict[str, dict[str, Any]] = {
    'ddos': {
        'label': 'DDoS',
        'message_type': 'ATTACK_DDOS',
        'default_vehicle': 'FAKE-DDoS-01',
        'default_target': 'A',
        'interval_seconds': 0.2,
        'speed_range': (60.0, 70.0),
        'lat_center': 25.2048,
        'lon_center': 55.2708,
        'lat_jitter': 0.0001,
        'lon_jitter': 0.0001,
    },
    'gps_spoof': {
        'label': 'GPS Spoof',
        'message_type': 'ATTACK_GPS_SPOOF',
        'default_vehicle': 'FAKE-GPS-01',
        'default_target': 'B',
        'interval_seconds': 0.5,
        'speed_range': (40.0, 80.0),
        'lat_center': 25.0,
        'lon_center': 55.0,
        'lat_jitter': 1.0,
        'lon_jitter': 1.0,
    },
    'prompt_injection': {
        'label': 'Prompt Injection',
        'message_type': 'ATTACK_PROMPT_INJECTION',
        'default_vehicle': 'FAKE-PROMPT-01',
        'default_target': 'B',
        'interval_seconds': 0.45,
        'speed_range': (45.0, 95.0),
        'lat_center': 25.2048,
        'lon_center': 55.2708,
        'lat_jitter': 0.02,
        'lon_jitter': 0.02,
    },
    'indirect_prompt_injection': {
        'label': 'Indirect Prompt Injection',
        'message_type': 'ATTACK_INDIRECT_PROMPT',
        'default_vehicle': 'FAKE-IPI-01',
        'default_target': 'B',
        'interval_seconds': 0.5,
        'speed_range': (40.0, 90.0),
        'lat_center': 25.2048,
        'lon_center': 55.2708,
        'lat_jitter': 0.03,
        'lon_jitter': 0.03,
    },
    'v2x_exploitation': {
        'label': 'V2X Exploitation',
        'message_type': 'ATTACK_V2X_EXPLOITATION',
        'default_vehicle': 'FAKE-V2X-01',
        'default_target': 'A',
        'interval_seconds': 0.3,
        'speed_range': (70.0, 140.0),
        'lat_center': 25.2048,
        'lon_center': 55.2708,
        'lat_jitter': 0.08,
        'lon_jitter': 0.08,
    },
    'data_poisoning': {
        'label': 'Data Poisoning',
        'message_type': 'ATTACK_DATA_POISONING',
        'default_vehicle': 'FAKE-DP-01',
        'default_target': 'A',
        'interval_seconds': 0.4,
        'speed_range': (35.0, 95.0),
        'lat_center': 25.2048,
        'lon_center': 55.2708,
        'lat_jitter': 0.03,
        'lon_jitter': 0.03,
    },
}

ATTACK_LABELS = {
    'ddos': 'DDoS',
    'gps_spoof': 'GPS Spoofing',
    'prompt_injection': 'Prompt Injection',
    'indirect_prompt_injection': 'Indirect Prompt Injection',
    'v2x_exploitation': 'V2X Exploitation',
    'data_poisoning': 'Data Poisoning',
}

# Attack state
attack_state = {
    'is_attacking': False,
    'attack_type': None,
    'packet_sent': 0,
    'packets_delivered': 0,
    'packets_failed': 0,
    'start_time': None,
    'history': [],
    'vehicles': {}
}

# Default vehicle configuration
DEFAULT_VEHICLES = {
    'V001': {'speed': 60, 'lat': 25.2048, 'lon': 55.2708, 'heading': 90},
    'V002': {'speed': 55, 'lat': 25.2050, 'lon': 55.2710, 'heading': 95},
    'V003': {'speed': 65, 'lat': 25.2045, 'lon': 55.2705, 'heading': 85},
}

# Initialize vehicles
attack_state['vehicles'] = DEFAULT_VEHICLES.copy()


def initialize_client():
    """Initialize the attack client"""
    print(f"\n{Fore.CYAN}{'='*70}")
    print(f"Initializing Attack Generation Client")
    print(f"{'='*70}")
    print(f"Attack Client Port: {ATTACK_CLIENT_PORT}")
    print(f"IDS Server A URL: {IDS_A_URL}")
    print(f"IDS Server B URL: {IDS_B_URL}")
    print(f"Master Coordinator: {MASTER_COORDINATOR_URL}")
    print(f"Global Model URL: {GLOBAL_MODEL_URL}")
    print(f"Available Vehicles:")
    for vehicle_id, config in DEFAULT_VEHICLES.items():
        print(f"  {vehicle_id}: Speed={config['speed']}, Location=[{config['lat']}, {config['lon']}]")
    print(f"{'='*70}\n")


@app.route('/', methods=['GET'])
def index():
    """Serve the web interface"""
    return render_template('attack_panel.html', servers={
        'ids_a': IDS_A_URL,
        'ids_b': IDS_B_URL,
        'master': MASTER_COORDINATOR_URL
    })


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'online',
        'service': 'Attack Generation Client',
        'timestamp': datetime.datetime.now().isoformat(),
        'is_attacking': attack_state['is_attacking'],
        'total_packets_sent': attack_state['packet_sent'],
        'packets_delivered': attack_state['packets_delivered'],
        'packets_failed': attack_state['packets_failed']
    })


@app.route('/api/servers/status', methods=['GET'])
def check_servers():
    """Check status of all IDS servers"""
    status = {
        'timestamp': datetime.datetime.now().isoformat(),
        'servers': {}
    }

    # Prefer orchestrator topology map when legacy URLs point to orchestrator.
    try:
        orch_response = requests.get(f"{ORCHESTRATOR_URL}/api/servers/status", timeout=4)
        orch_response.raise_for_status()
        orch_data = orch_response.json()
        servers_map = orch_data.get('servers', {})
        if isinstance(servers_map, dict) and servers_map:
            ids_a_info = servers_map.get('ids_node_a', {})
            ids_b_info = servers_map.get('ids_node_b', {})
            global_info = servers_map.get('global_model', {})
            status['servers']['A'] = _with_node_profile('A', {
                'status': _coerce_status(ids_a_info),
                'source': 'ids-node-a',
                'detail': ids_a_info.get('detail', ''),
            })
            status['servers']['B'] = _with_node_profile('B', {
                'status': _coerce_status(ids_b_info),
                'source': 'ids-node-b',
                'detail': ids_b_info.get('detail', ''),
            })
            status['servers']['master'] = _with_node_profile('master', {
                'status': _coerce_status(global_info),
                'source': 'global-model',
                'detail': global_info.get('detail', ''),
            })
            status['servers']['orchestrator'] = _with_node_profile('orchestrator', {
                'status': 'online',
                'source': 'orchestrator',
                'detail': ORCHESTRATOR_URL,
            })
            return jsonify(status)
    except Exception as e:
        status['servers']['orchestrator'] = _with_node_profile('orchestrator', {'status': 'offline', 'error': str(e)})

    # Fallback: direct URL probing in legacy mode.
    status['servers']['A'] = _with_node_profile('A', _probe_service(IDS_A_URL))
    status['servers']['B'] = _with_node_profile('B', _probe_service(IDS_B_URL))
    status['servers']['master'] = _with_node_profile('master', _probe_service(MASTER_COORDINATOR_URL))
    return jsonify(status)


def _probe_service(base_url: str) -> dict:
    try:
        response = requests.get(base_url, timeout=3)
        if response.status_code == 200:
            payload = response.json() if response.headers.get('Content-Type', '').startswith('application/json') else {}
            return {'status': 'online', 'data': payload}
    except Exception:
        pass

    health_url = f"{base_url.rstrip('/')}/health"
    try:
        response = requests.get(health_url, timeout=3)
        if response.status_code == 200:
            payload = response.json() if response.headers.get('Content-Type', '').startswith('application/json') else {}
            return {'status': 'online', 'data': payload, 'detail': health_url}
        return {'status': 'error', 'code': response.status_code, 'detail': health_url}
    except Exception as e:
        return {'status': 'offline', 'error': str(e), 'detail': health_url}


def _coerce_status(info: dict) -> str:
    raw_status = str(info.get('status', 'offline')).strip().lower()
    if raw_status in {'online', 'ok'}:
        return 'online'
    if raw_status in {'degraded'}:
        return 'degraded'
    if raw_status in {'offline', 'down'}:
        return 'offline'
    return 'error'


def _with_node_profile(node_key: str, payload: dict) -> dict:
    info = dict(payload)
    profile = NODE_PROFILES.get(node_key, {})
    if profile:
        info.setdefault('display_name', profile.get('display_name', node_key))
        info.setdefault('role', profile.get('role', ''))
    return info


def _read_detection_branches() -> dict[str, bool]:
    try:
        response = requests.get(f"{ORCHESTRATOR_URL}/api/detection/branches", timeout=4)
        response.raise_for_status()
        payload = response.json()
        return {
            'ddos_enabled': bool(payload.get('ddos_enabled', True)),
            'gps_enabled': bool(payload.get('gps_enabled', True)),
        }
    except Exception:
        return {
            'ddos_enabled': True,
            'gps_enabled': True,
        }


def _write_detection_branches(*, ddos_enabled: bool, gps_enabled: bool) -> dict[str, bool]:
    payload = {'ddos_enabled': bool(ddos_enabled), 'gps_enabled': bool(gps_enabled)}
    response = requests.put(
        f"{ORCHESTRATOR_URL}/api/detection/branches",
        json=payload,
        timeout=5,
    )
    response.raise_for_status()
    data = response.json()
    return {
        'ddos_enabled': bool(data.get('ddos_enabled', ddos_enabled)),
        'gps_enabled': bool(data.get('gps_enabled', gps_enabled)),
    }


def _docker_client() -> tuple[Any | None, str | None]:
    if not ATTACK_DOCKER_CONTROL_ENABLED:
        return None, 'docker_control_disabled'
    if docker is None:
        return None, 'docker_sdk_unavailable'
    try:
        client = docker.from_env()
        client.ping()
        return client, None
    except Exception as exc:
        return None, str(exc)


def _container_summary(service_name: str) -> dict[str, Any]:
    client, error = _docker_client()
    if client is None:
        return {
            'service': service_name,
            'available': False,
            'running': None,
            'status': 'unknown',
            'detail': error or 'docker_unavailable',
        }
    try:
        containers = client.containers.list(
            all=True,
            filters={'label': f'com.docker.compose.service={service_name}'},
        )
        if not containers:
            return {
                'service': service_name,
                'available': True,
                'running': False,
                'status': 'not_found',
                'detail': 'container_not_found',
            }
        container = containers[0]
        container.reload()
        state = container.attrs.get('State', {}) if isinstance(container.attrs, dict) else {}
        running = bool(state.get('Running', False))
        return {
            'service': service_name,
            'available': True,
            'running': running,
            'status': str(container.status),
            'container_name': container.name,
            'container_id': container.short_id,
        }
    except Exception as exc:
        return {
            'service': service_name,
            'available': False,
            'running': None,
            'status': 'error',
            'detail': str(exc),
        }
    finally:
        try:
            client.close()
        except Exception:
            pass


def _set_container_running(service_name: str, *, enabled: bool) -> dict[str, Any]:
    client, error = _docker_client()
    if client is None:
        raise RuntimeError(error or 'docker_unavailable')
    try:
        containers = client.containers.list(
            all=True,
            filters={'label': f'com.docker.compose.service={service_name}'},
        )
        if not containers:
            raise RuntimeError(f'container_not_found_for_service:{service_name}')
        container = containers[0]
        container.reload()
        is_running = bool(container.attrs.get('State', {}).get('Running', False))
        if enabled and not is_running:
            container.start()
        if not enabled and is_running:
            container.stop(timeout=5)
        container.reload()
        now_running = bool(container.attrs.get('State', {}).get('Running', False))
        return {
            'service': service_name,
            'container_name': container.name,
            'container_id': container.short_id,
            'running': now_running,
            'status': str(container.status),
        }
    finally:
        try:
            client.close()
        except Exception:
            pass


def _fetch_specialist_fl_state(direct_url: str) -> dict[str, Any]:
    """Fetch FL model state directly from a specialist node."""
    try:
        resp = requests.get(f"{direct_url.rstrip('/')}/v1/federated/model/state", timeout=4)
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return {}


def _node_score(fl_state: dict[str, Any], attack_type: str, fallback: float) -> float:
    """Extract a node's EWA FL score for the given attack type from its model state."""
    scores = fl_state.get('node_fl_scores', {})
    if attack_type in scores:
        return round(float(scores[attack_type]), 3)
    return fallback


def _edge_node_state() -> dict[str, Any]:
    # Fetch specialist enable/disable state from orchestrator.
    toggle_state: dict[str, Any] = {
        'ids_node_a': {'enabled': True},
        'ids_node_b': {'enabled': True},
    }
    try:
        resp = requests.get(f"{ORCHESTRATOR_URL}/api/specialist-nodes/state", timeout=4)
        resp.raise_for_status()
        toggle_state = resp.json()
    except Exception:
        pass

    # Fetch FL model state directly from each specialist node.
    fl_a = _fetch_specialist_fl_state(IDS_A_DIRECT_URL)
    fl_b = _fetch_specialist_fl_state(IDS_B_DIRECT_URL)

    # Per-node FL scores come directly from the specialist nodes' own EWA tracking.
    # Node A: specialty=ddos (primary), cross=gps_spoof
    # Node B: specialty=gps_spoof (primary), cross=ddos
    node_a_specialty_score = _node_score(fl_a, 'ddos', 0.80)
    node_a_cross_score = _node_score(fl_a, 'gps_spoof', 0.30)
    node_b_specialty_score = _node_score(fl_b, 'gps_spoof', 0.80)
    node_b_cross_score = _node_score(fl_b, 'ddos', 0.30)

    return {
        'edge_nodes': {
            'A': {
                **NODE_PROFILES['A'],
                'enabled': bool(toggle_state.get('ids_node_a', {}).get('enabled', True)),
                'fl_revision': int(fl_a.get('revision', 0)),
                'cross_learning_active': bool(fl_a.get('cross_learning_active', True)),
                'fl_score': node_a_specialty_score,
                'fl_cross_score': node_a_cross_score,
                'cross_type_alert_threshold': float(fl_a.get('cross_type_alert_threshold', 0.80)),
            },
            'B': {
                **NODE_PROFILES['B'],
                'enabled': bool(toggle_state.get('ids_node_b', {}).get('enabled', True)),
                'fl_revision': int(fl_b.get('revision', 0)),
                'cross_learning_active': bool(fl_b.get('cross_learning_active', True)),
                'fl_score': node_b_specialty_score,
                'fl_cross_score': node_b_cross_score,
                'cross_type_alert_threshold': float(fl_b.get('cross_type_alert_threshold', 0.80)),
            },
        },
    }


def _read_specialist_enabled_state() -> tuple[bool, bool]:
    node_a_enabled = True
    node_b_enabled = True
    try:
        ns_resp = requests.get(f"{ORCHESTRATOR_URL}/api/specialist-nodes/state", timeout=3)
        if ns_resp.status_code == 200:
            ns_data = ns_resp.json()
            node_a_enabled = bool(ns_data.get('ids_node_a', {}).get('enabled', True))
            node_b_enabled = bool(ns_data.get('ids_node_b', {}).get('enabled', True))
    except Exception:
        pass
    return node_a_enabled, node_b_enabled


def _detect_attack_type_from_context(*, node_a_enabled: bool, node_b_enabled: bool) -> str:
    active = str(attack_state.get('attack_type') or '').strip().lower()
    if active in ATTACK_PROFILES:
        return active

    combined: list[dict[str, Any]] = []
    try:
        if node_a_enabled:
            events_a = requests.get(f"{IDS_A_DIRECT_URL}/v1/events/recent", timeout=3).json()
            if isinstance(events_a, list):
                combined.extend([e for e in events_a[:8] if isinstance(e, dict)])
        if node_b_enabled:
            events_b = requests.get(f"{IDS_B_DIRECT_URL}/v1/events/recent", timeout=3).json()
            if isinstance(events_b, list):
                combined.extend([e for e in events_b[:8] if isinstance(e, dict)])
    except Exception:
        return ''

    for evt in combined:
        evt_attack_type = str(evt.get('attack_type', '')).strip().lower()
        evt_label = str(evt.get('label', 'benign')).strip().lower()
        if evt_attack_type in ATTACK_PROFILES and evt_label != 'benign':
            return evt_attack_type
    return ''


def _resolve_detector_node(
    *,
    attack_type: str,
    node_a_enabled: bool,
    node_b_enabled: bool,
    fl_score_a: float,
    fl_score_b: float,
) -> str:
    if attack_type == 'ddos':
        return 'A' if node_a_enabled else 'B'
    if attack_type in {'gps_spoof', 'prompt_injection', 'indirect_prompt_injection'}:
        return 'B' if node_b_enabled else 'A'
    if attack_type in {'v2x_exploitation', 'data_poisoning'}:
        return 'A' if node_a_enabled else 'B'
    if node_a_enabled and node_b_enabled:
        return 'A' if fl_score_a >= fl_score_b else 'B'
    return 'A' if node_a_enabled else 'B'


def _build_prompt_master_recommendation(
    *,
    question: str,
    attack_type: str,
    current_round: dict[str, Any],
    detected_by: str,
    fl_score_a: float,
    fl_score_b: float,
    fl_cross_score_a: float,
    fl_cross_score_b: float,
) -> tuple[str, str]:
    round_id = current_round.get('round_id', '-')
    attack_label = ATTACK_LABELS.get(attack_type, 'Network Readiness')
    context_line = (
        f"Current FL round={round_id}; detector={detected_by}; "
        f"NodeA_ddos={fl_score_a:.2f}; NodeB_gps={fl_score_b:.2f}; "
        f"NodeA_cross_gps={fl_cross_score_a:.2f}; NodeB_cross_ddos={fl_cross_score_b:.2f}."
    )

    if attack_type:
        reason = (
            f"Prompt focus set to {attack_label} using live telemetry and specialist confidence."
        )
        prompt = (
            f"You are a SOC incident commander for a vehicular IDS. {context_line} "
            f"Treat this as a possible {attack_label} incident and answer: \"{question}\". "
            "Return four sections: (1) evidence that confirms or rejects the attack, "
            "(2) confidence rationale tied to FL scores and detector ownership, "
            "(3) immediate containment actions for the next 15 minutes, "
            "(4) verification checks with expected healthy signals."
        )
        return prompt, reason

    reason = "No specific attack is active, so Prompt Master generated a readiness-focused query."
    prompt = (
        f"You are a SOC readiness analyst for a vehicular IDS. {context_line} "
        f"Answer: \"{question}\" with an operations-ready baseline report. "
        "Return four sections: (1) current risk posture, (2) top 3 monitoring priorities, "
        "(3) preventive hardening actions for the next 30 minutes, "
        "(4) quick checks that confirm the system remains stable."
    )
    return prompt, reason


def _build_prompt_master_options(
    *,
    question: str,
    attack_type: str,
    current_round: dict[str, Any],
    detected_by: str,
    fl_score_a: float,
    fl_score_b: float,
) -> list[dict[str, str]]:
    round_id = current_round.get('round_id', '-')
    label = ATTACK_LABELS.get(attack_type, 'network readiness')
    evidence_prompt = (
        f"For round {round_id}, analyze {label} with detector node {detected_by}. "
        f"FL specialty scores: A={fl_score_a:.2f}, B={fl_score_b:.2f}. "
        f"Question: \"{question}\". Provide concise evidence, confidence, and impact."
    )
    containment_prompt = (
        f"Given a potential {label} event in round {round_id}, produce an immediate "
        "15-minute containment checklist with command-level priorities, sequence, and fallback actions."
    )
    validation_prompt = (
        f"Create a post-action validation checklist for {label}: what to measure, "
        "which telemetry confirms recovery, and how to detect false positives quickly."
    )

    if attack_type:
        return [
            {
                'id': 'incident_brief',
                'title': 'Incident Brief',
                'description': 'Confirm attack status and impact',
                'prompt': evidence_prompt,
            },
            {
                'id': 'containment_plan',
                'title': 'Containment Plan',
                'description': 'Immediate tactical actions',
                'prompt': containment_prompt,
            },
            {
                'id': 'validation_checklist',
                'title': 'Validation Checklist',
                'description': 'Verify recovery and reduce false positives',
                'prompt': validation_prompt,
            },
        ]

    return [
        {
            'id': 'readiness_snapshot',
            'title': 'Readiness Snapshot',
            'description': 'Current risk posture and priorities',
            'prompt': (
                f"Use round {round_id} FL context to provide a concise network readiness snapshot and "
                "the top 3 near-term risks to watch."
            ),
        },
        {
            'id': 'hardening_priorities',
            'title': 'Hardening Priorities',
            'description': 'Preventive controls for next 30 minutes',
            'prompt': (
                "Recommend preventive hardening actions for DDoS, GPS spoofing, prompt attacks, V2X abuse, "
                "and data poisoning using the current federated state."
            ),
        },
        {
            'id': 'operator_question_refine',
            'title': 'Refine Operator Question',
            'description': 'Sharper wording for faster AI answers',
            'prompt': (
                f"Rewrite this operator query to be more actionable and concise: \"{question}\". "
                "Keep the same intent, but optimize for rapid incident response."
            ),
        },
    ]


@app.route('/api/edge-nodes/state', methods=['GET'])
def edge_nodes_state():
    return jsonify(_edge_node_state())


@app.route('/api/edge-nodes/soft-toggle', methods=['POST'])
def edge_nodes_soft_toggle():
    """Enable or disable a specialist IDS node by toggling the orchestrator's fanout."""
    payload = request.get_json() or {}
    node = str(payload.get('node', '')).strip().upper()
    enabled = bool(payload.get('enabled', True))
    if node not in {'A', 'B'}:
        return jsonify({'error': 'node must be A or B'}), 400
    try:
        resp = requests.put(
            f"{ORCHESTRATOR_URL}/api/specialist-nodes/toggle",
            json={'node': node, 'enabled': enabled},
            timeout=5,
        )
        resp.raise_for_status()
        return jsonify({
            'ok': True,
            'node': node,
            'enabled': enabled,
            'state': _edge_node_state(),
        })
    except Exception as exc:
        return jsonify({'ok': False, 'error': str(exc)}), 502


@app.route('/api/edge-nodes/hard-toggle', methods=['POST'])
def edge_nodes_hard_toggle():
    """Docker control has been removed. Use Enable/Disable Server (soft-toggle) instead."""
    return jsonify({'ok': False, 'error': 'Docker control removed. Use Enable/Disable Server.'}), 501


@app.route('/api/federated/status', methods=['GET'])
def federated_status():
    """Fetch federated learning state plus live network context."""
    result = {
        'timestamp': datetime.datetime.now().isoformat(),
        'global_model_url': GLOBAL_MODEL_URL,
        'orchestrator_url': ORCHESTRATOR_URL,
        'federated_online': False,
        'current_round': {},
        'policy': {},
        'history': [],
        'network_context': {},
        'detection_branches': {},
        'federated_learning': {},
    }
    try:
        state_resp = requests.get(f"{GLOBAL_MODEL_URL}/v1/federated/state", timeout=3)
        state_resp.raise_for_status()
        state_data = state_resp.json()
        result['federated_online'] = True
        result['current_round'] = state_data.get('current_round', {})
        result['policy'] = result['current_round'].get('policy', {})
    except Exception as e:
        result['state_error'] = str(e)

    try:
        history_resp = requests.get(f"{GLOBAL_MODEL_URL}/v1/federated/history", timeout=3)
        history_resp.raise_for_status()
        history_data = history_resp.json()
        if isinstance(history_data, list):
            result['history'] = history_data[:5]
    except Exception as e:
        result['history_error'] = str(e)

    try:
        live_resp = requests.get(f"{ORCHESTRATOR_URL}/api/live/overview", timeout=3)
        live_resp.raise_for_status()
        live_data = live_resp.json()
        result['network_context'] = {
            'pipeline_events': len(live_data.get('pipeline', [])),
            'sensor_events': len(live_data.get('sensor_events', [])),
            'filter_cases': len(live_data.get('filter_cases', [])),
            'brain_reports': len(live_data.get('brain_reports', [])),
            'attack_logs': len(live_data.get('attack_logs', [])),
            'stats': live_data.get('stats', {}),
        }
        result['detection_branches'] = live_data.get('detection_branches', {})
        result['federated_learning'] = live_data.get('federated_learning', {})
        if not result.get('policy'):
            result['policy'] = live_data.get('global_policy', {})
    except Exception as e:
        result['network_error'] = str(e)

    return jsonify(result)


@app.route('/api/master/prompt-master', methods=['POST'])
def prompt_master_recommendation():
    """Generate attack-aware prompt recommendations without waiting on LLM response."""
    body = request.get_json(silent=True) or {}
    question = str(body.get('question', '')).strip() or "What is happening now and what should I do next?"

    requested_attack_type = str(body.get('attack_type', 'auto')).strip().lower().replace('-', '_')
    if requested_attack_type in {'', 'auto', 'none'}:
        requested_attack_type = ''
    elif requested_attack_type not in ATTACK_PROFILES:
        return jsonify({'error': 'attack_type must be auto or one of supported attack keys'}), 400

    node_a_enabled, node_b_enabled = _read_specialist_enabled_state()

    current_round: dict[str, Any] = {}
    try:
        state_resp = requests.get(f"{GLOBAL_MODEL_URL}/v1/federated/state", timeout=3)
        if state_resp.status_code == 200:
            state_data = state_resp.json()
            current_round = state_data.get('current_round', {})
    except Exception:
        pass

    fl_a: dict[str, Any] = {}
    fl_b: dict[str, Any] = {}
    try:
        fl_a = requests.get(f"{IDS_A_DIRECT_URL}/v1/federated/model/state", timeout=3).json()
    except Exception:
        pass
    try:
        fl_b = requests.get(f"{IDS_B_DIRECT_URL}/v1/federated/model/state", timeout=3).json()
    except Exception:
        pass

    fl_score_a = _node_score(fl_a, 'ddos', 0.80)
    fl_score_b = _node_score(fl_b, 'gps_spoof', 0.80)
    fl_cross_score_a = _node_score(fl_a, 'gps_spoof', 0.30)
    fl_cross_score_b = _node_score(fl_b, 'ddos', 0.30)

    attack_type = requested_attack_type or _detect_attack_type_from_context(
        node_a_enabled=node_a_enabled,
        node_b_enabled=node_b_enabled,
    )
    detected_by = _resolve_detector_node(
        attack_type=attack_type,
        node_a_enabled=node_a_enabled,
        node_b_enabled=node_b_enabled,
        fl_score_a=fl_score_a,
        fl_score_b=fl_score_b,
    )

    recommended_prompt, recommendation_reason = _build_prompt_master_recommendation(
        question=question,
        attack_type=attack_type,
        current_round=current_round,
        detected_by=detected_by,
        fl_score_a=fl_score_a,
        fl_score_b=fl_score_b,
        fl_cross_score_a=fl_cross_score_a,
        fl_cross_score_b=fl_cross_score_b,
    )
    options = _build_prompt_master_options(
        question=question,
        attack_type=attack_type,
        current_round=current_round,
        detected_by=detected_by,
        fl_score_a=fl_score_a,
        fl_score_b=fl_score_b,
    )

    return jsonify({
        'ok': True,
        'mode': 'manual' if requested_attack_type else 'auto',
        'attack_type': attack_type,
        'attack_label': ATTACK_LABELS.get(attack_type, 'No Active Attack'),
        'detected_by': detected_by,
        'question': question,
        'recommended_prompt': recommended_prompt,
        'recommendation_reason': recommendation_reason,
        'options': options,
        'fl_score_a': round(fl_score_a, 3),
        'fl_score_b': round(fl_score_b, 3),
        'fl_cross_score_a': round(fl_cross_score_a, 3),
        'fl_cross_score_b': round(fl_cross_score_b, 3),
        'node_a_enabled': node_a_enabled,
        'node_b_enabled': node_b_enabled,
        'round_id': current_round.get('round_id', '-'),
    }), 200


@app.route('/api/master/chat', methods=['POST'])
def master_chat():
    """Ask the cloud/master AI for network + federated insight."""
    body = request.get_json() or {}
    question = str(body.get('question', '')).strip()
    if not question:
        return jsonify({'error': 'question is required'}), 400

    # --- Collect live telemetry context ---
    telemetry_context: dict[str, Any] = {}
    attack_type = ''
    try:
        live_resp = requests.get(f"{ORCHESTRATOR_URL}/api/live/overview", timeout=5)
        if live_resp.status_code == 200:
            live_data = live_resp.json()
            stats = live_data.get('stats', {})
            telemetry_context = {
                'pipeline_events': len(live_data.get('pipeline', [])),
                'sensor_events': len(live_data.get('sensor_events', [])),
                'filter_cases': len(live_data.get('filter_cases', [])),
                'brain_reports': len(live_data.get('brain_reports', [])),
                'attack_logs': len(live_data.get('attack_logs', [])),
                'stats': stats,
                'detection_branches': live_data.get('detection_branches', {}),
                'federated_learning': live_data.get('federated_learning', {}),
            }
    except Exception:
        pass

    # Fetch specialist node enabled/disabled state — used for the disabled-specialist gate below.
    node_a_enabled = True
    node_b_enabled = True
    try:
        ns_resp = requests.get(f"{ORCHESTRATOR_URL}/api/specialist-nodes/state", timeout=3)
        if ns_resp.status_code == 200:
            ns_data = ns_resp.json()
            node_a_enabled = bool(ns_data.get('ids_node_a', {}).get('enabled', True))
            node_b_enabled = bool(ns_data.get('ids_node_b', {}).get('enabled', True))
    except Exception:
        pass

    # Determine attack type: check local attack state first, then infer from IDS node detections.
    # Only query a specialist node's recent events if that node is currently enabled —
    # stale events from a disabled node must not trigger alerts.
    if attack_state.get('attack_type') in ('ddos', 'gps_spoof'):
        attack_type = attack_state['attack_type']
    if not attack_type:
        try:
            combined = []
            if node_a_enabled:
                events_a = requests.get(f"{IDS_A_DIRECT_URL}/v1/events/recent", timeout=3).json()
                if isinstance(events_a, list):
                    combined.extend(events_a[:5])
            if node_b_enabled:
                events_b = requests.get(f"{IDS_B_DIRECT_URL}/v1/events/recent", timeout=3).json()
                if isinstance(events_b, list):
                    combined.extend(events_b[:5])
            for evt in combined:
                if not isinstance(evt, dict):
                    continue
                at = evt.get('attack_type', '')
                label = evt.get('label', 'benign')
                if at in {
                    'ddos',
                    'gps_spoof',
                    'prompt_injection',
                    'indirect_prompt_injection',
                    'v2x_exploitation',
                    'data_poisoning',
                } and label != 'benign':
                    attack_type = at
                    break
        except Exception:
            pass

    # --- Fetch FL scores from global model (for policy/round context) ---
    current_round: dict[str, Any] = {}
    policy: dict[str, Any] = {}
    try:
        state_resp = requests.get(f"{GLOBAL_MODEL_URL}/v1/federated/state", timeout=3)
        if state_resp.status_code == 200:
            state_data = state_resp.json()
            current_round = state_data.get('current_round', {})
            policy = current_round.get('policy', {})
    except Exception:
        pass

    # --- Fetch per-node FL state directly from specialist nodes ---
    # FL scores come from each node's own EWA tracking (node_fl_scores), not the
    # global model's transient round scores — these persist and reflect real learning.
    fl_a: dict[str, Any] = {}
    fl_b: dict[str, Any] = {}
    try:
        fl_a = requests.get(f"{IDS_A_DIRECT_URL}/v1/federated/model/state", timeout=3).json()
    except Exception:
        pass
    try:
        fl_b = requests.get(f"{IDS_B_DIRECT_URL}/v1/federated/model/state", timeout=3).json()
    except Exception:
        pass

    node_a_revision = int(fl_a.get('revision', 0))
    node_b_revision = int(fl_b.get('revision', 0))
    node_a_cross_learning = bool(fl_a.get('cross_learning_active', True))
    node_b_cross_learning = bool(fl_b.get('cross_learning_active', True))

    # Per-node specialty scores from their own EWA tracking
    fl_score_a = _node_score(fl_a, 'ddos', 0.80)       # Node A: DDoS specialist
    fl_score_b = _node_score(fl_b, 'gps_spoof', 0.80)  # Node B: GPS specialist
    fl_cross_score_a = _node_score(fl_a, 'gps_spoof', 0.30)  # Node A cross-type
    fl_cross_score_b = _node_score(fl_b, 'ddos', 0.30)       # Node B cross-type

    # --- Disabled-specialist gate ---
    # If the dedicated specialist for an attack type is offline and the backup node
    # hasn't yet reached 0.80 cross-type FL confidence, suppress ALL detection output
    # entirely — the system should look completely idle, not just "None Detected".
    _CROSS_ALERT_THRESHOLD = 0.80
    _detection_suppressed = False
    if attack_type == 'ddos' and not node_a_enabled:
        if fl_cross_score_b < _CROSS_ALERT_THRESHOLD:
            _detection_suppressed = True
    elif attack_type == 'gps_spoof' and not node_b_enabled:
        if fl_cross_score_a < _CROSS_ALERT_THRESHOLD:
            _detection_suppressed = True

    # When suppressed, return an idle/normal response immediately — do NOT query the LLM.
    # Querying the LLM with high FL scores in context would still produce a CRITICAL
    # alert_level even with attack_type cleared, which is exactly what we don't want.
    if _detection_suppressed:
        _disabled_node = 'A' if not node_a_enabled else 'B'
        _cross_score = fl_cross_score_b if not node_a_enabled else fl_cross_score_a
        return jsonify({
            'summary': (
                f"IDS Node {_disabled_node} is offline. "
                f"Backup node cross-type FL confidence is {_cross_score:.2f} "
                f"(threshold: {_CROSS_ALERT_THRESHOLD:.2f}) — insufficient to classify this traffic. "
                f"System operating in degraded mode."
            ),
            'details': [],
            'alert_level': 'normal',
            'attack_type': '',
            'detected_by': 'B' if not node_a_enabled else 'A',
            'recommended_actions': [
                f'Re-enable IDS Node {_disabled_node} to restore full detection capability.',
                'Monitor cross-type FL score — detection will resume automatically when it reaches 0.80.',
                'Review network baselines manually while the specialist node is offline.',
            ],
            'fl_score_a': round(fl_score_a, 3),
            'fl_score_b': round(fl_score_b, 3),
            'fl_cross_score_a': round(fl_cross_score_a, 3),
            'fl_cross_score_b': round(fl_cross_score_b, 3),
            'node_a_revision': node_a_revision,
            'node_b_revision': node_b_revision,
            'node_a_cross_learning': node_a_cross_learning,
            'node_b_cross_learning': node_b_cross_learning,
        }), 200

    # Determine which node is the primary detector for the current attack.
    if attack_type == 'ddos':
        detected_by = 'A' if node_a_enabled else 'B'
    elif attack_type == 'gps_spoof':
        detected_by = 'B' if node_b_enabled else 'A'
    else:
        if node_a_enabled and node_b_enabled:
            detected_by = 'A' if fl_score_a >= fl_score_b else 'B'
        elif node_a_enabled:
            detected_by = 'A'
        else:
            detected_by = 'B'

    # --- Query the master AI LLM ---
    payload = {
        'question': question,
        'include_history': bool(body.get('include_history', True)),
        'telemetry_context': {
            **telemetry_context,
            'current_attack_type': attack_type,
            'fl_score_node_a_ddos': round(fl_score_a, 3),
            'fl_score_node_b_gps': round(fl_score_b, 3),
            'fl_cross_score_node_a_gps': round(fl_cross_score_a, 3),
            'fl_cross_score_node_b_ddos': round(fl_cross_score_b, 3),
            'node_a_fl_revision': node_a_revision,
            'node_b_fl_revision': node_b_revision,
            'node_a_cross_learning_active': node_a_cross_learning,
            'node_b_cross_learning_active': node_b_cross_learning,
        },
    }

    def _recommended_operator_prompt() -> str:
        labels = {
            'ddos': 'DDoS',
            'gps_spoof': 'GPS Spoofing',
            'prompt_injection': 'Prompt Injection',
            'indirect_prompt_injection': 'Indirect Prompt Injection',
            'v2x_exploitation': 'V2X Exploitation',
            'data_poisoning': 'Data Poisoning',
        }
        score_text = (
            f"NodeA_ddos={fl_score_a:.2f}, NodeB_gps={fl_score_b:.2f}, "
            f"NodeA_cross_gps={fl_cross_score_a:.2f}, NodeB_cross_ddos={fl_cross_score_b:.2f}"
        )
        base = (
            f"Original operator question: {question}. "
            f"Use current FL context ({score_text}) and current_round={current_round.get('round_id', '-')}. "
        )
        if attack_type in labels:
            return (
                base
                + f"Treat this as {labels[attack_type]} and produce a professional incident brief with "
                "evidence, confidence rationale, immediate containment actions, and verification checks."
            )
        return (
            base
            + "Produce a professional readiness report with top risks, monitoring priorities, "
              "and preventive hardening actions for the next 30 minutes."
        )

    def _enrich(base: dict[str, Any]) -> dict[str, Any]:
        base['fl_score_a'] = round(fl_score_a, 3)
        base['fl_score_b'] = round(fl_score_b, 3)
        base['fl_cross_score_a'] = round(fl_cross_score_a, 3)
        base['fl_cross_score_b'] = round(fl_cross_score_b, 3)
        base['node_a_revision'] = node_a_revision
        base['node_b_revision'] = node_b_revision
        base['node_a_cross_learning'] = node_a_cross_learning
        base['node_b_cross_learning'] = node_b_cross_learning
        base['attack_type'] = attack_type
        base['detected_by'] = detected_by
        if not str(base.get('recommended_prompt', '')).strip():
            base['recommended_prompt'] = _recommended_operator_prompt()
        return base

    try:
        response = requests.post(
            f"{GLOBAL_MODEL_URL}/v1/assistant/query",
            json=payload,
            timeout=5,
        )
        response.raise_for_status()
        return jsonify(_enrich(response.json()))
    except Exception as e:
        # Fallback when LLM is unreachable.
        highest = max(fl_score_a, fl_score_b)
        alert_level = 'critical' if highest >= 0.80 else ('elevated' if highest >= 0.60 else 'normal')
        summary = (
            f"Federated round {current_round.get('round_id', '-')} is active with "
            f"{current_round.get('update_count', 0)} updates. "
            f"Current specialist confidence: Node A DDoS {fl_score_a:.2f}, Node B GPS {fl_score_b:.2f}."
        )
        return jsonify(_enrich({
            'summary': summary,
            'details': [],
            'alert_level': alert_level,
            'recommended_actions': policy.get('recommended_actions', [
                'Monitor network flow baselines for unusual burst patterns.',
                'Validate GNSS integrity and flag impossible coordinate jumps.',
                'Increase sampling rate on events with anomaly score above 0.7.',
            ]),
            'policy': policy,
            'current_round': current_round,
            'fallback': 'master_ai_unreachable',
            'fallback_error': str(e),
            'recommended_prompt': _recommended_operator_prompt(),
        })), 200


@app.route('/api/send/normal-traffic', methods=['POST'])
def send_normal_traffic():
    """Send normal BSM (Basic Safety Message) traffic"""
    try:
        data = request.get_json() or {}
        vehicle_id = data.get('vehicle_id', 'V001')
        target_server = data.get('target_server', 'both')  # 'A', 'B', or 'both'
        
        if vehicle_id not in attack_state['vehicles']:
            return jsonify({'error': f'Vehicle {vehicle_id} not found'}), 400
        
        vehicle_config = attack_state['vehicles'][vehicle_id]
        
        # Simulate movement
        vehicle_config['speed'] += random.uniform(-5, 5)
        vehicle_config['speed'] = max(40, min(120, vehicle_config['speed']))
        vehicle_config['lat'] += random.uniform(-0.001, 0.001)
        vehicle_config['lon'] += random.uniform(-0.001, 0.001)
        vehicle_config['heading'] = (vehicle_config['heading'] + random.uniform(-10, 10)) % 360
        
        telemetry = {
            'vehicle_id': vehicle_id,
            'timestamp': datetime.datetime.now().isoformat(),
            'speed': round(vehicle_config['speed'], 2),
            'location': [round(vehicle_config['lat'], 6), round(vehicle_config['lon'], 6)],
            'heading': round(vehicle_config['heading'], 2),
            'message_type': 'BSM'
        }
        
        results = {}
        
        # Send to IDS A
        if target_server in ['A', 'both']:
            try:
                response = requests.post(
                    f"{IDS_A_URL}/v2x/telemetry",
                    json=telemetry,
                    timeout=5
                )
                results['A'] = {
                    'status': 'sent',
                    'code': response.status_code,
                    'response': response.json() if response.status_code == 200 else None
                }
                attack_state['packet_sent'] += 1
                if response.status_code == 200:
                    attack_state['packets_delivered'] += 1
                else:
                    attack_state['packets_failed'] += 1
            except Exception as e:
                results['A'] = {'status': 'failed', 'error': str(e)}
                attack_state['packet_sent'] += 1
                attack_state['packets_failed'] += 1
        
        # Send to IDS B
        if target_server in ['B', 'both']:
            try:
                response = requests.post(
                    f"{IDS_B_URL}/v2x/telemetry",
                    json=telemetry,
                    timeout=5
                )
                results['B'] = {
                    'status': 'sent',
                    'code': response.status_code,
                    'response': response.json() if response.status_code == 200 else None
                }
                attack_state['packet_sent'] += 1
                if response.status_code == 200:
                    attack_state['packets_delivered'] += 1
                else:
                    attack_state['packets_failed'] += 1
            except Exception as e:
                results['B'] = {'status': 'failed', 'error': str(e)}
                attack_state['packet_sent'] += 1
                attack_state['packets_failed'] += 1
        
        print(f"{Fore.GREEN}[Attack Client] Sent normal traffic from {vehicle_id}")
        
        return jsonify({
            'status': 'sent',
            'vehicle_id': vehicle_id,
            'telemetry': telemetry,
            'results': results
        }), 200
        
    except Exception as e:
        print(f"{Fore.RED}Error sending normal traffic: {str(e)}")
        return jsonify({'error': str(e)}), 500


def _normalize_target(value: Any) -> str:
    target = str(value or '').strip().upper()
    if target in {'A', 'B', 'BOTH'}:
        return target
    return 'BOTH'


def _resolve_attack_targets(requested: Any, *, default_target: str) -> list[str]:
    normalized = _normalize_target(requested)
    if normalized in {'A', 'B'}:
        return [normalized]
    return [default_target]


def _target_url(target_key: str) -> str:
    return IDS_A_URL if target_key == 'A' else IDS_B_URL


def _build_attack_payload(profile: dict[str, Any], vehicle_id: str) -> dict[str, Any]:
    speed_min, speed_max = profile['speed_range']
    return {
        'vehicle_id': vehicle_id,
        'timestamp': datetime.datetime.now().isoformat(),
        'speed': random.uniform(speed_min, speed_max),
        'location': [
            profile['lat_center'] + random.uniform(-profile['lat_jitter'], profile['lat_jitter']),
            profile['lon_center'] + random.uniform(-profile['lon_jitter'], profile['lon_jitter']),
        ],
        'heading': random.uniform(0, 360),
        'message_type': profile['message_type'],
    }


def _launch_attack(attack_key: str):
    profile = ATTACK_PROFILES[attack_key]
    try:
        if attack_state['is_attacking']:
            return jsonify({
                'error': 'another_attack_is_running',
                'current_attack': attack_state.get('attack_type'),
            }), 409

        data = request.get_json() or {}
        vehicle_id = str(data.get('vehicle_id', profile['default_vehicle'])).strip() or profile['default_vehicle']
        duration = int(data.get('duration_seconds', 5))
        packet_count = int(data.get('packet_count', 10))
        targets = _resolve_attack_targets(
            data.get('target_server', 'both'),
            default_target=str(profile['default_target']),
        )

        attack_state['is_attacking'] = True
        attack_state['attack_type'] = attack_key
        attack_state['start_time'] = time.time()

        print(f"\n{Fore.RED}{'='*70}")
        print(f"[Attack Client] Launching {profile['label']} Attack")
        print(f"{'='*70}")
        print(f"Vehicle ID: {vehicle_id}")
        print(f"Duration: {duration} seconds")
        print(f"Expected Packets: {packet_count}")
        print(f"Target Edge Node(s): {', '.join(targets)}")
        print(f"{'='*70}\n")

        thread = threading.Thread(
            target=_execute_attack,
            args=(attack_key, vehicle_id, duration, packet_count, targets),
            daemon=True,
        )
        thread.start()

        return jsonify({
            'status': 'attack_started',
            'attack_type': attack_key,
            'vehicle_id': vehicle_id,
            'duration': duration,
            'packet_count': packet_count,
            'targets': targets,
        }), 200
    except Exception as e:
        attack_state['is_attacking'] = False
        attack_state['attack_type'] = None
        attack_state['start_time'] = None
        print(f"{Fore.RED}Error launching {profile['label']} attack: {str(e)}")
        return jsonify({'error': str(e)}), 500


def _execute_attack(attack_key: str, vehicle_id: str, duration: int, packet_count: int, targets: list[str]):
    profile = ATTACK_PROFILES[attack_key]
    start = time.time()

    for i in range(packet_count):
        if not attack_state['is_attacking']:
            break
        if time.time() - start > duration:
            break

        payload = _build_attack_payload(profile, vehicle_id)
        for target in targets:
            try:
                response = requests.post(
                    f"{_target_url(target)}/v2x/telemetry",
                    json=payload,
                    timeout=3,
                )
                attack_state['packet_sent'] += 1
                if response.status_code == 200:
                    attack_state['packets_delivered'] += 1
                else:
                    attack_state['packets_failed'] += 1
            except Exception as e:
                attack_state['packet_sent'] += 1
                attack_state['packets_failed'] += 1
                print(f"{Fore.YELLOW}[Attack] Failed to send {profile['label']} packet to {target}: {str(e)}")

        print(
            f"{Fore.YELLOW}[Attack] {profile['label']} packet {i+1}/{packet_count} "
            f"from {vehicle_id} -> {', '.join(targets)}"
        )
        time.sleep(float(profile['interval_seconds']))

    attack_state['is_attacking'] = False
    attack_state['attack_type'] = None
    attack_state['start_time'] = None
    print(f"\n{Fore.YELLOW}{profile['label']} attack completed")


@app.route('/api/attack/ddos', methods=['POST'])
def launch_ddos_attack():
    """Launch DDoS attack"""
    return _launch_attack('ddos')


@app.route('/api/attack/gps-spoof', methods=['POST'])
def launch_gps_spoof_attack():
    """Launch GPS Spoofing attack"""
    return _launch_attack('gps_spoof')


@app.route('/api/attack/prompt-injection', methods=['POST'])
def launch_prompt_injection_attack():
    """Launch prompt injection attack"""
    return _launch_attack('prompt_injection')


@app.route('/api/attack/indirect-prompt', methods=['POST'])
def launch_indirect_prompt_injection_attack():
    """Launch indirect prompt injection attack"""
    return _launch_attack('indirect_prompt_injection')


@app.route('/api/attack/v2x-deception', methods=['POST'])
def launch_v2x_exploitation_attack():
    """Launch V2X exploitation attack"""
    return _launch_attack('v2x_exploitation')


@app.route('/api/attack/data-poisoning', methods=['POST'])
def launch_data_poisoning_attack():
    """Launch data poisoning attack"""
    return _launch_attack('data_poisoning')


@app.route('/api/attack/stop', methods=['POST'])
def stop_attack():
    """Stop ongoing attack"""
    attack_state['is_attacking'] = False
    attack_state['attack_type'] = None
    attack_state['start_time'] = None
    print(f"\n{Fore.YELLOW}Attack stopped by user")
    
    return jsonify({
        'status': 'stopped',
        'total_packets_sent': attack_state['packet_sent'],
        'packets_delivered': attack_state['packets_delivered'],
        'packets_failed': attack_state['packets_failed']
    }), 200


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get attack client statistics"""
    return jsonify({
        'is_attacking': attack_state['is_attacking'],
        'attack_type': attack_state['attack_type'],
        'total_packets_sent': attack_state['packet_sent'],
        'packets_delivered': attack_state['packets_delivered'],
        'packets_failed': attack_state['packets_failed'],
        'vehicles': attack_state['vehicles']
    })


if __name__ == '__main__':
    initialize_client()
    print(f"\n{Fore.GREEN}Starting Attack Generation Client on port {ATTACK_CLIENT_PORT}...\n")
    app.run(host='0.0.0.0', port=ATTACK_CLIENT_PORT, debug=False, threaded=True)
