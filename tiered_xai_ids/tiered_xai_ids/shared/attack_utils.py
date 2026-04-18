from datetime import datetime, timezone

from tiered_xai_ids.shared.correlation import get_correlation_id
from tiered_xai_ids.shared.schemas import AttackType, LocalModelSignal, LocalModelUpdate


_DDOS_HINTS = (
    "ddos",
    "flood",
    "syn",
    "burst",
    "amplification",
    "packet storm",
)

_PROMPT_INJECTION_HINTS = (
    "prompt injection",
    "jailbreak",
    "ignore previous",
    "override instruction",
    "system prompt",
    "instruction hijack",
)

_INDIRECT_PROMPT_INJECTION_HINTS = (
    "indirect prompt",
    "hidden instruction",
    "untrusted content",
    "navigation feed",
    "malicious route description",
    "third party content",
)

_V2X_EXPLOITATION_HINTS = (
    "v2x",
    "bsm forgery",
    "cam replay",
    "phantom vehicle",
    "sybil",
    "platoon inconsistency",
    "inter-vehicle deception",
)

_DATA_POISONING_HINTS = (
    "data poisoning",
    "poisoned training",
    "label skew",
    "backdoor trigger",
    "model poisoning",
    "federated gradient",
)

_GPS_HINTS = (
    "gps",
    "spoof",
    "location jump",
    "coordinates",
    "trajectory",
    "impossible location",
)


def infer_attack_type(log_type: str, text: str) -> AttackType:
    combined = f"{log_type} {text}".lower()
    # Keep semantic/model-pipeline attacks ahead of GPS keyword matching.
    if any(token in combined for token in _DATA_POISONING_HINTS):
        return "data_poisoning"
    if any(token in combined for token in _INDIRECT_PROMPT_INJECTION_HINTS):
        return "indirect_prompt_injection"
    if any(token in combined for token in _PROMPT_INJECTION_HINTS):
        return "prompt_injection"
    if any(token in combined for token in _V2X_EXPLOITATION_HINTS):
        return "v2x_exploitation"
    if any(token in combined for token in _DDOS_HINTS):
        return "ddos"
    if any(token in combined for token in _GPS_HINTS):
        return "gps_spoof"
    return "unknown"


def pick_specialized_model(
    *,
    default_model: str,
    ddos_model: str,
    gps_model: str,
    attack_type: AttackType,
) -> str:
    if attack_type == "ddos":
        return ddos_model
    if attack_type == "gps_spoof":
        return gps_model
    if attack_type in {
        "prompt_injection",
        "indirect_prompt_injection",
        "v2x_exploitation",
        "data_poisoning",
    }:
        return default_model
    return default_model


def build_local_update(
    *,
    node_id: str,
    node_role: str,
    signal: LocalModelSignal,
    metadata: dict[str, str] | None = None,
) -> LocalModelUpdate:
    correlation_id = get_correlation_id().strip() or "unknown"
    return LocalModelUpdate(
        node_id=node_id,
        node_role=node_role,
        correlation_id=correlation_id,
        timestamp=datetime.now(timezone.utc),
        signals=[signal],
        metadata=metadata or {},
    )
