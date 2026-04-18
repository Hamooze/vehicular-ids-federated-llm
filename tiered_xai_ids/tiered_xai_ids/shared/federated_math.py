import math
from typing import Literal

from tiered_xai_ids.shared.schemas import AttackType

_WEIGHT_KEYS = ("bias", "confidence", "anomaly_score", "priority_score", "context_score")


def default_weight_vector() -> dict[str, float]:
    return {
        "bias": 0.0,
        "confidence": 0.40,
        "anomaly_score": 0.50,
        "priority_score": 0.10,
        "context_score": 0.10,
    }


def default_attack_weights() -> dict[AttackType, dict[str, float]]:
    return {
        "ddos": default_weight_vector(),
        "gps_spoof": default_weight_vector(),
        "prompt_injection": default_weight_vector(),
        "indirect_prompt_injection": default_weight_vector(),
        "v2x_exploitation": default_weight_vector(),
        "data_poisoning": default_weight_vector(),
    }


def specialist_initial_weights(specialty: str) -> dict[str, dict[str, float]]:
    """Return initial weights biased toward a node's specialty attack type.

    The specialist attack type starts with strong weights so the node detects
    it well from round one.  The opposing primary attack type starts near-zero
    so the node gains that knowledge only through the federated global model
    (i.e. genuine cross-learning).  All other attack types use neutral defaults.

    specialty values: "ddos", "gps_spoof", or "neutral" (no bias).
    """
    base = default_attack_weights()
    _STRONG = {"bias": 0.10, "confidence": 0.70, "anomaly_score": 0.65, "priority_score": 0.20, "context_score": 0.15}
    _WEAK   = {"bias": 0.00, "confidence": 0.04, "anomaly_score": 0.04, "priority_score": 0.04, "context_score": 0.04}
    if specialty == "ddos":
        base["ddos"]      = dict(_STRONG)
        base["gps_spoof"] = dict(_WEAK)
    elif specialty == "gps_spoof":
        base["gps_spoof"] = dict(_STRONG)
        base["ddos"]      = dict(_WEAK)
    # "neutral" or unknown → default_weight_vector() for everything (already set)
    return base


def priority_to_score(priority: str) -> float:
    values = {"low": 0.2, "medium": 0.5, "high": 0.8, "critical": 1.0}
    return values.get(priority, 0.5)


def build_feature_vector(
    *,
    confidence: float,
    anomaly_score: float,
    priority_score: float,
    context_score: float,
) -> dict[str, float]:
    return {
        "confidence": clamp01(confidence),
        "anomaly_score": clamp01(anomaly_score),
        "priority_score": clamp01(priority_score),
        "context_score": clamp01(context_score),
    }


def predict_score(weights: dict[str, float], features: dict[str, float]) -> float:
    z = float(weights.get("bias", 0.0))
    z += float(weights.get("confidence", 0.0)) * float(features.get("confidence", 0.0))
    z += float(weights.get("anomaly_score", 0.0)) * float(features.get("anomaly_score", 0.0))
    z += float(weights.get("priority_score", 0.0)) * float(features.get("priority_score", 0.0))
    z += float(weights.get("context_score", 0.0)) * float(features.get("context_score", 0.0))
    return _sigmoid(z)


def compute_average_delta(
    *,
    weights: dict[str, float],
    samples: list[dict[str, float | dict[str, float]]],
) -> tuple[dict[str, float], float]:
    if not samples:
        return zero_delta(), 0.0

    grads = zero_delta()
    loss_total = 0.0
    for item in samples:
        features_obj = item.get("features", {})
        features = features_obj if isinstance(features_obj, dict) else {}
        target = clamp01(float(item.get("target", 0.0)))
        prediction = predict_score(weights, features)
        error = target - prediction
        grads["bias"] += error
        grads["confidence"] += error * float(features.get("confidence", 0.0))
        grads["anomaly_score"] += error * float(features.get("anomaly_score", 0.0))
        grads["priority_score"] += error * float(features.get("priority_score", 0.0))
        grads["context_score"] += error * float(features.get("context_score", 0.0))
        loss_total += (target - prediction) ** 2

    count = float(len(samples))
    averaged = {key: value / count for key, value in grads.items()}
    return averaged, loss_total / count


def apply_delta(weights: dict[str, float], delta: dict[str, float], learning_rate: float) -> dict[str, float]:
    updated: dict[str, float] = {}
    safe_lr = min(1.0, max(0.01, learning_rate))
    for key in _WEIGHT_KEYS:
        step = max(-0.25, min(0.25, float(delta.get(key, 0.0))))
        base = float(weights.get(key, 0.0))
        updated[key] = max(-3.0, min(3.0, base + (safe_lr * step)))
    return updated


def zero_delta() -> dict[str, float]:
    return {key: 0.0 for key in _WEIGHT_KEYS}


def clamp01(value: float) -> float:
    return min(1.0, max(0.0, float(value)))


def _sigmoid(value: float) -> float:
    if value >= 0:
        exponent = math.exp(-value)
        return 1.0 / (1.0 + exponent)
    exponent = math.exp(value)
    return exponent / (1.0 + exponent)
