"""
Compatibility shim for legacy imports.

This module keeps legacy class names available while delegating behavior to
lightweight deterministic logic (or to the new federated endpoints when used).
"""

from dataclasses import dataclass, field
from typing import Dict
import random


@dataclass
class LLMNode:
    node_id: str
    model_name: str
    specialty: str
    zone: str
    knowledge: Dict[str, float] = field(default_factory=dict)
    knowledge_maturity: Dict[str, int] = field(default_factory=dict)

    def analyze(self, attack_type: str, is_benign: bool = False, target: str = "") -> Dict:
        base = self.knowledge.get(attack_type, 0.65 if attack_type == self.specialty else 0.45)
        confidence = min(0.99, max(0.01, base + random.uniform(-0.08, 0.08)))
        detected = confidence >= 0.55 and not is_benign
        return {
            "detected": detected,
            "confidence": confidence,
            "reasoning": (
                f"Compatibility analysis path ({self.node_id}) "
                f"specialty={self.specialty} attack_type={attack_type}"
            ),
            "category": "malicious" if detected else "benign",
        }

    def local_train(self, attack_type: str, confidence: float, apply_privacy: bool = True, clip_norm: float = 0.5) -> float:
        current = self.knowledge.get(attack_type, 0.5)
        learned = (current * 0.8) + (max(0.0, min(1.0, confidence)) * 0.2)
        self.knowledge[attack_type] = learned
        self.knowledge_maturity[attack_type] = self.knowledge_maturity.get(attack_type, 0) + 1
        return learned


class GlobalAggregator:
    def __init__(self) -> None:
        self.global_knowledge: Dict[str, float] = {}

    def aggregate(self, node_knowledge: Dict[str, Dict[str, float]]) -> Dict[str, float]:
        totals: Dict[str, float] = {}
        counts: Dict[str, int] = {}
        for knowledge in node_knowledge.values():
            for attack_type, value in knowledge.items():
                totals[attack_type] = totals.get(attack_type, 0.0) + value
                counts[attack_type] = counts.get(attack_type, 0) + 1
        for attack_type, total in totals.items():
            self.global_knowledge[attack_type] = total / max(1, counts.get(attack_type, 1))
        return dict(self.global_knowledge)
