import re
from dataclasses import dataclass, field

from tiered_xai_ids.shared.schemas import PriorityType, SensorEvent


@dataclass(slots=True)
class RuleAssessment:
    suspicious: bool
    anomaly_score: float
    priority: PriorityType
    evidence: list[str] = field(default_factory=list)
    ioc_candidates: list[str] = field(default_factory=list)


class RuleEngine:
    _high_risk_patterns = (
        ("ddos", 0.35),
        ("flood", 0.30),
        ("syn", 0.20),
        ("gps spoof", 0.45),
        ("fake sat", 0.35),
        ("c2", 0.45),
        ("beacon", 0.30),
        ("payload", 0.25),
        ("exploit", 0.40),
        ("sqlmap", 0.40),
    )

    _medium_risk_patterns = (
        ("failed login", 0.20),
        ("port scan", 0.20),
        ("suspicious dns", 0.20),
        ("unknown protocol", 0.15),
        ("latency spike", 0.10),
        ("packet loss", 0.10),
    )

    _ioc_regexes = (
        re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b"),
        re.compile(r"\bport[:=]?\s?\d{1,5}\b", re.IGNORECASE),
    )

    def evaluate_raw_log(self, log_type: str, raw_log: str) -> RuleAssessment:
        content = raw_log.lower()
        score = 0.0
        evidence: list[str] = []

        for pattern, weight in self._high_risk_patterns:
            if pattern in content:
                score += weight
                evidence.append(f"high-risk token matched: {pattern}")

        for pattern, weight in self._medium_risk_patterns:
            if pattern in content:
                score += weight
                evidence.append(f"medium-risk token matched: {pattern}")

        if log_type.lower() in {"pcap", "netflow"} and "burst" in content:
            score += 0.10
            evidence.append("traffic burst marker detected in flow data")

        iocs = self._extract_iocs(raw_log)
        if iocs:
            score += min(0.20, len(iocs) * 0.03)
            evidence.append(f"ioc extraction found {len(iocs)} candidate(s)")

        normalized = min(score, 1.0)
        suspicious = normalized >= 0.45
        return RuleAssessment(
            suspicious=suspicious,
            anomaly_score=normalized,
            priority=self._priority_for_score(normalized),
            evidence=evidence,
            ioc_candidates=iocs,
        )

    def evaluate_sensor_event(self, event: SensorEvent) -> RuleAssessment:
        derived_score = max(event.classification.anomaly_score, event.classification.confidence)
        if event.classification.label == "malicious":
            derived_score = max(derived_score, 0.85)
        elif event.classification.label == "suspicious":
            derived_score = max(derived_score, 0.55)

        iocs = self._extract_iocs(event.raw_excerpt)
        if iocs:
            derived_score = min(1.0, derived_score + min(0.10, len(iocs) * 0.02))

        return RuleAssessment(
            suspicious=event.classification.label != "benign" or derived_score >= 0.55,
            anomaly_score=min(1.0, derived_score),
            priority=self._priority_for_score(derived_score),
            evidence=list(event.evidence),
            ioc_candidates=iocs,
        )

    def _extract_iocs(self, text: str) -> list[str]:
        iocs: set[str] = set()
        for regex in self._ioc_regexes:
            for match in regex.findall(text):
                iocs.add(match)
        return sorted(iocs)

    @staticmethod
    def _priority_for_score(score: float) -> PriorityType:
        if score >= 0.85:
            return "critical"
        if score >= 0.65:
            return "high"
        if score >= 0.45:
            return "medium"
        return "low"
