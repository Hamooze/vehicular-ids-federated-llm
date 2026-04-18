from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


LabelType = Literal["benign", "suspicious", "malicious"]
PriorityType = Literal["low", "medium", "high", "critical"]
LogType = Literal["netflow", "dns", "http", "syslog", "pcap", "gps", "telemetry", "other"]
AttackType = Literal[
    "ddos",
    "gps_spoof",
    "prompt_injection",
    "indirect_prompt_injection",
    "v2x_exploitation",
    "data_poisoning",
    "unknown",
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DetectionBranchConfig(StrictModel):
    ddos_enabled: bool = True
    gps_enabled: bool = True


class Classification(StrictModel):
    label: LabelType
    confidence: float = Field(ge=0.0, le=1.0)
    anomaly_score: float = Field(ge=0.0, le=1.0)


class SensorEvent(StrictModel):
    event_id: str
    timestamp: datetime
    source_device: str = Field(min_length=1)
    log_type: LogType | str
    detection: DetectionBranchConfig = Field(default_factory=DetectionBranchConfig)
    classification: Classification
    evidence: list[str] = Field(default_factory=list)
    priority: PriorityType
    raw_excerpt: str = Field(min_length=1, max_length=2000)


class CaseSummary(StrictModel):
    case_id: str
    time_window: str
    affected_assets: list[str] = Field(default_factory=list)
    attack_hypothesis: list[str] = Field(default_factory=list)
    detection: DetectionBranchConfig = Field(default_factory=DetectionBranchConfig)
    protocol_notes: str
    ioc_candidates: list[str] = Field(default_factory=list)
    timeline: list[str] = Field(default_factory=list)
    risk_score: float = Field(ge=0.0, le=100.0)
    justification: list[str] = Field(default_factory=list)
    referenced_event_ids: list[str] = Field(default_factory=list)


class EvidenceRow(StrictModel):
    indicator: str
    source: str
    relevance: str


class XAIReport(StrictModel):
    case_id: str
    executive_summary: str
    incident_narrative: str
    evidence_table: list[EvidenceRow] = Field(default_factory=list)
    risk_assessment: str
    recommended_actions: list[str] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)
    appendix: list[str] = Field(default_factory=list)


class RawLogInput(StrictModel):
    source_device: str = Field(min_length=1)
    log_type: LogType | str = "other"
    raw_log: str = Field(min_length=1, max_length=12000)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    detection: DetectionBranchConfig = Field(default_factory=DetectionBranchConfig)


class LegacyV2XTelemetry(StrictModel):
    vehicle_id: str = Field(min_length=1)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    speed: float = 0.0
    location: list[float] = Field(default_factory=lambda: [0.0, 0.0], min_length=2, max_length=2)
    heading: float = 0.0
    message_type: str = "BSM"


class AttackCommandRequest(StrictModel):
    vehicle_id: str = "V001"
    duration_seconds: int = Field(default=6, ge=1, le=600)
    packet_count: int = Field(default=20, ge=1, le=5000)
    target_server: str = "both"


class LocalModelSignal(StrictModel):
    attack_type: AttackType = "unknown"
    confidence: float = Field(ge=0.0, le=1.0)
    anomaly_score: float = Field(ge=0.0, le=1.0)
    sample_count: int = Field(default=1, ge=1, le=10000)


class LocalModelUpdate(StrictModel):
    node_id: str = Field(min_length=1)
    node_role: str = Field(min_length=1)
    correlation_id: str = Field(min_length=1)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    signals: list[LocalModelSignal] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)


class CoordinationPolicy(StrictModel):
    round_id: int = Field(ge=1)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    strategy: str
    recommendation: str
    recommended_actions: list[str] = Field(default_factory=list)
    weights: dict[AttackType, float] = Field(default_factory=dict)
    contributing_nodes: list[str] = Field(default_factory=list)


class FederatedRoundSnapshot(StrictModel):
    round_id: int = Field(ge=1)
    started_at: datetime
    closed_at: datetime | None = None
    update_count: int = Field(ge=0)
    scores: dict[AttackType, float] = Field(default_factory=dict)
    node_participants: list[str] = Field(default_factory=list)
    policy: CoordinationPolicy


class FederatedIngestResponse(StrictModel):
    accepted: bool
    current_round: int = Field(ge=1)
    snapshot: FederatedRoundSnapshot


class LightweightModelWeights(StrictModel):
    bias: float = 0.0
    confidence: float = 0.40
    anomaly_score: float = 0.50
    priority_score: float = 0.10
    context_score: float = 0.10


class FederatedGlobalModelState(StrictModel):
    revision: int = Field(default=0, ge=0)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    weights: dict[AttackType, LightweightModelWeights] = Field(default_factory=dict)


class FederatedLearningConfig(StrictModel):
    enabled: bool = False
    auto_rounds: bool = False
    learning_rate: float = Field(default=0.20, ge=0.01, le=1.0)
    min_samples_per_node: int = Field(default=8, ge=1, le=2000)
    max_samples_per_node: int = Field(default=64, ge=1, le=2000)
    auto_round_interval_seconds: int = Field(default=120, ge=10, le=3600)


class FederatedLearningConfigPatch(StrictModel):
    enabled: bool | None = None
    auto_rounds: bool | None = None
    learning_rate: float | None = Field(default=None, ge=0.01, le=1.0)
    min_samples_per_node: int | None = Field(default=None, ge=1, le=2000)
    max_samples_per_node: int | None = Field(default=None, ge=1, le=2000)
    auto_round_interval_seconds: int | None = Field(default=None, ge=10, le=3600)


class NodeModelUpdateRequest(StrictModel):
    round_id: int = Field(ge=1)
    max_samples: int = Field(default=64, ge=1, le=2000)
    attack_types: list[AttackType] = Field(default_factory=lambda: ["ddos", "gps_spoof", "prompt_injection", "indirect_prompt_injection", "v2x_exploitation", "data_poisoning"])


class NodeModelDelta(StrictModel):
    bias: float = 0.0
    confidence: float = 0.0
    anomaly_score: float = 0.0
    priority_score: float = 0.0
    context_score: float = 0.0


class NodeModelUpdateResponse(StrictModel):
    node_id: str
    round_id: int = Field(ge=1)
    sample_count: int = Field(ge=0)
    sample_counts: dict[AttackType, int] = Field(default_factory=dict)
    avg_loss: float = Field(ge=0.0)
    weights: dict[AttackType, LightweightModelWeights] = Field(default_factory=dict)
    deltas: dict[AttackType, NodeModelDelta] = Field(default_factory=dict)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class NodeRoundResult(StrictModel):
    node_id: str
    status: Literal["ok", "skipped", "error"]
    sample_count: int = Field(default=0, ge=0)
    sample_counts: dict[AttackType, int] = Field(default_factory=dict)
    avg_loss: float = Field(default=0.0, ge=0.0)
    detail: str = ""


class FederatedRoundRunRequest(StrictModel):
    force: bool = False
    max_samples_per_node: int | None = Field(default=None, ge=1, le=2000)


class FederatedRoundRunResponse(StrictModel):
    round_id: int = Field(ge=1)
    applied: bool
    reason: str
    learning_config: FederatedLearningConfig
    model_state: FederatedGlobalModelState
    node_results: list[NodeRoundResult] = Field(default_factory=list)
    synced_nodes: list[str] = Field(default_factory=list)


class FederatedLearningStateResponse(StrictModel):
    service: str
    config: FederatedLearningConfig
    model_state: FederatedGlobalModelState
    current_round: FederatedRoundSnapshot
    latest_round_result: FederatedRoundRunResponse | None = None
    history_size: int = Field(ge=0)


class MasterAssistantRequest(StrictModel):
    question: str = Field(min_length=1, max_length=1200)
    include_history: bool = True
    telemetry_context: dict[str, Any] = Field(default_factory=dict)

    @field_validator("telemetry_context")
    @classmethod
    def _validate_telemetry_context(cls, v: dict[str, Any]) -> dict[str, Any]:
        if len(v) > 20:
            raise ValueError("telemetry_context must not exceed 20 keys")
        for k, val in v.items():
            if not isinstance(k, str) or len(k) > 100:
                raise ValueError("telemetry_context keys must be strings of at most 100 chars")
            if isinstance(val, str) and len(val) > 500:
                raise ValueError("telemetry_context string values must not exceed 500 chars")
        return v


class MasterAssistantResponse(StrictModel):
    summary: str
    details: list[str] = Field(default_factory=list)
    alert_level: Literal["normal", "elevated", "critical"] = "normal"
    recommended_actions: list[str] = Field(default_factory=list)
    recommended_prompt: str = ""
    policy: CoordinationPolicy
    current_round: FederatedRoundSnapshot


class ForwardStatus(StrictModel):
    forwarded: bool
    endpoint: str
    status_code: int | None = None
    error: str | None = None


class SensorIngestResponse(StrictModel):
    correlation_id: str
    suspicious: bool
    event: SensorEvent
    forward_status: ForwardStatus


class FilterCaseResponse(StrictModel):
    correlation_id: str
    case_summary: CaseSummary
    forward_status: ForwardStatus


class BrainReportResponse(StrictModel):
    correlation_id: str
    report: XAIReport


class OrchestratorIngestResponse(StrictModel):
    correlation_id: str
    sensor_response: SensorIngestResponse


class DependencyHealth(StrictModel):
    name: str
    status: Literal["ok", "degraded", "down"]
    detail: str


class HealthResponse(StrictModel):
    service: str
    status: Literal["ok", "degraded", "down"]
    model: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    dependencies: list[DependencyHealth] = Field(default_factory=list)
