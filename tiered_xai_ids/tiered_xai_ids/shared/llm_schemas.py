from pydantic import BaseModel, ConfigDict, Field

from tiered_xai_ids.shared.schemas import LabelType, PriorityType


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SensorLLMOutput(StrictModel):
    label: LabelType
    confidence: float = Field(ge=0.0, le=1.0)
    anomaly_score: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)
    priority: PriorityType


class FilterLLMOutput(StrictModel):
    affected_assets: list[str] = Field(default_factory=list)
    attack_hypothesis: list[str] = Field(default_factory=list)
    protocol_notes: str
    ioc_candidates: list[str] = Field(default_factory=list)
    timeline: list[str] = Field(default_factory=list)
    risk_score: float = Field(ge=0.0, le=100.0)
    justification: list[str] = Field(default_factory=list)


class BrainLLMOutputEvidence(StrictModel):
    indicator: str
    source: str
    relevance: str


class BrainLLMOutput(StrictModel):
    executive_summary: str
    incident_narrative: str
    evidence_table: list[BrainLLMOutputEvidence] = Field(default_factory=list)
    risk_assessment: str
    recommended_actions: list[str] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)
    appendix: list[str] = Field(default_factory=list)


class GlobalCoordinatorLLMOutput(StrictModel):
    strategy: str
    recommendation: str
    recommended_actions: list[str] = Field(default_factory=list)


class MasterAssistantLLMOutput(StrictModel):
    summary: str
    details: list[str] = Field(default_factory=list)
    alert_level: str = "normal"
    recommended_actions: list[str] = Field(default_factory=list)
    recommended_prompt: str = ""
