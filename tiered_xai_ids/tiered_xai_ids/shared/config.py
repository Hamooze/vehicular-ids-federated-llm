from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class BaseServiceSettings(BaseSettings):
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    request_timeout_seconds: float = Field(default=180.0, alias="REQUEST_TIMEOUT_SECONDS")
    max_model_retries: int = Field(default=3, alias="MAX_MODEL_RETRIES")
    # Shared inter-service API key.  Set to a strong random value in production
    # (e.g. openssl rand -hex 32).  Leave empty to disable enforcement in dev.
    internal_api_key: SecretStr = Field(default=SecretStr(""), alias="INTERNAL_API_KEY")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )


class SensorSettings(BaseServiceSettings):
    service_name: str = "sensor-node"
    bind_host: str = Field(default="0.0.0.0", alias="SENSOR_BIND_HOST")
    bind_port: int = Field(default=8101, alias="SENSOR_BIND_PORT")
    ollama_base_url: str = Field(default="http://127.0.0.1:11434", alias="SENSOR_OLLAMA_BASE_URL")
    model_name: str = Field(default="phi3.5", alias="SENSOR_MODEL_NAME")
    ddos_model_name: str = Field(default="phi3.5", alias="SENSOR_DDOS_MODEL_NAME")
    gps_model_name: str = Field(default="phi3.5", alias="SENSOR_GPS_MODEL_NAME")
    filter_node_url: str = Field(default="http://127.0.0.1:8102", alias="SENSOR_FILTER_NODE_URL")
    global_model_url: str = Field(default="http://127.0.0.1:8104", alias="SENSOR_GLOBAL_MODEL_URL")
    suspicious_threshold: float = Field(default=0.60, alias="SENSOR_SUSPICIOUS_THRESHOLD")


class FilterSettings(BaseServiceSettings):
    service_name: str = "filter-node"
    bind_host: str = Field(default="0.0.0.0", alias="FILTER_BIND_HOST")
    bind_port: int = Field(default=8102, alias="FILTER_BIND_PORT")
    ollama_base_url: str = Field(default="http://127.0.0.1:11434", alias="FILTER_OLLAMA_BASE_URL")
    model_name: str = Field(default="mistral:7b", alias="FILTER_MODEL_NAME")
    ddos_model_name: str = Field(default="mistral:7b", alias="FILTER_DDOS_MODEL_NAME")
    gps_model_name: str = Field(default="mistral:7b", alias="FILTER_GPS_MODEL_NAME")
    brain_node_url: str = Field(default="http://127.0.0.1:8103", alias="FILTER_BRAIN_NODE_URL")
    global_model_url: str = Field(default="http://127.0.0.1:8104", alias="FILTER_GLOBAL_MODEL_URL")
    min_risk_to_forward: float = Field(default=45.0, alias="FILTER_MIN_RISK_TO_FORWARD")


class BrainSettings(BaseServiceSettings):
    service_name: str = "brain-node"
    bind_host: str = Field(default="0.0.0.0", alias="BRAIN_BIND_HOST")
    bind_port: int = Field(default=8103, alias="BRAIN_BIND_PORT")
    ollama_base_url: str = Field(default="http://127.0.0.1:11434", alias="BRAIN_OLLAMA_BASE_URL")
    model_name: str = Field(default="qwen2.5:32b", alias="BRAIN_MODEL_NAME")
    ddos_model_name: str = Field(default="qwen2.5:32b", alias="BRAIN_DDOS_MODEL_NAME")
    gps_model_name: str = Field(default="qwen2.5:32b", alias="BRAIN_GPS_MODEL_NAME")
    global_model_url: str = Field(default="http://127.0.0.1:8104", alias="BRAIN_GLOBAL_MODEL_URL")


class OrchestratorSettings(BaseServiceSettings):
    service_name: str = "orchestrator"
    bind_host: str = Field(default="0.0.0.0", alias="ORCH_BIND_HOST")
    bind_port: int = Field(default=8100, alias="ORCH_BIND_PORT")
    sensor_node_url: str = Field(default="http://127.0.0.1:8101", alias="ORCH_SENSOR_NODE_URL")
    filter_node_url: str = Field(default="http://127.0.0.1:8102", alias="ORCH_FILTER_NODE_URL")
    brain_node_url: str = Field(default="http://127.0.0.1:8103", alias="ORCH_BRAIN_NODE_URL")
    global_model_url: str = Field(default="http://127.0.0.1:8104", alias="ORCH_GLOBAL_MODEL_URL")
    # Parallel specialist IDS nodes
    ids_a_url: str = Field(default="http://127.0.0.1:8001", alias="ORCH_IDS_A_URL")
    ids_b_url: str = Field(default="http://127.0.0.1:8002", alias="ORCH_IDS_B_URL")
    allowed_origins: str = Field(default="http://localhost:8200", alias="ORCH_ALLOWED_ORIGINS")
    websocket_heartbeat_seconds: float = Field(default=8.0, alias="ORCH_WEBSOCKET_HEARTBEAT_SECONDS")
    ddos_enabled: bool = Field(default=True, alias="ORCH_DDOS_ENABLED")
    gps_spoof_enabled: bool = Field(default=True, alias="ORCH_GPS_SPOOF_ENABLED")
    admin_email: str = Field(default="", alias="ADMIN_EMAIL")
    smtp_host: str = Field(default="", alias="SMTP_HOST")
    smtp_port: int = Field(default=587, alias="SMTP_PORT")
    smtp_user: str = Field(default="", alias="SMTP_USER")
    smtp_password: SecretStr = Field(default=SecretStr(""), alias="SMTP_PASSWORD")
    smtp_from: str = Field(default="ids-alerts@localhost", alias="SMTP_FROM")
    smtp_use_tls: bool = Field(default=True, alias="SMTP_USE_TLS")
    alert_cooldown_seconds: int = Field(default=120, alias="ALERT_COOLDOWN_SECONDS")
    alert_min_severity: str = Field(default="suspicious", alias="ALERT_MIN_SEVERITY")


class GlobalModelSettings(BaseServiceSettings):
    service_name: str = "global-model"
    bind_host: str = Field(default="0.0.0.0", alias="GLOBAL_BIND_HOST")
    bind_port: int = Field(default=8104, alias="GLOBAL_BIND_PORT")
    ollama_base_url: str = Field(default="http://127.0.0.1:11434", alias="GLOBAL_OLLAMA_BASE_URL")
    model_name: str = Field(default="mistral:7b", alias="GLOBAL_MODEL_NAME")
    round_duration_seconds: int = Field(default=30, alias="GLOBAL_ROUND_DURATION_SECONDS")
    history_size: int = Field(default=40, alias="GLOBAL_HISTORY_SIZE")
    sensor_node_url: str = Field(default="http://127.0.0.1:8101", alias="GLOBAL_SENSOR_NODE_URL")
    filter_node_url: str = Field(default="http://127.0.0.1:8102", alias="GLOBAL_FILTER_NODE_URL")
    brain_node_url: str = Field(default="http://127.0.0.1:8103", alias="GLOBAL_BRAIN_NODE_URL")
    learning_enabled: bool = Field(default=False, alias="GLOBAL_LEARNING_ENABLED")
    auto_rounds: bool = Field(default=False, alias="GLOBAL_AUTO_ROUNDS")
    # Parallel specialist IDS nodes — included in FL aggregation
    ids_a_url: str = Field(default="http://127.0.0.1:8001", alias="GLOBAL_IDS_A_URL")
    ids_b_url: str = Field(default="http://127.0.0.1:8002", alias="GLOBAL_IDS_B_URL")
    learning_rate: float = Field(default=0.20, alias="GLOBAL_LEARNING_RATE")
    min_samples_per_node: int = Field(default=8, alias="GLOBAL_MIN_SAMPLES_PER_NODE")
    max_samples_per_node: int = Field(default=64, alias="GLOBAL_MAX_SAMPLES_PER_NODE")
    auto_round_interval_seconds: int = Field(default=120, alias="GLOBAL_AUTO_ROUND_INTERVAL_SECONDS")


class SpecialistNodeSettings(BaseServiceSettings):
    """Settings for a parallel specialist IDS node (IDS-A or IDS-B).

    Both nodes share this settings class.  Each Docker service overrides the
    IDS_* env vars via its compose ``environment:`` block so the two containers
    get different values from the same .env file.
    """
    service_name: str = Field(default="ids-node-a", alias="IDS_SERVICE_NAME")
    bind_host: str = Field(default="0.0.0.0", alias="IDS_BIND_HOST")
    bind_port: int = Field(default=8001, alias="IDS_BIND_PORT")
    ollama_base_url: str = Field(default="http://127.0.0.1:11434", alias="IDS_OLLAMA_BASE_URL")
    model_name: str = Field(default="phi3.5", alias="IDS_MODEL_NAME")
    global_model_url: str = Field(default="http://127.0.0.1:8104", alias="IDS_GLOBAL_MODEL_URL")
    # "ddos" or "gps_spoof"
    node_specialty: str = Field(default="ddos", alias="IDS_SPECIALTY")
    # FL rounds before cross-type training begins (uses local_model_state.revision as counter)
    cross_learning_start_round: int = Field(default=3, alias="IDS_CROSS_LEARNING_START_ROUND")
    suspicious_threshold: float = Field(default=0.60, alias="IDS_SUSPICIOUS_THRESHOLD")


class PanelSettings(BaseServiceSettings):
    service_name: str = "panel-app"
    bind_host: str = Field(default="0.0.0.0", alias="PANEL_BIND_HOST")
    bind_port: int = Field(default=8200, alias="PANEL_BIND_PORT")
    orchestrator_url: str = Field(default="http://127.0.0.1:8100", alias="PANEL_ORCHESTRATOR_URL")
    global_model_url: str = Field(default="http://127.0.0.1:8104", alias="PANEL_GLOBAL_MODEL_URL")


class FederatedLabSettings(BaseServiceSettings):
    service_name: str = "federated-lab"
    bind_host: str = Field(default="0.0.0.0", alias="FEDLAB_BIND_HOST")
    bind_port: int = Field(default=8300, alias="FEDLAB_BIND_PORT")
    global_model_url: str = Field(default="http://127.0.0.1:8104", alias="FEDLAB_GLOBAL_MODEL_URL")
    orchestrator_url: str = Field(default="http://127.0.0.1:8100", alias="FEDLAB_ORCHESTRATOR_URL")


@lru_cache(maxsize=1)
def get_sensor_settings() -> SensorSettings:
    return SensorSettings()


@lru_cache(maxsize=1)
def get_filter_settings() -> FilterSettings:
    return FilterSettings()


@lru_cache(maxsize=1)
def get_brain_settings() -> BrainSettings:
    return BrainSettings()


@lru_cache(maxsize=1)
def get_orchestrator_settings() -> OrchestratorSettings:
    return OrchestratorSettings()


@lru_cache(maxsize=1)
def get_global_model_settings() -> GlobalModelSettings:
    return GlobalModelSettings()


@lru_cache(maxsize=1)
def get_panel_settings() -> PanelSettings:
    return PanelSettings()


@lru_cache(maxsize=1)
def get_federated_lab_settings() -> FederatedLabSettings:
    return FederatedLabSettings()


@lru_cache(maxsize=1)
def get_specialist_settings() -> SpecialistNodeSettings:
    return SpecialistNodeSettings()
