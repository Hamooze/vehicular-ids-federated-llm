# Tiered XAI IoT IDS (JSON APIs + Live + Federated Panels)

## Services
- `sensor_node` (JSON-only API, specialized DDoS/GPS model routing)
- `filter_node` (JSON-only API, specialized DDoS/GPS model routing)
- `brain_node` (JSON-only API, specialized DDoS/GPS model routing)
- `orchestrator` (JSON-only coordination layer + WebSocket live stream)
- `global_model` (dedicated federated coordination model)
- `panel_app` (dedicated UI application; separate from servers)
- `federated_lab` (dedicated federated-learning control and monitoring UI)

## Architecture Notes
- UI is isolated in `panel_app`.
- Server applications return JSON responses only.
- Live updates are pushed through orchestrator WebSocket (`/ws/live`).
- Each server reports local model signals to `global_model` for federated rounds.
- Lightweight federated parameter learning is available (manual by default, disabled at boot).
- Runtime branch toggles are available for DDoS and GPS spoof detection paths.
- Optional SMTP admin alerts can notify on suspicious/malicious detections.
- Legacy `attack_client` includes six simulations: DDoS, GPS spoof, prompt injection, indirect prompt injection, V2X exploitation, and data poisoning.

## Live UI
- Dedicated panel: `http://localhost:8200/dashboard`
- Federated learning panel: `http://localhost:8300/dashboard`

## Local Python Run
1. Copy `.env.example` to `.env` and update machine IPs/URLs.
2. Install dependencies:
   - `python -m venv .venv`
   - `.\.venv\Scripts\activate`
   - `pip install -r requirements.txt`
3. Install models:
   - All: `powershell -ExecutionPolicy Bypass -File .\scripts\install_models.ps1 -Role all`
   - Laptop only: `powershell -ExecutionPolicy Bypass -File .\scripts\install_models.ps1 -Role laptop`
   - Worker only: `powershell -ExecutionPolicy Bypass -File .\scripts\install_models.ps1 -Role worker`
4. Start services:
   - `uvicorn run_global_model:app --host 0.0.0.0 --port 8104`
   - `uvicorn run_sensor:app --host 0.0.0.0 --port 8101`
   - `uvicorn run_filter:app --host 0.0.0.0 --port 8102`
   - `uvicorn run_brain:app --host 0.0.0.0 --port 8103`
   - `uvicorn run_orchestrator:app --host 0.0.0.0 --port 8100`
   - `uvicorn run_panel:app --host 0.0.0.0 --port 8200`
   - `uvicorn run_federated_lab:app --host 0.0.0.0 --port 8300`

## Docker Build and Run
- Build all services:
  - `docker compose -f docker-compose.all.yml build`
- Run all services on one machine:
  - `docker compose -f docker-compose.all.yml up -d`
- Laptop mode (global + filter + brain + orchestrator + panel + federated-lab):
  - `docker compose -f docker-compose.laptop.yml up -d --build`
- Worker mode (sensor only):
  - `docker compose -f docker-compose.worker.yml up -d --build`

## API Highlights
- Pipeline ingest: `POST /v1/pipeline/log` (orchestrator)
- Legacy ingest bridge: `POST /v2x/telemetry` (orchestrator)
- Detection branch toggles: `GET/PUT/POST /api/detection/branches` (orchestrator)
- Alert smoke test: `POST /api/alerts/test-email` (orchestrator)
- Legacy attack controls:
  - `POST /api/attack/ddos`
  - `POST /api/attack/gps-spoof`
  - `POST /api/attack/prompt-injection`
  - `POST /api/attack/indirect-prompt`
  - `POST /api/attack/v2x-deception`
  - `POST /api/attack/data-poisoning`
  - `POST /api/attack/stop`
- Sensor ingest: `POST /v1/ingest/log`
- Filter intake: `POST /v1/cases/from-sensor`
- Brain intake: `POST /v1/reports/from-case`
- Global update ingest: `POST /v1/federated/local-update`
- Global policy: `GET /v1/federated/policy`
- Learning state: `GET /v1/federated/learning/state`
- Learning config: `POST /v1/federated/learning/config`
- Manual learning round: `POST /v1/federated/learning/round/run`
- Live push stream: `GET ws://<orchestrator>/ws/live`

## LiveOverviewV1 Contract
The orchestrator `GET /api/live/overview` and WS `/ws/live` snapshot/update payloads follow:

- `schema_version`: `LiveOverviewV1`
- `pipeline`: recent ingest records
- `sensor_events`, `filter_cases`, `brain_reports`
- `attack_logs`, `stats`
- `detection_branches`: `{ ddos_enabled, gps_enabled }`
- `federated_learning`: compact view from global model learning state
- `global_policy`: latest coordination policy

This payload is consumed by:
- `panel_app` live monitor UI
- `federated_lab` UI
- legacy `attack_client` federated status helpers

## Operator Runbook
1. Toggle detection branches at runtime:
   - `PUT /api/detection/branches` with:
     - `{ "ddos_enabled": true|false, "gps_enabled": true|false }`
2. Federated learning controls:
   - Enable/disable and auto rounds via `POST /v1/federated/learning/config`
   - Run manual round via `POST /v1/federated/learning/round/run`
3. SMTP alerting:
   - Set `ADMIN_EMAIL`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_USE_TLS`
   - Tune `ALERT_COOLDOWN_SECONDS` and `ALERT_MIN_SEVERITY`
   - Verify with `POST /api/alerts/test-email`

4. Attack simulation mapping (legacy attack client defaults):
   - Edge Node 1 (`sensor-node`/A): DDoS, V2X exploitation, data poisoning.
   - Edge Node 2 (`filter-node`/B): GPS spoof, prompt injection, indirect prompt injection.
   - If `target_server` is explicitly set to `A` or `B`, that override is respected.
