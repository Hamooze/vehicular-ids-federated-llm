# Distributed LLM-Based Vehicular IDS - Deployment Guide

## Overview

This is the **Unified Distributed Architecture** of the LLM-based Intrusion Detection System (IDS) for vehicular networks. The system is composed of tiered microservices that form a hierarchical detection pipeline, all orchestrated through a single compose file.

Services:
- **Sensor Node**: First-tier ingestion — receives raw V2X telemetry
- **Filter Node**: Second-tier filtering — pre-screens traffic before deep analysis
- **Brain Node**: Third-tier reasoning — runs LLM-based deep inspection
- **Global Model**: Federated global knowledge store — aggregates cross-node learning
- **Orchestrator**: Central API gateway — routes traffic and coordinates all nodes
- **Panel App**: Web UI — monitoring and control dashboard
- **Federated Lab**: Federated learning interface — manages knowledge sync
- **Vehicle Client**: Simulated vehicle — sends BSM telemetry to the orchestrator
- **Attack Client**: Attack control panel — launches DDoS and GPS spoofing simulations
- **Simulator**: Automated scenario runner — scripted traffic and attack generation

## Architecture

```
                        ┌──────────────────────┐
                        │   Global Model (8104) │
                        │  Federated Knowledge  │
                        └──────────┬───────────┘
                                   │ (all nodes query/update)
          ┌────────────────────────┼────────────────────────┐
          ▼                        ▼                        ▼
┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐
│  Sensor Node     │──▶│  Filter Node     │──▶│  Brain Node      │
│  (8101)          │   │  (8102)          │   │  (8103)          │
│  Raw ingestion   │   │  Pre-screening   │   │  LLM reasoning   │
└──────────────────┘   └──────────────────┘   └──────────────────┘
          ▲                                              │
          │                                              ▼
┌──────────────────────────────────────────────────────────────────┐
│                     Orchestrator (8100)                          │
│            Routes requests · Coordinates all nodes               │
└──────────────────────────────────────────────────────────────────┘
          ▲                    ▲                    ▲
          │                    │                    │
┌──────────────┐   ┌────────────────────┐   ┌──────────────────┐
│ Vehicle      │   │ Attack Client      │   │ Simulator        │
│ Client (5000)│   │ (7000)             │   │ (9000)           │
└──────────────┘   └────────────────────┘   └──────────────────┘

Panel App (8200) ──────────────────────────────▶ Orchestrator
Federated Lab (8300) ──────────────────────────▶ Orchestrator + Global Model
```

### Service Startup Order

Docker Compose enforces this dependency chain via health checks:

```
global-model
    └── brain-node
    └── filter-node (also waits on brain-node)
            └── sensor-node (also waits on filter-node)
                    └── orchestrator (waits on all 4 above)
                            └── panel-app
                            └── federated-lab
                            └── vehicle-client
                            └── attack-client
                            └── simulator
```

## Port Reference

| Service        | Port | Purpose                          |
|----------------|------|----------------------------------|
| orchestrator   | 8100 | Main API gateway                 |
| sensor-node    | 8101 | Raw telemetry ingestion          |
| filter-node    | 8102 | Traffic pre-screening            |
| brain-node     | 8103 | LLM-based deep inspection        |
| global-model   | 8104 | Federated global knowledge store |
| vehicle-client | 5000 | Simulated vehicle web UI         |
| attack-client  | 7000 | Attack simulation control panel  |
| panel-app      | 8200 | Monitoring and control dashboard |
| federated-lab  | 8300 | Federated learning interface     |
| simulator      | 9000 | Automated scenario runner        |

## Prerequisites

- Docker & Docker Compose installed
- Ollama running locally with at least one model pulled (used by brain-node, filter-node, etc.)
- The `tiered_xai_ids/.env` file configured (LLM model name, thresholds, etc.)
- 8GB+ RAM recommended

## Quick Start (Docker)

All commands are run from the `docker/` directory (where `docker-compose.unified.yml` lives).

### 1. Ensure Ollama is Running

The IDS nodes communicate with Ollama on the host via `host.docker.internal:11434`. Start Ollama before launching containers:

```bash
ollama serve
```

Pull a model if you haven't already (e.g.):
```bash
ollama pull phi3
```

### 2. Configure Environment

Edit `tiered_xai_ids/.env` to set the model name and any other parameters before deploying.

### 3. Deploy the Full Stack

```bash
cd docker/

# Build and start all services
docker-compose -f docker-compose.unified.yml up -d --build

# Follow logs (all services)
docker-compose -f docker-compose.unified.yml logs -f

# Follow logs for a specific service
docker-compose -f docker-compose.unified.yml logs -f brain-node
```

### 4. Check Service Status

```bash
docker-compose -f docker-compose.unified.yml ps
```

All services should show as `healthy`. Services with `starting` status are still warming up — the health checks retry up to 4 times (15s intervals) before marking unhealthy.

### 5. Access Services

| Interface         | URL                         |
|-------------------|-----------------------------|
| Panel App (main)  | http://localhost:8200        |
| Attack Client     | http://localhost:7000        |
| Federated Lab     | http://localhost:8300        |
| Orchestrator API  | http://localhost:8100        |
| Vehicle Client    | http://localhost:5000        |

---

## Common Docker Commands

```bash
# Stop all services (keep containers)
docker-compose -f docker-compose.unified.yml stop

# Stop and remove containers
docker-compose -f docker-compose.unified.yml down

# Stop, remove containers and volumes
docker-compose -f docker-compose.unified.yml down -v

# Rebuild after code changes
docker-compose -f docker-compose.unified.yml up -d --build

# Restart a single service
docker-compose -f docker-compose.unified.yml restart brain-node
```

---

## Monitoring & Troubleshooting

### Health Check Endpoints

```bash
curl http://localhost:8100/health   # Orchestrator
curl http://localhost:8101/health   # Sensor Node
curl http://localhost:8102/health   # Filter Node
curl http://localhost:8103/health   # Brain Node
curl http://localhost:8104/health   # Global Model
curl http://localhost:8200/health   # Panel App
curl http://localhost:8300/health   # Federated Lab
curl http://localhost:7000/api/health  # Attack Client
```

### View Logs

```bash
# All services
docker-compose -f docker-compose.unified.yml logs -f

# Specific service
docker-compose -f docker-compose.unified.yml logs -f brain-node
docker-compose -f docker-compose.unified.yml logs -f orchestrator
```

### Common Issues

**Ollama connection refused**
```
Cannot connect to host.docker.internal:11434
```
→ Start Ollama on the host: `ollama serve`
→ Ensure the model referenced in `tiered_xai_ids/.env` is pulled

**Service stuck in `starting` / health check failing**
→ Check logs: `docker-compose -f docker-compose.unified.yml logs -f <service>`
→ Containers wait for upstream dependencies — allow 1-2 minutes for the full chain to initialize

**Port already in use**
```
Bind for 0.0.0.0:8100 failed: port is already allocated
```
→ Find and stop the conflicting process: `lsof -ti:8100 | xargs kill -9`
→ Or stop all compose services: `docker-compose -f docker-compose.unified.yml down`

**`docker-compose` command not found**
→ Use `docker compose` (without the hyphen) if you have Docker Compose V2:
```bash
docker compose -f docker-compose.unified.yml up -d --build
```

---

## LLM Integration Details

All LLM inference is delegated to **Ollama running on the host machine**. Containers reach it via `host.docker.internal:11434`.

- `brain-node` — primary LLM-based deep inspection
- `filter-node` — uses LLM for pre-screening decisions
- `sensor-node` — uses LLM for anomaly flagging at ingestion
- `global-model` — uses LLM to reason over aggregated federated knowledge

The model to use is configured in `tiered_xai_ids/.env` via the relevant `*_OLLAMA_BASE_URL` environment variables already wired in the compose file.

---

## File Structure

```
docker/
├── docker-compose.unified.yml     # Main deployment file (use this)
├── docker-compose.yml             # Legacy basic setup (fog + vehicle only)
├── docker-compose-distributed.yml # Legacy distributed setup (superseded)
├── Dockerfile.vehicle             # Vehicle client container
├── Dockerfile.attack              # Attack client container
├── Dockerfile.simulator           # Simulator container
├── tiered_xai_ids/                # Core IDS services (all tiers)
│   ├── Dockerfile                 # Shared Dockerfile for all IDS nodes
│   ├── .env                       # IDS configuration (model name, thresholds)
│   ├── run_global_model.py
│   ├── run_brain.py
│   ├── run_filter.py
│   ├── run_sensor.py
│   ├── run_orchestrator.py
│   ├── run_panel.py
│   └── run_federated_lab.py
├── web_vehicle_client.py
├── attack_client.py
└── simulator.py
```

---

## Next Steps

1. **Start Ollama** and pull your preferred model
2. **Configure** `tiered_xai_ids/.env` with the model name and parameters
3. **Deploy**: `docker-compose -f docker-compose.unified.yml up -d --build`
4. **Open Panel App** at http://localhost:8200 to monitor the system
5. **Use Attack Client** at http://localhost:7000 to simulate DDoS and GPS spoofing attacks
6. **Observe Federated Learning** at http://localhost:8300

---

## Support & Documentation

For details on specific components:

- **IDS Pipeline Logic**: See `tiered_xai_ids/` source files
- **Orchestrator API**: `run_orchestrator.py`
- **Federated Learning**: `run_federated_lab.py` and `run_global_model.py`
- **Attack Scenarios**: `attack_client.py`
