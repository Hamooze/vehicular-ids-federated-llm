# vehicular-ids-federated-llm

Clean, GitHub-ready release for the Vehicular IDS platform (Docker-first, Ollama-backed).

## Publish To GitHub (GitHub Desktop)

1. Open **GitHub Desktop**.
2. Click **File -> Add local repository**.
3. Choose this folder:
   - `C:\Users\hamza\Downloads\SDPGITHUB\vehicular-ids-federated-llm`
4. If prompted, choose **Create a repository**.
5. Set:
   - **Name**: `vehicular-ids-federated-llm` (or your preferred repo name)
   - **Local path**: keep current
   - **Git ignore**: `Python` (optional, already included in `.gitignore`)
   - **License**: optional
6. Commit all files:
   - Summary example: `Initial clean release package`
7. Click **Publish repository**.
8. Choose **Public** or **Private**, then publish.

## Prerequisites

- Docker Desktop (running)
- GitHub Desktop
- Ollama installed on host machine
- Windows PowerShell

## Models To Install (Ollama)

From inside `tiered_xai_ids`:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install_models.ps1 -Role all
```

This installs:
- `phi3.5`
- `mistral:7b`
- `qwen2.5:32b`

Optional role-specific installs:

```powershell
# Laptop profile
powershell -ExecutionPolicy Bypass -File .\scripts\install_models.ps1 -Role laptop

# Worker profile
powershell -ExecutionPolicy Bypass -File .\scripts\install_models.ps1 -Role worker
```

## How To Run (Recommended: Unified Stack)

From project root:

```powershell
docker compose -f docker-compose.unified.yml up -d --build
```

Check status:

```powershell
docker compose -f docker-compose.unified.yml ps
```

Stop:

```powershell
docker compose -f docker-compose.unified.yml down
```

## Main URLs

- Attack Command Panel: `http://localhost:7700`
- Live Monitor: `http://localhost:8200/dashboard`
- Federated Lab: `http://localhost:8300/dashboard`
- Vehicle Console: `http://localhost:5000`
- Orchestrator Health: `http://localhost:8100/health`

## Notes

- Required env file is included at:
  - `tiered_xai_ids/.env`
- Example copy is also included:
  - `tiered_xai_ids/.env.example`
- The compose files are already configured to use host Ollama via:
  - `http://host.docker.internal:11434`

