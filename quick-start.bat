@echo off
REM Distributed Vehicular IDS - Windows Quick Start Script

setlocal enabledelayedexpansion

echo.
echo ╔════════════════════════════════════════════════════════════╗
echo ║   LLM-Based Distributed Vehicular IDS - Quick Start       ║
echo ║                                                            ║
echo ║   This script will start all services in Docker           ║
echo ╚════════════════════════════════════════════════════════════╝
echo.

REM Check if Docker is installed
docker --version >nul 2>&1
if errorlevel 1 (
    echo ✗ Docker is not installed or not in PATH
    echo   Please install Docker Desktop from: https://www.docker.com/products/docker-desktop
    pause
    exit /b 1
)

echo ✓ Docker is installed

REM Check if Docker is running
docker ps >nul 2>&1
if errorlevel 1 (
    echo ✗ Docker daemon is not running
    echo   Please start Docker Desktop
    pause
    exit /b 1
)

echo ✓ Docker daemon is running
echo.

REM determine directory of this script, even when run from other cwd
set "BASEDIR=%~dp0"
REM move one level up (script lives in vehicular-ids-network-v2)
for %%I in ("%BASEDIR%..") do set "PARENT=%%~fI"

REM Create models directory relative to project root
if not exist "%PARENT%\models" mkdir "%PARENT%\models"
if not exist "%PARENT%\models\phi2" mkdir "%PARENT%\models\phi2"

echo 📁 Directories ready (%PARENT%\models\phi2)

REM Check for models using absolute path
if not exist "%PARENT%\models\phi2\phi-2.Q4_K_M.gguf" (
    echo.
    echo ⚠️  WARNING: LLM model not found!
    echo.
    echo   You need to download the Phi-2 model:
    echo   - Download from: https://huggingface.co/ggml-org/models/
    echo   - File: phi-2.Q4_K_M.gguf (3.3GB)
    echo   - Place in: %PARENT%\models\phi2\
    echo.
    echo   Without this model, the IDS servers will not perform detection!
    echo.
    echo   Continue anyway? (Y/N)
    set /p continue=
    if /i "!continue!" neq "Y" (
        exit /b 1
    )
)

echo.
echo 🚀 Starting all services...
echo.
echo   Services starting:
echo   - Master Coordinator (9090)
echo   - IDS Server A - DDoS (8001)
echo   - IDS Server B - GPS Spoof (8002)
echo   - Attack Client (7000)
echo.

REM Build and start containers
docker-compose -f docker-compose-distributed.yml up -d

if errorlevel 1 (
    echo ✗ Failed to start services
    pause
    exit /b 1
)

echo.
echo ✓ Services started in background
echo.
echo 📊 Checking service status...
timeout /t 5 /nobreak

docker-compose -f docker-compose-distributed.yml ps

echo.
echo ✓ All services are starting!
echo.
echo 🌐 Access the following:
echo.
echo   Attack Control Panel:     http://localhost:7000
echo   IDS Server A (DDoS):      http://localhost:8001
echo   IDS Server B (GPS Spoof): http://localhost:8002
echo   Master Coordinator:       http://localhost:9090
echo.
echo 📋 Useful commands:
echo.
echo   View logs:
echo     docker-compose -f docker-compose-distributed.yml logs -f
echo.
echo   Stop services:
echo     docker-compose -f docker-compose-distributed.yml down
echo.
echo   Restart services:
echo     docker-compose -f docker-compose-distributed.yml restart
echo.
echo   Remove all data and containers:
echo     docker-compose -f docker-compose-distributed.yml down -v
echo.
echo   View specific service logs:
echo     docker logs vehicular-ids-attack-client
echo.

pause
