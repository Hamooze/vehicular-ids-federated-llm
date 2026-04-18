#!/bin/bash

# Distributed Vehicular IDS - Unix Quick Start Script
# Works on macOS and Linux

set -e

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║   LLM-Based Distributed Vehicular IDS - Quick Start       ║"
echo "║                                                            ║"
echo "║   This script will start all services in Docker           ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "✗ Docker is not installed"
    echo "  Please install Docker from: https://www.docker.com/products/docker-desktop"
    exit 1
fi

echo "✓ Docker is installed"

# Check if Docker daemon is running
if ! docker ps &> /dev/null; then
    echo "✗ Docker daemon is not running"
    echo "  Please start Docker daemon"
    exit 1
fi

echo "✓ Docker daemon is running"
echo ""

# calculate script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Create models directory relative to project root
mkdir -p "$PROJECT_ROOT/models/phi2"

echo "📁 Directories ready ($PROJECT_ROOT/models/phi2)"

# Check for models
MODEL_PATH="$PROJECT_ROOT/models/phi2/phi-2.Q4_K_M.gguf"
if [ ! -f "$MODEL_PATH" ]; then
    echo ""
    echo "⚠️  WARNING: LLM model not found!"
    echo ""
    echo "  You need to download the Phi-2 model:"
    echo "  - Download from: https://huggingface.co/ggml-org/models/"
    echo "  - File: phi-2.Q4_K_M.gguf (3.3GB)"
    echo "  - Place in: $PROJECT_ROOT/models/phi2/"
    echo ""
    echo "  Without this model, the IDS servers will not perform detection!"
    echo ""
    read -p "  Continue anyway? (y/n) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo ""
echo "🚀 Starting all services..."
echo ""
echo "   Services starting:"
echo "   - Master Coordinator (9090)"
echo "   - IDS Server A - DDoS (8001)"
echo "   - IDS Server B - GPS Spoof (8002)"
echo "   - Attack Client (7000)"
echo ""

# Build and start containers
docker-compose -f docker-compose-distributed.yml up -d

if [ $? -ne 0 ]; then
    echo "✗ Failed to start services"
    exit 1
fi

echo ""
echo "✓ Services started in background"
echo ""
echo "📊 Checking service status..."
sleep 5

docker-compose -f docker-compose-distributed.yml ps

echo ""
echo "✓ All services are starting!"
echo ""
echo "🌐 Access the following:"
echo ""
echo "   Attack Control Panel:     http://localhost:7000"
echo "   IDS Server A (DDoS):      http://localhost:8001"
echo "   IDS Server B (GPS Spoof): http://localhost:8002"
echo "   Master Coordinator:       http://localhost:9090"
echo ""
echo "📋 Useful commands:"
echo ""
echo "   View logs:"
echo "     docker-compose -f docker-compose-distributed.yml logs -f"
echo ""
echo "   Stop services:"
echo "     docker-compose -f docker-compose-distributed.yml down"
echo ""
echo "   Restart services:"
echo "     docker-compose -f docker-compose-distributed.yml restart"
echo ""
echo "   Remove all data and containers:"
echo "     docker-compose -f docker-compose-distributed.yml down -v"
echo ""
echo "   View specific service logs:"
echo "     docker logs vehicular-ids-attack-client"
echo ""
echo "ℹ️  For more information, see: DEPLOYMENT_DISTRIBUTED.md"
echo ""
