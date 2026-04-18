# Docker Setup Guide

This project is now fully dockerized with Option B (advanced setup). All configuration is managed through environment variables in the `.env` file.

## Prerequisites

- Docker installed ([Download](https://www.docker.com/products/docker-desktop))
- Docker Compose (comes with Docker Desktop)
- Two machines on the same WiFi network (optional, for two-laptop setup)

## Quick Start (Same Machine)

If running both the fog server and vehicle client on the **same machine**:

```bash
docker-compose up
```

That's it! The services will:
- Auto-build the Docker images
- Start the fog server on `http://localhost:8080`
- Start the vehicle client on `http://localhost:5000`
- Auto-connect to each other using Docker's internal network

Open your browser to: **`http://localhost:5000`**

## Setup for Two Laptops

If running on **separate machines** (as intended):

### Laptop 1 (Fog Server)

1. Edit `.env` file - no changes needed, just run:
```bash
docker-compose up fog-server
```

2. Note the IP address of Laptop 1:
   - **Windows:** `ipconfig` (look for IPv4 Address)
   - **Mac/Linux:** `ifconfig`
   - Example: `192.168.1.100`

### Laptop 2 (Vehicle Client)

1. Edit the `.env` file:
```
FOG_SERVER_IP=192.168.1.100  # Change to Laptop 1's IP from ipconfig
```

2. Run the vehicle client:
```bash
docker-compose up vehicle-client
```

3. Open your browser to: **`http://localhost:5000`**

## Configuration (.env file)

The `.env` file controls all settings:

```env
# Fog Server Configuration
FOG_SERVER_HOST=0.0.0.0
FOG_SERVER_PORT=8080

# Vehicle Client Configuration
VEHICLE_CLIENT_PORT=5000
VEHICLE_ID=V001
VEHICLE_SPEED=60
VEHICLE_LOCATION_LAT=25.2048
VEHICLE_LOCATION_LON=55.2708
VEHICLE_HEADING=90

# Fog Server IP (for two-laptop setup)
FOG_SERVER_IP=fog-server  # Change to actual IP for separate machines
# FOG_SERVER_IP=192.168.1.100  # Uncomment and set for two-laptop setup

PYTHONUNBUFFERED=1
FLASK_ENV=development
```

## Docker Commands

### Start services
```bash
# Start all services
docker-compose up

# Start specific service
docker-compose up fog-server
docker-compose up vehicle-client

# Start in background
docker-compose up -d
```

### Stop services
```bash
docker-compose stop
```

### View logs
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f fog-server
docker-compose logs -f vehicle-client
```

### Rebuild images (after code changes)
```bash
docker-compose up --build
```

### Remove containers and images
```bash
docker-compose down
docker-compose down -v  # Also remove volumes
```

### Check running containers
```bash
docker-compose ps
```

## Health Checks

Both services have health checks configured:
- Fog server: checks `http://localhost:8080`
- Vehicle client: checks `http://localhost:5000`

View health status:
```bash
docker-compose ps
```

Yellow health status = starting, Green = healthy, Red = unhealthy

## Troubleshooting

### "Cannot connect to fog server from vehicle client"
- **Single machine:** Make sure both containers are running (`docker-compose ps`)
- **Two machines:** 
  - Verify IP in `.env` file on Laptop 2: `FOG_SERVER_IP=<Laptop1-IP>`
  - Check Windows Firewall allows port 8080
  - Verify both laptops are on same WiFi

### "Port already in use"
Change ports in `.env`:
```env
FOG_SERVER_PORT=8081
VEHICLE_CLIENT_PORT=5001
```

### "Module not found" error
Rebuild the images:
```bash
docker-compose down
docker-compose up --build
```

### View detailed errors
```bash
docker-compose logs -f
```

## Production Setup

For production, create a `docker-compose.prod.yml`:

```yaml
version: '3.8'

services:
  fog-server:
    build:
      context: .
      dockerfile: Dockerfile.fog
    container_name: vehicular-ids-fog-server
    ports:
      - "8080:8080"
    environment:
      FLASK_ENV: production
      PYTHONUNBUFFERED: "1"
    networks:
      - vehicular-network
    restart: always

  vehicle-client:
    build:
      context: .
      dockerfile: Dockerfile.vehicle
    container_name: vehicular-ids-vehicle-client
    ports:
      - "5000:5000"
    environment:
      FOG_SERVER_URL: "http://fog-server:8080"
      FLASK_ENV: production
      PYTHONUNBUFFERED: "1"
    networks:
      - vehicular-network
    depends_on:
      fog-server:
        condition: service_healthy
    restart: always

networks:
  vehicular-network:
    driver: bridge
```

Run with:
```bash
docker-compose -f docker-compose.prod.yml up
```

## File Structure

```
vehicular-ids-network/
├── .env                          # Configuration (edit this for setup)
├── docker-compose.yml            # Development setup
├── Dockerfile.fog                # Fog server container
├── Dockerfile.vehicle            # Vehicle client container
├── fog_server_flask.py           # Fog server code
├── web_vehicle_client.py         # Vehicle client code
├── requirements.txt
├── templates/
│   └── control_panel.html
└── README.md
```

## Key Advantages of Docker Setup

✅ **No Python setup needed** - containers have everything
✅ **Configuration management** - all settings in `.env` file
✅ **Easy IP management** - change IP one place for two-laptop setup
✅ **Health monitoring** - automatic health checks
✅ **Service dependencies** - vehicle client waits for fog server
✅ **Isolation** - no conflicts with system Python
✅ **Scalability** - easily run multiple vehicle clients
✅ **Production ready** - same setup in dev and prod
