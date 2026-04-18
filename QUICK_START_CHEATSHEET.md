# Quick Start Cheat Sheet

## 🚀 Starting the System

### Option 1: Docker (Recommended - One Command)
```bash
cd vehicular-ids-network-v2
docker-compose -f docker-compose-distributed.yml up
```

### Option 2: Automated Start Script
```bash
# Windows
./quick-start.bat

# Linux/Mac
./quick-start.sh
```

### Option 3: Manual (4 Terminal Windows)
```bash
# Terminal 1: Master Coordinator
python master_coordinator.py

# Terminal 2: IDS Server A (DDoS)
python ids_server_a.py

# Terminal 3: IDS Server B (GPS)
python ids_server_b.py

# Terminal 4: Attack Generation Client
python attack_client.py
```

---

## 🌐 Accessing Dashboards

Open these URLs in your browser (after starting services):

| Service | URL | Purpose |
|---------|-----|---------|
| IDS-A Dashboard | http://localhost:8001/dashboard | DDoS detection analysis |
| IDS-B Dashboard | http://localhost:8002/dashboard | GPS spoofing analysis |
| Master Dashboard | http://localhost:9090/dashboard | Federated learning progress |
| Attack Panel | http://localhost:7000 | Send attacks/traffic |

**Tip**: Open all 4 in tabs to see real-time updates!

---

## 📡 Sending Traffic via Web UI

### Normal Traffic
1. Go to http://localhost:7000
2. Click "Generate Normal Traffic"
3. Watch dashboards show low anomaly scores
4. Traffic appears benign (confidence < threshold)

### DDoS-Like Patterns
1. Go to http://localhost:7000
2. Click "Generate DDoS Attack"
3. Watch IDS-A dashboard → detections increase
4. Check confidence scores (should be high: 0.8-0.95)
5. View LLM reasoning for why it's detected as attack

### GPS Spoofing Patterns
1. Go to http://localhost:7000
2. Click "Generate GPS Spoof Attack"
3. Watch IDS-B dashboard → detections increase
4. Check GPS spoof confidence scores
5. View LLM reasoning about location inconsistencies

---

## 🔌 API Calls (Command Line)

### Send Normal Traffic
```bash
curl -X POST http://localhost:7000/api/send/normal-traffic \
  -H "Content-Type: application/json" \
  -d '{"vehicle_id":"V001","target_server":"both"}'
```

### Start DDoS Attack (30 packets over 5 seconds)
```bash
curl -X POST http://localhost:7000/api/attack/ddos \
  -H "Content-Type: application/json" \
  -d '{"vehicle_id":"ATTACKER-01","duration_seconds":5,"packet_count":30}'
```

### Start GPS Spoof Attack
```bash
curl -X POST http://localhost:7000/api/attack/gps-spoof \
  -H "Content-Type: application/json" \
  -d '{"vehicle_id":"SPOOF-01","duration_seconds":5,"packet_count":20}'
```

### Stop Attack
```bash
curl -X POST http://localhost:7000/api/attack/stop
```

### Get Server Stats
```bash
# IDS-A stats
curl http://localhost:8001/stats | jq

# IDS-B stats
curl http://localhost:8002/stats | jq

# Master stats
curl http://localhost:9090/federated-learning/stats | jq
```

---

## 📊 Monitoring System Health

### Check All Services Running
```bash
# All 4 should return 200 and valid JSON
curl http://localhost:8001/
curl http://localhost:8002/
curl http://localhost:9090/
curl http://localhost:7000/api/health
```

### View Server Knowledge
```bash
# What does each server know?
curl http://localhost:8001/stats | jq '.knowledge'
curl http://localhost:8002/stats | jq '.knowledge'
```

### View Federated Learning Progress
```bash
# What has the network learned?
curl http://localhost:9090/federated-learning/stats | jq '.federated_knowledge'

# Which round are we on?
curl http://localhost:9090/federated-learning/stats | jq '.round'

# How many reports has master aggregated?
curl http://localhost:9090/federated-learning/stats | jq '.total_reports'
```

---

## 🧪 Run Interactive Demo

```bash
# Interactive menu
python test_llm_integration.py

# Health check
python test_llm_integration.py --health

# Automated demo
python test_llm_integration.py --demo
```

---

## 🛑 Stopping Services

### Docker
```bash
# In the terminal where docker-compose is running:
Ctrl+C

# Or from another terminal:
docker-compose -f vehicular-ids-network-v2/docker-compose-distributed.yml down
```

### Manual Servers
```bash
# In each terminal running a Python service:
Ctrl+C
```

---

## 🔧 Troubleshooting

### Services Won't Start
```bash
# Check Python version (3.8+)
python --version

# Check required packages
pip install flask requests colorama gpt4all

# Check port conflicts
lsof -i :8001  # Is port 8001 in use?
```

### Dashboards Show No Data
```bash
# Send traffic first
curl -X POST http://localhost:7000/api/send/normal-traffic \
  -H "Content-Type: application/json" \
  -d '{"vehicle_id":"V001"}'

# Wait 3-5 seconds for dashboard refresh
# Then reload browser
```

### LLM Not Loading
```bash
# Check model file exists
ls ../models/phi2/phi-2.Q4_K_M.gguf

# Check gpt4all version
pip show gpt4all

# Should be >=1.4.0
pip install --upgrade 'gpt4all>=1.4.0'

# Restart server
python ids_server_a.py
```

### Master Not Syncing
```bash
# Check servers can reach master
curl http://localhost:9090/

# Check if syncing is active (should change every 30s)
watch -n 1 'curl -s http://localhost:9090/federated-learning/stats | jq .round'
```

---

## 📈 Dashboard Features

### IDS-A & IDS-B Dashboards Show:
- **Total Analyses**: How many packets analyzed
- **Attacks Detected**: Count of detected attacks
- **Avg Confidence**: Average LLM confidence score
- **Detection Rate**: Percentage of detections
- **Recent Analyses**: Last 10 with confidence scores
- **Knowledge Level**: 0.0-1.0 - expertise in this attack type
- **Learning Maturity**: Number of federated learning rounds

### Master Dashboard Shows:
- **Learning Round**: Current federated sync iteration
- **Active Servers**: Number of connected IDS nodes
- **Node Knowledge Status**: Each server's expertise
- **Attacks by Type**: DDoS vs GPS spoof counts
- **Recent Reports**: Last 20 analysis reports
- **Knowledge Bars**: Visual progress of learning

---

## 🎯 Typical Demo Flow

### 1. Start System (2 min)
```bash
docker-compose -f vehicular-ids-network-v2/docker-compose-distributed.yml up
```

### 2. Open Dashboards (1 min)
- IDS-A: http://localhost:8001/dashboard
- IDS-B: http://localhost:8002/dashboard
- Master: http://localhost:9090/dashboard
- Attack Panel: http://localhost:7000

### 3. Send Normal Traffic (1 min)
```bash
python test_llm_integration.py
# Select option 4: Send Normal Traffic
```
Check dashboards → Low confidence scores

### 4. Send DDoS Attack (2 min)
```bash
# Keep test_llm_integration.py running
# Select option 5: Send DDoS Patterns
```
Watch IDS-A dashboard → High confidence scores (0.8-0.95)

### 5. Wait for Federated Sync (1 min)
```bash
# Wait for Master to complete sync round (30s default)
# From another terminal:
watch -n 1 'curl -s http://localhost:9090/federated-learning/stats | jq .round'
```

### 6. Send GPS Spoof (2 min)
```bash
# Select option 6: Send GPS Patterns
```
Watch IDS-B dashboard → High confidence scores

### 7. View Learning Progress
```bash
# Check Master dashboard
# http://localhost:9090/dashboard

# Check knowledge spread
curl http://localhost:8001/stats | jq '.knowledge'
curl http://localhost:8002/stats | jq '.knowledge'
```

**Total time**: ~10 minutes to full demonstration

---

## 💡 Key Concepts

### LLM-Based Detection
- No explicit attack labels in packets
- LLM infers attack type from network patterns
- Confidence score: 0.0 = benign, 1.0 = definitely attack

### Federated Learning
- Master aggregates detections from all servers every 30s
- Broadcasts aggregated knowledge back to servers
- Each round increases `knowledge_maturity`

### Semantic Knowledge
```
Round 1: "We've seen 3 DDoS attacks"
Round 2: "We've seen 5 GPS spoofing attacks"  
Round 3: "Here's what DDoS looks like: [patterns]"
Round 4: "Here's what GPS spoofing looks like: [patterns]"
```

### Cross-Domain Learning
- IDS-A (DDoS expert) learns about GPS spoofing from IDS-B
- IDS-B (GPS expert) learns about DDoS from IDS-A
- Both become more capable over time

---

## 📚 More Information

**Full Guides:**
- `LLM_INTEGRATION_GUIDE.md` - Comprehensive usage guide
- `PHASE2_INTEGRATION_SUMMARY.md` - Technical deep dive
- `README.md` (in V4 folder) - Project overview

**Code:**
- `ids_server_a.py` - DDoS detection server with dashboard
- `ids_server_b.py` - GPS detection server with dashboard
- `master_coordinator.py` - Federated learning orchestrator
- `attack_client.py` - Attack generation and web UI
- `llm_guardian.py` - LLM analysis core logic
- `llm_agent.py` - LLM model wrapper

---

## 🎓 Learning Path

### Beginner
1. Start system with `docker-compose`
2. Open all dashboards
3. Send normal traffic
4. Send DDoS attack
5. Observe detections

### Intermediate
1. Use API to send custom patterns
2. Monitor federated learning rounds
3. Check knowledge progression
4. Modify model in quick-start script

### Advanced
1. Edit LLM prompts in `llm_guardian.py`
2. Add new attack types
3. Deploy on multiple machines
4. Implement WebSocket for real-time updates
5. Add additional specialist IDS nodes

---

## ⏱️ Typical Timings

| Operation | Time |
|-----------|------|
| Start Docker | 30-60 sec |
| Dashboard load | 5 sec |
| Send traffic | 1-5 sec |
| LLM analysis | 200-500 ms |
| Dashboard refresh | 3-5 sec |
| Federated sync | 30 sec (default) |
| Full demo | 10-15 min |

---

## 🔐 Security Notes

- ⚠️ This is a research testbed, not production IDS
- All services run on localhost only
- No authentication/encryption
- LLM prompts are visible in console output
- Only use in controlled lab environments

---

## 🤝 Support

**Issues?**
1. Check `TROUBLESHOOTING.md` in V4 folder
2. Review `LLM_INTEGRATION_GUIDE.md` troubleshooting section
3. Check if all 4 services are running: `curl localhost:8001` etc
4. Review server logs in terminal windows
5. Restart everything and try again

**Want to customize?**
- Edit Python files directly
- Modify dashboards in code or templates
- Change LLM model in quick-start scripts
- Adjust sync intervals in environment variables
