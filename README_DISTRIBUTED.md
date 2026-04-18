# LLM-Based Distributed Vehicular IDS - Phase 2

## 🎯 Project Overview

This is **Phase 2** of our Senior Design Project: **LLM-Empowered Intrusion Detection System (IDS) for Vehicular Networks with Hierarchical Federated Learning**.

### What's New in Phase 2 (Distributed Architecture)

Phase 1 ran everything on a single machine. Phase 2 **separates the system into independent distributed services**:

- ✅ **IDS Server A**: Runs on dedicated machine/container - specializes in DDoS attack detection
- ✅ **IDS Server B**: Runs on dedicated machine/container - specializes in GPS Spoofing detection  
- ✅ **Master Coordinator**: Orchestrates federated learning across all servers
- ✅ **Attack Client**: Separate service for launching attacks and monitoring

### Key Improvements

| Feature | Phase 1 | Phase 2 |
|---------|---------|---------|
| **Deployment** | Single machine | Distributed (1-4+ machines) |
| **Scalability** | Limited | Horizontal scaling |
| **IDS Servers** | In-memory objects | Independent services with APIs |
| **Communication** | Function calls | REST APIs (HTTP) |
| **Attack Panel** | Integrated | Separate service |
| **Hosting** | Direct Python | Docker recommended |
| **Monitoring** | Console only | Web dashboards + APIs |
| **Federated Learning** | Basic | Full coordination with sync rounds |

---

## 🚀 Quick Start (2 Minutes)

### For Windows:
```bash
cd vehicular-ids-network-v2
quick-start.bat
```

### For macOS/Linux:
```bash
cd vehicular-ids-network-v2
chmod +x quick-start.sh
./quick-start.sh
```

Then open browser: **http://localhost:7000**

### Requirements

- Docker & Docker Compose
- 8GB+ RAM (for LLM models)
- ~3.3GB disk space (for Phi-2 model)

---

## 📋 Architecture Overview

```
                          ┌─────────────────────────┐
                          │  Master Coordinator     │
                          │   Federated Learning    │
                          │      (Port 9090)        │
                          └────────────┬────────────┘
                                       │
                    ┌──────────────────┼──────────────────┐
                    │                  │                  │
                    ▼                  ▼                  ▼
            ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
            │  IDS-A       │   │  IDS-B       │   │Attack Client │
            │  DDoS        │   │  GPS Spoof   │   │ Control      │
            │ (Port 8001)  │   │ (Port 8002)  │   │ (Port 7000)  │
            └──────────────┘   └──────────────┘   └──────────────┘
```

### Component Details

#### **IDS Server A (DDoS Specialist)**
- Runs Phi-2 LLM for attack analysis
- Specializes in detecting DDoS attacks
- Trained on high packet rates and connection floods
- Reports to Master Coordinator
- Receives federated learning updates

#### **IDS Server B (GPS Spoof Specialist)**
- Runs Phi-2 LLM for attack analysis
- Specializes in detecting GPS spoofing attacks
- Trained on location inconsistencies
- Reports to Master Coordinator
- Receives federated learning updates

#### **Master Coordinator**
- Aggregates detection reports every 30 seconds
- Calculates federated average knowledge
- Broadcasts updated knowledge to all servers
- Maintains learning history and statistics

#### **Attack Client (Control Panel)**
- Web interface for launching attacks
- Sends telemetry to IDS servers
- Monitors real-time detection results
- Shows server statistics and health

---

## 🔧 Installation & Setup

### Step 1: Clone/Download the Project

```bash
git clone <repo-url> vehicular-ids-network-v2
cd vehicular-ids-network-v2
```

### Step 2: Download LLM Model

The system uses **Phi-2** LLM model (~3.3GB).

**Option A: Automatic (Interactive)**
```bash
python setup_models.py
```

**Option B: Manual Download**
1. Download from: https://huggingface.co/ggml-org/models/
2. File: `phi-2.Q4_K_M.gguf`
3. Place in: `../models/phi2/`

**Option C: Use Different Model**
Edit `.env` to use Mistral-7B or TinyLLama instead.

### Step 3: Review Configuration

Edit `.env` for your setup:

```env
# Default (single machine)
IDS_A_URL=http://localhost:8001
IDS_B_URL=http://localhost:8002
MASTER_COORDINATOR_URL=http://localhost:9090

# Multi-machine (example with 4 machines)
IDS_A_URL=http://192.168.1.101:8001
IDS_B_URL=http://192.168.1.102:8002
MASTER_COORDINATOR_URL=http://192.168.1.100:9090
```

### Step 4: Deploy Services

**Using Docker (Recommended):**
```bash
docker-compose -f docker-compose-distributed.yml up -d
```

**Manual Python:**
```bash
# Terminal 1
python master_coordinator.py

# Terminal 2
python ids_server_a.py

# Terminal 3
python ids_server_b.py

# Terminal 4
python attack_client.py
```

---

## 🎮 Using the Attack Control Panel

### Access
Open browser: **http://localhost:7000**

### Features

**1. System Status**
- Shows which servers are online
- Displays health information
- Auto-refreshes every 5 seconds

**2. Send Normal Traffic**
- Generate benign BSM packets
- Select from predefined vehicles (V001, V002, V003)
- Or specify custom vehicle ID
- Choose which servers to target

**3. Launch DDoS Attack**
- Simulates high packet rate attack
- Configurable duration and packet count
- IDS-A (specialist) analyzes the traffic
- Watch confidence scores in real-time

**4. Launch GPS Spoofing Attack**
- Simulates inconsistent location data
- Rapid location changes
- IDS-B (specialist) analyzes the traffic
- Monitor detection accuracy

**5. Monitor Statistics**
- Total packets sent
- Successfully delivered
- Failed transmissions
- Attack status

**6. Activity Log**
- Real-time operation log
- Color-coded by status (success/error/warning)
- Timestamps for all events

---

## 📊 Understanding the Results

### IDS Output

When packets are analyzed, servers return:

```json
{
    "vehicle_id": "V001",
    "node_id": "IDS-A",
    "zone": "A",
    "analysis": {
        "attack_type": "ddos",
        "detected": true,
        "confidence": 0.85,
        "reasoning": "High packet rate with flood pattern detected"
    }
}
```

### Confidence Scores

- **0.0 - 0.2**: Clearly benign traffic
- **0.2 - 0.4**: Likely benign, minor anomalies
- **0.4 - 0.6**: Borderline, needs investigation
- **0.6 - 0.8**: Likely attack
- **0.8 - 1.0**: Definitely attack

### Server Specialization

**IDS-A (DDoS)**: Higher confidence when analyzing DDoS attacks
```
Attack Type    Own Specialty   Federated Learning
DDoS           0.8-0.95        0.4-0.6
GPS Spoof      0.2-0.4         0.3-0.5
```

**IDS-B (GPS Spoof)**: Higher confidence when analyzing GPS spoofing
```
Attack Type    Own Specialty   Federated Learning
GPS Spoof      0.8-0.95        0.4-0.6
DDoS           0.2-0.4         0.3-0.5
```

---

## 🔗 API Reference

### Health Checks
```bash
# Master Coordinator
curl http://localhost:9090/

# IDS Server A
curl http://localhost:8001/

# IDS Server B
curl http://localhost:8002/

# Attack Client
curl http://localhost:7000/api/health
```

### Send Telemetry to IDS

```bash
curl -X POST http://localhost:8001/v2x/telemetry \
  -H "Content-Type: application/json" \
  -d '{
    "vehicle_id": "V001",
    "speed": 60,
    "location": [25.2048, 55.2708],
    "heading": 90,
    "timestamp": "2025-02-28T14:30:00",
    "message_type": "BSM"
  }'
```

### Get Federated Learning Stats

```bash
curl http://localhost:9090/federated-learning/stats | jq .
```

### Check All Server Status

```bash
curl http://localhost:7000/api/servers/status | jq .
```

---

## 🐳 Docker Deployment Details

### Services Defined

| Service | Container | Port | Purpose |
|---------|-----------|------|---------|
| master-coordinator | vehicular-ids-master-coordinator | 9090 | Federated learning |
| ids-server-a | vehicular-ids-server-a | 8001 | DDoS detection |
| ids-server-b | vehicular-ids-server-b | 8002 | GPS spoof detection |
| attack-client | vehicular-ids-attack-client | 7000 | Attack panel |

### Common Docker Tasks

**View logs:**
```bash
docker-compose -f docker-compose-distributed.yml logs -f
```

**Stop all services:**
```bash
docker-compose -f docker-compose-distributed.yml down
```

**Restart a service:**
```bash
docker-compose -f docker-compose-distributed.yml restart ids-server-a
```

**Clean everything:**
```bash
docker-compose -f docker-compose-distributed.yml down -v
```

**Build from scratch:**
```bash
docker-compose -f docker-compose-distributed.yml build --no-cache
```

---

## 🌍 Multi-Machine Deployment

### Example: 4-Machine Setup

**Machine 1 (192.168.1.100)**: Master Coordinator
```bash
export MASTER_COORDINATOR_HOST=0.0.0.0
export MASTER_COORDINATOR_PORT=9090
export IDS_A_URL=http://192.168.1.101:8001
export IDS_B_URL=http://192.168.1.102:8002
python master_coordinator.py
```

**Machine 2 (192.168.1.101)**: IDS Server A
```bash
export IDS_A_PORT=8001
export MASTER_COORDINATOR_URL=http://192.168.1.100:9090
python ids_server_a.py
```

**Machine 3 (192.168.1.102)**: IDS Server B
```bash
export IDS_B_PORT=8002
export MASTER_COORDINATOR_URL=http://192.168.1.100:9090
python ids_server_b.py
```

**Machine 4 (192.168.1.103)**: Attack Client
```bash
export IDS_A_URL=http://192.168.1.101:8001
export IDS_B_URL=http://192.168.1.102:8002
export MASTER_COORDINATOR_URL=http://192.168.1.100:9090
python attack_client.py
```

Update `.env` on clients with the master IP.

---

## 🧠 How LLM Detection Works

### Detection Pipeline

1. **Feature Extraction**
   - Analyze packet rate, connection count, protocols
   - Calculate geographic consistency
   - Compute anomaly score

2. **LLM Prompt**
   ```
   "Analyze these network traffic patterns. Is this a DDoS attack?
   
   Traffic Features:
   - Packet Rate: 1500 packets/sec
   - Active Connections: 250
   - Protocol Distribution: TCP 0.9, UDP 0.1
   - Geographic Consistency: False
   - Request Pattern: flood
   - Anomaly Score: 0.92
   
   Respond with confidence (0.0-1.0) and reasoning."
   ```

3. **LLM Analysis**
   - GPT4All runs Phi-2 model locally
   - Returns confidence score
   - Includes reasoning

4. **Federation**
   - Server reports result to Master
   - Master aggregates all reports
   - Broadcasts updated knowledge
   - Servers update their models

### Knowledge Sharing

**Round 1:**
```
IDS-A detects DDoS: confidence 0.85
IDS-B detects DDoS: confidence 0.35 (not specialist)
Master calculates average: (0.85 + 0.35) / 2 = 0.60
Broadcasts 0.60 to both servers
```

**Round 2:**
```
IDS-A now has more confidence (0.60 + local 0.85 = avg)
IDS-B now has more confidence (0.60 + local 0.35 = avg)
Both servers are smarter!
```

---

## 📊 Monitoring & Metrics

### Key Metrics

1. **Detection Accuracy**
   - True Positives: Correctly detected attacks
   - False Positives: Benign flagged as attack
   - True Negatives: Correctly identified benign
   - False Negatives: Missed attacks

2. **Federated Learning Progress**
   - Knowledge per attack type (0.0-1.0)
   - Knowledge maturity (rounds learned)
   - Learning convergence speed

3. **System Performance**
   - Packets analyzed per second
   - Average detection latency
   - False positive rate
   - Memory usage per server

### View Metrics

```bash
# Master Coordinator statistics
curl http://localhost:9090/federated-learning/stats

# IDS Server A statistics
curl http://localhost:8001/stats

# IDS Server B statistics
curl http://localhost:8002/stats
```

---

## 🔒 Security Considerations

### Current Implementation
- ✅ LLM analysis (local, no cloud)
- ✅ Distributed detection
- ✅ Federated learning
- ❌ No authentication/authorization
- ❌ No encryption between services
- ❌ No rate limiting

### For Production

1. **Add TLS/SSL** between services
2. **Implement JWT** authentication
3. **Add rate limiting** on API endpoints
4. **Network segmentation** between servers
5. **Audit logging** for all actions
6. **Model versioning** and integrity checks

---

## 🐛 Troubleshooting

### Issue: "Model not found"
```
Error: Model file not found. Place the GGUF file locally.
```
→ Download Phi-2 model to `../models/phi2/`

### Issue: "Cannot connect to IDS Server"
```
ConnectionRefusedError: [Errno 111] Connection refused
```
→ Ensure IDS servers are running

### Issue: "LLM taking too long"
```
Waiting for LLM to load... (takes 30-120 seconds)
```
→ First load is slow. Subsequent calls are fast. Be patient!

### Issue: "Port already in use"
```
OSError: [Errno 48] Address already in use
```
→ Change port in `.env` or kill existing process

### Issue: Docker build fails
```
ERROR: Service 'ids-server-a' failed to build
```
→ Ensure llm_guardian.py and llm_agent.py are in directory

---

## 📚 File Structure

```
vehicular-ids-network-v2/
├── ids_server_a.py                 # DDoS-specialist IDS
├── ids_server_b.py                 # GPS-specialist IDS  
├── master_coordinator.py           # Federated learning master
├── attack_client.py                # Attack control panel
├── llm_guardian.py                 # From V4 (detection logic)
├── llm_agent.py                    # From V4 (LLM wrapper)
├── Dockerfile.ids_a                # Container for IDS-A
├── Dockerfile.ids_b                # Container for IDS-B
├── Dockerfile.master               # Container for master
├── Dockerfile.attack               # Container for attack client
├── docker-compose-distributed.yml  # Full stack
├── .env                            # Configuration
├── requirements_updated.txt        # Python packages
├── setup_models.py                 # Model downloader
├── quick-start.bat                 # Windows launcher
├── quick-start.sh                  # Unix launcher
├── README.md                       # This file
├── DEPLOYMENT_DISTRIBUTED.md       # Detailed deployment doc
├── templates/
│   └── attack_panel.html          # Web UI
└── ../models/
    └── phi2/
        └── phi-2.Q4_K_M.gguf      # LLM model
```

---

## 🚶 Next Steps

1. **Deploy the System**
   - Run `quick-start.bat` or `quick-start.sh`
   - Or use `docker-compose`

2. **Test Normal Traffic**
   - Click "Send Normal Traffic"
   - Verify both servers accept packets
   - Check logs for normal handling

3. **Launch Attacks**
   - Try DDoS attack on IDS-A
   - Try GPS Spoof on IDS-B
   - Observe detection confidence

4. **Monitor Federated Learning**
   - Check Master Coordinator logs
   - View knowledge updates
   - See cross-specialist learning

5. **Scale to Multiple Machines**
   - Update `.env` with IP addresses
   - Deploy each service to different machine
   - Verify network connectivity

---

## 📖 Documentation

- **DEPLOYMENT_DISTRIBUTED.md** - Detailed deployment guide
- **setup_models.py** - Interactive model downloader
- **../V4/README_V2.md** - Phase 1 documentation
- **../V4/AI_TRAINING_PLAYBOOK.md** - AI training guide

---

## 👥 Support

For issues or questions:
1. Check DEPLOYMENT_DISTRIBUTED.md
2. Review logs: `docker logs <container-name>`
3. Verify configuration in .env
4. Check network connectivity between services
5. Ensure LLM models are downloaded

---

## 📈 Performance Tips

1. **Use smaller model** (TinyLLama) for faster inference
2. **Increase sync interval** to reduce network traffic
3. **Deploy on separate machines** for parallel processing
4. **Use GPU** if available for faster LLM inference
5. **Monitor memory usage** to keep system responsive

---

## 🎓 Educational Value

This project demonstrates:

✅ **Distributed Systems Architecture**
- Microservices design
- Service-to-service communication
- Federated learning

✅ **LLM Integration**
- Local LLM inference
- Prompt engineering
- Real-time analysis

✅ **Cybersecurity**
- Attack detection
- Anomaly analysis
- Defense mechanisms

✅ **Vehicular Networks**
- V2X communication
- Network security
- Real-time processing

---

## 📝 License & Attribution

This project is part of a Senior Design Project on LLM-based IDS for vehicular networks.

**Key Contributors:**
- Distributed architecture design
- LLM integration & detection logic
- Federated learning implementation
- Docker containerization

---

## 🎉 Thank You!

Thank you for using the Distributed Vehicular IDS system. We hope it helps you understand how LLMs can be applied to network security and distributed systems.

Happy attacking! (In simulation, of course 😉)

---

*Last Updated: February 28, 2026*
