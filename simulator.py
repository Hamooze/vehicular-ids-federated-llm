import time
import math
import random
import threading
import os
import requests
import datetime
from flask import Flask, jsonify, render_template, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app) # Allow cross-origin requests from the Live Panel

# Use the Orchestrator's URL
ORCHESTRATOR_URL = os.environ.get("ORCHESTRATOR_URL", "http://localhost:8100")

NUM_VEHICLES = 10
vehicles = {}
simulation_running = False

# Simple circular track path parameters
TRACK_CENTER_X = 500
TRACK_CENTER_Y = 500
TRACK_RADIUS = 300

spoof_config = {"source": None, "target": None}

def get_area(x, y):
    if x >= 500 and y < 500: return 1
    if x >= 500 and y >= 500: return 2
    if x < 500 and y >= 500: return 3
    return 4

def mirror_to_area(x, y, target_area):
    offset_x = abs(x - 500)
    offset_y = abs(y - 500)
    if target_area == 1: return 500 + offset_x, 500 - offset_y
    if target_area == 2: return 500 + offset_x, 500 + offset_y
    if target_area == 3: return 500 - offset_x, 500 + offset_y
    if target_area == 4: return 500 - offset_x, 500 - offset_y
    return x, y

def init_vehicles():
    print(f"Initializing {NUM_VEHICLES} simulated vehicles...")
    for i in range(1, NUM_VEHICLES + 1):
        v_id = f"V{i:03d}"
        angle = (i / NUM_VEHICLES) * 2 * math.pi
        x = TRACK_CENTER_X + TRACK_RADIUS * math.cos(angle)
        y = TRACK_CENTER_Y + TRACK_RADIUS * math.sin(angle)
        
        vehicles[v_id] = {
            "vehicle_id": v_id,
            "angle": angle,  # radians on track
            "speed": random.uniform(40.0, 70.0), # km/h base speed
            "x": x,
            "y": y,
            "transmission_count": 0,
            "status": "DISCONNECTED"
        }

def simulation_loop():
    global simulation_running
    time.sleep(2) # Wait for web server startup
    print("Simulation transmission loop engaged. Waiting for start signal...")
    
    while True:
        if not simulation_running:
            time.sleep(1.0)
            continue
            
        try:
            for v_id, v in vehicles.items():
                # Add tiny variance to speed
                v['speed'] += random.uniform(-1.0, 1.0)
                v['speed'] = max(30.0, min(v['speed'], 90.0))

                # Update position based on speed
                # angular velocity = v / r. Speed is km/h. Scale by some factor to look good on screen.
                angular_speed = (v['speed'] / 3.6) / TRACK_RADIUS
                v['angle'] += angular_speed
                if v['angle'] > 2 * math.pi:
                    v['angle'] -= 2 * math.pi
                
                v['x'] = TRACK_CENTER_X + TRACK_RADIUS * math.cos(v['angle'])
                v['y'] = TRACK_CENTER_Y + TRACK_RADIUS * math.sin(v['angle'])
                
                # Heading in degrees
                heading = (math.degrees(v['angle']) + 90) % 360

                true_x, true_y = v['x'], v['y']
                reported_x, reported_y = true_x, true_y
                
                # GPS Spoofing physics override
                if spoof_config['source'] is not None and spoof_config['target'] is not None:
                    if get_area(true_x, true_y) == int(spoof_config['source']):
                        reported_x, reported_y = mirror_to_area(true_x, true_y, int(spoof_config['target']))
                        v['status'] = "SPOOFING"

                payload = {
                    "vehicle_id": v_id,
                    "timestamp": datetime.datetime.now().isoformat(),
                    "location": [round(reported_x, 6), round(reported_y, 6)],
                    "speed": round(v['speed'], 2),
                    "heading": round(heading, 2),
                    "message_type": "BSM"
                }

                try:
                    res = requests.post(f"{ORCHESTRATOR_URL}/v2x/telemetry", json=payload, timeout=2)
                    if res.status_code == 200:
                        v['transmission_count'] += 1
                        v['status'] = "TRANSMITTING"
                    else:
                        v['status'] = "ERROR_API"
                except Exception as e:
                    v['status'] = "ERROR_NET"
                    
        except Exception as e:
            print(f"Simulation loop error: {e}")
            
        time.sleep(1.0) # Transmit data every second

@app.route('/')
def index():
    return render_template('simulator_index.html')

@app.route('/api/state')
def get_state():
    return jsonify({
        "status": "active" if simulation_running else "halted",
        "timestamp": time.time(),
        "vehicles": list(vehicles.values()),
        "spoof_config": spoof_config
    })

@app.route('/api/spoof', methods=['POST'])
def set_spoof():
    data = request.json
    global spoof_config
    spoof_config['source'] = data.get('source')
    spoof_config['target'] = data.get('target')
    return jsonify({"success": True})

@app.route('/api/start', methods=['POST'])
def start_sim():
    global simulation_running
    simulation_running = True
    return jsonify({"success": True, "message": "Simulation started"})

@app.route('/api/stop', methods=['POST'])
def stop_sim():
    global simulation_running
    simulation_running = False
    for v in vehicles.values():
        v['status'] = "HALTED"
    return jsonify({"success": True, "message": "Simulation stopped"})

@app.route('/api/reset', methods=['POST'])
def reset_sim():
    global simulation_running, spoof_config
    simulation_running = False
    spoof_config['source'] = None
    spoof_config['target'] = None
    init_vehicles()
    return jsonify({"success": True})

if __name__ == '__main__':
    init_vehicles()
    t = threading.Thread(target=simulation_loop, daemon=True)
    t.start()
    print("Starting Simulation Host on port 9000...")
    app.run(host='0.0.0.0', port=9000)
