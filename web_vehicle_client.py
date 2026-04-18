"""
Web-based Vehicle Client
Provides a web interface to control the vehicle and send traffic/attacks
"""

from flask import Flask, render_template, jsonify, request
import requests
import datetime
import random
import threading
import time
import os

app = Flask(__name__)

# Configuration - Read from environment variables
FOG_SERVER_URL = os.getenv('FOG_SERVER_URL', 'http://localhost:8100')
VEHICLE_ID = os.getenv('VEHICLE_ID', 'V001')
VEHICLE_SPEED = float(os.getenv('VEHICLE_SPEED', '60'))
VEHICLE_LAT = float(os.getenv('VEHICLE_LOCATION_LAT', '25.2048'))
VEHICLE_LON = float(os.getenv('VEHICLE_LOCATION_LON', '55.2708'))
VEHICLE_HEADING = float(os.getenv('VEHICLE_HEADING', '90'))

# Vehicle state
vehicle_state = {
    'vehicle_id': VEHICLE_ID,
    'speed': VEHICLE_SPEED,
    'location': [VEHICLE_LAT, VEHICLE_LON],
    'heading': VEHICLE_HEADING,
    'is_transmitting': False,
    'transmission_count': 0,
    'last_response': None
}

# Transmission thread
transmission_thread = None

def simulate_movement():
    """Update vehicle position and speed"""
    vehicle_state['speed'] += random.uniform(-5, 5)
    vehicle_state['speed'] = max(40, min(120, vehicle_state['speed']))
    
    vehicle_state['location'][0] += random.uniform(-0.001, 0.001)
    vehicle_state['location'][1] += random.uniform(-0.001, 0.001)
    
    vehicle_state['heading'] = (vehicle_state['heading'] + random.uniform(-10, 10)) % 360

def send_normal_telemetry():
    """Send normal vehicle telemetry to fog server"""
    try:
        telemetry = {
            'vehicle_id': vehicle_state['vehicle_id'],
            'timestamp': datetime.datetime.now().isoformat(),
            'speed': round(vehicle_state['speed'], 2),
            'location': [round(x, 6) for x in vehicle_state['location']],
            'heading': round(vehicle_state['heading'], 2),
            'message_type': 'BSM'
        }
        
        response = requests.post(
            f"{FOG_SERVER_URL}/v2x/telemetry",
            json=telemetry,
            timeout=5
        )
        
        vehicle_state['transmission_count'] += 1
        vehicle_state['last_response'] = {
            'status': response.status_code,
            'data': response.json() if response.status_code == 200 else None,
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        return True
        
    except Exception as e:
        vehicle_state['last_response'] = {
            'status': 'error',
            'data': str(e),
            'timestamp': datetime.datetime.now().isoformat()
        }
        return False

def continuous_transmission_worker():
    """Background thread for continuous transmission"""
    while vehicle_state['is_transmitting']:
        send_normal_telemetry()
        simulate_movement()
        time.sleep(3)  # Send every 3 seconds

# ============ WEB ROUTES ============

@app.route('/')
def index():
    """Serve the main control panel webpage"""
    return render_template('control_panel.html')

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get current vehicle status"""
    status_data = vehicle_state.copy()
    status_data['fog_server'] = FOG_SERVER_URL
    status_data['local_ip'] = request.host.split(':')[0]
    return jsonify(status_data)

@app.route('/api/send-normal', methods=['POST'])
def send_normal():
    """Send single normal telemetry packet"""
    success = send_normal_telemetry()
    simulate_movement()
    
    return jsonify({
        'success': success,
        'message': 'Normal telemetry sent',
        'transmission_count': vehicle_state['transmission_count']
    })

@app.route('/api/set-vehicle', methods=['POST'])
def set_vehicle():
    """Change the vehicle ID"""
    data = request.json
    new_id = data.get('vehicle_id')
    if new_id:
        vehicle_state['vehicle_id'] = new_id
        return jsonify({'success': True, 'message': f'Vehicle ID changed to {new_id}'})
    return jsonify({'success': False, 'message': 'No ID provided'}), 400

@app.route('/api/send-attack-ddos', methods=['POST'])
def send_attack_ddos():
    """Simulate DDoS attack"""
    try:
        packets_sent = 0
        duration = 5  # 5 second attack
        
        start_time = time.time()
        while time.time() - start_time < duration:
            # Send rapid-fire fake packets
            fake_telemetry = {
                'vehicle_id': f"FAKE_{random.randint(1000, 9999)}",
                'timestamp': datetime.datetime.now().isoformat(),
                'speed': random.randint(0, 200),
                'location': [random.uniform(25.0, 25.5), random.uniform(55.0, 55.5)],
                'heading': random.randint(0, 360),
                'message_type': 'ATTACK_DDOS'
            }
            
            try:
                requests.post(
                    f"{FOG_SERVER_URL}/v2x/telemetry",
                    json=fake_telemetry,
                    timeout=1
                )
                packets_sent += 1
            except:
                pass
            
            time.sleep(0.01)  # 100 packets/second
        
        return jsonify({
            'success': True,
            'message': f'DDoS attack completed',
            'packets_sent': packets_sent
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/api/send-attack-gps-spoofing', methods=['POST'])
def send_attack_gps_spoofing():
    """Simulate GPS spoofing attack"""
    try:
        # Send impossible GPS jumps
        impossible_locations = [
            [25.2048, 55.2708],   # Dubai
            [40.7128, -74.0060],  # New York (instant teleport!)
            [51.5074, -0.1278],   # London
            [35.6762, 139.6503],  # Tokyo
        ]
        
        for idx, location in enumerate(impossible_locations):
            spoofed_telemetry = {
                'vehicle_id': vehicle_state['vehicle_id'],
                'timestamp': datetime.datetime.now().isoformat(),
                'speed': vehicle_state['speed'],
                'location': location,
                'heading': vehicle_state['heading'],
                'message_type': 'ATTACK_GPS_SPOOF'
            }
            
            response = requests.post(
                f"{FOG_SERVER_URL}/v2x/telemetry",
                json=spoofed_telemetry,
                timeout=5
            )
            
            time.sleep(0.5)  # 0.5 seconds between jumps
        
        return jsonify({
            'success': True,
            'message': 'GPS spoofing attack completed',
            'locations_spoofed': len(impossible_locations)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/api/start-continuous', methods=['POST'])
def start_continuous():
    """Start continuous normal transmission"""
    global transmission_thread
    
    if vehicle_state['is_transmitting']:
        return jsonify({
            'success': False,
            'message': 'Already transmitting'
        })
    
    vehicle_state['is_transmitting'] = True
    transmission_thread = threading.Thread(target=continuous_transmission_worker)
    transmission_thread.start()
    
    return jsonify({
        'success': True,
        'message': 'Continuous transmission started'
    })

@app.route('/api/stop-continuous', methods=['POST'])
def stop_continuous():
    """Stop continuous transmission"""
    vehicle_state['is_transmitting'] = False
    
    return jsonify({
        'success': True,
        'message': 'Continuous transmission stopped'
    })

@app.route('/api/reset', methods=['POST'])
def reset_vehicle():
    """Reset vehicle to default state"""
    vehicle_state['speed'] = 60
    vehicle_state['location'] = [25.2048, 55.2708]
    vehicle_state['heading'] = 90
    vehicle_state['transmission_count'] = 0
    vehicle_state['last_response'] = None
    
    return jsonify({
        'success': True,
        'message': 'Vehicle state reset'
    })

if __name__ == '__main__':
    # Configuration from environment variables
    VEHICLE_PORT = int(os.getenv('VEHICLE_CLIENT_PORT', '5000'))
    DEBUG = os.getenv('FLASK_ENV', 'development') == 'development'
    
    print("=" * 60)
    print("VEHICLE CONTROL PANEL - WEB INTERFACE")
    print("=" * 60)
    print(f"\nVehicle ID: {VEHICLE_ID}")
    print(f"Fog Server: {FOG_SERVER_URL}")
    print(f"\n🌐 Open your browser and go to:")
    print(f"   http://localhost:{VEHICLE_PORT}")
    print(f"   or use your Laptop 2 IP with port {VEHICLE_PORT}")
    print("\n" + "=" * 60 + "\n")
    
    app.run(host='0.0.0.0', port=VEHICLE_PORT, debug=DEBUG)
