"""

Flask-based Fog Server
More production-ready with REST API endpoints
"""

from flask import Flask, request, jsonify
import datetime
import json
import os
from colorama import Fore, init

init(autoreset=True)

app = Flask(__name__)

# Storage for received data (in-memory for now)
received_data = []

@app.route('/', methods=['GET'])
def home():
    """Health check endpoint"""
    return jsonify({
        'status': 'online',
        'service': 'Fog Node Server',
        'timestamp': datetime.datetime.now().isoformat(),
        'total_messages_received': len(received_data)
    })

@app.route('/v2x/telemetry', methods=['POST'])
def receive_telemetry():
    """
    Endpoint to receive vehicle telemetry
    
    Expected JSON format:
    {
        "vehicle_id": "V001",
        "speed": 60,
        "location": [25.2048, 55.2708],
        "heading": 90,
        "timestamp": "2025-02-01T14:30:00",
        "message_type": "BSM" or "ATTACK_DDOS" or "ATTACK_GPS_SPOOF"
    }
    """
    try:
        # Get JSON data from request
        vehicle_data = request.get_json()
        
        if not vehicle_data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Add server timestamp and source IP
        vehicle_data['server_timestamp'] = datetime.datetime.now().isoformat()
        vehicle_data['source_ip'] = request.remote_addr
        
        # Store data
        received_data.append(vehicle_data)
        
        # CHECK FOR ATTACK TYPES
        message_type = vehicle_data.get('message_type', 'BSM')
        
        if message_type == 'ATTACK_DDOS':
            print(f"\n{Fore.RED}🚨 DDoS ATTACK DETECTED!")
            print(f"   Fake Vehicle ID: {vehicle_data.get('vehicle_id')}")
            print(f"   Source IP: {request.remote_addr}")
            print(f"   Speed: {vehicle_data.get('speed')} km/h")
        
        elif message_type == 'ATTACK_GPS_SPOOF':
            print(f"\n{Fore.YELLOW}⚠️  GPS SPOOFING DETECTED!")
            print(f"   Vehicle: {vehicle_data.get('vehicle_id')}")
            print(f"   Suspicious Location: {vehicle_data.get('location')}")
            print(f"   Source IP: {request.remote_addr}")
        
        else:
            # Normal traffic (BSM)
            print(f"\n{Fore.GREEN}🚗 Telemetry received from {request.remote_addr}")
            print(f"   Vehicle ID: {vehicle_data.get('vehicle_id')}")
            print(f"   Speed: {vehicle_data.get('speed')} km/h")
            print(f"   Location: {vehicle_data.get('location')}")
        
        # Basic anomaly detection
        anomalies = detect_anomalies(vehicle_data)
        
        # Prepare response
        response = {
            'status': 'success',
            'message': 'Telemetry received',
            'timestamp': vehicle_data['server_timestamp'],
            'anomalies_detected': len(anomalies) > 0,
            'anomalies': anomalies
        }
        
        return jsonify(response), 200
        
    except Exception as e:
        print(f"{Fore.RED}✗ Error processing telemetry: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/v2x/attack', methods=['POST'])
def receive_attack():
    """
    Endpoint for simulated attack data
    Used for testing attack detection
    """
    try:
        attack_data = request.get_json()
        attack_data['server_timestamp'] = datetime.datetime.now().isoformat()
        attack_data['source_ip'] = request.remote_addr
        
        print(f"\n{Fore.RED}🚨 ATTACK DATA RECEIVED")
        print(f"   Type: {attack_data.get('attack_type')}")
        print(f"   Source: {request.remote_addr}")
        print(f"   Details: {attack_data.get('details')}")
        
        # Here you would trigger LLM analysis
        
        return jsonify({
            'status': 'attack_logged',
            'timestamp': attack_data['server_timestamp']
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/stats', methods=['GET'])
def get_stats():
    """Get server statistics"""
    if not received_data:
        return jsonify({'message': 'No data received yet'}), 200
    
    # Calculate statistics
    speeds = [d.get('speed', 0) for d in received_data]
    
    stats = {
        'total_messages': len(received_data),
        'unique_vehicles': len(set(d.get('vehicle_id') for d in received_data)),
        'average_speed': sum(speeds) / len(speeds) if speeds else 0,
        'max_speed': max(speeds) if speeds else 0,
        'min_speed': min(speeds) if speeds else 0,
        'last_update': received_data[-1].get('server_timestamp')
    }
    
    return jsonify(stats), 200

def detect_anomalies(data):
    """
    Basic anomaly detection
    Returns list of detected anomalies
    """
    anomalies = []
    
    speed = data.get('speed', 0)
    if speed > 120:
        anomalies.append({
            'type': 'excessive_speed',
            'severity': 'high',
            'value': speed,
            'threshold': 120
        })
    elif speed < 0:
        anomalies.append({
            'type': 'invalid_speed',
            'severity': 'critical',
            'value': speed
        })
    
    return anomalies

if __name__ == '__main__':
    # Configuration from environment variables
    FOG_HOST = os.getenv('FOG_SERVER_HOST', '0.0.0.0')
    FOG_PORT = int(os.getenv('FOG_SERVER_PORT', '8080'))
    DEBUG = os.getenv('FLASK_ENV', 'development') == 'development'
    
    print(f"{Fore.MAGENTA}{'='*60}")
    print(f"{Fore.MAGENTA}       FLASK FOG NODE SERVER")
    print(f"{Fore.MAGENTA}{'='*60}\n")
    
    # Run server
    # host='0.0.0.0' allows connections from any IP
    # debug=True for development (disable in production)
    app.run(host=FOG_HOST, port=FOG_PORT, debug=DEBUG)