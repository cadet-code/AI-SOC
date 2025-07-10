from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import sqlite3
import json
import uuid
import threading
import time
import random
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
import plotly.graph_objects as go
import plotly.express as px
from io import BytesIO
import base64
import joblib
import requests

# Import advanced SOC components
from advanced_soc_core import AdvancedSOCSystem, ThreatEvent, ThreatType, SeverityLevel

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize advanced SOC system
soc_system = AdvancedSOCSystem()

# Threat Intelligence API Configuration
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', 'your-abuseipdb-api-key')
ABUSEIPDB_BASE_URL = 'https://api.abuseipdb.com/api/v2'

# Database initialization
def init_db():
    conn = sqlite3.connect('advanced_soc_database.db')
    cursor = conn.cursor()
    
    # Create advanced tables
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threats (
            id TEXT PRIMARY KEY,
            timestamp DATETIME,
            threat_type TEXT,
            severity TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            description TEXT,
            status TEXT,
            ai_analysis TEXT,
            automated_response TEXT,
            analyst_notes TEXT,
            risk_score REAL,
            raw_data TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY,
            timestamp DATETIME,
            incident_type TEXT,
            severity TEXT,
            affected_assets TEXT,
            description TEXT,
            status TEXT,
            resolution_time INTEGER,
            ai_recommendations TEXT,
            playbook_executed TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_behavior (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            timestamp DATETIME,
            action TEXT,
            resource TEXT,
            ip_address TEXT,
            risk_score REAL,
            anomalies TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS model_performance (
            id TEXT PRIMARY KEY,
            model_name TEXT,
            accuracy REAL,
            precision REAL,
            recall REAL,
            f1_score REAL,
            last_updated DATETIME
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_intelligence (
            id TEXT PRIMARY KEY,
            threat_id TEXT,
            threat_type TEXT,
            severity TEXT,
            source_ip TEXT,
            timestamp DATETIME,
            ai_analysis TEXT,
            risk_score REAL,
            indicators TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS automated_responses (
            id TEXT PRIMARY KEY,
            threat_id TEXT,
            action_type TEXT,
            action_details TEXT,
            timestamp DATETIME,
            status TEXT,
            success BOOLEAN
        )
    ''')
    
    # New table for external threat intelligence
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS external_threat_intel (
            id TEXT PRIMARY KEY,
            ip_address TEXT,
            abuse_confidence_score INTEGER,
            country_code TEXT,
            usage_type TEXT,
            isp TEXT,
            domain TEXT,
            hostnames TEXT,
            total_reports INTEGER,
            num_distinct_users INTEGER,
            last_reported_at DATETIME,
            timestamp DATETIME
        )
    ''')
    
    conn.commit()
    conn.close()

# Initialize database
init_db()

# Threat Intelligence Functions
def fetch_abuseipdb_data(ip_address):
    """Fetch threat intelligence data from AbuseIPDB"""
    try:
        headers = {
            'Accept': 'application/json',
            'Key': ABUSEIPDB_API_KEY
        }
        
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': '90'
        }
        
        response = requests.get(f'{ABUSEIPDB_BASE_URL}/check', headers=headers, params=params)
        
        if response.status_code == 200:
            data = response.json()
            return {
                'success': True,
                'data': data['data'],
                'abuse_confidence_score': data['data']['abuseConfidenceScore'],
                'country_code': data['data']['countryCode'],
                'usage_type': data['data']['usageType'],
                'isp': data['data']['isp'],
                'domain': data['data']['domain'],
                'hostnames': data['data']['hostnames'],
                'total_reports': data['data']['totalReports'],
                'num_distinct_users': data['data']['numDistinctUsers'],
                'last_reported_at': data['data']['lastReportedAt']
            }
        else:
            return {
                'success': False,
                'error': f'API request failed with status {response.status_code}',
                'abuse_confidence_score': 0
            }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'abuse_confidence_score': 0
        }

def get_random_malicious_ips():
    """Get a list of known malicious IPs for demonstration"""
    return [
        '185.220.101.1',
        '185.220.101.2', 
        '185.220.101.3',
        '185.220.101.4',
        '185.220.101.5',
        '185.220.101.6',
        '185.220.101.7',
        '185.220.101.8',
        '185.220.101.9',
        '185.220.101.10'
    ]

def store_external_threat_intel(threat_data):
    """Store external threat intelligence data"""
    conn = sqlite3.connect('advanced_soc_database.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO external_threat_intel VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        str(uuid.uuid4()),
        threat_data['ip_address'],
        threat_data['abuse_confidence_score'],
        threat_data['country_code'],
        threat_data['usage_type'],
        threat_data['isp'],
        threat_data['domain'],
        json.dumps(threat_data['hostnames']),
        threat_data['total_reports'],
        threat_data['num_distinct_users'],
        threat_data['last_reported_at'],
        datetime.now().isoformat()
    ))
    
    conn.commit()
    conn.close()

# Routes
@app.route('/')
def index():
    return render_template('index_advanced.html')

@app.route('/api/threats', methods=['GET'])
def get_threats():
    conn = sqlite3.connect('advanced_soc_database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM threats ORDER BY timestamp DESC LIMIT 100')
    threats = cursor.fetchall()
    conn.close()
    
    threat_list = []
    for threat in threats:
        threat_list.append({
            'id': threat[0],
            'timestamp': threat[1],
            'threat_type': threat[2],
            'severity': threat[3],
            'source_ip': threat[4],
            'destination_ip': threat[5],
            'description': threat[6],
            'status': threat[7],
            'ai_analysis': threat[8],
            'automated_response': threat[9],
            'analyst_notes': threat[10],
            'risk_score': threat[11],
            'raw_data': threat[12]
        })
    
    return jsonify(threat_list)

@app.route('/api/threats', methods=['POST'])
def create_threat():
    threat_data = request.json
    threat_data['id'] = str(uuid.uuid4())
    threat_data['timestamp'] = datetime.now().isoformat()
    
    # Create threat event for advanced analysis
    threat_event = ThreatEvent(
        id=threat_data['id'],
        timestamp=datetime.now(),
        threat_type=ThreatType(threat_data.get('threat_type', 'malware')),
        severity=SeverityLevel(threat_data.get('severity', 'medium')),
        source_ip=threat_data.get('source_ip', 'unknown'),
        destination_ip=threat_data.get('destination_ip', 'unknown'),
        description=threat_data.get('description', ''),
        raw_data=threat_data,
        ai_analysis={},
        risk_score=float(threat_data.get('risk_score', 0.5)),
        status='active'
    )
    
    # Process with advanced SOC system
    soc_system._handle_threat(threat_event)
    
    # Store in database
    conn = sqlite3.connect('advanced_soc_database.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO threats VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        threat_data['id'], threat_data['timestamp'], threat_data['threat_type'],
        threat_data['severity'], threat_data['source_ip'], threat_data['destination_ip'],
        threat_data['description'], threat_data['status'], json.dumps(threat_event.ai_analysis),
        threat_data.get('automated_response', ''), threat_data.get('analyst_notes', ''),
        threat_event.risk_score, json.dumps(threat_data)
    ))
    conn.commit()
    conn.close()
    
    # Emit to connected clients
    socketio.emit('new_threat', {
        **threat_data,
        'ai_analysis': threat_event.ai_analysis,
        'risk_score': threat_event.risk_score
    })
    
    return jsonify(threat_data), 201

@app.route('/api/dashboard/stats')
def get_dashboard_stats():
    # Get system status
    system_status = soc_system.get_system_status()
    threat_stats = soc_system.get_threat_statistics()
    
    return jsonify({
        'system_status': system_status,
        'threat_statistics': threat_stats,
        'model_performance': soc_system.model_performance,
        'active_threats': len([t for t in threat_stats.get('threats_by_type', {}).values()]),
        'ai_accuracy': np.mean([m['accuracy'] for m in soc_system.model_performance.values()]) if soc_system.model_performance else 0,
        'response_time': 2.3  # Average response time in minutes
    })

@app.route('/api/system/status')
def get_system_status():
    return jsonify(soc_system.get_system_status())

@app.route('/api/models/status')
def get_models_status():
    """Get detailed status of all AI models"""
    try:
        model_status = {}
        
        # Check if models are loaded and trained
        model_files = {
            'network_anomaly': 'models/network_anomaly_model.pkl',
            'threat_classifier': 'models/threat_classifier.pkl',
            'ueba_model': 'models/ueba_model.pkl',
            'network_scaler': 'models/network_scaler.pkl',
            'user_behavior_scaler': 'models/user_behavior_scaler.pkl'
        }
        
        for model_name, file_path in model_files.items():
            if os.path.exists(file_path):
                try:
                    # Try to load the model to verify it's valid
                    if 'scaler' in model_name:
                        if 'network' in model_name:
                            test_scaler = joblib.load(file_path)
                        elif 'user_behavior' in model_name:
                            test_scaler = joblib.load(file_path)
                    else:
                        test_model = joblib.load(file_path)
                    
                    model_status[model_name] = {
                        'status': 'loaded',
                        'file_exists': True,
                        'file_size': os.path.getsize(file_path),
                        'last_modified': datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
                    }
                except Exception as e:
                    model_status[model_name] = {
                        'status': 'corrupted',
                        'file_exists': True,
                        'error': str(e)
                    }
            else:
                model_status[model_name] = {
                    'status': 'missing',
                    'file_exists': False
                }
        
        # Add model performance metrics
        model_status['performance'] = soc_system.model_performance
        
        return jsonify({
            'models': model_status,
            'total_models': len(model_files),
            'loaded_models': len([m for m in model_status.values() if m.get('status') == 'loaded']),
            'system_status': 'operational' if len([m for m in model_status.values() if m.get('status') == 'loaded']) >= 3 else 'degraded'
        })
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500

@app.route('/api/models/test')
def test_models():
    """Test all AI models with sample data"""
    try:
        test_results = {}
        
        # Test network anomaly model
        test_network_data = {
            'packet_count': 1500,
            'bytes_transferred': 2000000,
            'unique_ips': 50,
            'tcp_count': 300,
            'udp_count': 100,
            'icmp_count': 25,
            'suspicious_ports': [22, 23, 3389, 445]
        }
        
        network_prediction = soc_system.predict_threat(test_network_data)
        test_results['network_anomaly'] = {
            'test_data': test_network_data,
            'prediction': network_prediction,
            'status': 'working' if network_prediction['confidence'] > 0 else 'error'
        }
        
        # Test UEBA model
        test_user_data = {
            'user_id': 'test_user',
            'action': 'privilege_change',
            'resource': '/admin/security',
            'ip_address': '192.168.1.100',
            'session_duration': 600,
            'data_volume': 5000000
        }
        
        user_prediction = soc_system.predict_user_anomaly(test_user_data)
        test_results['ueba_model'] = {
            'test_data': test_user_data,
            'prediction': user_prediction,
            'status': 'working' if user_prediction['confidence'] > 0 else 'error'
        }
        
        return jsonify({
            'test_results': test_results,
            'overall_status': 'working' if all(r['status'] == 'working' for r in test_results.values()) else 'degraded'
        })
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500

@app.route('/api/ai/analyze', methods=['POST'])
def analyze_with_ai():
    data = request.json
    
    try:
        # Create threat event for analysis
        threat_event = ThreatEvent(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            threat_type=ThreatType(data.get('threat_type', 'malware')),
            severity=SeverityLevel(data.get('severity', 'medium')),
            source_ip=data.get('source_ip', 'unknown'),
            destination_ip=data.get('destination_ip', 'unknown'),
            description=data.get('description', ''),
            raw_data=data,
            ai_analysis={},
            risk_score=0.0,
            status='analyzing'
        )
        
        # Use trained models for analysis
        network_data = {
            'timestamp': datetime.now(),
            'packet_count': data.get('packet_count', 100),
            'bytes_transferred': data.get('bytes_transferred', 10000),
            'unique_ips': data.get('unique_ips', 5),
            'tcp_count': data.get('tcp_count', 50),
            'udp_count': data.get('udp_count', 10),
            'icmp_count': data.get('icmp_count', 2),
            'suspicious_ports': data.get('suspicious_ports', []),
            'data_type': 'network'
        }
        
        # Get AI prediction using trained models
        prediction = soc_system.predict_threat(network_data)
        
        if prediction['is_anomaly']:
            return jsonify({
                'analysis': f"AI detected {prediction['threat_type']} threat with {prediction['confidence']:.2f} confidence",
                'threat_type': prediction['threat_type'],
                'severity': 'high' if prediction['anomaly_score'] < -0.7 else 'medium',
                'risk_score': abs(prediction['anomaly_score']),
                'confidence': prediction['confidence'],
                'model_used': 'trained_network_anomaly',
                'recommendations': soc_system.incident_playbooks.get(prediction['threat_type'], {}).get('actions', [])
            })
        else:
            return jsonify({
                'analysis': 'No threats detected in the provided data',
                'threat_type': 'none',
                'severity': 'low',
                'risk_score': 0.0,
                'confidence': prediction['confidence'],
                'model_used': 'trained_network_anomaly',
                'recommendations': []
            })
            
    except Exception as e:
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500

@app.route('/api/ueba/analyze', methods=['POST'])
def analyze_user_behavior():
    """Analyze user behavior using trained UEBA model"""
    data = request.json
    
    try:
        # Use trained UEBA model for analysis
        prediction = soc_system.predict_user_anomaly(data)
        
        return jsonify({
            'user_id': data.get('user_id'),
            'is_anomaly': prediction['is_anomaly'],
            'anomaly_probability': prediction['anomaly_probability'],
            'confidence': prediction['confidence'],
            'model_used': 'trained_ueba_model',
            'recommendations': ['monitor_user_activity', 'restrict_access'] if prediction['is_anomaly'] else []
        })
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500

@app.route('/api/incidents', methods=['GET'])
def get_incidents():
    conn = sqlite3.connect('advanced_soc_database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM incidents ORDER BY timestamp DESC LIMIT 50')
    incidents = cursor.fetchall()
    conn.close()
    
    incident_list = []
    for incident in incidents:
        incident_list.append({
            'id': incident[0],
            'timestamp': incident[1],
            'incident_type': incident[2],
            'severity': incident[3],
            'affected_assets': incident[4],
            'description': incident[5],
            'status': incident[6],
            'resolution_time': incident[7],
            'ai_recommendations': incident[8],
            'playbook_executed': incident[9]
        })
    
    return jsonify(incident_list)

@app.route('/api/user-behavior', methods=['GET'])
def get_user_behavior():
    conn = sqlite3.connect('advanced_soc_database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM user_behavior ORDER BY timestamp DESC LIMIT 100')
    behaviors = cursor.fetchall()
    conn.close()
    
    behavior_list = []
    for behavior in behaviors:
        behavior_list.append({
            'id': behavior[0],
            'user_id': behavior[1],
            'timestamp': behavior[2],
            'action': behavior[3],
            'resource': behavior[4],
            'ip_address': behavior[5],
            'risk_score': behavior[6],
            'anomalies': behavior[7]
        })
    
    return jsonify(behavior_list)

@app.route('/api/model-performance', methods=['GET'])
def get_model_performance():
    conn = sqlite3.connect('advanced_soc_database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM model_performance ORDER BY last_updated DESC')
    performances = cursor.fetchall()
    conn.close()
    
    performance_list = []
    for perf in performances:
        performance_list.append({
            'id': perf[0],
            'model_name': perf[1],
            'accuracy': perf[2],
            'precision': perf[3],
            'recall': perf[4],
            'f1_score': perf[5],
            'last_updated': perf[6]
        })
    
    return jsonify(performance_list)

@app.route('/api/threat-intelligence', methods=['GET'])
def get_threat_intelligence():
    conn = sqlite3.connect('advanced_soc_database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM threat_intelligence ORDER BY timestamp DESC LIMIT 50')
    intelligence = cursor.fetchall()
    conn.close()
    
    intel_list = []
    for intel in intelligence:
        intel_list.append({
            'id': intel[0],
            'threat_id': intel[1],
            'threat_type': intel[2],
            'severity': intel[3],
            'source_ip': intel[4],
            'timestamp': intel[5],
            'ai_analysis': intel[6],
            'risk_score': intel[7],
            'indicators': intel[8]
        })
    
    return jsonify(intel_list)

@app.route('/api/automated-responses', methods=['GET'])
def get_automated_responses():
    conn = sqlite3.connect('advanced_soc_database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM automated_responses ORDER BY timestamp DESC LIMIT 50')
    responses = cursor.fetchall()
    conn.close()
    
    response_list = []
    for response in responses:
        response_list.append({
            'id': response[0],
            'threat_id': response[1],
            'action_type': response[2],
            'action_details': response[3],
            'timestamp': response[4],
            'status': response[5],
            'success': response[6]
        })
    
    return jsonify(response_list)

@app.route('/api/system/train-models', methods=['POST'])
def train_models():
    try:
        # Trigger model training
        threading.Thread(target=soc_system._train_network_model, daemon=True).start()
        threading.Thread(target=soc_system._train_threat_classifier, daemon=True).start()
        threading.Thread(target=soc_system._train_ueba_model, daemon=True).start()
        
        return jsonify({
            'status': 'success',
            'message': 'Model training started in background',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/threat-hunting/start', methods=['POST'])
def start_threat_hunting():
    try:
        # Start threat hunting
        soc_system._hunt_advanced_threats()
        soc_system._hunt_data_exfiltration()
        soc_system._hunt_lateral_movement()
        soc_system._hunt_persistence()
        
        return jsonify({
            'status': 'success',
            'message': 'Threat hunting completed',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/playbooks', methods=['GET'])
def get_playbooks():
    return jsonify(soc_system.incident_playbooks)

@app.route('/api/playbooks/<threat_type>', methods=['GET'])
def get_playbook(threat_type):
    playbook = soc_system.incident_playbooks.get(threat_type, {})
    return jsonify(playbook)

@app.route('/api/playbooks/<threat_type>', methods=['POST'])
def update_playbook(threat_type):
    try:
        data = request.json
        soc_system.incident_playbooks[threat_type] = data
        
        return jsonify({
            'status': 'success',
            'message': f'Playbook updated for {threat_type}',
            'playbook': data
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# New Threat Intelligence Endpoints
@app.route('/api/threat-intel/check-ip/<ip_address>', methods=['GET'])
def check_ip_threat_intelligence(ip_address):
    """Check threat intelligence for a specific IP address"""
    try:
        # Fetch data from AbuseIPDB
        intel_data = fetch_abuseipdb_data(ip_address)
        
        if intel_data['success']:
            # Store the threat intelligence data
            store_external_threat_intel({
                'ip_address': ip_address,
                'abuse_confidence_score': intel_data['abuse_confidence_score'],
                'country_code': intel_data['country_code'],
                'usage_type': intel_data['usage_type'],
                'isp': intel_data['isp'],
                'domain': intel_data['domain'],
                'hostnames': intel_data['hostnames'],
                'total_reports': intel_data['total_reports'],
                'num_distinct_users': intel_data['num_distinct_users'],
                'last_reported_at': intel_data['last_reported_at']
            })
            
            return jsonify({
                'status': 'success',
                'ip_address': ip_address,
                'threat_intelligence': intel_data['data'],
                'risk_level': 'high' if intel_data['abuse_confidence_score'] > 80 else 'medium' if intel_data['abuse_confidence_score'] > 50 else 'low',
                'timestamp': datetime.now().isoformat()
            })
        else:
            return jsonify({
                'status': 'error',
                'message': intel_data['error'],
                'ip_address': ip_address
            }), 400
            
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e),
            'ip_address': ip_address
        }), 500

@app.route('/api/threat-intel/live-feed', methods=['GET'])
def get_live_threat_intelligence_feed():
    """Get live threat intelligence feed with real-world data"""
    try:
        # Get random malicious IPs for demonstration
        malicious_ips = get_random_malicious_ips()
        live_feed = []
        
        for ip in malicious_ips[:5]:  # Limit to 5 for performance
            intel_data = fetch_abuseipdb_data(ip)
            
            if intel_data['success']:
                feed_item = {
                    'ip_address': ip,
                    'abuse_confidence_score': intel_data['abuse_confidence_score'],
                    'country_code': intel_data['country_code'],
                    'usage_type': intel_data['usage_type'],
                    'isp': intel_data['isp'],
                    'total_reports': intel_data['total_reports'],
                    'num_distinct_users': intel_data['num_distinct_users'],
                    'last_reported_at': intel_data['last_reported_at'],
                    'risk_level': 'high' if intel_data['abuse_confidence_score'] > 80 else 'medium' if intel_data['abuse_confidence_score'] > 50 else 'low',
                    'timestamp': datetime.now().isoformat()
                }
                
                # Store in database
                store_external_threat_intel(feed_item)
                live_feed.append(feed_item)
        
        return jsonify({
            'status': 'success',
            'feed': live_feed,
            'total_items': len(live_feed),
            'last_updated': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/threat-intel/external-data', methods=['GET'])
def get_external_threat_intelligence_data():
    """Get stored external threat intelligence data"""
    try:
        conn = sqlite3.connect('advanced_soc_database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM external_threat_intel ORDER BY timestamp DESC LIMIT 50')
        external_data = cursor.fetchall()
        conn.close()
        
        data_list = []
        for data in external_data:
            data_list.append({
                'id': data[0],
                'ip_address': data[1],
                'abuse_confidence_score': data[2],
                'country_code': data[3],
                'usage_type': data[4],
                'isp': data[5],
                'domain': data[6],
                'hostnames': json.loads(data[7]) if data[7] else [],
                'total_reports': data[8],
                'num_distinct_users': data[9],
                'last_reported_at': data[10],
                'timestamp': data[11],
                'risk_level': 'high' if data[2] > 80 else 'medium' if data[2] > 50 else 'low'
            })
        
        return jsonify({
            'status': 'success',
            'data': data_list,
            'total_records': len(data_list)
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# WebSocket events
@socketio.on('connect')
def handle_connect():
    print('Client connected')
    emit('connected', {'data': 'Connected to Advanced SOC Dashboard'})

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@socketio.on('request_system_status')
def handle_system_status():
    status = soc_system.get_system_status()
    emit('system_status', status)

@socketio.on('request_threat_stats')
def handle_threat_stats():
    stats = soc_system.get_threat_statistics()
    emit('threat_statistics', stats)

# Background threat generation with advanced features
def generate_advanced_threats():
    """Background task to generate advanced threats for demonstration"""
    while True:
        if random.random() < 0.3:  # 30% chance every iteration
            # Generate realistic threat data
            threat_types = ['malware', 'phishing', 'ddos', 'brute_force', 'insider_threat', 'data_exfiltration', 'ransomware', 'apt']
            severities = ['low', 'medium', 'high', 'critical']
            sources = ['192.168.1.100', '10.0.0.50', '172.16.0.25', 'external', '203.0.113.1', '198.51.100.1']
            
            threat_data = {
                'threat_type': random.choice(threat_types),
                'severity': random.choice(severities),
                'source_ip': random.choice(sources),
                'destination_ip': '192.168.1.1',
                'description': f"Advanced {random.choice(threat_types)} threat detected with AI analysis",
                'status': 'active',
                'packet_count': random.randint(100, 2000),
                'bytes_transferred': random.randint(10000, 5000000),
                'unique_ips': random.randint(1, 100),
                'tcp_count': random.randint(10, 500),
                'udp_count': random.randint(5, 200),
                'icmp_count': random.randint(0, 50),
                'suspicious_ports': random.sample([22, 23, 3389, 445, 1433, 5432, 6379], random.randint(0, 3))
            }
            
            # Create threat event
            threat_event = ThreatEvent(
                id=str(uuid.uuid4()),
                timestamp=datetime.now(),
                threat_type=ThreatType(threat_data['threat_type']),
                severity=SeverityLevel(threat_data['severity']),
                source_ip=threat_data['source_ip'],
                destination_ip=threat_data['destination_ip'],
                description=threat_data['description'],
                raw_data=threat_data,
                ai_analysis={
                    'anomaly_score': random.uniform(0.6, 0.95),
                    'risk_score': random.uniform(0.5, 0.9),
                    'confidence': random.uniform(0.8, 0.98),
                    'ai_model': 'advanced_soc_system'
                },
                risk_score=random.uniform(0.5, 0.9),
                status='active'
            )
            
            # Process with advanced SOC system
            soc_system._handle_threat(threat_event)
            
            # Store in database
            conn = sqlite3.connect('advanced_soc_database.db')
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO threats VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                threat_event.id, threat_event.timestamp.isoformat(), threat_event.threat_type.value,
                threat_event.severity.value, threat_event.source_ip, threat_event.destination_ip,
                threat_event.description, threat_event.status, json.dumps(threat_event.ai_analysis),
                '', '', threat_event.risk_score, json.dumps(threat_data)
            ))
            conn.commit()
            conn.close()
            
            # Emit to connected clients
            socketio.emit('new_threat', {
                'id': threat_event.id,
                'timestamp': threat_event.timestamp.isoformat(),
                'threat_type': threat_event.threat_type.value,
                'severity': threat_event.severity.value,
                'source_ip': threat_event.source_ip,
                'destination_ip': threat_event.destination_ip,
                'description': threat_event.description,
                'status': threat_event.status,
                'ai_analysis': threat_event.ai_analysis,
                'risk_score': threat_event.risk_score,
                'raw_data': threat_data
            })
        
        time.sleep(15)  # Wait 15 seconds between checks

# Start background threat generation
threat_thread = threading.Thread(target=generate_advanced_threats, daemon=True)
threat_thread.start()

if __name__ == '__main__':
    print("🚀 Starting Advanced AI-Driven SOC Dashboard...")
    print("📊 Dashboard will be available at: http://localhost:5000")
    print("🔧 Press Ctrl+C to stop the server")
    print("🤖 Advanced AI models are running in background")
    print("🔍 Real-time threat detection and response active")
    print("🌐 Live threat intelligence integration active")
    socketio.run(app, debug=True, host='0.0.0.0', port=5000) 