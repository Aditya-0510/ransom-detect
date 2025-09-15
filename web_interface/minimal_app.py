from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import json
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
import threading
import time
import logging

# Add the src directory to the path to import our modules
current_dir = Path(__file__).parent  # web_interface directory
project_root = current_dir.parent    # project root directory
src_dir = project_root / "src"       # src directory
sys.path.insert(0, str(src_dir))

# Import our modules with error handling
try:
    from config import config
    WEB_HOST = config.WEB_CONFIG['host']
    WEB_PORT = config.WEB_CONFIG['port']
    WEB_DEBUG = config.WEB_CONFIG['debug']
    SECRET_KEY = config.WEB_CONFIG['secret_key']
    print("Config loaded successfully")
except ImportError as e:
    print(f"Warning: Could not import config: {e}")
    WEB_HOST = '127.0.0.1'
    WEB_PORT = 5000
    WEB_DEBUG = True
    SECRET_KEY = 'your-secret-key-change-this'

try:
    from main_detector import RansomwareDetectionSystem
    print("✓ Main detector imported successfully")
    DETECTOR_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Could not import main detector: {e}")
    DETECTOR_AVAILABLE = False

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY

# Initialize SocketIO for real-time updates
socketio = SocketIO(app, cors_allowed_origins="*")

# Global detection system instance
detection_system = None
system_status = {
    'running': False,
    'error': None,
    'initialization_progress': 'Not started'
}

class WebInterface:
    """Web interface controller"""
    
    def __init__(self):
        self.last_status_update = None
        self.update_thread = None
        self.running = False
        
    def start_background_updates(self):
        """Start background thread for real-time updates"""
        if not self.running:
            self.running = True
            self.update_thread = threading.Thread(target=self._update_loop)
            self.update_thread.daemon = True
            self.update_thread.start()
            print("✓ Background updates started")
    
    def stop_background_updates(self):
        """Stop background updates"""
        self.running = False
        if self.update_thread:
            self.update_thread.join(timeout=5)
        print("✓ Background updates stopped")
    
    def _update_loop(self):
        """Background loop for sending updates to connected clients"""
        while self.running:
            try:
                if detection_system and detection_system.running:
                    # Get system status
                    status = detection_system.get_system_status()
                    
                    # Emit status update to all connected clients
                    socketio.emit('status_update', status)
                    
                    # Check for recent alerts
                    if hasattr(detection_system, 'response_orchestrator') and detection_system.response_orchestrator:
                        try:
                            recent_alerts = detection_system.response_orchestrator.response_system.alert_manager.get_recent_alerts(5)
                            if recent_alerts:
                                socketio.emit('alert_update', {'alerts': recent_alerts})
                        except Exception as e:
                            print(f"Error getting alerts: {e}")
                
                time.sleep(5)  # Update every 5 seconds
                
            except Exception as e:
                print(f"Error in update loop: {e}")
                time.sleep(10)

# Initialize web interface
web_interface = WebInterface()

# Route definitions
@app.route('/')
def dashboard():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/status')
def get_status():
    """Get system status API"""
    global system_status
    
    if not DETECTOR_AVAILABLE:
        return jsonify({
            'running': False,
            'error': 'Detection system not available - import failed',
            'statistics': {
                'detections_performed': 0,
                'alerts_triggered': 0,
                'models_trained': 0
            },
            'uptime_seconds': 0
        })
    
    if not detection_system:
        return jsonify({
            'running': False,
            'error': 'Detection system not initialized',
            'initialization_progress': system_status.get('initialization_progress', 'Not started'),
            'statistics': {
                'detections_performed': 0,
                'alerts_triggered': 0,
                'models_trained': 0
            },
            'uptime_seconds': 0
        })
    
    try:
        status = detection_system.get_system_status()
        status['initialization_progress'] = system_status.get('initialization_progress', 'Complete')
        return jsonify(status)
    except Exception as e:
        return jsonify({
            'running': False,
            'error': str(e),
            'statistics': {
                'detections_performed': 0,
                'alerts_triggered': 0,
                'models_trained': 0
            },
            'uptime_seconds': 0
        })

@app.route('/api/alerts')
def get_alerts():
    """Get recent alerts API"""
    try:
        if not detection_system:
            return jsonify({'alerts': []})
        
        if hasattr(detection_system, 'response_orchestrator') and detection_system.response_orchestrator:
            alerts = detection_system.response_orchestrator.response_system.alert_manager.get_recent_alerts(50)
            return jsonify({'alerts': alerts})
        else:
            return jsonify({'alerts': []})
        
    except Exception as e:
        print(f"Error getting alerts: {e}")
        return jsonify({'alerts': [], 'error': str(e)})

@app.route('/api/detection_history')
def get_detection_history():
    """Get detection history API"""
    try:
        if not detection_system or not hasattr(detection_system, 'real_time_detector') or not detection_system.real_time_detector:
            return jsonify({'detections': []})
        
        history = detection_system.real_time_detector.detection_history[-100:]
        return jsonify({'detections': history})
        
    except Exception as e:
        print(f"Error getting detection history: {e}")
        return jsonify({'detections': [], 'error': str(e)})

@app.route('/api/feature_importance')
def get_feature_importance():
    """Get feature importance API"""
    try:
        if not detection_system or not detection_system.ml_detector.is_trained:
            return jsonify({'error': 'Model not trained'})
        
        importance = detection_system.get_feature_importance()
        return jsonify(importance)
        
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/manual_detection', methods=['POST'])
def manual_detection():
    """Trigger manual detection API"""
    try:
        if not detection_system:
            return jsonify({'error': 'Detection system not initialized'})
        
        data = request.get_json()
        time_window = data.get('time_window_minutes', 5)
        
        result = detection_system.manual_detection(time_window)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/system_control', methods=['POST'])
def system_control():
    """Control system operations API"""
    global detection_system, system_status
    
    try:
        data = request.get_json()
        action = data.get('action')
        
        if not DETECTOR_AVAILABLE:
            return jsonify({
                'success': False, 
                'error': 'Detection system not available - import failed'
            })
        
        if action == 'start':
            if detection_system and detection_system.running:
                return jsonify({
                    'success': False, 
                    'message': 'System is already running'
                })
            
            # Start system in background thread to avoid blocking
            def start_system():
                global detection_system, system_status
                try:
                    system_status['initialization_progress'] = 'Creating detection system...'
                    detection_system = RansomwareDetectionSystem(
                        model_type='ensemble',
                        auto_train=True,
                        enable_response=True
                    )
                    
                    system_status['initialization_progress'] = 'Starting detection system...'
                    detection_system.start()
                    
                    system_status['initialization_progress'] = 'Starting background updates...'
                    web_interface.start_background_updates()
                    
                    system_status['initialization_progress'] = 'Complete'
                    system_status['error'] = None
                    
                except Exception as e:
                    system_status['error'] = str(e)
                    system_status['initialization_progress'] = f'Failed: {e}'
                    print(f"Error starting system: {e}")
            
            start_thread = threading.Thread(target=start_system)
            start_thread.daemon = True
            start_thread.start()
            
            return jsonify({
                'success': True, 
                'message': 'System startup initiated - check status for progress'
            })
        
        elif action == 'stop':
            if detection_system:
                try:
                    detection_system.stop()
                    web_interface.stop_background_updates()
                    system_status['initialization_progress'] = 'Stopped'
                    return jsonify({'success': True, 'message': 'System stopped'})
                except Exception as e:
                    return jsonify({'success': False, 'error': str(e)})
            else:
                return jsonify({'success': True, 'message': 'System was not running'})
        
        elif action == 'restart':
            # Stop first
            if detection_system:
                try:
                    detection_system.stop()
                    web_interface.stop_background_updates()
                except Exception as e:
                    print(f"Error stopping system for restart: {e}")
            
            # Wait a moment
            time.sleep(2)
            
            # Start again
            def restart_system():
                global detection_system, system_status
                try:
                    system_status['initialization_progress'] = 'Restarting...'
                    detection_system = RansomwareDetectionSystem(
                        model_type='ensemble',
                        auto_train=False,  # Skip training on restart
                        enable_response=True
                    )
                    detection_system.start()
                    web_interface.start_background_updates()
                    system_status['initialization_progress'] = 'Complete'
                    system_status['error'] = None
                except Exception as e:
                    system_status['error'] = str(e)
                    system_status['initialization_progress'] = f'Restart failed: {e}'
            
            restart_thread = threading.Thread(target=restart_system)
            restart_thread.daemon = True
            restart_thread.start()
            
            return jsonify({'success': True, 'message': 'System restart initiated'})
        
        else:
            return jsonify({'success': False, 'error': f'Unknown action: {action}'})
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/response_action', methods=['POST'])
def response_action():
    """Execute response action API"""
    try:
        data = request.get_json()
        action = data.get('action')
        parameters = data.get('parameters', {})
        
        if not detection_system or not hasattr(detection_system, 'response_orchestrator') or not detection_system.response_orchestrator:
            return jsonify({'error': 'Response system not available'})
        
        result = detection_system.response_orchestrator.response_system.manual_response_action(action, parameters)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)})

# Socket.IO events
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    status_msg = 'Connected to Ransomware Detection System'
    if not DETECTOR_AVAILABLE:
        status_msg += ' (Detection system not available)'
    elif not detection_system:
        status_msg += ' (Detection system not started)'
    
    emit('connected', {'message': status_msg})

@socketio.on('request_status')
def handle_status_request():
    """Handle status request from client"""
    if detection_system:
        try:
            status = detection_system.get_system_status()
            emit('status_update', status)
        except Exception as e:
            emit('status_update', {
                'running': False, 
                'error': str(e),
                'statistics': {'detections_performed': 0, 'alerts_triggered': 0, 'models_trained': 0}
            })
    else:
        emit('status_update', {
            'running': False, 
            'error': 'System not initialized',
            'statistics': {'detections_performed': 0, 'alerts_triggered': 0, 'models_trained': 0}
        })

def create_templates():
    """Create HTML templates for the web interface"""
    
    templates_dir = Path(__file__).parent / 'templates'
    templates_dir.mkdir(exist_ok=True)
    
    dashboard_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ransomware Detection System</title>
    <script src="https://cdn.socket.io/4.5.0/socket.io.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            min-height: 100vh;
        }
        
        .header {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-bottom: 1px solid rgba(255, 255, 255, 0.2);
            padding: 1rem 2rem;
            margin-bottom: 2rem;
        }
        
        .header h1 {
            color: white;
            font-size: 2.5rem;
            font-weight: 300;
            text-align: center;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 0 2rem;
        }
        
        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 2rem;
            margin-bottom: 2rem;
        }
        
        .card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 2rem;
            box-shadow: 0 8px 32px rgba(31, 38, 135, 0.37);
            border: 1px solid rgba(255, 255, 255, 0.18);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 12px 40px rgba(31, 38, 135, 0.5);
        }
        
        .status-card {
            text-align: center;
        }
        
        .status-indicator {
            width: 80px;
            height: 80px;
            border-radius: 50%;
            margin: 0 auto 1rem;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.2rem;
            font-weight: bold;
            color: white;
            text-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }
        
        .status-running {
            background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        }
        
        .status-stopped {
            background: linear-gradient(135deg, #fa709a 0%, #fee140 100%);
        }
        
        .status-error {
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%);
        }
        
        .status-starting {
            background: linear-gradient(135deg, #ffa726 0%, #ffcc02 100%);
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 1rem;
            margin-top: 1rem;
        }
        
        .stat-item {
            background: rgba(0, 0, 0, 0.05);
            padding: 1rem;
            border-radius: 10px;
            text-align: center;
        }
        
        .stat-value {
            font-size: 2rem;
            font-weight: bold;
            color: #667eea;
        }
        
        .stat-label {
            font-size: 0.9rem;
            color: #666;
            margin-top: 0.5rem;
        }
        
        .controls {
            display: flex;
            gap: 1rem;
            justify-content: center;
            margin: 2rem 0;
            flex-wrap: wrap;
        }
        
        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 25px;
            font-size: 1rem;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-block;
            text-align: center;
            min-width: 120px;
        }
        
        .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        
        .btn-secondary {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            color: white;
        }
        
        .btn-success {
            background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
            color: white;
        }
        
        .btn:not(:disabled):hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }
        
        .alert-item {
            background: rgba(255, 107, 107, 0.1);
            border: 1px solid rgba(255, 107, 107, 0.3);
            border-radius: 10px;
            padding: 1rem;
            margin: 0.5rem 0;
        }
        
        .alert-high, .alert-critical {
            border-color: #ff6b6b;
            background: rgba(255, 107, 107, 0.1);
        }
        
        .alert-medium {
            border-color: #ffa726;
            background: rgba(255, 167, 38, 0.1);
        }
        
        .alert-low {
            border-color: #66bb6a;
            background: rgba(102, 187, 106, 0.1);
        }
        
        .chart-container {
            position: relative;
            height: 300px;
            margin-top: 1rem;
        }
        
        #alertsLog {
            max-height: 400px;
            overflow-y: auto;
        }
        
        .loading {
            text-align: center;
            padding: 2rem;
            color: #666;
        }
        
        .progress-info {
            background: rgba(255, 167, 38, 0.1);
            border: 1px solid rgba(255, 167, 38, 0.3);
            border-radius: 8px;
            padding: 10px;
            margin: 10px 0;
            font-size: 0.9rem;
        }
        
        .error-info {
            background: rgba(255, 107, 107, 0.1);
            border: 1px solid rgba(255, 107, 107, 0.3);
            border-radius: 8px;
            padding: 10px;
            margin: 10px 0;
            font-size: 0.9rem;
        }
        
        @media (max-width: 768px) {
            .dashboard-grid {
                grid-template-columns: 1fr;
            }
            
            .controls {
                flex-direction: column;
                align-items: center;
            }
            
            .btn {
                width: 200px;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Ransomware Detection System</h1>
    </div>
    
    <div class="container">
        <div class="dashboard-grid">
            <!-- System Status -->
            <div class="card status-card">
                <h3>System Status</h3>
                <div id="statusIndicator" class="status-indicator status-stopped">
                    STOP
                </div>
                <div id="statusText">Checking...</div>
                <div id="progressInfo" class="progress-info" style="display: none;"></div>
                <div id="errorInfo" class="error-info" style="display: none;"></div>
                <div class="stats-grid">
                    <div class="stat-item">
                        <div id="uptimeValue" class="stat-value">--</div>
                        <div class="stat-label">Uptime (min)</div>
                    </div>
                    <div class="stat-item">
                        <div id="detectionsValue" class="stat-value">--</div>
                        <div class="stat-label">Detections</div>
                    </div>
                    <div class="stat-item">
                        <div id="alertsValue" class="stat-value">--</div>
                        <div class="stat-label">Alerts</div>
                    </div>
                    <div class="stat-item">
                        <div id="modelsValue" class="stat-value">--</div>
                        <div class="stat-label">Models Trained</div>
                    </div>
                </div>
            </div>
            
            <!-- Recent Alerts -->
            <div class="card">
                <h3>Recent Alerts</h3>
                <div id="alertsLog">
                    <div class="loading">Loading alerts...</div>
                </div>
            </div>
            
            <!-- Detection Activity -->
            <div class="card">
                <h3>Detection Activity</h3>
                <div class="chart-container">
                    <canvas id="activityChart"></canvas>
                </div>
            </div>
            
            <!-- Feature Importance -->
            <div class="card">
                <h3>Top Risk Factors</h3>
                <div class="chart-container">
                    <canvas id="featuresChart"></canvas>
                </div>
            </div>
        </div>
        
        <!-- Control Panel -->
        <div class="card">
            <h3>Control Panel</h3>
            <div class="controls">
                <button id="startBtn" class="btn btn-success">Start System</button>
                <button id="stopBtn" class="btn btn-secondary">Stop System</button>
                <button id="restartBtn" class="btn btn-primary">Restart System</button>
                <button id="detectBtn" class="btn btn-primary">Manual Detection</button>
                <button id="refreshBtn" class="btn btn-primary">Refresh Data</button>
            </div>
        </div>
    </div>

    <script>
        // Initialize Socket.IO connection
        const socket = io();
        
        // Chart instances
        let activityChart;
        let featuresChart;
        let isSystemStarting = false;
        
        // Initialize dashboard
        document.addEventListener('DOMContentLoaded', function() {
            initializeCharts();
            loadInitialData();
            setupEventHandlers();
        });
        
        // Socket.IO event handlers
        socket.on('connect', function() {
            console.log('Connected to server');
            socket.emit('request_status');
        });
        
        socket.on('status_update', function(data) {
            updateSystemStatus(data);
        });
        
        socket.on('alert_update', function(data) {
            updateAlerts(data.alerts);
        });
        
        // Initialize charts
        function initializeCharts() {
            // Activity Chart
            const activityCtx = document.getElementById('activityChart').getContext('2d');
            activityChart = new Chart(activityCtx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Threat Probability',
                        data: [],
                        borderColor: 'rgb(255, 99, 132)',
                        backgroundColor: 'rgba(255, 99, 132, 0.1)',
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true,
                            max: 1
                        }
                    }
                }
            });
            
            // Features Chart
            const featuresCtx = document.getElementById('featuresChart').getContext('2d');
            featuresChart = new Chart(featuresCtx, {
                type: 'bar',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Importance',
                        data: [],
                        backgroundColor: [
                            'rgba(255, 99, 132, 0.8)',
                            'rgba(54, 162, 235, 0.8)',
                            'rgba(255, 205, 86, 0.8)',
                            'rgba(75, 192, 192, 0.8)',
                            'rgba(153, 102, 255, 0.8)'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    indexAxis: 'y'
                }
            });
        }
        
        // Load initial data
        function loadInitialData() {
            fetch('/api/status')
                .then(response => response.json())
                .then(data => updateSystemStatus(data))
                .catch(error => console.error('Error loading status:', error));
                
            fetch('/api/alerts')
                .then(response => response.json())
                .then(data => updateAlerts(data.alerts))
                .catch(error => console.error('Error loading alerts:', error));
                
            loadFeatureImportance();
        }
        
        // Update system status display
        function updateSystemStatus(data) {
            const indicator = document.getElementById('statusIndicator');
            const statusText = document.getElementById('statusText');
            const progressInfo = document.getElementById('progressInfo');
            const errorInfo = document.getElementById('errorInfo');
            
            // Handle progress info
            if (data.initialization_progress && data.initialization_progress !== 'Complete' && data.initialization_progress !== 'Not started') {
                progressInfo.textContent = data.initialization_progress;
                progressInfo.style.display = 'block';
            } else {
                progressInfo.style.display = 'none';
            }
            
            // Handle error info
            if (data.error) {
                errorInfo.textContent = 'Error: ' + data.error;
                errorInfo.style.display = 'block';
            } else {
                errorInfo.style.display = 'none';
            }
            
            // Update status indicator
            if (data.running) {
                indicator.className = 'status-indicator status-running';
                indicator.textContent = 'RUN';
                statusText.textContent = 'System Running';
                isSystemStarting = false;
            } else if (data.initialization_progress && data.initialization_progress.includes('...')) {
                indicator.className = 'status-indicator status-starting';
                indicator.textContent = 'INIT';
                statusText.textContent = 'System Starting...';
                isSystemStarting = true;
            } else {
                indicator.className = 'status-indicator status-stopped';
                indicator.textContent = 'STOP';
                statusText.textContent = data.error ? 'System Error' : 'System Stopped';
                isSystemStarting = false;
            }
            
            // Update button states
            updateButtonStates(data.running, isSystemStarting);
            
            // Update statistics
            const stats = data.statistics || {};
            document.getElementById('uptimeValue').textContent = 
                Math.floor((data.uptime_seconds || 0) / 60);
            document.getElementById('detectionsValue').textContent = 
                stats.detections_performed || 0;
            document.getElementById('alertsValue').textContent = 
                stats.alerts_triggered || 0;
            document.getElementById('modelsValue').textContent = 
                stats.models_trained || 0;
        }
        
        // Update button states
        function updateButtonStates(running, starting) {
            const startBtn = document.getElementById('startBtn');
            const stopBtn = document.getElementById('stopBtn');
            const restartBtn = document.getElementById('restartBtn');
            const detectBtn = document.getElementById('detectBtn');
            
            startBtn.disabled = running || starting;
            stopBtn.disabled = !running && !starting;
            restartBtn.disabled = starting;
            detectBtn.disabled = !running;
        }
        
        // Update alerts display
        function updateAlerts(alerts) {
            const alertsLog = document.getElementById('alertsLog');
            
            if (!alerts || alerts.length === 0) {
                alertsLog.innerHTML = '<div class="loading">No recent alerts</div>';
                return;
            }
            
            const alertsHtml = alerts.slice(0, 10).map(alert => {
                const severity = alert.severity || 'MEDIUM';
                const severityClass = severity.toLowerCase();
                const timestamp = new Date(alert.timestamp).toLocaleString();
                
                return `
                    <div class="alert-item alert-${severityClass}">
                        <strong>${alert.type || 'Alert'}</strong> - ${severity}
                        <br><small>${timestamp}</small>
                        <br>${JSON.stringify(alert.details || {}).substring(0, 100)}...
                    </div>
                `;
            }).join('');
            
            alertsLog.innerHTML = alertsHtml;
        }
        
        // Load feature importance
        function loadFeatureImportance() {
            fetch('/api/feature_importance')
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        console.log('Feature importance not available:', data.error);
                        return;
                    }
                    
                    // Use the first model's features
                    const firstModel = Object.keys(data)[0];
                    if (firstModel && data[firstModel]) {
                        const features = data[firstModel].features.slice(0, 5);
                        const importances = data[firstModel].importances.slice(0, 5);
                        
                        featuresChart.data.labels = features;
                        featuresChart.data.datasets[0].data = importances;
                        featuresChart.update();
                    }
                })
                .catch(error => console.error('Error loading feature importance:', error));
        }
        
        // Setup event handlers
        function setupEventHandlers() {
            document.getElementById('startBtn').addEventListener('click', function() {
                controlSystem('start');
            });
            
            document.getElementById('stopBtn').addEventListener('click', function() {
                controlSystem('stop');
            });
            
            document.getElementById('restartBtn').addEventListener('click', function() {
                controlSystem('restart');
            });
            
            document.getElementById('detectBtn').addEventListener('click', function() {
                performManualDetection();
            });
            
            document.getElementById('refreshBtn').addEventListener('click', function() {
                loadInitialData();
            });
        }
        
        // Control system
        function controlSystem(action) {
            const button = document.querySelector(`#${action}Btn`);
            const originalText = button.textContent;
            
            button.disabled = true;
            button.textContent = 'Working...';
            
            fetch('/api/system_control', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ action: action })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    console.log(data.message);
                    // Start checking status more frequently during startup
                    if (action === 'start' || action === 'restart') {
                        const checkInterval = setInterval(() => {
                            loadInitialData();
                        }, 2000);
                        
                        // Stop frequent checking after 2 minutes
                        setTimeout(() => {
                            clearInterval(checkInterval);
                        }, 120000);
                    } else {
                        setTimeout(loadInitialData, 2000);
                    }
                } else {
                    alert('Error: ' + (data.error || 'Unknown error'));
                }
            })
            .catch(error => {
                console.error('Error controlling system:', error);
                alert('Error controlling system: ' + error.message);
            })
            .finally(() => {
                // Reset button after a delay
                setTimeout(() => {
                    button.disabled = false;
                    button.textContent = originalText;
                    loadInitialData(); // Refresh status
                }, 3000);
            });
        }
        
        // Perform manual detection
        function performManualDetection() {
            const timeWindow = prompt('Enter time window in minutes (default: 5):', '5');
            if (!timeWindow) return;
            
            const button = document.getElementById('detectBtn');
            button.disabled = true;
            button.textContent = 'Analyzing...';
            
            fetch('/api/manual_detection', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ time_window_minutes: parseInt(timeWindow) })
            })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    alert('Error: ' + data.error);
                } else {
                    const probability = data.max_probability || 0;
                    const detected = data.ransomware_detected || false;
                    
                    const message = detected ? 
                        `THREAT DETECTED! Probability: ${(probability * 100).toFixed(1)}%` :
                        `No threats detected. Max probability: ${(probability * 100).toFixed(1)}%`;
                    
                    alert(message);
                    
                    // Refresh alerts and data
                    loadInitialData();
                }
            })
            .catch(error => {
                console.error('Error performing detection:', error);
                alert('Error performing manual detection: ' + error.message);
            })
            .finally(() => {
                button.disabled = false;
                button.textContent = 'Manual Detection';
            });
        }
        
        // Auto-refresh data every 30 seconds (less frequent when not running)
        setInterval(function() {
            loadInitialData();
        }, 30000);
        
        // More frequent updates when system is starting
        setInterval(function() {
            if (isSystemStarting) {
                loadInitialData();
            }
        }, 5000);
    </script>
</body>
</html>
    '''
    
    # Write with explicit UTF-8 encoding
    with open(templates_dir / 'dashboard.html', 'w', encoding='utf-8') as f:
        f.write(dashboard_html)
    
    print(f"✓ Template created at: {templates_dir / 'dashboard.html'}")

def main():
    """Run the integrated web interface"""
    print("Starting Integrated Ransomware Detection Web Interface...")
    print("=" * 60)
    
    # Check system requirements
    if not DETECTOR_AVAILABLE:
        print("⚠️  Warning: Detection system modules not available")
        print("   The web interface will run in limited mode")
        print("   Check that all dependencies are installed")
    else:
        print("✓ Detection system modules available")
    
    # Create templates
    create_templates()
    
    print(f"✓ Web interface starting on http://{WEB_HOST}:{WEB_PORT}")
    print("✓ Open your browser to access the dashboard")
    print("=" * 60)
    
    if DETECTOR_AVAILABLE:
        print("Instructions:")
        print("1. Click 'Start System' to initialize the detection system")
        print("2. The system will collect data and train models automatically")
        print("3. Monitor the initialization progress in the status card")
        print("4. Once running, you can perform manual detections")
        print("5. Alerts will appear automatically when threats are detected")
    else:
        print("Limited Mode:")
        print("- Web interface is functional but detection system is disabled")
        print("- Install missing dependencies to enable full functionality")
    
    print("=" * 60)
    
    try:
        # Run the Flask app with SocketIO
        socketio.run(
            app, 
            host=WEB_HOST, 
            port=WEB_PORT,
            debug=WEB_DEBUG
        )
    except KeyboardInterrupt:
        print("\nShutting down web interface...")
        if detection_system:
            print("Stopping detection system...")
            detection_system.stop()
        web_interface.stop_background_updates()
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()