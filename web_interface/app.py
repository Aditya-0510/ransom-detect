# web_interface/app.py - Web interface for ransomware detection system

from flask import Flask, render_template, jsonify, request, send_from_directory
from flask_socketio import SocketIO, emit
import json
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
import threading
import time

# Add the src directory to the path to import our modules
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from main_detector import RansomwareDetectionSystem
from config import config

app = Flask(__name__)
app.config['SECRET_KEY'] = config.WEB_CONFIG['secret_key']

# Initialize SocketIO for real-time updates
socketio = SocketIO(app, cors_allowed_origins="*")

# Global detection system instance
detection_system = None

class WebInterface:
    """Web interface for the ransomware detection system"""
    
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
    
    def stop_background_updates(self):
        """Stop background updates"""
        self.running = False
        if self.update_thread:
            self.update_thread.join(timeout=5)
    
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
                    if detection_system.response_orchestrator:
                        recent_alerts = detection_system.response_orchestrator.response_system.alert_manager.get_recent_alerts(5)
                        if recent_alerts:
                            socketio.emit('alert_update', {'alerts': recent_alerts})
                
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
    if not detection_system:
        return jsonify({'error': 'Detection system not initialized'}), 500
    
    try:
        status = detection_system.get_system_status()
        return jsonify(status)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts')
def get_alerts():
    """Get recent alerts API"""
    try:
        limit = request.args.get('limit', 50, type=int)
        
        if not detection_system or not detection_system.response_orchestrator:
            return jsonify({'alerts': []})
        
        alerts = detection_system.response_orchestrator.response_system.alert_manager.get_recent_alerts(limit)
        return jsonify({'alerts': alerts})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/detection_history')
def get_detection_history():
    """Get detection history API"""
    try:
        limit = request.args.get('limit', 100, type=int)
        
        if not detection_system or not detection_system.real_time_detector:
            return jsonify({'detections': []})
        
        # Get recent detections from the real-time detector
        history = detection_system.real_time_detector.detection_history[-limit:]
        return jsonify({'detections': history})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/feature_importance')
def get_feature_importance():
    """Get feature importance API"""
    try:
        if not detection_system or not detection_system.ml_detector.is_trained:
            return jsonify({'error': 'Model not trained'})
        
        importance = detection_system.get_feature_importance()
        return jsonify(importance)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/manual_detection', methods=['POST'])
def manual_detection():
    """Trigger manual detection API"""
    try:
        data = request.get_json()
        time_window = data.get('time_window_minutes', 5)
        
        if not detection_system:
            return jsonify({'error': 'Detection system not initialized'}), 500
        
        result = detection_system.manual_detection(time_window)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/system_control', methods=['POST'])
def system_control():
    """Control system operations API"""
    try:
        data = request.get_json()
        action = data.get('action')
        
        global detection_system
        
        if action == 'start':
            if not detection_system:
                detection_system = RansomwareDetectionSystem()
                detection_system.start()
                web_interface.start_background_updates()
            return jsonify({'success': True, 'message': 'System started'})
        
        elif action == 'stop':
            if detection_system:
                detection_system.stop()
                web_interface.stop_background_updates()
            return jsonify({'success': True, 'message': 'System stopped'})
        
        elif action == 'restart':
            if detection_system:
                detection_system.stop()
                time.sleep(2)
                detection_system.start()
            return jsonify({'success': True, 'message': 'System restarted'})
        
        else:
            return jsonify({'error': 'Unknown action'}), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/response_action', methods=['POST'])
def response_action():
    """Execute response action API"""
    try:
        data = request.get_json()
        action = data.get('action')
        parameters = data.get('parameters', {})
        
        if not detection_system or not detection_system.response_orchestrator:
            return jsonify({'error': 'Response system not available'}), 500
        
        result = detection_system.response_orchestrator.response_system.manual_response_action(action, parameters)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Socket.IO events
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    emit('connected', {'message': 'Connected to Ransomware Detection System'})

@socketio.on('request_status')
def handle_status_request():
    """Handle status request from client"""
    if detection_system:
        status = detection_system.get_system_status()
        emit('status_update', status)

# Template creation (since we can't create separate files easily)
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
            font-size: 2rem;
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
        
        .btn:hover {
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
        
        .alert-high {
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
        <h1>🛡️ Ransomware Detection System</h1>
    </div>
    
    <div class="container">
        <div class="dashboard-grid">
            <!-- System Status -->
            <div class="card status-card">
                <h3>System Status</h3>
                <div id="statusIndicator" class="status-indicator status-stopped">
                    ❌
                </div>
                <div id="statusText">Checking...</div>
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
            
            if (data.running) {
                indicator.className = 'status-indicator status-running';
                indicator.textContent = '✅';
                statusText.textContent = 'System Running';
            } else {
                indicator.className = 'status-indicator status-stopped';
                indicator.textContent = '❌';
                statusText.textContent = 'System Stopped';
            }
            
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
            
            document.getElementById('detectBtn').addEventListener('click', function() {
                performManualDetection();
            });
            
            document.getElementById('refreshBtn').addEventListener('click', function() {
                loadInitialData();
            });
        }
        
        // Control system
        function controlSystem(action) {
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
                    setTimeout(loadInitialData, 2000); // Refresh after 2 seconds
                } else {
                    alert('Error: ' + (data.error || 'Unknown error'));
                }
            })
            .catch(error => {
                console.error('Error controlling system:', error);
                alert('Error controlling system');
            });
        }
        
        // Perform manual detection
        function performManualDetection() {
            const timeWindow = prompt('Enter time window in minutes (default: 5):', '5');
            if (!timeWindow) return;
            
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
                        `⚠️ THREAT DETECTED! Probability: ${(probability * 100).toFixed(1)}%` :
                        `✅ No threats detected. Max probability: ${(probability * 100).toFixed(1)}%`;
                    
                    alert(message);
                }
            })
            .catch(error => {
                console.error('Error performing detection:', error);
                alert('Error performing manual detection');
            });
        }
        
        // Auto-refresh data every 30 seconds
        setInterval(function() {
            loadInitialData();
        }, 30000);
    </script>
</body>
</html>
    '''
    
    with open(templates_dir / 'dashboard.html', 'w') as f:
        f.write(dashboard_html)

def run_web_interface():
    """Run the web interface"""
    global detection_system
    
    print("Starting Ransomware Detection System Web Interface...")
    
    # Create templates
    create_templates()
    
    # Initialize detection system
    try:
        detection_system = RansomwareDetectionSystem(
            model_type='ensemble',
            auto_train=True,
            enable_response=True
        )
        
        # Start the detection system
        detection_system.start()
        
        # Start background updates
        web_interface.start_background_updates()
        
        print(f"Web interface starting on http://{config.WEB_CONFIG['host']}:{config.WEB_CONFIG['port']}")
        print("Open your browser to access the dashboard")
        
        # Run the Flask app with SocketIO
        socketio.run(
            app, 
            host=config.WEB_CONFIG['host'], 
            port=config.WEB_CONFIG['port'],
            debug=config.WEB_CONFIG['debug']
        )
        
    except KeyboardInterrupt:
        print("\nShutting down web interface...")
    except Exception as e:
        print(f"Error starting web interface: {e}")
    finally:
        # Cleanup
        if detection_system:
            detection_system.stop()
        web_interface.stop_background_updates()

if __name__ == "__main__":
    run_web_interface()