import time
import json
import logging
import threading
import signal
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path
import pandas as pd
import numpy as np

# Import our modules
from data_collector import DataCollector
from feature_extractor import RansomwareFeatureExtractor, create_synthetic_labels
from ml_models import RansomwareMLDetector, RealTimeDetector
from response_system import ResponseOrchestrator
from config import config

class RansomwareDetectionSystem:
    """Main ransomware detection system coordinator"""
    
    def __init__(self, 
                 model_type: str = 'ensemble',
                 auto_train: bool = True,
                 enable_response: bool = True):
        
        self.logger = self._setup_logging()
        
        # System components
        self.data_collector = DataCollector()
        self.feature_extractor = RansomwareFeatureExtractor()
        self.ml_detector = RansomwareMLDetector(model_type)
        self.real_time_detector = None
        self.response_orchestrator = None
        
        # Configuration
        self.auto_train = auto_train
        self.enable_response = enable_response
        self.model_type = model_type
        
        # State management
        self.running = False
        self.last_training_time = None
        self.last_detection_time = None
        
        # Threading
        self.detection_thread = None
        self.training_thread = None
        
        # Statistics
        self.stats = {
            'detections_performed': 0,
            'alerts_triggered': 0,
            'models_trained': 0,
            'start_time': None,
            'uptime_seconds': 0
        }
        
        # Initialize response system if enabled
        if enable_response:
            self.response_orchestrator = ResponseOrchestrator(self.ml_detector)
        
        self.logger.info(f"Ransomware Detection System initialized (model: {model_type})")
    
    def _setup_logging(self):
        """Setup comprehensive logging"""
        logger = logging.getLogger(__name__)
        logger.setLevel(config.LOG_CONFIG['level'])
        
        if not logger.handlers:
            # File handler
            file_handler = logging.FileHandler(config.LOG_CONFIG['file'])
            file_formatter = logging.Formatter(config.LOG_CONFIG['format'])
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)
            
            # Console handler with colors
            console_handler = logging.StreamHandler()
            console_formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s'
            )
            console_handler.setFormatter(console_formatter)
            logger.addHandler(console_handler)
        
        return logger
    
    def initialize_system(self):
        """Initialize all system components"""
        self.logger.info("Initializing ransomware detection system...")
        
        try:
            # Check if we have a pre-trained model
            model_files = list(config.MODELS_DIR.glob("*.pkl"))
            
            if model_files and not self.auto_train:
                # Load most recent model
                latest_model = max(model_files, key=lambda x: x.stat().st_mtime)
                self.logger.info(f"Loading pre-trained model: {latest_model}")
                self.ml_detector.load_model(str(latest_model))
                
                # Initialize real-time detector
                self.real_time_detector = RealTimeDetector(self.ml_detector)
                
            elif self.auto_train:
                self.logger.info("Auto-training enabled - will train model with initial data")
                self._perform_initial_training()
            
            # Initialize response system
            if self.response_orchestrator:
                self.response_orchestrator.start_monitoring()
            
            self.logger.info("System initialization completed")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize system: {e}")
            raise
    
    def _perform_initial_training(self):
        """Perform initial model training with collected data"""
        self.logger.info("Starting initial model training...")
        
        # Collect some initial data
        self.logger.info("Collecting initial training data...")
        self.data_collector.start()
        
        # Wait for some data to be collected
        collection_time = 30  # seconds
        self.logger.info(f"Collecting data for {collection_time} seconds...")
        time.sleep(collection_time)
        
        # Get collected data
        events_data = {
            'file_events': self.data_collector.get_recent_events('file', limit=1000),
            'process_events': self.data_collector.get_recent_events('process', limit=1000),
            'system_metrics': self.data_collector.get_recent_events('metrics', limit=200),
            'alerts': self.data_collector.get_recent_events('alerts', limit=100)
        }
        
        # Check if we have sufficient data
        total_events = sum(len(events) for events in events_data.values())
        
        if total_events < 50:
            self.logger.warning("Insufficient data for training. Loading simulated data...")
            self._load_simulated_training_data(events_data)
        
        # Extract features
        self.logger.info("Extracting features for training...")
        features_list = self.feature_extractor.extract_time_window_features(events_data)
        
        if not features_list:
            self.logger.error("No features extracted - cannot train model")
            return False
        
        # Create feature matrix
        features_df, feature_names = self.feature_extractor.create_feature_matrix(features_list)
        
        # Create synthetic labels for training
        # In a real implementation, you would have expert-labeled data
        self.logger.info("Creating synthetic labels for training...")
        labels = create_synthetic_labels(features_df)
        
        # Train the model
        self.logger.info(f"Training model with {len(features_df)} samples...")
        training_results = self.ml_detector.train_model(features_df, labels)
        
        # Save the trained model
        model_path = self.ml_detector.save_model()
        self.logger.info(f"Model saved to: {model_path}")
        
        # Initialize real-time detector
        self.real_time_detector = RealTimeDetector(self.ml_detector)
        
        # Update stats
        self.stats['models_trained'] += 1
        self.last_training_time = datetime.now()
        
        self.logger.info("Initial training completed successfully")
        return True
    
    def _load_simulated_training_data(self, events_data: Dict[str, List]):
        """Load simulated data for training when insufficient real data"""
        self.logger.info("Generating simulated training data...")
        
        # Generate simulated file events
        simulated_file_events = []
        base_time = datetime.now()
        
        for i in range(100):
            event_time = base_time - timedelta(seconds=i*10)
            
            # Mix of normal and suspicious events
            if i % 10 == 0:  # 10% suspicious
                event = {
                    'timestamp': event_time.isoformat(),
                    'event_type': 'created',
                    'src_path': f'/path/to/file_{i}.encrypted',
                    'is_directory': False
                }
            else:  # 90% normal
                extensions = ['.txt', '.doc', '.pdf', '.jpg', '.png']
                ext = extensions[i % len(extensions)]
                event = {
                    'timestamp': event_time.isoformat(),
                    'event_type': 'modified',
                    'src_path': f'/path/to/file_{i}{ext}',
                    'is_directory': False
                }
            
            simulated_file_events.append(event)
        
        # Generate simulated process events
        simulated_process_events = []
        for i in range(50):
            event_time = base_time - timedelta(seconds=i*20)
            
            if i % 15 == 0:  # Some suspicious processes
                process_name = 'cipher.exe'
            else:
                process_name = f'normal_process_{i}.exe'
            
            event = {
                'timestamp': event_time.isoformat(),
                'pid': 1000 + i,
                'name': process_name,
                'exe': f'C:\\Program Files\\{process_name}',
                'cmdline': f'{process_name} /normal /operations',
                'create_time': event_time.timestamp()
            }
            
            simulated_process_events.append(event)
        
        # Generate simulated system metrics
        simulated_metrics = []
        for i in range(30):
            event_time = base_time - timedelta(seconds=i*60)
            
            metrics = {
                'timestamp': event_time.isoformat(),
                'cpu_percent': 20 + (i % 5) * 10,  # 20-60% CPU
                'memory_percent': 30 + (i % 3) * 15,  # 30-60% memory
                'disk_usage': {'C:': 50 + (i % 2) * 10},
                'network_io': {'bytes_sent': 1000 * i, 'bytes_recv': 2000 * i},
                'disk_io': {'read_bytes': 5000 * i, 'write_bytes': 3000 * i}
            }
            
            simulated_metrics.append(metrics)
        
        # Add simulated data to events_data
        events_data['file_events'].extend(simulated_file_events)
        events_data['process_events'].extend(simulated_process_events)
        events_data['system_metrics'].extend(simulated_metrics)
        
        self.logger.info("Simulated data generated successfully")
    
    def start(self):
        """Start the ransomware detection system"""
        if self.running:
            self.logger.warning("System is already running")
            return
        
        self.logger.info("Starting Ransomware Detection System...")
        
        try:
            # Initialize system components
            self.initialize_system()
            
            # Start data collection
            self.data_collector.start()
            
            # Start detection loop
            self.running = True
            self.stats['start_time'] = datetime.now()
            
            # Start detection thread
            self.detection_thread = threading.Thread(target=self._detection_loop)
            self.detection_thread.daemon = True
            self.detection_thread.start()
            
            # Start periodic training thread if auto-training is enabled
            if self.auto_train:
                self.training_thread = threading.Thread(target=self._training_loop)
                self.training_thread.daemon = True
                self.training_thread.start()
            
            self.logger.info("Ransomware Detection System started successfully")
            self.logger.info("Press Ctrl+C to stop the system")
            
        except Exception as e:
            self.logger.error(f"Failed to start system: {e}")
            self.stop()
            raise
    
    def stop(self):
        """Stop the ransomware detection system"""
        if not self.running:
            return
        
        self.logger.info("Stopping Ransomware Detection System...")
        
        self.running = False
        
        # Stop data collection
        self.data_collector.stop()
        
        # Stop response monitoring
        if self.response_orchestrator:
            self.response_orchestrator.stop_monitoring()
        
        # Wait for threads to finish
        if self.detection_thread and self.detection_thread.is_alive():
            self.detection_thread.join(timeout=10)
        
        if self.training_thread and self.training_thread.is_alive():
            self.training_thread.join(timeout=10)
        
        # Calculate uptime
        if self.stats['start_time']:
            uptime = datetime.now() - self.stats['start_time']
            self.stats['uptime_seconds'] = uptime.total_seconds()
        
        # Save final statistics
        self._save_session_statistics()
        
        self.logger.info("Ransomware Detection System stopped")
    
    def _detection_loop(self):
        """Main detection loop"""
        self.logger.info("Starting detection loop...")
        
        detection_interval = config.ML_CONFIG.get('detection_interval', 30)  # seconds
        
        while self.running:
            try:
                start_time = time.time()
                
                # Perform detection
                self._perform_detection()
                
                # Calculate sleep time to maintain interval
                elapsed_time = time.time() - start_time
                sleep_time = max(0, detection_interval - elapsed_time)
                
                if sleep_time > 0:
                    time.sleep(sleep_time)
                else:
                    self.logger.warning(f"Detection took {elapsed_time:.2f}s, longer than interval {detection_interval}s")
                
            except Exception as e:
                self.logger.error(f"Error in detection loop: {e}")
                time.sleep(detection_interval)
    
    def _perform_detection(self):
        """Perform ransomware detection on recent data"""
        if not self.real_time_detector:
            return
        
        try:
            # Get recent events
            events_data = {
                'file_events': self.data_collector.get_recent_events('file', limit=500),
                'process_events': self.data_collector.get_recent_events('process', limit=200),
                'system_metrics': self.data_collector.get_recent_events('metrics', limit=50),
                'alerts': self.data_collector.get_recent_events('alerts', limit=50)
            }
            
            # Check if we have sufficient data
            total_events = sum(len(events) for events in events_data.values())
            
            if total_events < 10:
                self.logger.debug("Insufficient events for detection")
                return
            
            # Extract features from recent data
            features_list = self.feature_extractor.extract_time_window_features(
                events_data, window_size=config.ML_CONFIG['feature_window_size']
            )
            
            if not features_list:
                self.logger.debug("No features extracted from recent data")
                return
            
            # Create feature matrix
            features_df, _ = self.feature_extractor.create_feature_matrix(features_list)
            
            # Perform detection
            detection_result = self.real_time_detector.detect(features_df)
            
            # Update statistics
            self.stats['detections_performed'] += 1
            self.last_detection_time = datetime.now()
            
            # Log detection result
            if detection_result['ransomware_detected']:
                self.logger.warning(f"RANSOMWARE DETECTED! Probability: {detection_result['max_probability']:.3f}")
                self.stats['alerts_triggered'] += 1
                
                # Enhance detection result with additional context
                enhanced_result = self._enhance_detection_result(detection_result, events_data)
                
                # Trigger response if enabled
                if self.response_orchestrator:
                    self.response_orchestrator.handle_detection(enhanced_result)
                
            else:
                self.logger.debug(f"Normal activity detected (max prob: {detection_result['max_probability']:.3f})")
        
        except Exception as e:
            self.logger.error(f"Error during detection: {e}")
    
    def _enhance_detection_result(self, detection_result: Dict[str, Any], 
                                events_data: Dict[str, List]) -> Dict[str, Any]:
        """Enhance detection result with additional context"""
        enhanced = detection_result.copy()
        
        # Add suspicious processes
        suspicious_processes = []
        for event in events_data.get('process_events', []):
            process_name = event.get('name', '').lower()
            if any(susp_proc.lower() in process_name for susp_proc in config.SUSPICIOUS_PROCESS_NAMES):
                suspicious_processes.append({
                    'pid': event.get('pid'),
                    'name': event.get('name'),
                    'cmdline': event.get('cmdline', ''),
                    'timestamp': event.get('timestamp')
                })
        
        enhanced['suspicious_processes'] = suspicious_processes
        
        # Add suspicious files
        suspicious_files = []
        for event in events_data.get('file_events', []):
            file_path = event.get('src_path', '')
            if any(ext in file_path.lower() for ext in config.SUSPICIOUS_EXTENSIONS):
                suspicious_files.append(file_path)
        
        enhanced['suspicious_files'] = suspicious_files
        
        # Add network connections context
        if hasattr(self, 'response_orchestrator') and self.response_orchestrator:
            connections = self.response_orchestrator.response_system.network_controller.get_active_connections()
            enhanced['active_connections'] = connections
        
        return enhanced
    
    def _training_loop(self):
        """Periodic model retraining loop"""
        self.logger.info("Starting periodic training loop...")
        
        retrain_interval = config.ML_CONFIG.get('model_retrain_interval', 3600)  # seconds
        
        while self.running:
            try:
                time.sleep(retrain_interval)
                
                if not self.running:
                    break
                
                self.logger.info("Starting periodic model retraining...")
                self._retrain_model()
                
            except Exception as e:
                self.logger.error(f"Error in training loop: {e}")
                time.sleep(retrain_interval // 2)  # Wait half interval on error
    
    def _retrain_model(self):
        """Retrain the model with accumulated data"""
        try:
            # Get accumulated data
            events_data = {
                'file_events': self.data_collector.get_recent_events('file', limit=2000),
                'process_events': self.data_collector.get_recent_events('process', limit=1000),
                'system_metrics': self.data_collector.get_recent_events('metrics', limit=500),
                'alerts': self.data_collector.get_recent_events('alerts', limit=200)
            }
            
            # Check if we have sufficient data
            total_events = sum(len(events) for events in events_data.values())
            
            if total_events < 100:
                self.logger.info("Insufficient data for retraining")
                return
            
            # Extract features
            features_list = self.feature_extractor.extract_time_window_features(events_data)
            
            if len(features_list) < 20:
                self.logger.info("Insufficient feature windows for retraining")
                return
            
            # Create feature matrix
            features_df, _ = self.feature_extractor.create_feature_matrix(features_list)
            
            # Create labels (in real implementation, use expert annotations)
            labels = create_synthetic_labels(features_df)
            
            # Retrain model
            self.logger.info(f"Retraining model with {len(features_df)} samples...")
            training_results = self.ml_detector.train_model(features_df, labels)
            
            # Save updated model
            model_path = self.ml_detector.save_model()
            
            # Update real-time detector
            self.real_time_detector = RealTimeDetector(self.ml_detector)
            
            # Update statistics
            self.stats['models_trained'] += 1
            self.last_training_time = datetime.now()
            
            self.logger.info(f"Model retrained and saved to: {model_path}")
            
        except Exception as e:
            self.logger.error(f"Error during model retraining: {e}")
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status"""
        status = {
            'running': self.running,
            'model_type': self.model_type,
            'auto_train_enabled': self.auto_train,
            'response_enabled': self.enable_response,
            'statistics': self.stats.copy(),
            'last_training_time': self.last_training_time.isoformat() if self.last_training_time else None,
            'last_detection_time': self.last_detection_time.isoformat() if self.last_detection_time else None,
        }
        
        # Add component status
        if self.data_collector:
            status['data_collector_stats'] = self.data_collector.get_statistics()
        
        if self.real_time_detector:
            status['detection_summary'] = self.real_time_detector.get_detection_summary()
        
        if self.response_orchestrator:
            status['response_status'] = self.response_orchestrator.response_system.get_system_status()
        
        # Calculate uptime
        if self.stats['start_time']:
            uptime = datetime.now() - self.stats['start_time']
            status['uptime_seconds'] = uptime.total_seconds()
        
        return status
    
    def _save_session_statistics(self):
        """Save session statistics to file"""
        try:
            stats_file = config.LOGS_DIR / "session_statistics.json"
            
            session_stats = {
                'session_end': datetime.now().isoformat(),
                'statistics': self.stats,
                'configuration': {
                    'model_type': self.model_type,
                    'auto_train': self.auto_train,
                    'enable_response': self.enable_response,
                }
            }
            
            # Load existing stats
            existing_stats = []
            if stats_file.exists():
                with open(stats_file, 'r') as f:
                    existing_stats = json.load(f)
            
            # Add current session
            existing_stats.append(session_stats)
            
            # Keep only last 100 sessions
            existing_stats = existing_stats[-100:]
            
            # Save updated stats
            with open(stats_file, 'w') as f:
                json.dump(existing_stats, f, indent=2)
            
            self.logger.info(f"Session statistics saved to {stats_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to save session statistics: {e}")
    
    def manual_detection(self, time_window_minutes: int = 5) -> Dict[str, Any]:
        """Perform manual detection on recent data"""
        if not self.real_time_detector:
            raise ValueError("Real-time detector not initialized")
        
        # Get recent events
        events_data = {
            'file_events': self.data_collector.get_recent_events('file', limit=1000),
            'process_events': self.data_collector.get_recent_events('process', limit=500),
            'system_metrics': self.data_collector.get_recent_events('metrics', limit=100),
            'alerts': self.data_collector.get_recent_events('alerts', limit=100)
        }
        
        # Filter by time window
        cutoff_time = datetime.now() - timedelta(minutes=time_window_minutes)
        
        for event_type, events in events_data.items():
            events_data[event_type] = [
                event for event in events
                if datetime.fromisoformat(event['timestamp']) >= cutoff_time
            ]
        
        # Extract features
        features_list = self.feature_extractor.extract_time_window_features(events_data)
        
        if not features_list:
            return {'error': 'No features could be extracted from recent data'}
        
        # Create feature matrix
        features_df, _ = self.feature_extractor.create_feature_matrix(features_list)
        
        # Perform detection
        detection_result = self.real_time_detector.detect(features_df)
        
        return detection_result
    
    def get_feature_importance(self) -> Dict[str, Any]:
        """Get feature importance from the trained model"""
        if not self.ml_detector.is_trained:
            return {'error': 'Model is not trained'}
        
        return self.ml_detector.get_feature_importance()

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    global detector_system
    
    print("\nReceived shutdown signal. Stopping detection system...")
    
    if 'detector_system' in globals() and detector_system:
        detector_system.stop()
    
    sys.exit(0)

def main():
    """Main entry point for the ransomware detection system"""
    global detector_system
    
    print("="*60)
    print("  RANSOMWARE DETECTION SYSTEM")
    print("  Intelligent ML-based Protection")
    print("="*60)
    
    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Create and configure the detection system
        detector_system = RansomwareDetectionSystem(
            model_type='ensemble',
            auto_train=True,
            enable_response=True
        )
        
        # Start the system
        detector_system.start()
        
        # Keep the main thread alive
        while detector_system.running:
            time.sleep(1)
            
            # Print status every 5 minutes
            if int(time.time()) % 300 == 0:
                status = detector_system.get_system_status()
                print(f"\n[STATUS UPDATE]")
                print(f"Uptime: {status.get('uptime_seconds', 0):.0f} seconds")
                print(f"Detections performed: {status['statistics']['detections_performed']}")
                print(f"Alerts triggered: {status['statistics']['alerts_triggered']}")
                print(f"Models trained: {status['statistics']['models_trained']}")
                print("-" * 40)
    
    except KeyboardInterrupt:
        print("\nShutdown requested by user")
    except Exception as e:
        print(f"\nFatal error: {e}")
        logging.getLogger(__name__).critical(f"Fatal error: {e}")
    finally:
        if 'detector_system' in locals() and detector_system:
            detector_system.stop()

if __name__ == "__main__":
    main()