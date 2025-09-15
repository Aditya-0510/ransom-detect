# src/data_collector.py - System monitoring and data collection

import os
import time
import json
import psutil
import threading
from datetime import datetime
from pathlib import Path
from collections import defaultdict, deque
from typing import Dict, List, Any
import logging

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except ImportError:
    print("Please install watchdog: pip install watchdog")

from config import config

class FileSystemMonitor(FileSystemEventHandler):
    """Monitor file system events for suspicious activity"""
    
    def __init__(self, data_collector):
        self.data_collector = data_collector
        self.logger = logging.getLogger(__name__)
    
    def on_any_event(self, event):
        """Handle all file system events"""
        if event.is_directory:
            return
            
        event_data = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event.event_type,
            'src_path': event.src_path,
            'is_directory': event.is_directory,
        }
        
        # Add destination path for moved events
        if hasattr(event, 'dest_path'):
            event_data['dest_path'] = event.dest_path
            
        self.data_collector.add_file_event(event_data)
        
        # Check for suspicious file extensions
        if event.event_type in ['created', 'modified']:
            self._check_suspicious_file(event.src_path)
    
    def _check_suspicious_file(self, file_path: str):
        """Check if file has suspicious extension"""
        file_ext = Path(file_path).suffix.lower()
        if file_ext in config.SUSPICIOUS_EXTENSIONS:
            self.logger.warning(f"Suspicious file detected: {file_path}")
            self.data_collector.add_alert({
                'type': 'suspicious_file',
                'file_path': file_path,
                'extension': file_ext,
                'timestamp': datetime.now().isoformat()
            })

class ProcessMonitor:
    """Monitor running processes for suspicious activity"""
    
    def __init__(self, data_collector):
        self.data_collector = data_collector
        self.logger = logging.getLogger(__name__)
        self.running = False
        self.thread = None
        self.known_processes = set()
    
    def start(self):
        """Start process monitoring"""
        self.running = True
        self.thread = threading.Thread(target=self._monitor_processes)
        self.thread.daemon = True
        self.thread.start()
        self.logger.info("Process monitoring started")
    
    def stop(self):
        """Stop process monitoring"""
        self.running = False
        if self.thread:
            self.thread.join()
        self.logger.info("Process monitoring stopped")
    
    def _monitor_processes(self):
        """Monitor processes continuously"""
        while self.running:
            try:
                current_processes = set()
                for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time']):
                    try:
                        proc_info = proc.info
                        proc_id = proc_info['pid']
                        current_processes.add(proc_id)
                        
                        # New process detected
                        if proc_id not in self.known_processes:
                            self._analyze_new_process(proc_info)
                            
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                # Update known processes
                self.known_processes = current_processes
                time.sleep(1)  # Check every second
                
            except Exception as e:
                self.logger.error(f"Error in process monitoring: {e}")
                time.sleep(5)
    
    def _analyze_new_process(self, proc_info: Dict[str, Any]):
        """Analyze newly detected process"""
        proc_name = proc_info.get('name', '').lower()
        proc_exe = proc_info.get('exe', '')
        cmdline = proc_info.get('cmdline', [])
        
        # Fix: Handle cmdline properly - it might be None or a string
        if cmdline is None:
            cmdline_str = ''
        elif isinstance(cmdline, list):
            cmdline_str = ' '.join(str(arg) for arg in cmdline)
        else:
            cmdline_str = str(cmdline)
        
        process_data = {
            'timestamp': datetime.now().isoformat(),
            'pid': proc_info['pid'],
            'name': proc_name,
            'exe': proc_exe,
            'cmdline': cmdline_str,
            'create_time': proc_info.get('create_time', 0)
        }
        
        self.data_collector.add_process_event(process_data)
        
        # Check for suspicious processes
        if any(susp.lower() in proc_name for susp in config.SUSPICIOUS_PROCESS_NAMES):
            self.logger.warning(f"Suspicious process detected: {proc_name}")
            self.data_collector.add_alert({
                'type': 'suspicious_process',
                'process_name': proc_name,
                'pid': proc_info['pid'],
                'exe': proc_exe,
                'timestamp': datetime.now().isoformat()
            })
        
        # Check for suspicious command line arguments
        suspicious_args = ['vssadmin delete shadows', 'cipher /w', 'bcdedit /set', 'wbadmin delete catalog']
        for suspicious_arg in suspicious_args:
            if suspicious_arg in cmdline_str.lower():
                self.logger.warning(f"Suspicious command line detected: {cmdline_str}")
                self.data_collector.add_alert({
                    'type': 'suspicious_command',
                    'command': cmdline_str,
                    'process': proc_name,
                    'timestamp': datetime.now().isoformat()
                })

class SystemMetricsMonitor:
    """Monitor system performance metrics"""
    
    def __init__(self, data_collector):
        self.data_collector = data_collector
        self.logger = logging.getLogger(__name__)
        self.running = False
        self.thread = None
    
    def start(self):
        """Start system metrics monitoring"""
        self.running = True
        self.thread = threading.Thread(target=self._monitor_metrics)
        self.thread.daemon = True
        self.thread.start()
        self.logger.info("System metrics monitoring started")
    
    def stop(self):
        """Stop system metrics monitoring"""
        self.running = False
        if self.thread:
            self.thread.join()
        self.logger.info("System metrics monitoring stopped")
    
    def _monitor_metrics(self):
        """Monitor system metrics continuously"""
        while self.running:
            try:
                metrics = {
                    'timestamp': datetime.now().isoformat(),
                    'cpu_percent': psutil.cpu_percent(interval=1),
                    'memory_percent': psutil.virtual_memory().percent,
                    'disk_usage': {disk.mountpoint: psutil.disk_usage(disk.mountpoint).percent 
                                 for disk in psutil.disk_partitions()},
                    'network_io': psutil.net_io_counters()._asdict(),
                    'disk_io': psutil.disk_io_counters()._asdict() if psutil.disk_io_counters() else {},
                }
                
                self.data_collector.add_system_metrics(metrics)
                time.sleep(5)  # Collect metrics every 5 seconds
                
            except Exception as e:
                self.logger.error(f"Error collecting system metrics: {e}")
                time.sleep(10)

class DataCollector:
    """Main data collection orchestrator"""
    
    def __init__(self):
        self.logger = self._setup_logging()
        
        # Data storage
        self.file_events = deque(maxlen=10000)
        self.process_events = deque(maxlen=5000)
        self.system_metrics = deque(maxlen=1000)
        self.alerts = deque(maxlen=1000)
        
        # Monitoring components
        self.fs_monitor = FileSystemMonitor(self)
        self.process_monitor = ProcessMonitor(self)
        self.metrics_monitor = SystemMetricsMonitor(self)
        
        # File system observer
        self.observer = Observer()
        
        # Statistics
        self.stats = defaultdict(int)
        
        self.logger.info("Data collector initialized")
    
    def _setup_logging(self):
        """Setup logging configuration"""
        logger = logging.getLogger(__name__)
        logger.setLevel(config.LOG_CONFIG['level'])
        
        if not logger.handlers:
            handler = logging.FileHandler(config.LOG_CONFIG['file'])
            formatter = logging.Formatter(config.LOG_CONFIG['format'])
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            
            # Also add console handler
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)
        
        return logger
    
    def start(self):
        """Start all monitoring components"""
        try:
            # Start file system monitoring
            for directory in config.MONITOR_DIRECTORIES:
                if os.path.exists(directory):
                    self.observer.schedule(self.fs_monitor, directory, recursive=True)
                    self.logger.info(f"Monitoring directory: {directory}")
            
            self.observer.start()
            
            # Start process monitoring
            self.process_monitor.start()
            
            # Start system metrics monitoring
            self.metrics_monitor.start()
            
            self.logger.info("All monitoring components started successfully")
            
        except Exception as e:
            self.logger.error(f"Error starting monitoring: {e}")
            raise
    
    def stop(self):
        """Stop all monitoring components"""
        try:
            self.observer.stop()
            self.observer.join()
            
            self.process_monitor.stop()
            self.metrics_monitor.stop()
            
            self.logger.info("All monitoring components stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping monitoring: {e}")
    
    def add_file_event(self, event_data: Dict[str, Any]):
        """Add file system event"""
        self.file_events.append(event_data)
        self.stats['file_events'] += 1
    
    def add_process_event(self, event_data: Dict[str, Any]):
        """Add process event"""
        self.process_events.append(event_data)
        self.stats['process_events'] += 1
    
    def add_system_metrics(self, metrics_data: Dict[str, Any]):
        """Add system metrics"""
        self.system_metrics.append(metrics_data)
        self.stats['system_metrics'] += 1
    
    def add_alert(self, alert_data: Dict[str, Any]):
        """Add security alert"""
        self.alerts.append(alert_data)
        self.stats['alerts'] += 1
        self.logger.warning(f"Security alert: {alert_data}")
    
    def get_recent_events(self, event_type: str = 'all', limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent events of specified type"""
        if event_type == 'file' or event_type == 'all':
            return list(self.file_events)[-limit:]
        elif event_type == 'process':
            return list(self.process_events)[-limit:]
        elif event_type == 'metrics':
            return list(self.system_metrics)[-limit:]
        elif event_type == 'alerts':
            return list(self.alerts)[-limit:]
        else:
            return []
    
    def get_statistics(self) -> Dict[str, int]:
        """Get collection statistics"""
        return dict(self.stats)
    
    def save_data_snapshot(self, filepath: str = None):
        """Save current data to file"""
        if not filepath:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = config.RAW_DATA_DIR / f"data_snapshot_{timestamp}.json"
        
        data = {
            'timestamp': datetime.now().isoformat(),
            'file_events': list(self.file_events),
            'process_events': list(self.process_events),
            'system_metrics': list(self.system_metrics),
            'alerts': list(self.alerts),
            'statistics': self.get_statistics()
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        self.logger.info(f"Data snapshot saved to {filepath}")
        return filepath

if __name__ == "__main__":
    # Test the data collector
    collector = DataCollector()
    
    try:
        print("Starting data collection...")
        collector.start()
        
        # Run for a specified time or until interrupted
        time.sleep(60)  # Collect data for 1 minute
        
    except KeyboardInterrupt:
        print("\nStopping data collection...")
    finally:
        collector.stop()
        
        # Save collected data
        snapshot_file = collector.save_data_snapshot()
        print(f"Data saved to: {snapshot_file}")
        
        # Print statistics
        stats = collector.get_statistics()
        print("\nCollection Statistics:")
        for key, value in stats.items():
            print(f"  {key}: {value}")