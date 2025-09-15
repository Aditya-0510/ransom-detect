# src/response_system.py - Automated response and mitigation system

import os
import json
import time
import smtplib
import subprocess
from datetime import datetime
from typing import Dict, List, Any, Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
import threading
from pathlib import Path
import shutil

import psutil

from config import config

class AlertManager:
    """Manage and dispatch security alerts"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.alert_history = []
        self.alert_count = 0
        
        # Email configuration (if enabled)
        self.smtp_server = "smtp.gmail.com"  # Configure for your email provider
        self.smtp_port = 587
        self.email_user = ""  # Configure your email
        self.email_password = ""  # Configure your password/app password
        
        self.logger.info("Alert Manager initialized")
    
    def send_alert(self, alert_data: Dict[str, Any], severity: str = "HIGH"):
        """Send alert through configured channels"""
        
        alert_id = self.alert_count + 1
        self.alert_count = alert_id
        
        # Create comprehensive alert
        full_alert = {
            'alert_id': alert_id,
            'timestamp': datetime.now().isoformat(),
            'severity': severity,
            'type': alert_data.get('type', 'ransomware_detection'),
            'details': alert_data,
            'hostname': os.getenv('COMPUTERNAME', 'Unknown'),
            'user': os.getenv('USERNAME', 'Unknown')
        }
        
        # Store alert
        self.alert_history.append(full_alert)
        
        # Log alert
        if config.ALERT_CONFIG['log_alerts']:
            self._log_alert(full_alert)
        
        # Send email alert
        if config.ALERT_CONFIG['email_enabled']:
            self._send_email_alert(full_alert)
        
        # SMS alert (placeholder)
        if config.ALERT_CONFIG['sms_enabled']:
            self._send_sms_alert(full_alert)
        
        self.logger.critical(f"SECURITY ALERT #{alert_id}: {alert_data.get('message', 'Ransomware detected')}")
        
        return alert_id
    
    def _log_alert(self, alert: Dict[str, Any]):
        """Log alert to file and console"""
        log_message = f"""
========== SECURITY ALERT #{alert['alert_id']} ==========
Time: {alert['timestamp']}
Severity: {alert['severity']}
Type: {alert['type']}
Host: {alert['hostname']}
User: {alert['user']}
Details: {json.dumps(alert['details'], indent=2)}
================================================
"""
        self.logger.critical(log_message)
        
        # Also write to dedicated alert log
        alert_log_path = config.LOGS_DIR / "security_alerts.log"
        with open(alert_log_path, 'a') as f:
            f.write(log_message + "\n")
    
    def _send_email_alert(self, alert: Dict[str, Any]):
        """Send email alert"""
        if not self.email_user or not self.email_password:
            self.logger.warning("Email credentials not configured")
            return
        
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.email_user
            msg['To'] = ', '.join(config.ALERT_CONFIG['email_recipients'])
            msg['Subject'] = f"🚨 RANSOMWARE ALERT #{alert['alert_id']} - {alert['hostname']}"
            
            # Email body
            body = f"""
CRITICAL SECURITY ALERT

Alert ID: {alert['alert_id']}
Time: {alert['timestamp']}
Severity: {alert['severity']}
Host: {alert['hostname']}
User: {alert['user']}

THREAT DETECTED: {alert['type']}

Details:
{json.dumps(alert['details'], indent=2)}

IMMEDIATE ACTION REQUIRED:
1. Isolate the affected system
2. Do not pay any ransom demands
3. Contact your IT security team
4. Begin incident response procedures

This is an automated alert from the Ransomware Detection System.
"""
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.email_user, self.email_password)
            text = msg.as_string()
            server.sendmail(self.email_user, config.ALERT_CONFIG['email_recipients'], text)
            server.quit()
            
            self.logger.info(f"Email alert sent for Alert #{alert['alert_id']}")
            
        except Exception as e:
            self.logger.error(f"Failed to send email alert: {e}")
    
    def _send_sms_alert(self, alert: Dict[str, Any]):
        """Send SMS alert (placeholder implementation)"""
        # This would integrate with SMS service like Twilio, AWS SNS, etc.
        self.logger.info(f"SMS alert would be sent for Alert #{alert['alert_id']}")
    
    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent alerts"""
        return self.alert_history[-limit:]
    
    def get_alert_statistics(self) -> Dict[str, Any]:
        """Get alert statistics"""
        if not self.alert_history:
            return {'total_alerts': 0}
        
        # Count by severity
        severity_counts = {}
        type_counts = {}
        
        for alert in self.alert_history:
            severity = alert.get('severity', 'UNKNOWN')
            alert_type = alert.get('type', 'unknown')
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            type_counts[alert_type] = type_counts.get(alert_type, 0) + 1
        
        return {
            'total_alerts': len(self.alert_history),
            'by_severity': severity_counts,
            'by_type': type_counts,
            'last_alert_time': self.alert_history[-1]['timestamp'] if self.alert_history else None
        }

class ProcessManager:
    """Manage and control suspicious processes"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.quarantined_processes = []
        
    def kill_process(self, pid: int, force: bool = False) -> bool:
        """Terminate a process by PID"""
        try:
            process = psutil.Process(pid)
            process_name = process.name()
            
            self.logger.warning(f"Attempting to terminate process {process_name} (PID: {pid})")
            
            if force:
                process.kill()  # SIGKILL
            else:
                process.terminate()  # SIGTERM
            
            # Wait for process to die
            try:
                process.wait(timeout=10)
                self.logger.info(f"Successfully terminated process {process_name} (PID: {pid})")
                return True
            except psutil.TimeoutExpired:
                if not force:
                    # Try force kill
                    self.logger.warning(f"Process {process_name} did not terminate gracefully, force killing...")
                    return self.kill_process(pid, force=True)
                else:
                    self.logger.error(f"Failed to kill process {process_name} (PID: {pid})")
                    return False
                    
        except psutil.NoSuchProcess:
            self.logger.info(f"Process with PID {pid} no longer exists")
            return True
        except psutil.AccessDenied:
            self.logger.error(f"Access denied when trying to terminate PID {pid}")
            return False
        except Exception as e:
            self.logger.error(f"Error terminating process PID {pid}: {e}")
            return False
    
    def kill_process_by_name(self, process_name: str) -> int:
        """Kill all processes with given name"""
        killed_count = 0
        
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'].lower() == process_name.lower():
                    if self.kill_process(proc.info['pid']):
                        killed_count += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        self.logger.info(f"Killed {killed_count} processes named '{process_name}'")
        return killed_count
    
    def suspend_process(self, pid: int) -> bool:
        """Suspend a process (pause execution)"""
        try:
            process = psutil.Process(pid)
            process.suspend()
            
            self.quarantined_processes.append({
                'pid': pid,
                'name': process.name(),
                'suspended_at': datetime.now().isoformat(),
                'action': 'suspended'
            })
            
            self.logger.info(f"Suspended process {process.name()} (PID: {pid})")
            return True
            
        except psutil.NoSuchProcess:
            self.logger.info(f"Process with PID {pid} no longer exists")
            return False
        except psutil.AccessDenied:
            self.logger.error(f"Access denied when trying to suspend PID {pid}")
            return False
        except Exception as e:
            self.logger.error(f"Error suspending process PID {pid}: {e}")
            return False
    
    def resume_process(self, pid: int) -> bool:
        """Resume a suspended process"""
        try:
            process = psutil.Process(pid)
            process.resume()
            
            # Remove from quarantined list
            self.quarantined_processes = [
                p for p in self.quarantined_processes if p['pid'] != pid
            ]
            
            self.logger.info(f"Resumed process {process.name()} (PID: {pid})")
            return True
            
        except psutil.NoSuchProcess:
            self.logger.info(f"Process with PID {pid} no longer exists")
            return False
        except psutil.AccessDenied:
            self.logger.error(f"Access denied when trying to resume PID {pid}")
            return False
        except Exception as e:
            self.logger.error(f"Error resuming process PID {pid}: {e}")
            return False

class FileSystemProtector:
    """Protect and backup critical files"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.quarantine_dir = config.DATA_DIR / "quarantine"
        self.backup_dir = config.DATA_DIR / "backups"
        
        # Create directories
        self.quarantine_dir.mkdir(exist_ok=True)
        self.backup_dir.mkdir(exist_ok=True)
        
    def quarantine_file(self, file_path: str) -> bool:
        """Move suspicious file to quarantine"""
        try:
            source_path = Path(file_path)
            if not source_path.exists():
                self.logger.warning(f"File not found for quarantine: {file_path}")
                return False
            
            # Create quarantine subdirectory with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantine_subdir = self.quarantine_dir / f"quarantine_{timestamp}"
            quarantine_subdir.mkdir(exist_ok=True)
            
            # Move file to quarantine
            dest_path = quarantine_subdir / source_path.name
            shutil.move(str(source_path), str(dest_path))
            
            # Create metadata file
            metadata = {
                'original_path': str(source_path),
                'quarantined_at': datetime.now().isoformat(),
                'file_size': dest_path.stat().st_size,
                'reason': 'suspicious_activity'
            }
            
            metadata_path = quarantine_subdir / f"{source_path.name}_metadata.json"
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            self.logger.info(f"File quarantined: {file_path} -> {dest_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to quarantine file {file_path}: {e}")
            return False
    
    def create_backup(self, file_path: str) -> Optional[str]:
        """Create backup of important file"""
        try:
            source_path = Path(file_path)
            if not source_path.exists():
                return None
            
            # Create backup with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"{source_path.stem}_{timestamp}{source_path.suffix}"
            backup_path = self.backup_dir / backup_name
            
            # Copy file to backup
            shutil.copy2(str(source_path), str(backup_path))
            
            self.logger.info(f"Backup created: {file_path} -> {backup_path}")
            return str(backup_path)
            
        except Exception as e:
            self.logger.error(f"Failed to create backup for {file_path}: {e}")
            return None
    
    def restore_from_quarantine(self, quarantine_path: str) -> bool:
        """Restore file from quarantine"""
        try:
            quarantine_file = Path(quarantine_path)
            metadata_file = quarantine_file.parent / f"{quarantine_file.name}_metadata.json"
            
            # Read metadata to get original path
            if metadata_file.exists():
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
                
                original_path = Path(metadata['original_path'])
                
                # Restore file
                shutil.move(str(quarantine_file), str(original_path))
                
                # Remove metadata
                metadata_file.unlink()
                
                self.logger.info(f"File restored from quarantine: {quarantine_path} -> {original_path}")
                return True
            else:
                self.logger.error(f"Metadata file not found for {quarantine_path}")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to restore from quarantine {quarantine_path}: {e}")
            return False
    
    def protect_critical_directories(self):
        """Enable write protection for critical directories"""
        # This is platform-specific and would require admin privileges
        # On Windows, you might use icacls or similar
        # On Linux, you might change file permissions
        
        critical_dirs = [
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/Desktop"),
        ]
        
        for directory in critical_dirs:
            try:
                # Placeholder for directory protection logic
                # In real implementation, you might:
                # 1. Set read-only permissions
                # 2. Enable file system auditing
                # 3. Create shadow copies/snapshots
                
                self.logger.info(f"Would protect directory: {directory}")
                
            except Exception as e:
                self.logger.error(f"Failed to protect directory {directory}: {e}")

class NetworkController:
    """Control network access and monitor suspicious connections"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.blocked_ips = set()
        self.blocked_domains = set()
    
    def block_network_access(self, process_name: str) -> bool:
        """Block network access for a specific process"""
        try:
            # This would typically use Windows Firewall API or iptables on Linux
            # For demonstration, we'll log the action
            
            self.logger.info(f"Would block network access for process: {process_name}")
            
            # On Windows, you might use:
            # netsh advfirewall firewall add rule name="Block {process_name}" 
            # dir=out action=block program="{process_path}"
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to block network for {process_name}: {e}")
            return False
    
    def block_ip_address(self, ip_address: str) -> bool:
        """Block connection to specific IP address"""
        try:
            self.blocked_ips.add(ip_address)
            
            # Implementation would add firewall rule
            self.logger.info(f"Would block IP address: {ip_address}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to block IP {ip_address}: {e}")
            return False
    
    def block_domain(self, domain: str) -> bool:
        """Block access to specific domain"""
        try:
            self.blocked_domains.add(domain)
            
            # Implementation might modify hosts file or DNS settings
            self.logger.info(f"Would block domain: {domain}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to block domain {domain}: {e}")
            return False
    
    def get_active_connections(self) -> List[Dict[str, Any]]:
        """Get list of active network connections"""
        connections = []
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == psutil.CONN_ESTABLISHED:
                    try:
                        process = psutil.Process(conn.pid) if conn.pid else None
                        
                        connection_info = {
                            'pid': conn.pid,
                            'process_name': process.name() if process else 'Unknown',
                            'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                            'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else 'N/A',
                            'status': conn.status
                        }
                        
                        connections.append(connection_info)
                        
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                        
        except Exception as e:
            self.logger.error(f"Error getting network connections: {e}")
        
        return connections

class AutomatedResponseSystem:
    """Main automated response coordinator"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Initialize subsystems
        self.alert_manager = AlertManager()
        self.process_manager = ProcessManager()
        self.fs_protector = FileSystemProtector()
        self.network_controller = NetworkController()
        
        # Response history
        self.response_history = []
        
        self.logger.info("Automated Response System initialized")
    
    def respond_to_detection(self, detection_result: Dict[str, Any]) -> Dict[str, Any]:
        """Execute automated response to ransomware detection"""
        
        response_id = len(self.response_history) + 1
        response_start = datetime.now()
        
        self.logger.critical(f"INITIATING AUTOMATED RESPONSE #{response_id}")
        
        response_actions = []
        
        try:
            # 1. Send immediate alert
            alert_id = self.alert_manager.send_alert({
                'type': 'ransomware_detection',
                'message': 'Ransomware activity detected by ML model',
                'detection_details': detection_result,
                'response_id': response_id
            }, severity="CRITICAL")
            
            response_actions.append({
                'action': 'alert_sent',
                'status': 'success',
                'details': f'Alert #{alert_id} sent'
            })
            
            # 2. Identify and handle suspicious processes
            if 'suspicious_processes' in detection_result:
                for process_info in detection_result['suspicious_processes']:
                    pid = process_info.get('pid')
                    process_name = process_info.get('name')
                    
                    if pid:
                        # First try to suspend the process
                        if self.process_manager.suspend_process(pid):
                            response_actions.append({
                                'action': 'process_suspended',
                                'status': 'success',
                                'details': f'Suspended {process_name} (PID: {pid})'
                            })
                        else:
                            # If suspension fails, try to kill it
                            if self.process_manager.kill_process(pid):
                                response_actions.append({
                                    'action': 'process_killed',
                                    'status': 'success',
                                    'details': f'Terminated {process_name} (PID: {pid})'
                                })
                            else:
                                response_actions.append({
                                    'action': 'process_termination_failed',
                                    'status': 'failed',
                                    'details': f'Could not stop {process_name} (PID: {pid})'
                                })
            
            # 3. Quarantine suspicious files
            if 'suspicious_files' in detection_result:
                for file_path in detection_result['suspicious_files']:
                    if self.fs_protector.quarantine_file(file_path):
                        response_actions.append({
                            'action': 'file_quarantined',
                            'status': 'success',
                            'details': f'Quarantined {file_path}'
                        })
                    else:
                        response_actions.append({
                            'action': 'file_quarantine_failed',
                            'status': 'failed',
                            'details': f'Could not quarantine {file_path}'
                        })
            
            # 4. Block network connections
            if 'suspicious_connections' in detection_result:
                for conn_info in detection_result['suspicious_connections']:
                    remote_ip = conn_info.get('remote_ip')
                    process_name = conn_info.get('process_name')
                    
                    if remote_ip:
                        if self.network_controller.block_ip_address(remote_ip):
                            response_actions.append({
                                'action': 'ip_blocked',
                                'status': 'success',
                                'details': f'Blocked IP {remote_ip}'
                            })
                    
                    if process_name:
                        if self.network_controller.block_network_access(process_name):
                            response_actions.append({
                                'action': 'network_blocked',
                                'status': 'success',
                                'details': f'Blocked network access for {process_name}'
                            })
            
            # 5. Create backups of critical files
            critical_extensions = ['.doc', '.docx', '.pdf', '.jpg', '.png', '.txt']
            documents_dir = Path.home() / "Documents"
            
            if documents_dir.exists():
                for file_path in documents_dir.rglob("*"):
                    if (file_path.is_file() and 
                        file_path.suffix.lower() in critical_extensions and
                        file_path.stat().st_size < 10 * 1024 * 1024):  # Less than 10MB
                        
                        backup_path = self.fs_protector.create_backup(str(file_path))
                        if backup_path:
                            response_actions.append({
                                'action': 'backup_created',
                                'status': 'success',
                                'details': f'Backed up {file_path.name}'
                            })
            
            # 6. System isolation (if configured)
            if config.ALERT_CONFIG.get('isolate_system', False):
                self._isolate_system()
                response_actions.append({
                    'action': 'system_isolated',
                    'status': 'success',
                    'details': 'System isolated from network'
                })
            
            response_status = 'completed'
            
        except Exception as e:
            self.logger.error(f"Error during automated response: {e}")
            response_actions.append({
                'action': 'response_error',
                'status': 'failed',
                'details': str(e)
            })
            response_status = 'failed'
        
        # Record response
        response_record = {
            'response_id': response_id,
            'timestamp': response_start.isoformat(),
            'duration': (datetime.now() - response_start).total_seconds(),
            'detection_result': detection_result,
            'actions_taken': response_actions,
            'status': response_status
        }
        
        self.response_history.append(response_record)
        
        self.logger.info(f"Automated response #{response_id} {response_status}")
        
        return response_record
    
    def _isolate_system(self):
        """Isolate system from network (emergency measure)"""
        try:
            # This would disable network interfaces
            # Implementation is platform-specific and requires admin privileges
            
            self.logger.critical("SYSTEM ISOLATION INITIATED")
            
            # On Windows: netsh interface set interface "Wi-Fi" admin=disable
            # On Linux: sudo ifconfig eth0 down
            
            # For now, we'll just log the action
            self.logger.info("System would be isolated from network")
            
        except Exception as e:
            self.logger.error(f"Failed to isolate system: {e}")
    
    def manual_response_action(self, action: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute manual response action"""
        
        result = {
            'action': action,
            'timestamp': datetime.now().isoformat(),
            'status': 'failed',
            'details': ''
        }
        
        try:
            if action == 'kill_process':
                pid = parameters.get('pid')
                if pid and self.process_manager.kill_process(pid):
                    result['status'] = 'success'
                    result['details'] = f'Process {pid} terminated'
                else:
                    result['details'] = f'Failed to terminate process {pid}'
            
            elif action == 'quarantine_file':
                file_path = parameters.get('file_path')
                if file_path and self.fs_protector.quarantine_file(file_path):
                    result['status'] = 'success'
                    result['details'] = f'File {file_path} quarantined'
                else:
                    result['details'] = f'Failed to quarantine {file_path}'
            
            elif action == 'block_ip':
                ip_address = parameters.get('ip_address')
                if ip_address and self.network_controller.block_ip_address(ip_address):
                    result['status'] = 'success'
                    result['details'] = f'IP {ip_address} blocked'
                else:
                    result['details'] = f'Failed to block IP {ip_address}'
            
            elif action == 'send_alert':
                alert_data = parameters.get('alert_data', {})
                alert_id = self.alert_manager.send_alert(alert_data)
                result['status'] = 'success'
                result['details'] = f'Alert {alert_id} sent'
            
            else:
                result['details'] = f'Unknown action: {action}'
        
        except Exception as e:
            result['details'] = f'Error executing {action}: {e}'
        
        self.logger.info(f"Manual action executed: {result}")
        return result
    
    def get_response_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent response history"""
        return self.response_history[-limit:]
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get current system security status"""
        return {
            'total_responses': len(self.response_history),
            'alert_statistics': self.alert_manager.get_alert_statistics(),
            'quarantined_processes': len(self.process_manager.quarantined_processes),
            'blocked_ips': len(self.network_controller.blocked_ips),
            'blocked_domains': len(self.network_controller.blocked_domains),
            'active_connections': len(self.network_controller.get_active_connections()),
            'last_response_time': self.response_history[-1]['timestamp'] if self.response_history else None
        }

class ResponseOrchestrator:
    """High-level orchestrator for the response system"""
    
    def __init__(self, ml_detector=None):
        self.logger = logging.getLogger(__name__)
        self.response_system = AutomatedResponseSystem()
        self.ml_detector = ml_detector
        
        self.running = False
        self.monitoring_thread = None
        
    def start_monitoring(self):
        """Start continuous monitoring and response"""
        if self.running:
            self.logger.warning("Response monitoring already running")
            return
        
        self.running = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop)
        self.monitoring_thread.daemon = True
        self.monitoring_thread.start()
        
        self.logger.info("Response monitoring started")
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.running = False
        if self.monitoring_thread:
            self.monitoring_thread.join()
        
        self.logger.info("Response monitoring stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                # This would integrate with the data collector and ML detector
                # For now, it's a placeholder for the monitoring logic
                
                time.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(30)  # Wait longer on error
    
    def handle_detection(self, detection_result: Dict[str, Any]) -> Dict[str, Any]:
        """Handle a detection result from the ML system"""
        
        self.logger.info(f"Handling detection result: {detection_result.get('ransomware_detected', False)}")
        
        if detection_result.get('ransomware_detected', False):
            # Execute automated response
            response_record = self.response_system.respond_to_detection(detection_result)
            return response_record
        else:
            # Log normal activity
            self.logger.debug("No threats detected")
            return {'status': 'no_action_required'}

if __name__ == "__main__":
    # Test the response system
    response_system = AutomatedResponseSystem()
    
    # Test alert
    test_detection = {
        'ransomware_detected': True,
        'max_probability': 0.95,
        'suspicious_processes': [
            {'pid': 1234, 'name': 'suspicious.exe'}
        ],
        'suspicious_files': [],
        'suspicious_connections': []
    }
    
    print("Testing automated response system...")
    response = response_system.respond_to_detection(test_detection)
    print(f"Response completed with {len(response['actions_taken'])} actions")
    
    # Get system status
    status = response_system.get_system_status()
    print(f"System status: {status}")