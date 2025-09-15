import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple
from collections import Counter, defaultdict
import logging
import json
import re
from pathlib import Path

from config import config

class RansomwareFeatureExtractor:
    """Extract behavioral features for ransomware detection"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Compile regex patterns for efficiency
        self.crypto_patterns = [
            re.compile(r'encrypt|decrypt|cipher|crypt|aes|rsa', re.IGNORECASE),
            re.compile(r'key|password|ransom|bitcoin|btc', re.IGNORECASE),
        ]
        
        self.file_patterns = [
            re.compile(r'\.(?:doc|pdf|jpg|png|txt|xls)$', re.IGNORECASE),  # Target files
            re.compile(r'\.(?:encrypted|locked|crypto)$', re.IGNORECASE),   # Encrypted files
        ]
        
    def extract_time_window_features(self, events_data: Dict[str, List[Dict]], 
                                   window_size: int = 60) -> List[Dict[str, Any]]:
        """Extract features from time windows of events"""
        features_list = []
        
        # Get all timestamps and sort
        all_timestamps = []
        for event_type, events in events_data.items():
            for event in events:
                timestamp = datetime.fromisoformat(event['timestamp'])
                all_timestamps.append(timestamp)
        
        if not all_timestamps:
            return features_list
            
        all_timestamps.sort()
        start_time = all_timestamps[0]
        end_time = all_timestamps[-1]
        
        # Create sliding windows
        current_time = start_time
        window_delta = timedelta(seconds=window_size)
        
        while current_time < end_time:
            window_end = current_time + window_delta
            
            # Get events in this window
            window_events = self._get_events_in_window(
                events_data, current_time, window_end
            )
            
            # Extract features for this window
            if self._has_sufficient_activity(window_events):
                features = self._extract_window_features(
                    window_events, current_time, window_end
                )
                features_list.append(features)
            
            current_time += timedelta(seconds=window_size // 2)  # 50% overlap
        
        self.logger.info(f"Extracted features for {len(features_list)} time windows")
        return features_list
    
    def _get_events_in_window(self, events_data: Dict[str, List[Dict]], 
                            start_time: datetime, end_time: datetime) -> Dict[str, List[Dict]]:
        """Get events within specified time window"""
        window_events = defaultdict(list)
        
        for event_type, events in events_data.items():
            for event in events:
                event_time = datetime.fromisoformat(event['timestamp'])
                if start_time <= event_time < end_time:
                    window_events[event_type].append(event)
        
        return window_events
    
    def _has_sufficient_activity(self, window_events: Dict[str, List[Dict]]) -> bool:
        """Check if window has sufficient activity for analysis"""
        total_events = sum(len(events) for events in window_events.values())
        return total_events >= 10  # Minimum threshold
    
    def _extract_window_features(self, window_events: Dict[str, List[Dict]], 
                               start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Extract comprehensive features for a time window"""
        features = {
            'timestamp': start_time.isoformat(),
            'window_duration': (end_time - start_time).total_seconds(),
        }
        
        # Basic event counts
        features.update(self._extract_event_count_features(window_events))
        
        # File system features
        features.update(self._extract_file_features(window_events.get('file_events', [])))
        
        # Process features
        features.update(self._extract_process_features(window_events.get('process_events', [])))
        
        # System metrics features
        features.update(self._extract_system_features(window_events.get('system_metrics', [])))
        
        # Behavioral pattern features
        features.update(self._extract_behavioral_features(window_events))
        
        # Alert features
        features.update(self._extract_alert_features(window_events.get('alerts', [])))
        
        return features
    
    def _extract_event_count_features(self, window_events: Dict[str, List[Dict]]) -> Dict[str, int]:
        """Extract basic event count features"""
        return {
            'total_file_events': len(window_events.get('file_events', [])),
            'total_process_events': len(window_events.get('process_events', [])),
            'total_system_metrics': len(window_events.get('system_metrics', [])),
            'total_alerts': len(window_events.get('alerts', [])),
            'total_events': sum(len(events) for events in window_events.values()),
        }
    
    def _extract_file_features(self, file_events: List[Dict]) -> Dict[str, Any]:
        """Extract file system related features"""
        if not file_events:
            return self._get_empty_file_features()
        
        features = {}
        
        # Event type distribution
        event_types = [event.get('event_type', '') for event in file_events]
        event_counter = Counter(event_types)
        
        features.update({
            'file_created_count': event_counter.get('created', 0),
            'file_modified_count': event_counter.get('modified', 0),
            'file_deleted_count': event_counter.get('deleted', 0),
            'file_moved_count': event_counter.get('moved', 0),
        })
        
        # File extension analysis
        file_paths = [event.get('src_path', '') for event in file_events]
        features.update(self._analyze_file_extensions(file_paths))
        
        # File path entropy (randomness)
        features['avg_filename_entropy'] = self._calculate_avg_filename_entropy(file_paths)
        
        # Rapid file operations (potential mass encryption)
        features['rapid_file_operations'] = self._detect_rapid_operations(file_events)
        
        # File size changes (if available)
        features.update(self._analyze_file_sizes(file_events))
        
        return features
    
    def _get_empty_file_features(self) -> Dict[str, Any]:
        """Return zero values for file features when no events exist"""
        return {
            'file_created_count': 0, 'file_modified_count': 0, 'file_deleted_count': 0,
            'file_moved_count': 0, 'document_files_affected': 0, 'image_files_affected': 0,
            'encrypted_files_created': 0, 'avg_filename_entropy': 0.0,
            'rapid_file_operations': 0, 'suspicious_extension_ratio': 0.0,
        }
    
    def _analyze_file_extensions(self, file_paths: List[str]) -> Dict[str, Any]:
        """Analyze file extensions for suspicious patterns"""
        features = {}
        
        # Count by file type
        document_count = image_count = encrypted_count = 0
        all_extensions = []
        
        for path in file_paths:
            if not path:
                continue
                
            ext = Path(path).suffix.lower()
            all_extensions.append(ext)
            
            # Categorize extensions
            if ext in [item for sublist in config.MONITORED_EXTENSIONS.values() for item in sublist]:
                if ext in config.MONITORED_EXTENSIONS['documents']:
                    document_count += 1
                elif ext in config.MONITORED_EXTENSIONS['images']:
                    image_count += 1
            
            if ext in config.SUSPICIOUS_EXTENSIONS:
                encrypted_count += 1
        
        total_files = len(file_paths)
        features.update({
            'document_files_affected': document_count,
            'image_files_affected': image_count,
            'encrypted_files_created': encrypted_count,
            'suspicious_extension_ratio': encrypted_count / max(total_files, 1),
        })
        
        return features
    
    def _calculate_avg_filename_entropy(self, file_paths: List[str]) -> float:
        """Calculate average entropy of filenames (randomness indicator)"""
        if not file_paths:
            return 0.0
        
        entropies = []
        for path in file_paths:
            if not path:
                continue
                
            filename = Path(path).stem
            if filename:
                entropy = self._calculate_entropy(filename)
                entropies.append(entropy)
        
        return np.mean(entropies) if entropies else 0.0
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        
        # Count character frequencies
        char_counts = Counter(text.lower())
        text_length = len(text)
        
        # Calculate entropy
        entropy = 0.0
        for count in char_counts.values():
            probability = count / text_length
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        return entropy
    
    def _detect_rapid_operations(self, file_events: List[Dict]) -> int:
        """Detect rapid file operations (potential mass encryption)"""
        if len(file_events) < 5:
            return 0
        
        # Sort events by timestamp
        sorted_events = sorted(file_events, key=lambda x: x.get('timestamp', ''))
        
        rapid_count = 0
        window_size = 5  # Check every 5 events
        time_threshold = 2.0  # 2 seconds
        
        for i in range(len(sorted_events) - window_size + 1):
            window_events = sorted_events[i:i + window_size]
            
            try:
                start_time = datetime.fromisoformat(window_events[0]['timestamp'])
                end_time = datetime.fromisoformat(window_events[-1]['timestamp'])
                duration = (end_time - start_time).total_seconds()
                
                if duration <= time_threshold:
                    rapid_count += 1
            except (ValueError, KeyError):
                continue
        
        return rapid_count
    
    def _analyze_file_sizes(self, file_events: List[Dict]) -> Dict[str, Any]:
        """Analyze file size patterns (placeholder - would need actual file sizes)"""
        # This would require additional system calls to get file sizes
        # For now, return placeholder values
        return {
            'avg_file_size_change': 0.0,
            'large_files_affected': 0,
        }
    
    def _extract_process_features(self, process_events: List[Dict]) -> Dict[str, Any]:
        """Extract process-related features"""
        if not process_events:
            return self._get_empty_process_features()
        
        features = {}
        
        # Process names and commands
        process_names = [event.get('name', '') for event in process_events]
        cmdlines = [event.get('cmdline', '') for event in process_events]
        
        # Suspicious process detection
        features['suspicious_processes'] = sum(
            1 for name in process_names 
            if name.lower() in [p.lower() for p in config.SUSPICIOUS_PROCESS_NAMES]
        )
        
        # Crypto-related process analysis
        features['crypto_related_processes'] = self._count_crypto_processes(process_names, cmdlines)
        
        # Unique processes
        features['unique_processes_started'] = len(set(process_names))
        
        # Process execution rate
        features['process_execution_rate'] = len(process_events)
        
        # System administration tools
        features['admin_tools_executed'] = self._count_admin_tools(process_names)
        
        # Command line analysis
        features.update(self._analyze_command_lines(cmdlines))
        
        return features
    
    def _get_empty_process_features(self) -> Dict[str, Any]:
        """Return zero values for process features when no events exist"""
        return {
            'suspicious_processes': 0, 'crypto_related_processes': 0,
            'unique_processes_started': 0, 'process_execution_rate': 0,
            'admin_tools_executed': 0, 'suspicious_commands': 0,
            'avg_cmdline_length': 0.0, 'powershell_executions': 0,
        }
    
    def _count_crypto_processes(self, process_names: List[str], cmdlines: List[str]) -> int:
        """Count processes related to cryptographic operations"""
        crypto_count = 0
        
        for name, cmdline in zip(process_names, cmdlines):
            text_to_check = f"{name} {cmdline}".lower()
            
            for pattern in self.crypto_patterns:
                if pattern.search(text_to_check):
                    crypto_count += 1
                    break
        
        return crypto_count
    
    def _count_admin_tools(self, process_names: List[str]) -> int:
        """Count system administration tools"""
        admin_tools = ['vssadmin.exe', 'wbadmin.exe', 'bcdedit.exe', 'sdelete.exe', 'cipher.exe']
        return sum(1 for name in process_names if name.lower() in admin_tools)
    
    def _analyze_command_lines(self, cmdlines: List[str]) -> Dict[str, Any]:
        """Analyze command line arguments"""
        features = {}
        
        # Suspicious command patterns
        suspicious_patterns = [
            'vssadmin delete shadows', 'cipher /w', 'bcdedit /set',
            'wbadmin delete catalog', 'reg delete', 'taskkill /f'
        ]
        
        suspicious_count = 0
        powershell_count = 0
        total_length = 0
        
        for cmdline in cmdlines:
            if not cmdline:
                continue
                
            cmdline_lower = cmdline.lower()
            total_length += len(cmdline)
            
            # Check for suspicious patterns
            for pattern in suspicious_patterns:
                if pattern in cmdline_lower:
                    suspicious_count += 1
                    break
            
            # Count PowerShell executions
            if 'powershell' in cmdline_lower:
                powershell_count += 1
        
        features.update({
            'suspicious_commands': suspicious_count,
            'avg_cmdline_length': total_length / max(len(cmdlines), 1),
            'powershell_executions': powershell_count,
        })
        
        return features
    
    def _extract_system_features(self, system_metrics: List[Dict]) -> Dict[str, Any]:
        """Extract system performance features"""
        if not system_metrics:
            return self._get_empty_system_features()
        
        features = {}
        
        # Extract numeric metrics
        cpu_values = []
        memory_values = []
        disk_io_reads = []
        disk_io_writes = []
        network_sent = []
        network_recv = []
        
        for metric in system_metrics:
            cpu_values.append(metric.get('cpu_percent', 0))
            memory_values.append(metric.get('memory_percent', 0))
            
            disk_io = metric.get('disk_io', {})
            disk_io_reads.append(disk_io.get('read_bytes', 0))
            disk_io_writes.append(disk_io.get('write_bytes', 0))
            
            network_io = metric.get('network_io', {})
            network_sent.append(network_io.get('bytes_sent', 0))
            network_recv.append(network_io.get('bytes_recv', 0))
        
        # Calculate statistics
        features.update({
            'avg_cpu_usage': np.mean(cpu_values),
            'max_cpu_usage': np.max(cpu_values),
            'avg_memory_usage': np.mean(memory_values),
            'max_memory_usage': np.max(memory_values),
        })
        
        # Disk I/O features
        if len(disk_io_reads) > 1:
            read_diff = np.diff(disk_io_reads)
            write_diff = np.diff(disk_io_writes)
            features.update({
                'avg_disk_read_rate': np.mean(read_diff),
                'avg_disk_write_rate': np.mean(write_diff),
                'max_disk_write_rate': np.max(write_diff),
            })
        else:
            features.update({
                'avg_disk_read_rate': 0, 'avg_disk_write_rate': 0, 'max_disk_write_rate': 0
            })
        
        # Network I/O features
        if len(network_sent) > 1:
            sent_diff = np.diff(network_sent)
            recv_diff = np.diff(network_recv)
            features.update({
                'avg_network_sent_rate': np.mean(sent_diff),
                'avg_network_recv_rate': np.mean(recv_diff),
            })
        else:
            features.update({
                'avg_network_sent_rate': 0, 'avg_network_recv_rate': 0
            })
        
        return features
    
    def _get_empty_system_features(self) -> Dict[str, Any]:
        """Return zero values for system features when no metrics exist"""
        return {
            'avg_cpu_usage': 0.0, 'max_cpu_usage': 0.0, 'avg_memory_usage': 0.0,
            'max_memory_usage': 0.0, 'avg_disk_read_rate': 0, 'avg_disk_write_rate': 0,
            'max_disk_write_rate': 0, 'avg_network_sent_rate': 0, 'avg_network_recv_rate': 0,
        }
    
    def _extract_behavioral_features(self, window_events: Dict[str, List[Dict]]) -> Dict[str, Any]:
        """Extract behavioral pattern features"""
        features = {}
        
        # Cross-event correlations
        file_events = window_events.get('file_events', [])
        process_events = window_events.get('process_events', [])
        
        # File encryption patterns
        features['potential_mass_encryption'] = self._detect_mass_encryption_pattern(file_events)
        
        # Process-file correlation
        features['process_file_correlation'] = self._calculate_process_file_correlation(
            process_events, file_events
        )
        
        # Temporal patterns
        features.update(self._extract_temporal_patterns(window_events))
        
        return features
    
    def _detect_mass_encryption_pattern(self, file_events: List[Dict]) -> int:
        """Detect patterns indicative of mass file encryption"""
        if len(file_events) < 10:
            return 0
        
        # Look for rapid file modifications followed by new file creation
        # This is a simplified heuristic
        modifications = sum(1 for event in file_events if event.get('event_type') == 'modified')
        creations = sum(1 for event in file_events if event.get('event_type') == 'created')
        
        # High ratio of modifications to total events + suspicious file creation
        modification_ratio = modifications / len(file_events)
        
        if modification_ratio > 0.7 and creations > 5:
            return 1
        return 0
    
    def _calculate_process_file_correlation(self, process_events: List[Dict], 
                                          file_events: List[Dict]) -> float:
        """Calculate correlation between process starts and file operations"""
        if not process_events or not file_events:
            return 0.0
        
        # Simple temporal correlation - count overlapping time periods
        process_times = [datetime.fromisoformat(p['timestamp']) for p in process_events]
        file_times = [datetime.fromisoformat(f['timestamp']) for f in file_events]
        
        # Count file events that occur within 5 seconds of process starts
        correlation_count = 0
        for proc_time in process_times:
            for file_time in file_times:
                if abs((file_time - proc_time).total_seconds()) <= 5:
                    correlation_count += 1
                    break
        
        return correlation_count / len(process_events)
    
    def _extract_temporal_patterns(self, window_events: Dict[str, List[Dict]]) -> Dict[str, Any]:
        """Extract temporal behavior patterns"""
        features = {}
        
        all_events = []
        for events in window_events.values():
            all_events.extend(events)
        
        if not all_events:
            return {'event_burst_intensity': 0.0, 'activity_consistency': 0.0}
        
        # Sort all events by timestamp
        try:
            timestamps = [datetime.fromisoformat(event['timestamp']) for event in all_events]
            timestamps.sort()
            
            # Calculate event burst intensity
            if len(timestamps) > 1:
                time_diffs = [(timestamps[i+1] - timestamps[i]).total_seconds() 
                             for i in range(len(timestamps)-1)]
                
                # Burst intensity - inverse of average time between events
                avg_time_diff = np.mean(time_diffs)
                features['event_burst_intensity'] = 1.0 / max(avg_time_diff, 0.1)
                
                # Activity consistency - standard deviation of time differences
                features['activity_consistency'] = 1.0 / (np.std(time_diffs) + 1.0)
            else:
                features['event_burst_intensity'] = 0.0
                features['activity_consistency'] = 0.0
                
        except (ValueError, KeyError):
            features['event_burst_intensity'] = 0.0
            features['activity_consistency'] = 0.0
        
        return features
    
    def _extract_alert_features(self, alerts: List[Dict]) -> Dict[str, Any]:
        """Extract alert-based features"""
        features = {}
        
        if not alerts:
            return {
                'suspicious_file_alerts': 0, 'suspicious_process_alerts': 0,
                'suspicious_command_alerts': 0, 'total_alert_score': 0.0
            }
        
        # Count alert types
        alert_types = [alert.get('type', '') for alert in alerts]
        alert_counter = Counter(alert_types)
        
        features.update({
            'suspicious_file_alerts': alert_counter.get('suspicious_file', 0),
            'suspicious_process_alerts': alert_counter.get('suspicious_process', 0),
            'suspicious_command_alerts': alert_counter.get('suspicious_command', 0),
        })
        
        # Calculate total alert score (weighted)
        weights = {'suspicious_file': 2.0, 'suspicious_process': 3.0, 'suspicious_command': 4.0}
        total_score = sum(alert_counter[alert_type] * weights.get(alert_type, 1.0) 
                         for alert_type in alert_counter)
        features['total_alert_score'] = total_score
        
        return features
    
    def create_feature_matrix(self, features_list: List[Dict[str, Any]]) -> Tuple[pd.DataFrame, List[str]]:
        """Create feature matrix from extracted features"""
        if not features_list:
            raise ValueError("No features to create matrix from")
        
        # Create DataFrame
        df = pd.DataFrame(features_list)
        
        # Get feature columns (exclude timestamp and metadata)
        feature_columns = [col for col in df.columns if col not in ['timestamp', 'window_duration']]
        
        # Handle missing values
        df[feature_columns] = df[feature_columns].fillna(0)
        
        # Ensure all features are numeric
        for col in feature_columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
        
        self.logger.info(f"Created feature matrix with shape: {df[feature_columns].shape}")
        return df[feature_columns], feature_columns
    
    def save_features(self, features_list: List[Dict[str, Any]], filepath: str = None):
        """Save extracted features to file"""
        if not filepath:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = config.PROCESSED_DATA_DIR / f"features_{timestamp}.json"
        
        with open(filepath, 'w') as f:
            json.dump(features_list, f, indent=2)
        
        self.logger.info(f"Features saved to {filepath}")
        return filepath
    
    def load_features(self, filepath: str) -> List[Dict[str, Any]]:
        """Load features from file"""
        with open(filepath, 'r') as f:
            features_list = json.load(f)
        
        self.logger.info(f"Loaded {len(features_list)} feature windows from {filepath}")
        return features_list

def create_synthetic_labels(features_df: pd.DataFrame, 
                          alert_threshold: float = 3.0,
                          ensure_both_classes: bool = True) -> np.ndarray:
    """Create synthetic labels for training with better class distribution"""
    
    labels = []
    scores = []
    
    for _, row in features_df.iterrows():
        score = 0
        
        # High alert score (weighted more heavily)
        if row.get('total_alert_score', 0) >= alert_threshold:
            score += 4
        elif row.get('total_alert_score', 0) > 0:
            score += 2
        
        # Suspicious file patterns
        if row.get('encrypted_files_created', 0) > 3:
            score += 3
        elif row.get('encrypted_files_created', 0) > 0:
            score += 1
        
        if row.get('suspicious_extension_ratio', 0) > 0.2:
            score += 2
        
        # Rapid file operations
        if row.get('rapid_file_operations', 0) > 5:
            score += 2
        
        # Process indicators
        if row.get('suspicious_processes', 0) > 0:
            score += 3
        
        if row.get('suspicious_commands', 0) > 0:
            score += 4
        
        # System resource usage
        if row.get('max_disk_write_rate', 0) > 500000:  # High disk writes
            score += 1
        
        # Mass encryption pattern
        if row.get('potential_mass_encryption', 0) > 0:
            score += 5
        
        # High file activity
        if row.get('total_file_events', 0) > 50:
            score += 1
        
        # Process-file correlation
        if row.get('process_file_correlation', 0) > 0.7:
            score += 2
        
        scores.append(score)
    
    # Determine threshold for binary classification
    scores = np.array(scores)
    
    if ensure_both_classes and len(features_df) > 1:
        # Ensure we have both classes by using a threshold that creates a reasonable split
        sorted_scores = np.sort(scores)
        
        # Try to create roughly 20-30% positive samples
        threshold_idx = int(len(sorted_scores) * 0.75)  # Top 25% as positive
        threshold = sorted_scores[threshold_idx]
        
        # Ensure threshold is at least 3
        threshold = max(3, threshold)
        
        # If all scores are the same, randomly assign some as positive
        if np.all(scores == scores[0]):
            n_positive = max(1, len(scores) // 4)  # At least 1, up to 25%
            positive_indices = np.random.choice(len(scores), n_positive, replace=False)
            labels = np.zeros(len(scores), dtype=int)
            labels[positive_indices] = 1
        else:
            labels = (scores >= threshold).astype(int)
        
        # Ensure we have at least one positive and one negative sample
        if np.sum(labels) == 0:
            # If no positives, make the highest score positive
            max_idx = np.argmax(scores)
            labels[max_idx] = 1
        elif np.sum(labels) == len(labels):
            # If all positives, make the lowest score negative
            min_idx = np.argmin(scores)
            labels[min_idx] = 0
    else:
        # Use fixed threshold
        labels = (scores >= 4).astype(int)
    
    labels = np.array(labels)
    
    print(f"Generated labels: {np.sum(labels)} positive out of {len(labels)} total")
    print(f"Class distribution: {dict(zip(*np.unique(labels, return_counts=True)))}")
    
    return labels

if __name__ == "__main__":
    # Test feature extraction
    extractor = RansomwareFeatureExtractor()
    
    # Load sample data (you would load from data collector)
    print("Feature extraction module ready for testing!")
    print("Use with DataCollector to extract features from collected system events.")