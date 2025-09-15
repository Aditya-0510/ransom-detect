import os
import logging
from pathlib import Path

class Config:
    """Configuration settings for the ransomware detection system"""
    MONITOR_DIRECTORIES = [
        "C:\\Users\\saiad\\Documents",  # Windows
        "C:\\Users\\saiad\\Desktop",
    ]

    # ALERT_CONFIG = {
    #     'email_enabled': True,
    #     'email_recipients': ['your-email@domain.com'],
    #     'log_alerts': True,
    # }

    # Adjust ML parameters
    ML_CONFIG = {
        'prediction_threshold': 0.7,  
        'feature_window_size': 60,    # seconds
        'model_retrain_interval': 3600, # seconds
    }
    
    # Base directories
    BASE_DIR = Path(__file__).parent
    DATA_DIR = BASE_DIR / "data"
    RAW_DATA_DIR = DATA_DIR / "raw"
    PROCESSED_DATA_DIR = DATA_DIR / "processed"
    MODELS_DIR = DATA_DIR / "models"
    LOGS_DIR = BASE_DIR / "logs"
    
    # Ensure directories exist
    for directory in [DATA_DIR, RAW_DATA_DIR, PROCESSED_DATA_DIR, MODELS_DIR, LOGS_DIR]:
        directory.mkdir(parents=True, exist_ok=True)
    
    # Monitoring Configuration
    MONITOR_DIRECTORIES = [
        os.path.expanduser("~/Documents"),
        os.path.expanduser("~/Desktop"),
        os.path.expanduser("~/Downloads"),
    ]
    
    # File extensions to monitor (commonly targeted by ransomware)
    MONITORED_EXTENSIONS = {
        'documents': ['.doc', '.docx', '.pdf', '.txt', '.rtf', '.odt'],
        'spreadsheets': ['.xls', '.xlsx', '.csv', '.ods'],
        'presentations': ['.ppt', '.pptx', '.odp'],
        'images': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff'],
        'videos': ['.mp4', '.avi', '.mkv', '.mov', '.wmv'],
        'archives': ['.zip', '.rar', '.7z', '.tar', '.gz'],
        'databases': ['.db', '.sqlite', '.mdb', '.accdb'],
    }
    
    # Suspicious file extensions (often created by ransomware)
    SUSPICIOUS_EXTENSIONS = [
        '.encrypted', '.locked', '.crypto', '.crypt', '.enc', '.axx',
        '.zzz', '.xyz', '.aaa', '.abc', '.micro', '.ttt', '.xxx',
        '.locky', '.zepto', '.thor', '.sage', '.cerber'
    ]
    
    # Process monitoring settings
    SUSPICIOUS_PROCESS_NAMES = [
        'cipher.exe', 'vssadmin.exe', 'wbadmin.exe', 'bcdedit.exe',
        'sdelete.exe', 'wmic.exe', 'reg.exe', 'powershell.exe'
    ]
    
    # Network monitoring
    SUSPICIOUS_DOMAINS = [
        # Common ransomware C&C domains (examples)
        'torproject.org', '.onion', 'bit.ly', 'tinyurl.com'
    ]
    
    # Machine Learning Configuration
    ML_CONFIG = {
        'feature_window_size': 60,  # seconds
        'prediction_threshold': 0.7,
        'model_retrain_interval': 3600,  # seconds
        'max_features': 50,
        'test_size': 0.2,
        'random_state': 42,
    }
    
    # Alert Configuration
    ALERT_CONFIG = {
        'email_enabled': False,
        'email_recipients': ['admin@company.com'],
        'sms_enabled': False,
        'log_alerts': True,
        'quarantine_enabled': True,
    }
    
    # Logging Configuration
    LOG_CONFIG = {
        'level': logging.INFO,
        'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        'file': LOGS_DIR / 'ransomware_detector.log',
        'max_bytes': 10 * 1024 * 1024,  # 10MB
        'backup_count': 5,
    }
    
    # Web Interface Configuration (optional)
    WEB_CONFIG = {
        'host': '127.0.0.1',
        'port': 5000,
        'debug': True,
        # 'secret_key': 'your-secret-key-here-change-this',
    }

# Global configuration instance
config = Config()