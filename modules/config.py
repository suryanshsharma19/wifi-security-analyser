"""
Configuration module for WiFi Security Analyzer
"""
import os
import platform
import json
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get system-specific defaults
SYSTEM = platform.system().lower()
IS_WINDOWS = SYSTEM == 'windows'
DEFAULT_INTERFACE = "Wi-Fi" if IS_WINDOWS else "wlan0"

DEFAULT_CONFIG = {
    "simulation_mode": True,  # Default to simulation mode for testing
    "interface": DEFAULT_INTERFACE,    # System-specific default interface
    "scan_interval": 2,      # Scan interval in seconds
    "web_port": 5000,        # Web dashboard port
    "save_logs": True,       # Whether to save logs
    "log_file": "wifi_analyzer.log",
    "simulation_data": {
        "networks": {
            "00:11:22:33:44:55": {
                "SSID": "Home_Network",
                "Signal Strength": -45,
                "Channel": 6,
                "Encryption": "WPA2"
            },
            "AA:BB:CC:DD:EE:FF": {
                "SSID": "Public_WiFi",
                "Signal Strength": -75,
                "Channel": 11,
                "Encryption": "None"
            }
        }
    }
}

class Config:
    # Application settings
    DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
    SIMULATION_MODE = os.getenv('SIMULATION_MODE', 'True').lower() == 'true'
    
    # Network settings
    SCAN_INTERVAL = int(os.getenv('SCAN_INTERVAL', '5'))  # seconds
    MAX_NETWORKS = int(os.getenv('MAX_NETWORKS', '100'))
    
    # Web server settings
    HOST = os.getenv('HOST', '127.0.0.1')
    PORT = int(os.getenv('PORT', '5000'))
    
    # Security thresholds
    SIGNAL_STRENGTH_THRESHOLD = int(os.getenv('SIGNAL_STRENGTH_THRESHOLD', '-80'))
    CHANNEL_CONGESTION_THRESHOLD = int(os.getenv('CHANNEL_CONGESTION_THRESHOLD', '3'))
    
    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = os.getenv('LOG_FILE', 'wifi_analyzer.log')
    
    # Paths
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    DATA_DIR = os.path.join(BASE_DIR, 'data')
    MODELS_DIR = os.path.join(BASE_DIR, 'models')
    
    def __init__(self):
        self.config_file = Path(os.path.join(self.BASE_DIR, "config.json"))
        self.config = self.load_config()
        
        # Create necessary directories
        os.makedirs(self.DATA_DIR, exist_ok=True)
        os.makedirs(self.MODELS_DIR, exist_ok=True)
    
    def load_config(self):
        """Load configuration from file or create default"""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
                    # Merge with defaults, preserving system-specific values
                    merged_config = DEFAULT_CONFIG.copy()
                    merged_config.update(loaded_config)
                    # Ensure interface is system-appropriate
                    if IS_WINDOWS and merged_config["interface"] in ["wlan0", "wlan0mon"]:
                        merged_config["interface"] = DEFAULT_INTERFACE
                    return merged_config
            return DEFAULT_CONFIG.copy()
        except Exception as e:
            print(f"Error loading config: {str(e)}")
            return DEFAULT_CONFIG.copy()
    
    def save_config(self):
        """Save current configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            print(f"Error saving config: {str(e)}")
    
    def get(self, key, default=None):
        """Get configuration value"""
        return self.config.get(key, default)
    
    def set(self, key, value):
        """Set configuration value"""
        self.config[key] = value
        self.save_config()
    
    @property
    def is_windows(self):
        """Check if running on Windows"""
        return IS_WINDOWS
    
    @property
    def simulation_mode(self):
        """Get simulation mode status"""
        return self.config['simulation_mode']
    
    @simulation_mode.setter
    def simulation_mode(self, value):
        """Set simulation mode status"""
        self.config['simulation_mode'] = bool(value)
        self.save_config()

# Global configuration instance
config = Config() 