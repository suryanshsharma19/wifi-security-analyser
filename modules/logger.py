import logging
import os
from datetime import datetime
from .config import config

# Create logs directory if it doesn't exist
log_dir = os.path.join(config.BASE_DIR, 'logs')
os.makedirs(log_dir, exist_ok=True)

# Configure logging
log_file = os.path.join(log_dir, config.LOG_FILE)
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('wifi_analyzer')

def log_scan_results(networks):
    """Log the results of a WiFi scan"""
    logger.info(f"Scan completed. Found {len(networks['Visible Networks'])} visible networks "
                f"and {len(networks['Hidden Networks'])} hidden networks")
    
    for bssid, network in networks['Visible Networks'].items():
        logger.info(f"Network: {network['SSID']} (BSSID: {bssid})")
        logger.info(f"  Signal Strength: {network['Signal Strength']} dBm")
        logger.info(f"  Channel: {network['Channel']}")
        logger.info(f"  Encryption: {network['Encryption']}")

def log_threat(threat_type, details):
    """Log a security threat"""
    logger.warning(f"Threat detected - {threat_type}: {details}")

def log_error(error, context=None):
    """Log an error with context"""
    if context:
        logger.error(f"{context}: {str(error)}")
    else:
        logger.error(str(error)) 