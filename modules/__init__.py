"""
WiFi Security Analyzer Modules

This package contains all the core modules for the WiFi Security Analyzer:
- Packet Analysis
- WiFi Scanning
- Vulnerability Prediction
- Heatmap Visualization
- Threat Detection
- Web Dashboard (Backend & Frontend)
"""

from .packet_analysis import analyze_live_traffic
from .wifi_scanning import advanced_scan
from .vulnerability_prediction import train_model, predict_vulnerability
from .heatmap_visualization import visualize_heatmap
from .threat_detection import detect_threats
from .web_dashboard_backend import start_server

__all__ = [
    'analyze_live_traffic',
    'advanced_scan',
    'train_model',
    'predict_vulnerability',
    'visualize_heatmap',
    'detect_threats',
    'start_server'
] 