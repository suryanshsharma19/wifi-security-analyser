import sys
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QPushButton, QLabel, QTableWidget, 
                            QTableWidgetItem, QTabWidget, QProgressBar, 
                            QComboBox, QMessageBox, QGroupBox, QMenuBar, 
                            QMenu, QStatusBar, QFileDialog)
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt6.QtGui import QIcon, QColor, QAction
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import numpy as np
from datetime import datetime, timedelta
import os

from modules.wifi_scanning import advanced_scan, get_windows_interfaces
from modules.config import config
from modules.logger import logger

class WiFiScannerThread(QThread):
    update_signal = pyqtSignal(dict)
    threat_signal = pyqtSignal(str, str)
    performance_signal = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.running = True
        self.historical_data = {}  # Store historical network data
        self.device_fingerprints = {}  # Store device fingerprints
        self.simulation_data = config.get("simulation_data", {}).get("networks", {})
        
    def get_simulation_networks(self):
        """Get simulated network data"""
        networks = {}
        for bssid, info in self.simulation_data.items():
            # Add some randomness to make it more realistic
            signal_variation = np.random.randint(-5, 5)
            info["Signal Strength"] += signal_variation
            
            # Add performance data
            info["Performance"] = {
                "Signal Quality": self.calculate_signal_quality(info["Signal Strength"]),
                "Channel Congestion": self.calculate_channel_congestion(info["Channel"]),
                "Network Stability": "Stable",
                "Device Count": np.random.randint(1, 10),
                "Health Score": self.calculate_health_score(info)
            }
            
            # Add security status
            if info["Encryption"] == "None":
                info["Security"] = "Vulnerable"
            elif info["Encryption"] == "WEP":
                info["Security"] = "Moderate"
            else:
                info["Security"] = "Secure"
                
            networks[bssid] = info
            
        return networks
        
    def analyze_network_performance(self, network):
        """Analyze network performance metrics"""
        try:
            performance = {
                "Signal Quality": self.calculate_signal_quality(network["Signal Strength"]),
                "Channel Congestion": self.calculate_channel_congestion(network["Channel"]),
                "Network Stability": self.calculate_network_stability(network["BSSID"]),
                "Device Count": len(self.device_fingerprints.get(network["BSSID"], [])),
                "Health Score": self.calculate_health_score(network)
            }
            self.performance_signal.emit(performance)
            return performance
        except Exception as e:
            logger.error(f"Failed to analyze performance: {str(e)}")
            return {}
            
    def calculate_signal_quality(self, signal_strength):
        """Calculate signal quality based on signal strength"""
        if signal_strength >= -50:
            return "Excellent"
        elif signal_strength >= -60:
            return "Good"
        elif signal_strength >= -70:
            return "Fair"
        else:
            return "Poor"
            
    def calculate_channel_congestion(self, channel):
        """Calculate channel congestion based on overlapping networks"""
        overlapping_channels = [channel-1, channel, channel+1]
        congestion = sum(1 for net in self.historical_data.values() 
                        if net["Channel"] in overlapping_channels)
        return "High" if congestion > 3 else "Medium" if congestion > 1 else "Low"
        
    def calculate_network_stability(self, bssid):
        """Calculate network stability based on historical data"""
        if bssid not in self.historical_data:
            return "Unknown"
            
        history = self.historical_data[bssid]
        if len(history) < 2:
            return "New"
            
        # Calculate signal strength variation
        signal_variation = max(h["Signal Strength"] for h in history) - min(h["Signal Strength"] for h in history)
        return "Stable" if signal_variation < 10 else "Unstable"
        
    def calculate_health_score(self, network):
        """Calculate overall network health score"""
        score = 100
        
        # Deduct points based on various factors
        if network["Encryption"] == "None":
            score -= 30
        elif network["Encryption"] == "WEP":
            score -= 20
        elif network["Encryption"] == "WPA":
            score -= 10
            
        if network["Signal Strength"] < -70:
            score -= 20
        elif network["Signal Strength"] < -60:
            score -= 10
            
        # Deduct points for channel congestion
        congestion = self.calculate_channel_congestion(network["Channel"])
        if congestion == "High":
            score -= 15
        elif congestion == "Medium":
            score -= 10
            
        return max(0, min(100, score))
        
    def detect_rogue_ap(self, network):
        """Detect potential rogue access points"""
        try:
            # Check for common rogue AP indicators
            indicators = []
            
            # Check for unusual signal strength patterns
            if network["Signal Strength"] > -50 and network["Encryption"] == "None":
                indicators.append("Strong open network - potential honeypot")
                
            # Check for unusual vendor information
            if "Vendor" in network and network["Vendor"] == "Unknown":
                indicators.append("Unknown vendor - potential rogue AP")
                
            # Check for unusual channel usage
            if network["Channel"] in [1, 6, 11]:  # Common channels
                if self.calculate_channel_congestion(network["Channel"]) == "High":
                    indicators.append("High congestion on common channel - potential jamming")
                    
            return indicators
        except Exception as e:
            logger.error(f"Failed to detect rogue AP: {str(e)}")
            return []
            
    def update_device_fingerprint(self, network):
        """Update device fingerprint database"""
        try:
            bssid = network["BSSID"]
            if bssid not in self.device_fingerprints:
                self.device_fingerprints[bssid] = []
                
            # Add new device information
            device_info = {
                "First Seen": network.get("First Seen", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                "Last Seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "Signal History": [network["Signal Strength"]],
                "Channel History": [network["Channel"]]
            }
            
            self.device_fingerprints[bssid].append(device_info)
            
            # Keep only last 24 hours of data
            cutoff_time = datetime.now() - timedelta(hours=24)
            self.device_fingerprints[bssid] = [
                d for d in self.device_fingerprints[bssid]
                if datetime.strptime(d["Last Seen"], "%Y-%m-%d %H:%M:%S") > cutoff_time
            ]
            
        except Exception as e:
            logger.error(f"Failed to update device fingerprint: {str(e)}")
            
    def run(self):
        while self.running:
            try:
                if config.simulation_mode:
                    # Use simulation data
                    networks = self.get_simulation_networks()
                else:
                    # Get real network data
                    scan_results = advanced_scan(interface=config.get("interface"))
                    networks = scan_results["Visible Networks"]
                
                # Update network information
                for bssid, info in networks.items():
                    # Update last seen time
                    info["Last Seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    if "First Seen" not in info:
                        info["First Seen"] = info["Last Seen"]
                    
                    # Update historical data
                    if bssid not in self.historical_data:
                        self.historical_data[bssid] = []
                    self.historical_data[bssid].append(info)
                    
                    # Update device fingerprints
                    self.update_device_fingerprint(info)
                    
                    # Check for threats
                    if info["Encryption"] == "None":
                        self.threat_signal.emit("No Encryption", 
                            f"{info['SSID']}: Network is completely open")
                    elif info["Encryption"] == "WEP":
                        self.threat_signal.emit("Weak Encryption", 
                            f"{info['SSID']}: WEP can be cracked in minutes")
                    elif info["Encryption"] == "WPA":
                        self.threat_signal.emit("Older Encryption", 
                            f"{info['SSID']}: WPA is vulnerable to attacks")
                    
                    if info["Signal Strength"] > -50:
                        self.threat_signal.emit("Strong Signal", 
                            f"{info['SSID']}: Signal strength is very high")
                
                self.update_signal.emit(networks)
                
            except Exception as e:
                logger.error(f"Failed to scan networks: {str(e)}")
                
            self.msleep(config.SCAN_INTERVAL * 1000)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WiFi Security Analyzer")
        self.setGeometry(100, 100, 1200, 800)
        
        # Initialize components
        self.init_ui()
        self.setup_connections()
        
        # Start scanner thread
        self.scanner_thread = WiFiScannerThread()
        self.scanner_thread.update_signal.connect(self.update_network_list)
        self.scanner_thread.threat_signal.connect(self.log_threat)
        self.scanner_thread.start()
        
    def init_ui(self):
        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Create control panel
        control_group = QGroupBox("Scanner Controls")
        control_layout = QHBoxLayout()
        
        self.interface_combo = QComboBox()
        interfaces = get_windows_interfaces()
        self.interface_combo.addItems(interfaces)
        
        self.start_button = QPushButton("Start Scan")
        self.stop_button = QPushButton("Stop Scan")
        self.stop_button.setEnabled(False)
        
        control_layout.addWidget(QLabel("Interface:"))
        control_layout.addWidget(self.interface_combo)
        control_layout.addWidget(self.start_button)
        control_layout.addWidget(self.stop_button)
        control_group.setLayout(control_layout)
        layout.addWidget(control_group)
        
        # Create network table
        self.network_table = QTableWidget()
        self.network_table.setColumnCount(8)
        self.network_table.setHorizontalHeaderLabels([
            "SSID", "Signal Strength", "Channel", "Encryption", 
            "Security Status", "Vendor", "First Seen", "Last Seen"
        ])
        layout.addWidget(self.network_table)
        
        # Create status bar
        self.statusBar().showMessage("Ready")
        
    def setup_connections(self):
        self.start_button.clicked.connect(self.start_scan)
        self.stop_button.clicked.connect(self.stop_scan)
        
    def start_scan(self):
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.statusBar().showMessage("Scanning...")
        config.set("interface", self.interface_combo.currentText())
        
    def stop_scan(self):
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.statusBar().showMessage("Scan stopped")
        
    def update_network_list(self, networks):
        self.network_table.setRowCount(len(networks))
        for row, (bssid, network) in enumerate(networks.items()):
            self.network_table.setItem(row, 0, QTableWidgetItem(network["SSID"]))
            self.network_table.setItem(row, 1, QTableWidgetItem(str(network["Signal Strength"])))
            self.network_table.setItem(row, 2, QTableWidgetItem(str(network["Channel"])))
            self.network_table.setItem(row, 3, QTableWidgetItem(network["Encryption"]))
            self.network_table.setItem(row, 4, QTableWidgetItem("Analyzing..."))
            self.network_table.setItem(row, 5, QTableWidgetItem("Unknown"))
            self.network_table.setItem(row, 6, QTableWidgetItem(network.get("First Seen", "")))
            self.network_table.setItem(row, 7, QTableWidgetItem(network.get("Last Seen", "")))
            
    def log_threat(self, threat_type, details):
        self.statusBar().showMessage(f"Threat detected: {details}")
        logger.warning(f"{threat_type}: {details}")
        
    def closeEvent(self, event):
        self.scanner_thread.running = False
        self.scanner_thread.wait()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec()) 