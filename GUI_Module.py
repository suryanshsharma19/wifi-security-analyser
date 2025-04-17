from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QPushButton, QLabel, QTableWidget, 
                            QTableWidgetItem, QTabWidget, QProgressBar, 
                            QComboBox, QMessageBox, QGroupBox, QMenuBar, 
                            QMenu, QStatusBar, QFileDialog, QInputDialog, 
                            QDialog, QDialogButtonBox)
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt6.QtGui import QIcon, QColor, QAction
import sys
import json
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import numpy as np
from datetime import datetime
import os
import platform

# Import our modules
from modules import (
    analyze_live_traffic,
    advanced_scan,
    train_model,
    predict_vulnerability,
    visualize_heatmap,
    detect_threats,
    start_server
)
from modules.config import config
from modules.logger import logger
from modules.error_handler import error_handler
from modules.wifi_scanning import get_windows_interfaces

class WiFiScannerThread(QThread):
    update_signal = pyqtSignal(dict)
    threat_signal = pyqtSignal(str, str)
    
    def __init__(self):
        super().__init__()
        self.running = True
        try:
            self.model = train_model()
            logger.info("Vulnerability prediction model trained successfully")
        except Exception as e:
            error_handler.handle_error(e, "Failed to train model")
            self.running = False
        
    def analyze_security(self, network):
        """Analyze network security using the trained model"""
        try:
            # Convert network data to model input format
            encryption_map = {"WEP": 0, "WPA": 1, "WPA2": 1, "WPA2-Enterprise": 2, "None": 0}
            encryption_val = encryption_map.get(network["Encryption"], 0)
            
            network_data = [
                encryption_val,
                network["Signal Strength"],
                network.get("Channel", 1)  # Default to channel 1 if not specified
            ]
            
            return predict_vulnerability(self.model, network_data)
        except Exception as e:
            error_handler.handle_error(e, "Failed to analyze security")
            return "Unknown"
        
    def detect_threats(self, network):
        """Detect potential security threats"""
        try:
            threats = []
            if network["Encryption"] == "None":
                threats.append(("No Encryption", "Network is completely open"))
            elif network["Encryption"] == "WEP":
                threats.append(("Weak Encryption", "WEP can be cracked in minutes"))
            elif network["Encryption"] == "WPA":
                threats.append(("Older Encryption", "WPA is vulnerable to attacks"))
                
            if network["Signal Strength"] > -50:
                threats.append(("Strong Signal", "Network might be too close"))
                
            return threats
        except Exception as e:
            error_handler.handle_error(e, "Failed to detect threats")
            return []
        
    def run(self):
        while self.running:
            try:
                # Get network data using our scanning module
                scan_results = advanced_scan(interface=config.get("interface"))
                networks = scan_results["Visible Networks"]
                
                # Update network information
                for bssid, info in networks.items():
                    # Update last seen time
                    info["Last Seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    if "First Seen" not in info:
                        info["First Seen"] = info["Last Seen"]
                        
                    # Update security status
                    info["Security"] = self.analyze_security(info)
                    
                    # Check for threats
                    threats = self.detect_threats(info)
                    for threat_type, details in threats:
                        self.threat_signal.emit(threat_type, f"{info['SSID']}: {details}")
                
                self.update_signal.emit(networks)
                
            except Exception as e:
                error_handler.handle_error(e, "Failed to scan networks")
                if not config.simulation_mode:
                    error_handler.handle_error(None, "Switching to simulation mode...")
                    config.simulation_mode = True
                
            self.msleep(config.get("scan_interval", 2) * 1000)

class MainWindow(QMainWindow):
    def __init__(self):
        try:
            super().__init__()
            logger.info("Initializing main window")
            
            # Set window properties
            self.setWindowTitle("WiFi Security Analyzer")
            self.setGeometry(100, 100, 1200, 800)
            
            # Initialize components
            self.init_ui()
            self.setup_connections()
            
            # Start web server
            self.start_web_server()
            
            logger.info("Main window initialized successfully")
            
        except Exception as e:
            error_handler.handle_critical_error(e, "Failed to initialize main window")

    def start_web_server(self):
        try:
            start_server(config.HOST, config.PORT)
            logger.info(f"Web server started on {config.HOST}:{config.PORT}")
        except Exception as e:
            error_handler.handle_error(e, "Failed to start web server")

    def init_ui(self):
        # Create menu bar
        self.create_menu_bar()
        
        # Create status bar
        self.statusBar().showMessage("Ready")
        
        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Create tab widget
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)
        
        # Add tabs
        self.tabs.addTab(self.create_scan_tab(), "Network Scanner")
        self.tabs.addTab(self.create_threat_tab(), "Threat Detection")
        self.tabs.addTab(self.create_analysis_tab(), "Security Analysis")
        self.tabs.addTab(self.create_visualization_tab(), "Network Visualization")
        self.tabs.addTab(self.create_logs_tab(), "Network Logs")
        
        # Initialize scanner thread
        self.scanner_thread = WiFiScannerThread()
        self.scanner_thread.update_signal.connect(self.update_network_list)
        self.scanner_thread.threat_signal.connect(self.log_threat)
        self.scanner_thread.start()
        
        # Initialize log file
        self.log_file = config.get("log_file", "wifi_analyzer.log")
        
    def create_menu_bar(self):
        """Create the application menu bar"""
        try:
            menubar = self.menuBar()
            
            # File menu
            file_menu = menubar.addMenu("File")
            
            self.export_action = QAction("Export Results", self)
            self.export_action.setShortcut("Ctrl+E")
            file_menu.addAction(self.export_action)
            
            self.settings_action = QAction("Settings", self)
            self.settings_action.setShortcut("Ctrl+S")
            file_menu.addAction(self.settings_action)
            
            file_menu.addSeparator()
            
            exit_action = QAction("Exit", self)
            exit_action.setShortcut("Ctrl+Q")
            exit_action.triggered.connect(self.close)
            file_menu.addAction(exit_action)
            
            # Help menu
            help_menu = menubar.addMenu("Help")
            
            self.about_action = QAction("About", self)
            self.about_action.setShortcut("F1")
            help_menu.addAction(self.about_action)
            
            logger.info("Menu bar created successfully")
        except Exception as e:
            error_handler.handle_error(e, "Failed to create menu bar")
            
    def create_scan_tab(self):
        """Create the network scanner tab"""
        try:
            tab = QWidget()
            layout = QVBoxLayout(tab)
            
            # Control panel
            control_group = QGroupBox("Scanner Controls")
            control_layout = QHBoxLayout()
            
            self.interface_combo = QComboBox()
            interfaces = get_windows_interfaces()
            self.interface_combo.addItems(interfaces)
            
            self.start_button = QPushButton("Start Scan")
            self.stop_button = QPushButton("Stop Scan")
            self.stop_button.setEnabled(False)
            
            self.demo_button = QPushButton("Start Demo")
            self.demo_button.setStyleSheet("background-color: #4CAF50; color: white;")
            self.demo_button.clicked.connect(self.start_demo)
            
            control_layout.addWidget(QLabel("Interface:"))
            control_layout.addWidget(self.interface_combo)
            control_layout.addWidget(self.start_button)
            control_layout.addWidget(self.stop_button)
            control_layout.addWidget(self.demo_button)
            
            control_group.setLayout(control_layout)
            layout.addWidget(control_group)
            
            # Simulation mode indicator
            if config.simulation_mode:
                sim_label = QLabel("⚠ Running in Simulation Mode")
                sim_label.setStyleSheet("color: orange; font-weight: bold;")
                layout.addWidget(sim_label)
                
                # Add simulation info
                sim_info = QLabel(
                    "Demo Networks:\n"
                    "- Home_Network (WPA2, Channel 6)\n"
                    "- Public_WiFi (Open, Channel 11)\n"
                    "- Office_Network (WPA2-Enterprise, Channel 1)\n"
                    "- Guest_WiFi (WPA, Channel 6)\n"
                    "- Rogue_AP (Open, Channel 6)"
                )
                sim_info.setStyleSheet("color: gray;")
                layout.addWidget(sim_info)
            
            # Network table
            self.network_table = QTableWidget()
            self.network_table.setColumnCount(8)
            self.network_table.setHorizontalHeaderLabels([
                "SSID", "Signal Strength", "Channel", "Encryption", 
                "Security Status", "Vendor", "First Seen", "Last Seen"
            ])
            layout.addWidget(self.network_table)
            
            logger.info("Scan tab created successfully")
            return tab
        except Exception as e:
            error_handler.handle_error(e, "Failed to create scan tab")
            return QWidget()
        
    def create_threat_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Threat detection status
        status_group = QGroupBox("Threat Detection Status")
        status_layout = QVBoxLayout()
        
        self.threat_status = QLabel("No threats detected")
        self.threat_status.setStyleSheet("color: green; font-weight: bold;")
        status_layout.addWidget(self.threat_status)
        
        # Threat log
        self.threat_log = QTableWidget()
        self.threat_log.setColumnCount(3)
        self.threat_log.setHorizontalHeaderLabels(["Time", "Type", "Details"])
        status_layout.addWidget(self.threat_log)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        return tab
        
    def create_analysis_tab(self):
        """Create the security analysis tab"""
        try:
            tab = QWidget()
            layout = QVBoxLayout(tab)
            
            # Network Health Score
            health_group = QGroupBox("Network Health Score")
            health_layout = QVBoxLayout()
            
            self.health_score = QLabel("Score: --")
            self.health_score.setStyleSheet("font-size: 24px; font-weight: bold;")
            health_layout.addWidget(self.health_score)
            
            self.health_details = QLabel()
            self.health_details.setWordWrap(True)
            health_layout.addWidget(self.health_details)
            
            health_group.setLayout(health_layout)
            layout.addWidget(health_group)
            
            # Performance Metrics
            perf_group = QGroupBox("Performance Metrics")
            perf_layout = QVBoxLayout()
            
            self.signal_quality = QLabel("Signal Quality: --")
            self.channel_congestion = QLabel("Channel Congestion: --")
            self.network_stability = QLabel("Network Stability: --")
            self.device_count = QLabel("Connected Devices: --")
            
            perf_layout.addWidget(self.signal_quality)
            perf_layout.addWidget(self.channel_congestion)
            perf_layout.addWidget(self.network_stability)
            perf_layout.addWidget(self.device_count)
            
            perf_group.setLayout(perf_layout)
            layout.addWidget(perf_group)
            
            # Historical Data
            history_group = QGroupBox("Historical Data")
            history_layout = QVBoxLayout()
            
            self.history_table = QTableWidget()
            self.history_table.setColumnCount(4)
            self.history_table.setHorizontalHeaderLabels([
                "Time", "Signal Strength", "Channel", "Health Score"
            ])
            history_layout.addWidget(self.history_table)
            
            history_group.setLayout(history_layout)
            layout.addWidget(history_group)
            
            # Add refresh button
            refresh_button = QPushButton("Refresh Analysis")
            refresh_button.clicked.connect(self.refresh_analysis)
            layout.addWidget(refresh_button)
            
            logger.info("Analysis tab created successfully")
            return tab
        except Exception as e:
            error_handler.handle_error(e, "Failed to create analysis tab")
            return QWidget()
            
    def create_visualization_tab(self):
        """Create the network visualization tab"""
        try:
            tab = QWidget()
            layout = QVBoxLayout(tab)
            
            # Create matplotlib figure with a white background
            self.figure = Figure(figsize=(8, 6), facecolor='white')
            self.canvas = FigureCanvas(self.figure)
            self.canvas.setStyleSheet("background-color: white;")
            layout.addWidget(self.canvas)
            
            # Add controls for visualization
            controls = QHBoxLayout()
            
            self.visualization_type = QComboBox()
            self.visualization_type.addItems(["Signal Strength", "Security Status", "Channel Distribution"])
            self.visualization_type.currentIndexChanged.connect(self.update_visualization)
            
            self.refresh_button = QPushButton("Refresh")
            self.refresh_button.clicked.connect(self.update_visualization)
            
            controls.addWidget(QLabel("View:"))
            controls.addWidget(self.visualization_type)
            controls.addWidget(self.refresh_button)
            controls.addStretch()
            
            layout.addLayout(controls)
            
            # Initial visualization
            self.update_visualization()
            
            logger.info("Visualization tab created successfully")
            return tab
        except Exception as e:
            error_handler.handle_error(e, "Failed to create visualization tab")
            return QWidget()
            
    def create_logs_tab(self):
        """Create the logs tab"""
        try:
            tab = QWidget()
            layout = QVBoxLayout(tab)
            
            # Log controls
            log_controls = QHBoxLayout()
            self.clear_logs_button = QPushButton("Clear Logs")
            self.save_logs_button = QPushButton("Save Logs")
            log_controls.addWidget(self.clear_logs_button)
            log_controls.addWidget(self.save_logs_button)
            layout.addLayout(log_controls)
            
            # Log display
            self.log_display = QTableWidget()
            self.log_display.setColumnCount(4)
            self.log_display.setHorizontalHeaderLabels(["Timestamp", "Event", "Details", "Severity"])
            self.log_display.horizontalHeader().setStretchLastSection(True)
            self.log_display.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
            self.log_display.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
            
            # Set column widths
            self.log_display.setColumnWidth(0, 150)  # Timestamp
            self.log_display.setColumnWidth(1, 100)  # Event
            self.log_display.setColumnWidth(2, 300)  # Details
            self.log_display.setColumnWidth(3, 100)  # Severity
            
            layout.addWidget(self.log_display)
            
            # Connect buttons
            self.clear_logs_button.clicked.connect(self.clear_logs)
            self.save_logs_button.clicked.connect(self.save_logs)
            
            # Add initial log entries
            self.add_log_entry("Application Started", "WiFi Security Analyzer initialized", "Info")
            self.add_log_entry("Simulation Mode", "Running in simulation mode with demo networks", "Info")
            
            logger.info("Logs tab created successfully")
            return tab
        except Exception as e:
            error_handler.handle_error(e, "Failed to create logs tab")
            return QWidget()
            
    def setup_connections(self):
        """Setup signal connections for the GUI"""
        try:
            # Connect scanner thread signals
            self.scanner_thread.update_signal.connect(self.update_network_list)
            self.scanner_thread.threat_signal.connect(self.log_threat)
            self.scanner_thread.performance_signal.connect(self.update_performance)
            
            # Connect button signals
            self.start_button.clicked.connect(self.start_scan)
            self.stop_button.clicked.connect(self.stop_scan)
            
            # Connect menu actions
            self.export_action.triggered.connect(self.export_results)
            self.settings_action.triggered.connect(self.show_settings)
            self.about_action.triggered.connect(self.show_about)
            
            logger.info("GUI connections setup successfully")
        except Exception as e:
            error_handler.handle_error(e, "Failed to setup GUI connections")
            
    def update_network_list(self, networks):
        """Update the network list table with new scan results"""
        try:
            self.network_table.setRowCount(len(networks))
            for row, (bssid, network) in enumerate(networks.items()):
                # Create and set items for each column
                self.network_table.setItem(row, 0, QTableWidgetItem(network["SSID"]))
                self.network_table.setItem(row, 1, QTableWidgetItem(f"{network['Signal Strength']} dBm"))
                self.network_table.setItem(row, 2, QTableWidgetItem(str(network["Channel"])))
                self.network_table.setItem(row, 3, QTableWidgetItem(network["Encryption"]))
                self.network_table.setItem(row, 4, QTableWidgetItem(network.get("Security", "Analyzing...")))
                self.network_table.setItem(row, 5, QTableWidgetItem("Simulated" if config.simulation_mode else "Unknown"))
                self.network_table.setItem(row, 6, QTableWidgetItem(network.get("First Seen", "")))
                self.network_table.setItem(row, 7, QTableWidgetItem(network.get("Last Seen", "")))
                
                # Set background color based on security status
                color = QColor(200, 255, 200)  # Default green
                if network.get("Security") == "Vulnerable":
                    color = QColor(255, 200, 200)  # Red
                elif network.get("Security") == "Moderate":
                    color = QColor(255, 255, 200)  # Yellow
                    
                for col in range(8):
                    item = self.network_table.item(row, col)
                    if item:  # Check if item exists
                        item.setBackground(color)
                        
            # Update performance metrics if available
            if networks and "Performance" in list(networks.values())[0]:
                self.update_performance(list(networks.values())[0]["Performance"])
                
            # Update visualization
            self.update_visualization()
                
        except Exception as e:
            error_handler.handle_error(e, "Failed to update network list")
            
    def update_performance(self, performance):
        """Update performance metrics display"""
        try:
            self.health_score.setText(f"Score: {performance['Health Score']}")
            self.signal_quality.setText(f"Signal Quality: {performance['Signal Quality']}")
            self.channel_congestion.setText(f"Channel Congestion: {performance['Channel Congestion']}")
            self.network_stability.setText(f"Network Stability: {performance['Network Stability']}")
            self.device_count.setText(f"Connected Devices: {performance['Device Count']}")
        except Exception as e:
            error_handler.handle_error(e, "Failed to update performance metrics")
        
    def log_threat(self, threat_type, details):
        """Log detected threats"""
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Update threat log
        row = self.threat_log.rowCount()
        self.threat_log.insertRow(row)
        self.threat_log.setItem(row, 0, QTableWidgetItem(current_time))
        self.threat_log.setItem(row, 1, QTableWidgetItem(threat_type))
        self.threat_log.setItem(row, 2, QTableWidgetItem(details))
        
        # Update status
        self.threat_status.setText(f"Threat detected: {threat_type}")
        self.threat_status.setStyleSheet("color: red; font-weight: bold;")
        
        # Log to file
        if config.get("save_logs", True):
            with open(self.log_file, "a") as f:
                f.write(f"{current_time} - {threat_type}: {details}\n")
            
    def start_scan(self):
        """Start the WiFi scanning process"""
        try:
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.statusBar().showMessage("Scanning...")
            self.scanner_thread.running = True
            logger.info("Scanning started")
        except Exception as e:
            error_handler.handle_error(e, "Failed to start scan")
            
    def stop_scan(self):
        """Stop the WiFi scanning process"""
        try:
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.statusBar().showMessage("Scan stopped")
            self.scanner_thread.running = False
            logger.info("Scanning stopped")
        except Exception as e:
            error_handler.handle_error(e, "Failed to stop scan")
            
    def export_results(self):
        """Export scan results to a file"""
        try:
            filename, _ = QFileDialog.getSaveFileName(
                self, "Export Results", "", "CSV Files (*.csv);;All Files (*)"
            )
            if filename:
                with open(filename, 'w') as f:
                    # Write header
                    f.write("SSID,Signal Strength,Channel,Encryption,Security,Vendor,First Seen,Last Seen\n")
                    
                    # Write data
                    for row in range(self.network_table.rowCount()):
                        row_data = []
                        for col in range(self.network_table.columnCount()):
                            item = self.network_table.item(row, col)
                            row_data.append(item.text() if item else "")
                        f.write(",".join(row_data) + "\n")
                        
                self.statusBar().showMessage(f"Results exported to {filename}")
                logger.info(f"Results exported to {filename}")
        except Exception as e:
            error_handler.handle_error(e, "Failed to export results")
            
    def show_settings(self):
        """Show the settings dialog"""
        try:
            settings_dialog = QDialog(self)
            settings_dialog.setWindowTitle("Settings")
            settings_dialog.setModal(True)
            
            layout = QVBoxLayout()
            
            # Add settings controls here
            # For example:
            # scan_interval = QSpinBox()
            # scan_interval.setValue(config.SCAN_INTERVAL)
            # layout.addWidget(QLabel("Scan Interval (seconds):"))
            # layout.addWidget(scan_interval)
            
            buttons = QDialogButtonBox(
                QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
            )
            buttons.accepted.connect(settings_dialog.accept)
            buttons.rejected.connect(settings_dialog.reject)
            
            layout.addWidget(buttons)
            settings_dialog.setLayout(layout)
            
            if settings_dialog.exec() == QDialog.DialogCode.Accepted:
                # Save settings here
                pass
                
        except Exception as e:
            error_handler.handle_error(e, "Failed to show settings dialog")
            
    def show_about(self):
        """Show the about dialog"""
        try:
            QMessageBox.about(
                self,
                "About WiFi Security Analyzer",
                "WiFi Security Analyzer v1.0\n\n"
                "A comprehensive tool for analyzing WiFi network security.\n\n"
                "Features:\n"
                "- Real-time network scanning\n"
                "- Threat detection\n"
                "- Security analysis\n"
                "- Network visualization\n"
                "- Performance monitoring\n\n"
                "© 2024 WiFi Security Team"
            )
        except Exception as e:
            error_handler.handle_error(e, "Failed to show about dialog")
        
    def closeEvent(self, event):
        try:
            logger.info("Application closing")
            # Stop demo mode if running
            self.stop_demo()
            # Cleanup code here
            self.scanner_thread.running = False
            self.scanner_thread.wait()
            event.accept()
        except Exception as e:
            error_handler.handle_error(e, "Error during application closure")
            event.accept()

    def update_history_table(self, network):
        """Update the historical data table"""
        try:
            bssid = network["BSSID"]
            if bssid in self.scanner_thread.historical_data:
                history = self.scanner_thread.historical_data[bssid]
                self.history_table.setRowCount(len(history))
                
                for row, entry in enumerate(history):
                    self.history_table.setItem(row, 0, QTableWidgetItem(entry["Last Seen"]))
                    self.history_table.setItem(row, 1, QTableWidgetItem(str(entry["Signal Strength"])))
                    self.history_table.setItem(row, 2, QTableWidgetItem(str(entry["Channel"])))
                    if "Performance" in entry:
                        self.history_table.setItem(row, 3, QTableWidgetItem(str(entry["Performance"]["Health Score"])))
        except Exception as e:
            logger.error(f"Failed to update history table: {str(e)}")

    def update_visualization(self):
        """Update the network visualization"""
        try:
            self.figure.clear()
            ax = self.figure.add_subplot(111)
            
            # Get current networks from the scanner thread
            networks = {}
            try:
                if hasattr(self.scanner_thread, 'get_simulation_networks'):
                    networks = self.scanner_thread.get_simulation_networks()
                else:
                    # Use simulation data from config if method not available
                    config_path = os.path.join(os.path.dirname(__file__), 'config.json')
                    with open(config_path, 'r') as f:
                        config_data = json.load(f)
                        networks = config_data.get("simulation_data", {}).get("networks", {})
            except Exception as e:
                logger.error(f"Failed to get network data: {str(e)}")
                # Use hardcoded demo data as fallback
                networks = {
                    "00:11:22:33:44:55": {
                        "SSID": "Home_Network",
                        "Signal Strength": -45,
                        "Channel": 6,
                        "Encryption": "WPA2",
                        "Vendor": "TP-Link"
                    },
                    "AA:BB:CC:DD:EE:FF": {
                        "SSID": "Public_WiFi",
                        "Signal Strength": -75,
                        "Channel": 11,
                        "Encryption": "None",
                        "Vendor": "Unknown"
                    },
                    "11:22:33:44:55:66": {
                        "SSID": "Office_Network",
                        "Signal Strength": -60,
                        "Channel": 1,
                        "Encryption": "WPA2-Enterprise",
                        "Vendor": "Cisco"
                    },
                    "22:33:44:55:66:77": {
                        "SSID": "Guest_WiFi",
                        "Signal Strength": -65,
                        "Channel": 6,
                        "Encryption": "WPA",
                        "Vendor": "Netgear"
                    },
                    "33:44:55:66:77:88": {
                        "SSID": "Rogue_AP",
                        "Signal Strength": -50,
                        "Channel": 6,
                        "Encryption": "None",
                        "Vendor": "Unknown"
                    }
                }
            
            if not networks:
                ax.text(0.5, 0.5, "No network data available", 
                       ha='center', va='center', transform=ax.transAxes)
                self.canvas.draw()
                return
                
            view_type = self.visualization_type.currentText()
            
            if view_type == "Signal Strength":
                # Create signal strength scatter plot
                x = []
                y = []
                strengths = []
                labels = []
                
                for bssid, network in networks.items():
                    channel = network.get("Channel", 0)
                    signal = network.get("Signal Strength", -100)
                    x.append(channel)
                    y.append(signal)
                    strengths.append(signal)
                    labels.append(network.get("SSID", "Unknown"))
                
                # Create scatter plot
                scatter = ax.scatter(x, y, c=strengths, cmap='viridis', s=100)
                plt.colorbar(scatter, ax=ax, label='Signal Strength (dBm)')
                
                # Add labels to points
                for i, label in enumerate(labels):
                    ax.annotate(label, (x[i], y[i]), xytext=(5, 5), textcoords='offset points')
                
                ax.set_xlabel('Channel')
                ax.set_ylabel('Signal Strength (dBm)')
                ax.set_title('Signal Strength Distribution')
                ax.grid(True, linestyle='--', alpha=0.7)
                
                # Set axis limits
                ax.set_xlim(0, 14)  # Channels typically 1-13
                ax.set_ylim(-100, -20)  # Typical signal strength range
                
            elif view_type == "Security Status":
                # Create security status pie chart
                security_counts = {"Secure": 0, "Moderate": 0, "Vulnerable": 0}
                for bssid, network in networks.items():
                    if network["Encryption"] in ["WPA2", "WPA2-Enterprise"]:
                        security_counts["Secure"] += 1
                    elif network["Encryption"] == "WPA":
                        security_counts["Moderate"] += 1
                    else:
                        security_counts["Vulnerable"] += 1
                            
                labels = list(security_counts.keys())
                sizes = [security_counts[label] for label in labels]
                colors = ['#4CAF50', '#FFC107', '#F44336']  # Green, Yellow, Red
                
                if sum(sizes) > 0:  # Only create pie chart if there's data
                    wedges, texts, autotexts = ax.pie(sizes, labels=labels, colors=colors, 
                                                     autopct='%1.1f%%', startangle=90)
                    # Make percentage labels easier to read
                    plt.setp(autotexts, size=9, weight="bold")
                    plt.setp(texts, size=10)
                    ax.axis('equal')
                else:
                    ax.text(0.5, 0.5, "No security data available", 
                           ha='center', va='center', transform=ax.transAxes)
                
                ax.set_title('Network Security Distribution')
                
            elif view_type == "Channel Distribution":
                # Create channel usage bar chart
                channel_counts = {}
                for bssid, network in networks.items():
                    channel = network.get("Channel", 0)
                    channel_counts[channel] = channel_counts.get(channel, 0) + 1
                        
                channels = sorted(channel_counts.keys())
                counts = [channel_counts[channel] for channel in channels]
                
                bars = ax.bar(channels, counts, color='#2196F3')  # Material Blue
                ax.set_xlabel('Channel')
                ax.set_ylabel('Number of Networks')
                ax.set_title('Channel Usage Distribution')
                
                # Add value labels on top of bars
                for bar in bars:
                    height = bar.get_height()
                    ax.text(bar.get_x() + bar.get_width()/2., height,
                           f'{int(height)}',
                           ha='center', va='bottom')
                
                # Set axis limits and grid
                ax.set_xlim(-0.5, 13.5)
                ax.set_xticks(range(1, 14))
                ax.grid(True, axis='y', linestyle='--', alpha=0.7)
                
            # Adjust layout to prevent label cutoff
            self.figure.tight_layout()
            
            # Draw the canvas
            self.canvas.draw()
            logger.info("Visualization updated successfully")
        except Exception as e:
            error_handler.handle_error(e, "Failed to update visualization")
            logger.error(f"Visualization error details: {str(e)}")
            # Show error on the plot
            self.figure.clear()
            ax = self.figure.add_subplot(111)
            ax.text(0.5, 0.5, f"Error updating visualization:\n{str(e)}", 
                   ha='center', va='center', transform=ax.transAxes, color='red')
            self.canvas.draw()
            
    def refresh_analysis(self):
        """Refresh the security analysis data"""
        try:
            # Get latest network data
            networks = self.scanner_thread.historical_data
            
            if not networks:
                self.health_score.setText("Score: --")
                self.health_details.setText("No network data available")
                return
                
            # Calculate average health score
            total_score = 0
            count = 0
            for bssid, history in networks.items():
                if history and "Performance" in history[-1]:
                    total_score += history[-1]["Performance"]["Health Score"]
                    count += 1
                    
            if count > 0:
                avg_score = total_score / count
                self.health_score.setText(f"Score: {avg_score:.1f}")
                
                # Update health details
                details = []
                for bssid, history in networks.items():
                    if history and "Performance" in history[-1]:
                        perf = history[-1]["Performance"]
                        if perf["Channel Congestion"] == "High":
                            details.append(f"⚠ High congestion on channel {history[-1].get('Channel', '?')}")
                        if perf["Network Stability"] == "Unstable":
                            details.append(f"⚠ Unstable network: {history[-1].get('SSID', 'Unknown')}")
                            
                self.health_details.setText("\n".join(details) if details else "All networks are healthy")
                
                # Update performance metrics
                self.update_performance(history[-1]["Performance"])
                
                # Update history table
                self.update_history_table(history[-1])
                
        except Exception as e:
            error_handler.handle_error(e, "Failed to refresh analysis")

    def start_demo(self):
        """Start the demo mode to showcase all features"""
        try:
            self.demo_button.setEnabled(False)
            self.statusBar().showMessage("Demo mode started")
            
            # Start the scanner thread
            self.scanner_thread.running = True
            
            # Create a timer to simulate different scenarios
            self.demo_timer = QTimer()
            self.demo_timer.timeout.connect(self.update_demo_scenario)
            self.demo_timer.start(5000)  # Update every 5 seconds
            
            # Initial scan
            self.scanner_thread.update_signal.emit(self.scanner_thread.get_simulation_networks())
            
            logger.info("Demo mode started successfully")
        except Exception as e:
            error_handler.handle_error(e, "Failed to start demo mode")
            
    def update_demo_scenario(self):
        """Update the demo scenario to showcase different features"""
        try:
            # Get current networks
            networks = self.scanner_thread.get_simulation_networks()
            
            # Simulate different scenarios
            for bssid, network in networks.items():
                if network["SSID"] == "Rogue_AP":
                    # Simulate rogue AP behavior
                    network["Signal Strength"] = np.random.randint(-45, -35)
                    network["Channel"] = np.random.choice([1, 6, 11])
                    
                elif network["SSID"] == "Public_WiFi":
                    # Simulate public WiFi behavior
                    network["Signal Strength"] = np.random.randint(-80, -60)
                    
                elif network["SSID"] == "Home_Network":
                    # Simulate stable home network
                    network["Signal Strength"] = np.random.randint(-50, -40)
                    
                elif network["SSID"] == "Office_Network":
                    # Simulate enterprise network
                    network["Signal Strength"] = np.random.randint(-65, -55)
                    
                elif network["SSID"] == "Guest_WiFi":
                    # Simulate guest network
                    network["Signal Strength"] = np.random.randint(-70, -60)
                    
                # Update last seen time
                network["Last Seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
            # Emit update signal
            self.scanner_thread.update_signal.emit(networks)
            
            # Update visualization
            self.update_visualization()
            
            # Update analysis
            self.refresh_analysis()
            
        except Exception as e:
            error_handler.handle_error(e, "Failed to update demo scenario")
            
    def stop_demo(self):
        """Stop the demo mode"""
        try:
            if hasattr(self, 'demo_timer'):
                self.demo_timer.stop()
            self.demo_button.setEnabled(True)
            self.statusBar().showMessage("Demo mode stopped")
            logger.info("Demo mode stopped")
        except Exception as e:
            error_handler.handle_error(e, "Failed to stop demo mode")

    def add_log_entry(self, event, details, severity):
        """Add a new entry to the logs table"""
        try:
            row = self.log_display.rowCount()
            self.log_display.insertRow(row)
            
            # Set items
            self.log_display.setItem(row, 0, QTableWidgetItem(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            self.log_display.setItem(row, 1, QTableWidgetItem(event))
            self.log_display.setItem(row, 2, QTableWidgetItem(details))
            self.log_display.setItem(row, 3, QTableWidgetItem(severity))
            
            # Set color based on severity
            color = QColor(200, 255, 200)  # Light green for Info
            if severity == "Warning":
                color = QColor(255, 255, 200)  # Light yellow
            elif severity == "Error":
                color = QColor(255, 200, 200)  # Light red
                
            for col in range(4):
                item = self.log_display.item(row, col)
                if item:
                    item.setBackground(color)
                    
            # Scroll to the new entry
            self.log_display.scrollToBottom()
            
        except Exception as e:
            error_handler.handle_error(e, "Failed to add log entry")
            
    def clear_logs(self):
        """Clear all log entries"""
        try:
            self.log_display.setRowCount(0)
            self.add_log_entry("Logs Cleared", "All log entries have been cleared", "Info")
            logger.info("Logs cleared")
        except Exception as e:
            error_handler.handle_error(e, "Failed to clear logs")
            
    def save_logs(self):
        """Save logs to a file"""
        try:
            filename, _ = QFileDialog.getSaveFileName(
                self, "Save Logs", "", "Text Files (*.txt);;All Files (*)"
            )
            if filename:
                with open(filename, 'w') as f:
                    for row in range(self.log_display.rowCount()):
                        row_data = []
                        for col in range(self.log_display.columnCount()):
                            item = self.log_display.item(row, col)
                            row_data.append(item.text() if item else "")
                        f.write("\t".join(row_data) + "\n")
                        
                self.add_log_entry("Logs Saved", f"Logs saved to {filename}", "Info")
                logger.info(f"Logs saved to {filename}")
        except Exception as e:
            error_handler.handle_error(e, "Failed to save logs")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec()) 