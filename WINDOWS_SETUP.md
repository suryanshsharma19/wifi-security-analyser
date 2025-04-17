# Windows Setup Guide for WiFi Security Analyzer

This guide will help you set up the WiFi Security Analyzer on Windows.

## Prerequisites

1. Python 3.8 or higher
2. Git (optional)
3. **For Real Scanning**: A compatible WiFi adapter (Monitor mode support may vary on Windows)
4. **For Real Scanning**: Administrative privileges

## Installation Steps

1. **Install Required Software**:
   ```bash
   # Install Python dependencies from the project directory
   pip install -r requirements.txt
   ```

2. **Install Npcap (Recommended for Real Scanning)**:
   - WinPcap is older and less maintained. Npcap is generally preferred.
   - Download Npcap from [https://npcap.com/](https://npcap.com/)
   - During installation, ensure you check the option "Install Npcap in WinPcap API-compatible Mode" if you suspect compatibility issues, but it's often not needed for modern Scapy.
   - Restart your computer after installation.

## Running the Application

*   Navigate to the project directory (`wifi_security_analyser`).
*   Run the script: `python GUI_Module.py`

### Demo Mode (Default)

- The application starts in simulation/demo mode by default (controlled by `config.json`).
- You can explicitly start it using the **"Start Demo"** button on the "Network Scanner" tab.
- This mode is perfect for:
    - Testing the application interface.
    - Development without hardware.
    - Demonstrations.

### Real Hardware Scanning

To use real hardware scanning:

1.  **Run with Admin Rights**:
    *   Close the application if it's running.
    *   Right-click your terminal (Command Prompt/PowerShell) -> "Run as administrator".
    *   Navigate back to the project directory.
    *   Run the script: `python GUI_Module.py`
2.  **Select Interface**: In the GUI, use the **"Interface" dropdown** on the "Network Scanner" tab to select your actual WiFi adapter.
3.  **Start Scan**: Click the **"Start Scan"** button.

*Note: Monitor mode capabilities can be limited on Windows compared to Linux. Not all adapters/drivers fully support it.* 

## Troubleshooting

1. **Scanning Issues / "No libpcap provider" / Interface not found**:
   - Ensure Npcap (or WinPcap) is installed correctly.
   - **Run the script as Administrator.** This is the most common cause of scanning failures.
   - Verify your WiFi adapter is enabled and detected by Windows.
   - Try selecting a different interface in the GUI dropdown.
   - Check if your adapter actually supports scanning/monitor mode on Windows.

2. **"Access denied"**:
   - Ensure you are running as Administrator.
   - Check Windows Firewall or Antivirus settings; they might be blocking low-level network access.

## Support

If you encounter any issues:
1. Check the troubleshooting guide
2. Review the error logs
3. Open an issue on GitHub
4. Join our Discord community

## Notes

- Real-time scanning performance and capabilities heavily depend on your WiFi adapter and drivers on Windows.
- Using a dedicated USB WiFi adapter known for Windows compatibility might yield better results for real scanning.
- The Demo mode provides full feature visibility without hardware dependencies. 