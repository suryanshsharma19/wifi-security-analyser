# WiFi Security Analyzer

A comprehensive WiFi security analysis tool with a modern GUI interface built using PyQt6. It provides real-time network scanning (requires admin privileges), threat detection, security analysis, visualization, and a built-in demo mode.

## Features

-   **Network Scanner**:
    -   Real-time scanning of nearby WiFi networks (requires admin privileges).
    -   Simulation mode for demonstration without hardware or admin rights.
    -   Detailed network info: SSID, Signal Strength, Channel, Encryption, Security Status, Vendor, First/Last Seen timestamps.
    -   Color-coded security status (Secure, Moderate, Vulnerable).
-   **Threat Detection**:
    -   Identifies potential threats like open networks, weak/outdated encryption (WEP, WPA), and rogue access points.
    -   Logs threats with timestamps and details.
-   **Security Analysis**:
    -   Provides an overall Network Health Score.
    -   Displays performance metrics (Signal Quality, Channel Congestion, Stability).
    -   Tracks historical data for networks.
-   **Network Visualization**:
    -   Graphical representation of the network environment.
    -   Views include Signal Strength distribution, Security Status (pie chart), and Channel Usage (bar chart).
-   **Logging**:
    -   Detailed application event logging (Info, Warning, Error).
    -   Ability to clear and save logs to a file.
-   **Demo Mode**:
    -   Showcases all application features using simulated network data.
    -   Accessible via the "Start Demo" button on the Network Scanner tab.

## Requirements

-   Python 3.8+
-   Required Python packages (see `requirements.txt`)
-   **For Real Scanning**:
    -   A WiFi adapter capable of scanning.
    -   Administrator privileges to run the script.
    -   (Windows) Npcap or WinPcap might be needed (see `WINDOWS_SETUP.md`).

## Installation

1.  **Clone the repository** (or download the source code):
    ```bash
    # If you use git:
    # git clone https://github.com/suryanshsharma19/wifi-security-analyser.git
    # cd wifi_security_analyser
    ```

2.  **Navigate to the project directory** in your terminal (the one containing `GUI_Module.py`).

3.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

1.  **Navigate** to the main project directory (`wifi_security_analyser`) in your terminal.

2.  **Choose a Mode**:

    *   **Demo Mode (Recommended for first look)**:
        *   Run the script normally:
            ```bash
            python GUI_Module.py
            ```
        *   Click the **"Start Demo"** button on the "Network Scanner" tab. This will use simulated data.

    *   **Real Scanning Mode**:
        *   **IMPORTANT**: You MUST run the script with **administrator privileges**.
        *   On Windows: Right-click your terminal (Command Prompt/PowerShell) -> "Run as administrator".
        *   Navigate back to the project directory (`cd path/to/wifi_security_analyser`).
        *   Run the script:
            ```bash
            python GUI_Module.py
            ```
        *   Select your WiFi network interface from the dropdown on the "Network Scanner" tab.
        *   Click **"Start Scan"**.

3.  **Explore the Interface**:
    *   **Network Scanner**: View detected networks, start/stop scans, or start the demo.
    *   **Threat Detection**: See identified security risks.
    *   **Security Analysis**: Check network health scores and metrics.
    *   **Network Visualization**: View graphical data (Signal Strength, Security, Channels).
    *   **Network Logs**: Monitor application events and save logs.

4.  **Exporting Results**:
    *   Go to `File -> Export Results` to save the Network Scanner table data as a CSV file.

## Configuration

-   Settings like the scan interval and default simulation mode can be adjusted in `config.json`.

## Contributing

Contributions are welcome! Please refer to `CONTRIBUTING.md`.

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.

## Acknowledgments

- [Scapy](https://scapy.net/) - Packet manipulation library
- [PyQt6](https://www.riverbankcomputing.com/software/pyqt/) - GUI framework
- [Matplotlib](https://matplotlib.org/) - Visualization library

## Support

For support, please:
1. Check the [documentation](https://github.com/yourusername/wifi-security-analyzer/wiki)
2. Open an [issue](https://github.com/yourusername/wifi-security-analyzer/issues)
3. Join our [Discord community](https://discord.gg/your-server)

## Roadmap

- [ ] Add support for more WiFi adapters
- [ ] Implement packet capture and analysis
- [ ] Add network performance testing
- [ ] Create mobile companion app
- [ ] Develop API for integration with other tools 
