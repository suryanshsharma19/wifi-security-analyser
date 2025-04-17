from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeResp
from .config import config
import random
import time
import platform
import subprocess
import re

def get_windows_interfaces():
    """Get list of available WiFi interfaces on Windows"""
    try:
        result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], 
                              capture_output=True, text=True)
        interfaces = []
        for line in result.stdout.split('\n'):
            if 'Name' in line:
                interface = line.split(':')[1].strip()
                interfaces.append(interface)
        return interfaces
    except Exception as e:
        print(f"Error getting Windows interfaces: {str(e)}")
        return ["Wi-Fi"]  # Default fallback

def get_windows_networks():
    """Get WiFi networks using Windows netsh command"""
    try:
        result = subprocess.run(['netsh', 'wlan', 'show', 'networks', 'mode=bssid'], 
                              capture_output=True, text=True)
        
        networks = {}
        current_ssid = None
        current_bssid = None
        
        for line in result.stdout.split('\n'):
            line = line.strip()
            if 'SSID' in line and 'BSSID' not in line:
                current_ssid = line.split(':')[1].strip()
            elif 'BSSID' in line and current_ssid:
                current_bssid = line.split(':')[1].strip()
            elif 'Signal' in line and current_ssid and current_bssid:
                signal = int(line.split(':')[1].strip().replace('%', ''))
                # Convert percentage to dBm (approximate)
                signal_dbm = -100 + (signal * 0.5)
            elif 'Channel' in line and current_ssid and current_bssid:
                channel = int(line.split(':')[1].strip())
            elif 'Authentication' in line and current_ssid and current_bssid:
                auth = line.split(':')[1].strip()
                if 'WPA2' in auth:
                    encryption = 'WPA2'
                elif 'WPA' in auth:
                    encryption = 'WPA'
                elif 'WEP' in auth:
                    encryption = 'WEP'
                else:
                    encryption = 'None'
                
                networks[current_bssid] = {
                    "SSID": current_ssid,
                    "Signal Strength": signal_dbm,
                    "Channel": channel,
                    "Encryption": encryption
                }
                current_bssid = None
        
        return networks
    except Exception as e:
        print(f"Error getting Windows networks: {str(e)}")
        return {}

def simulate_scan():
    """Simulate WiFi scanning for testing purposes"""
    networks = {}
    hidden_networks = {}
    
    # Use simulation data from config
    sim_networks = config.get("simulation_data", {}).get("networks", {})
    
    for bssid, info in sim_networks.items():
        # Add some random variation to signal strength
        signal = info["Signal Strength"] + random.randint(-5, 5)
        
        network_info = {
            "SSID": info["SSID"],
            "Signal Strength": signal,
            "Channel": info["Channel"],
            "Encryption": info["Encryption"]
        }
        
        if random.random() < 0.1:  # 10% chance of being hidden
            hidden_networks[bssid] = network_info
        else:
            networks[bssid] = network_info
    
    return {"Visible Networks": networks, "Hidden Networks": hidden_networks}

def advanced_scan(interface=None):
    """Perform WiFi scanning with support for simulation mode and Windows"""
    if config.simulation_mode:
        return simulate_scan()
    
    if interface is None:
        interface = config.get("interface")
    
    networks = {}
    hidden_networks = {}

    try:
        if config.is_windows:
            # On Windows, use netsh to get network information
            networks = get_windows_networks()
            if not networks:
                print("No networks found or error occurred. Switching to simulation mode...")
                return simulate_scan()
        else:
            # On Linux/Unix systems, use scapy
            def packet_handler(packet):
                try:
                    if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
                        bssid = packet[Dot11].addr2
                        ssid = packet.info.decode(errors="ignore") if packet.info else "Hidden SSID"
                        signal = packet.dBm_AntSignal
                        channel = int(ord(packet[Dot11Elt:3].info))
                        encryption = "Open" if "privacy" not in str(packet.cap) else "Encrypted"

                        network_info = {
                            "SSID": ssid,
                            "Signal Strength": signal,
                            "Channel": channel,
                            "Encryption": encryption
                        }

                        if ssid == "Hidden SSID":
                            hidden_networks[bssid] = network_info
                        else:
                            networks[bssid] = network_info
                except Exception as e:
                    print(f"Error processing packet: {str(e)}")

            sniff(prn=packet_handler, iface=interface, timeout=30)
    except Exception as e:
        print(f"Error during scan: {str(e)}")
        if config.is_windows:
            print("Note: On Windows, you need a compatible WiFi adapter")
        else:
            print("Note: You need a WiFi adapter in monitor mode")
        print("Using simulation mode instead...")
        return simulate_scan()
        
    return {"Visible Networks": networks, "Hidden Networks": hidden_networks}

# Example execution
if __name__ == "__main__":
    networks = advanced_scan()
    print(networks) 