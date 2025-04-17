from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11ProbeResp

def detect_threats(interface="wlan0mon"):
    print("[*] Monitoring for threats...")

    def packet_handler(packet):
        if packet.type == 0 and packet.subtype == 12:  # Deauthentication frame
            print(f"[!] Deauthentication attack detected from {packet.addr2}")
        elif packet.haslayer(Dot11ProbeResp):
            ssid = packet.info.decode(errors="ignore")
            bssid = packet[Dot11].addr2
            print(f"[!] Rogue AP detected: SSID={ssid}, BSSID={bssid}")

    sniff(iface=interface, prn=packet_handler)

# Example execution
if __name__ == "__main__":
    detect_threats() 