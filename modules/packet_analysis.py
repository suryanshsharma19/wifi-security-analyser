import pyshark

def analyze_live_traffic(interface="wlan0mon"):
    print(f"[*] Analyzing live traffic on {interface}...")
    capture = pyshark.LiveCapture(interface=interface)

    for packet in capture.sniff_continuously(packet_count=20):
        if 'WLAN' in packet:
            print(f"[Packet] SSID: {packet.wlan.ssid}, Source: {packet.wlan.ta}, Dest: {packet.wlan.da}")

# Example execution
if __name__ == "__main__":
    analyze_live_traffic() 