from flask import Flask, jsonify
import threading

app = Flask(__name__)

# Simulated scan result
networks = {"00:11:22:33:44:55": {"SSID": "Network1", "Signal Strength": -45, "Encryption": "WPA2"}}

@app.route('/api/networks', methods=['GET'])
def get_networks():
    return jsonify(networks)

def start_server(debug=True):
    threading.Thread(target=app.run, kwargs={"debug": debug}).start()

# Example execution
if __name__ == "__main__":
    start_server() 