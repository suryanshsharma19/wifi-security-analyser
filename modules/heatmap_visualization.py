import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
from random import randint

def visualize_heatmap(networks):
    fig, ax = plt.subplots()
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 10)

    def update(frame):
        ax.clear()
        for bssid, info in networks.items():
            x, y = randint(0, 10), randint(0, 10)  # Random coordinates
            signal_strength = info["Signal Strength"]
            ax.scatter(x, y, s=100, c='blue' if signal_strength > -60 else 'red', alpha=0.7)
            ax.text(x, y, f"{info['SSID']} ({signal_strength} dBm)", fontsize=9)

    ani = FuncAnimation(fig, update, interval=1000)
    plt.show()

# Example execution
if __name__ == "__main__":
    # Simulated networks for testing
    networks = {"00:11:22:33:44:55": {"SSID": "Network1", "Signal Strength": -45}}
    visualize_heatmap(networks) 