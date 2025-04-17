import React, { useEffect, useState } from "react";

function App() {
  const [networks, setNetworks] = useState([]);
  const [error, setError] = useState(null);

  useEffect(() => {
    // Fetch data from the server or mock the API response
    fetch("/api/networks")
      .then((response) => {
        if (!response.ok) {
          throw new Error("Failed to fetch networks");
        }
        return response.json();
      })
      .then((data) => setNetworks(Object.entries(data)))
      .catch((err) => setError(err.message));
  }, []);

  // Mock data for local testing
  const mockNetworks = [
    ["00:11:22:33:44:55", { SSID: "Network1", "Signal Strength": -45, Encryption: "WPA2" }],
    ["AA:BB:CC:DD:EE:FF", { SSID: "Network2", "Signal Strength": -75, Encryption: "WEP" }],
    ["11:22:33:44:55:66", { SSID: "Network3", "Signal Strength": -30, Encryption: "Open" }],
  ];

  return (
    <div>
      <h1>Wi-Fi Security Analyzer</h1>
      {error && <p style={{ color: "red" }}>Error: {error}</p>}
      <table border="1">
        <thead>
          <tr>
            <th>SSID</th>
            <th>Signal Strength</th>
            <th>Encryption</th>
          </tr>
        </thead>
        <tbody>
          {(networks.length > 0 ? networks : mockNetworks).map(([bssid, info]) => (
            <tr key={bssid}>
              <td>{info.SSID}</td>
              <td>{info["Signal Strength"]} dBm</td>
              <td>{info.Encryption}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default App; 