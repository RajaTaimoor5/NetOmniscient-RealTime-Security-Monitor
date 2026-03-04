<img width="1919" height="903" alt="2" src="https://github.com/user-attachments/assets/eba55194-5b0c-4c46-82a6-f8a9ad6c62dc" /># NetOmniscient-RealTime-Security-Monitor
**Real-Time Windows Network Security & Monitoring Tool**

NetOmniscient is a sophisticated monitoring system designed to bridge the gap between traditional batch-processed logs and real-time incident response. Built specifically for Windows environments, it monitors native firewall logs and live network traffic to detect anomalies as they happen.A Python-based real-time network security tool for Windows. Uses Scapy for packet sniffing and WebSockets for instant threat alerting.# NetOmniscient 🛡️

## 🚀 Key Features

- **Live Packet Sniffing:** Captures network metadata using the Scapy library to identify suspicious traffic patterns.
- **Firewall Log Integration:** Real-time monitoring of `pfirewall.log` using the Watchdog API.
- **Instant Alerting:** Web-based GUI powered by Flask-SocketIO (WebSockets) for sub-second threat notifications.
- **Multi-Threaded Engine:** Optimized backend to handle concurrent data streams without GUI latency.

## 🛠️ Tech Stack
- **Language:** Python 3.x
- **Backend:** Flask, Flask-SocketIO (WebSockets)
- **Security Logic:** Scapy (Packet Analysis), Watchdog (Log Tracking)
- **Frontend:** HTML5, CSS3 (Tailwind CSS), JavaScript

## 📊 System Architecture
The system operates on a modular architecture:
1. **LogMonitor:** Watches for Windows Firewall file changes.
2. **PacketSniffer:** Captures raw network packets for metadata analysis.
3. **AlertManager:** Evaluates traffic against pre-defined threat thresholds (DDoS, Port Scans)

4. **WebSocket Server:** Pushes live updates to the dashboard.

## 📸 Screenshots

<img width="1919" height="895" alt="6" src="https://github.com/user-attachments/assets/b0647625-caae-45dc-bac0-0243e4928d79" />
<img width="1919" height="897" alt="5" src="https://github.com/user-attachments/assets/bc6fb6f0-8466-45bd-a19e-efccf4c67fb4" />
<img width="1919" height="896" alt="4" src="https://github.com/user-attachments/assets/15248811-fc36-4e90-9871-67ef78a0891a" />
<img width="1919" height="896" alt="3" src="https://github.com/user-attachments/assets/ad3e6faf-6316-4b3a-ba62-a248ffb4ef61" />
<img width="1919" height="903" alt="2" src="https://github.com/user-attachments/assets/fc528b52-1664-40cb-83f6-506d631c2551" />
<img width="1919" height="898" alt="1" src="https://github.com/user-attachments/assets/b7b5a1fd-45af-4f41-b105-4d6f4a005e12" />

[NetOminicient - Intrusion Detection System.zip](https://github.com/user-attachments/files/25739161/NetOminicient.-.Intrusion.Detection.System.zip)

## 🛠️ Installation
1. Clone the repository:
   ```bash
   git clone [https://github.com/YOUR_USERNAME/NetOmniscient.git](https://github.com/YOUR_USERNAME/NetOmniscient.git)
