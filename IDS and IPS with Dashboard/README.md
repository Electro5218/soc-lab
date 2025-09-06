# 🛡️ IDS/AutoIPS with Dashboard

An **Intrusion Detection and Prevention System (IDS/IPS)** with a graphical dashboard for real-time monitoring and analysis of network traffic.

---

## 🚀 Features
- Detects suspicious network activity (IDS).
- Blocks automatically malicious traffic (AUTOIPS).
- Dashboard provides:
  - 📊 Network statistics,
  - 🚨 Attack alerts,
  - 📝 Event logs and history.
- Customizable detection rules.
- Real-time live monitoring.
- Optional mapping of Countries and Cities(MaxMind)

---

## 🖼️ Screenshots

### Main Dashboard
![Dashboard](https://github.com/Electro5218/soc-lab/blob/main/IDS%20and%20IPS%20with%20Dashboard/screenshots/Dashboard.png)

### Alerts Chart 
![AlertsChart](https://github.com/Electro5218/soc-lab/blob/main/IDS%20and%20IPS%20with%20Dashboard/screenshots/Alerts.png)

### Traffic Statistics
![Stats](https://github.com/Electro5218/soc-lab/blob/main/IDS%20and%20IPS%20with%20Dashboard/screenshots/Statistics.png)

### Rules
![Rules](https://github.com/Electro5218/soc-lab/blob/main/IDS%20and%20IPS%20with%20Dashboard/screenshots/Rules.png)

### IDS and AUTOIPS Demonstration
![IDS/AUTOIPS](https://github.com/Electro5218/soc-lab/blob/main/IDS%20and%20IPS%20with%20Dashboard/screenshots/IDSandAUTOIPS.png)

---
## GeoLite2 City Database Setup (Optional)

**This project uses the MaxMind GeoLite2 City database (`GeoLite2-City.mmdb`) optionally for IP geolocation. Follow these steps to obtain and use it.**

---

## 1. Sign Up for a MaxMind Account

1. Go to the [GeoLite Sign Up page](https://www.maxmind.com/en/geolite2/signup) and create a free account.
2. Accept the GeoLite End User License Agreement during registration.

---

## 2. Download the GeoLite2 City Database

1. After logging in, visit the [GeoLite Databases page](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/).
2. Locate **GeoLite2 City** and download the `.tar.gz` archive.

---

## 3. Extract the Database

1. Use a tool like **7-Zip** or **WinRAR** to extract the `.tar.gz` file.
2. Inside the extracted folder, find the file `GeoLite2-City.mmdb`.

## ⚙️ Installation & Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/Electro5218/soc-lab.git
   cd "soc-lab/IDS and IPS with Dashboard"
    ```
2. Create a virtual environment:
    ```bash
   python -m venv .venv
    ```
3. Activate the virtual environment:
    **On Linux / macOS:**
    ```bash
    source .venv/bin/activate
    ```
    **On Windows (PowerShell):**
    ```powershell
    .venv\Scripts\Activate.ps1
    ```
4. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```
5. Run the IDS/IPS and dashboard:
    ```bash
    python ids-ips.py
    python webapp.py
    ```
6. Open the dashboard in your browser:
    [Dashboard - Localhost](http://localhost:5000)

---

## 🛠️ Technologies

**🐍⚡📡 Python (Flask / Scapy)**

**🌐🎨💻 Frontend (HTML/CSS/TS(Converted into JS))**

**🗄️🧩💾 Database (SQLite)**

**🌍📍 GeoLite2 City (IP Geolocation Database)**

---
## 📘 Usage

1. Start IDS/IPS and the application.

2. Go to the Dashboard in your webbrowser on localhost.

3. Monitor real-time network traffic.

4. In case of an alert, review the suspicious activity and take action (e.g., block an IP).

5. Browse logs with geolocation mapping(optional) for historical data.

---

## Author

**Name:** Pawel (Electro5218)  
**GitHub:** [github.com/Electro5218](https://github.com/Electro5218)  
**Date:** 06-09-2025 (DD/MM/YY)