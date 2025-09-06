# SOC Lab

This repository contains a **Security Operations Center (SOC) lab** project with two main components for monitoring, threat detection, and prevention.

---

## Repository Overview

This SOC lab includes:

1. **Python IDS/IPS with Dashboard**  
   - Monitors network traffic in real-time.  
   - Detects and automatically blocks malicious activity.  
   - Supports customizable detection rules.  
   - Provides a web-based dashboard with charts, statistics, and logs.  
   - Uses MaxMind GeoLite2 City database for IP geolocation.  
   - Folder: `IDS and IPS with Dashboard/` (see README inside for setup and usage)

2. **PowerShell Folder**  
   - `MonitoringFolders.ps1` monitors source folder every 2 seconds and transfers all of `.txt` files to the destination folders.  
   - `Api-Request.ps1` sends `.txt` files to the VirusTotal API for malware analysis.  
   - `Api-Request.ps1` logs results and alerts for detected threats.  
   - Folder: `PowerShell/` (see README inside for setup and usage)

---

## Notes

- This SOC lab is for **educational and research purposes only**.  
- Ensure you have permission to monitor networks or access files.  
- Private or unknown IPs are labeled `"private"` or `"unknown"` in the dashboard.