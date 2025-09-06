#!/usr/bin/env python3
import os
import json
import threading
import queue
import sqlite3
import platform
import subprocess
import atexit
import geoip2.database
from ipaddress import ip_address, IPv4Address
from datetime import datetime
import pytz
from scapy.all import sniff, IP, TCP, UDP


#Config
IDS_WORKERS = int(os.getenv("IDS_WORKERS", 3))
GEOIP_DB = os.getenv("GEOIP_DB", "./GeoLite2-City.mmdb")
ALERT_LOG = "alerts.log"
DB_FILE = "alerts.db"
RULES_FILE = "rules.json"
paris_tz = pytz.timezone("Europe/Paris")

# Try to load GeoIP database, but continue if not found
try:
    geoip_reader = geoip2.database.Reader(GEOIP_DB)
    geoip_available = True
    atexit.register(lambda: geoip_reader.close())
except FileNotFoundError:
    print(f"[WARNING] GeoIP database '{GEOIP_DB}' not found. City/Country info will be 'Unknown'.")
    geoip_reader = None
    geoip_available = False

AUTO_IPS = bool(int(os.getenv("AUTO_IPS", 1))) # 1 = ON, 0 = OFF


# IDS Rules load
try:
    with open(RULES_FILE, "r") as f:
        RULES = json.load(f)
except FileNotFoundError:
    RULES = {}

packet_queue = queue.Queue()

# table with startup
conn = sqlite3.connect(DB_FILE, check_same_thread=False)
c = conn.cursor()
c.execute("""
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    proto TEXT,
    alert TEXT,
    city TEXT DEFAULT 'Unknown',
    country TEXT DEFAULT 'Unknown'
)
""")
conn.commit()
conn.close()

# IPS
def block_ip(ip):
    system = platform.system().lower()
    try:
        if "windows" in system:
            cmd = ["netsh", "advfirewall", "firewall", "add", "rule",
                   "name=BlockMaliciousIP", "dir=in", "action=block", f"remoteip={ip}"]
        else:  # Linux / macOS
            cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]

        subprocess.run(cmd, check=True)
    except Exception as e:
        print(f"[IPS ERROR] Error in blocking ip {ip}: {e}")

def is_private_ip(ip):
    try:
        return ip_address(ip).is_private
    except ValueError:
        return False
    
#AUTO IPS
AUTO_IPS_RULE_KEYWORDS = {
    "syn_flood": ["syn flood"],
    "xmas_scan": ["xmas scan"],
    "icmp_flood": ["icmp flood"],
    "ssh_bruteforce": ["ssh brute-force"],
    "telnet_attempt": ["telnet attempt"]
}

# Global counter of alerts per IP
auto_ips_counters = {}
AUTO_IPS_THRESHOLD = {
    "syn_flood": 5,
    "xmas_scan": 3,
    "icmp_flood": 5,
    "ssh_bruteforce": 5,
    "telnet_attempt": 3
}

def auto_block_ip(src_ip, alert_msg):
    """Block only serious threats based on enabled AUTO_IPS rules."""
    if not AUTO_IPS:
        return

    msg_lower = alert_msg.lower()

    for rule, enabled in RULES.items():
        if enabled and rule in AUTO_IPS_RULE_KEYWORDS:
            keywords = AUTO_IPS_RULE_KEYWORDS[rule]
            for kw in keywords:
                if kw.lower() in msg_lower:
                    key = f"{src_ip}_{rule}"
                    auto_ips_counters[key] = auto_ips_counters.get(key, 0) + 1

                    threshold = AUTO_IPS_THRESHOLD.get(rule, 1)
                    if auto_ips_counters[key] >= threshold:
                        block_ip(src_ip)
                        print(f"[AUTO_IPS] Blocked IP {src_ip} due to rule: {rule}")
                        auto_ips_counters[key] = 0  # reset after blocking
                    return

def log_alert(src_ip, dst_ip, proto, alert_msg):
    timestamp = datetime.now(paris_tz).strftime("%d-%m-%Y %H:%M:%S")
    city, country = "Unknown", "Unknown"
    # GEOIP
    if not is_private_ip(src_ip) and geoip_available:
        try:
            response = geoip_reader.city(src_ip)
            country = response.country.name or "Unknown"
            city = response.city.name or "Unknown"
        except Exception as e:
            print(f"[GEOIP ERROR] Error for getting the geo info for {src_ip}: {e}")
            city, country = "Unknown", "Unknown"
    else:
        city, country = "Private" if is_private_ip(src_ip) else "Unknown", "Private" if is_private_ip(src_ip) else "Unknown"
    #Log to file
    with open(ALERT_LOG, "a") as f:
        f.write(f"[{timestamp}] {src_ip} ({city}, {country}) -> {dst_ip} [{proto}] {alert_msg}\n")
    # Save to SQL in a separate connection
    try:
        conn_thread = sqlite3.connect(DB_FILE, check_same_thread=False)
        c_thread = conn_thread.cursor()
        c_thread.execute(
            "INSERT INTO alerts (timestamp, src_ip, dst_ip, proto, alert, city, country) VALUES (?,?,?,?,?,?,?)",
            (timestamp, src_ip, dst_ip, proto, alert_msg, city, country)
        )
        conn_thread.commit()
        conn_thread.close()
    except Exception as e:
        print(f"Error saving to DB: {e}")

    # Optional IPS
    auto_block_ip(src_ip, alert_msg)
    
    # Console Print
    print(f"[ALERT] {timestamp} {src_ip} ({city}, {country}) -> {dst_ip} [{proto}] {alert_msg}")

def check_rules(pkt):
    if IP not in pkt:
        return

    src = pkt[IP].src
    dst = pkt[IP].dst
    proto = ""
    alert_msg = None

    # TCP
    if TCP in pkt:
        proto = "TCP"
        flags = pkt[TCP].flags

        if RULES.get("syn_scan", True) and flags == 0x02:
            alert_msg = "SYN scan detected"
        elif RULES.get("xmas_scan", True) and flags == 0x29:
            alert_msg = "XMAS scan detected"
        elif RULES.get("syn_flood", True) and flags & 0x02:
            alert_msg = "Possible SYN flood"
        elif RULES.get("brute_force_ssh", True) and pkt[TCP].dport == 22:
            alert_msg = "SSH brute force attempt"
        elif RULES.get("brute_force_rdp", True) and pkt[TCP].dport == 3389:
            alert_msg = "RDP brute force attempt"
        elif RULES.get("brute_force_telnet", True) and pkt[TCP].dport == 23:
            alert_msg = "Telnet brute force attempt"
        elif RULES.get("smb_exploit_attempt", True) and pkt[TCP].dport in [139, 445]:
            alert_msg = "SMB exploit attempt"
        elif RULES.get("ftp_brute_force", True) and pkt[TCP].dport == 21:
            alert_msg = "FTP brute force attempt"
        elif RULES.get("suspicious_tls_handshake", True) and proto == "TCP" and pkt[TCP].dport == 443:
            alert_msg = "Suspicious TLS handshake"

    # UDP
    elif UDP in pkt:
        proto = "UDP"
        if RULES.get("udp_suspicious", True):
            alert_msg = "UDP suspicious packet"
        elif RULES.get("dns_tunneling", True) and pkt[UDP].dport == 53:
            alert_msg = "Possible DNS tunneling"

    # ICMP / other protocols
    elif pkt.haslayer("ICMP"):
        proto = "ICMP"
        if RULES.get("icmp_flood", True):
            alert_msg = "ICMP flood detected"
        elif RULES.get("ping_sweep", True):
            alert_msg = "Ping sweep detected"

    # HTTP / other rules based on payloads
    if RULES.get("sql_injection", True) or RULES.get("xss_attack", True) or RULES.get("malicious_file_download", True) or RULES.get("suspicious_http_user_agent", True):
        if pkt.haslayer("Raw"):
            payload = pkt["Raw"].load.decode(errors="ignore").lower()
            if RULES.get("sql_injection", True) and any(s in payload for s in ["union select", "drop table", "insert into"]):
                alert_msg = "SQL injection attempt"
            elif RULES.get("xss_attack", True) and any(s in payload for s in ["<script>", "javascript:"]):
                alert_msg = "XSS attack attempt"
            elif RULES.get("malicious_file_download", True) and any(s in payload for s in [".exe", ".bat", ".scr", ".js"]):
                alert_msg = "Malicious file download attempt"
            elif RULES.get("suspicious_http_user_agent", True) and "sqlmap" in payload:
                alert_msg = "Suspicious HTTP User-Agent detected"

    # if alert is detected
    if alert_msg:
        # log to file and database
        log_alert(src, dst, proto, alert_msg)

#Worker and snifer
def worker():
    while True:
        pkt = packet_queue.get()
        try:
            check_rules(pkt)
        except Exception as e:
            print(f"Error processing packet: {e}")
        packet_queue.task_done()

def start_sniffer():
    sniff(prn=lambda pkt: packet_queue.put(pkt), store=False)

for _ in range(IDS_WORKERS):
    t = threading.Thread(target=worker, daemon=True)
    t.start()

if __name__ == "__main__":
    print("Starting IDS...")
    start_sniffer()
