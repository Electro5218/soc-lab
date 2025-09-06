#!/usr/bin/env python3
from flask import Flask, render_template, request, jsonify
import json
import sqlite3
from collections import Counter
from datetime import datetime

DB_FILE = "alerts.db"
RULES_FILE = "rules.json"
app = Flask(__name__)

# Download recent alerts
def get_alerts():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT timestamp, src_ip, dst_ip, proto, alert, city, country FROM alerts ORDER BY id DESC LIMIT 100")
    rows = c.fetchall()
    conn.close()

    alerts = []
    for ts, src, dst, proto, alert, city, country in rows:
        try:
            # Converting ISO 8601 to YYYY-MM-DD HH:MM:SS
            ts_formatted = datetime.fromisoformat(ts).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            ts_formatted = ts  # if error, leave raw
        alerts.append((ts_formatted, src, dst, proto, alert, city, country))

    return alerts

# chart data (alert amount per hour)
def get_chart_data():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT timestamp FROM alerts ORDER BY id DESC LIMIT 500")
    timestamps = [row[0] for row in c.fetchall()]
    conn.close()

    print("=== DEBUG CHART DATA ===")
    print("Timestamps from DB:", timestamps[:5])

    hours = []
    for ts in timestamps:
        dt = None
        try:
            # handle DD-MM-YYYY HH:MM:SS
            dt = datetime.strptime(ts, "%d-%m-%Y %H:%M:%S")
        except Exception as e:
            print("Parse error:", ts, e)
            continue
        hours.append(dt.strftime("%d-%m-%Y %H:00"))

    counts = Counter(hours)
    labels = sorted(counts.keys())
    data = [counts[h] for h in labels]

    print("Labels:", labels)
    print("Data:", data)
    print("========================")


    return labels, data


def load_rules():
    with open(RULES_FILE, "r") as f:
        return json.load(f)

def save_rules(rules):
    with open(RULES_FILE, "w") as f:
        json.dump(rules, f, indent=2)

@app.route("/", methods=["GET"])
def index():
    alerts = get_alerts()
    labels, data = get_chart_data()
    return render_template(
        "index.html",
        alerts=alerts,
        chart_labels=labels,
        chart_data=data
    )

@app.route("/stats")
def stats():
    # TOP 5 source IPs
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT src_ip FROM alerts")
    src_ips = [row[0] for row in c.fetchall()]
    conn.close()

    from collections import Counter
    counts = Counter(src_ips).most_common(5)
    labels = [ip for ip, _ in counts]
    data = [cnt for _, cnt in counts]

    return render_template("stats.html", labels=labels, data=data)

@app.route("/rules")
def rules():
    rules = load_rules()
    return render_template("rules.html", rules=rules)

@app.route('/update_rule', methods=['POST'])
def update_rule():
    data = request.get_json()
    rule = data.get('rule')
    enabled = data.get('enabled')
    #Load current rules
    rules = load_rules()

    if rule in rules:
        rules[rule] = enabled
        save_rules(rules) # Save rules to file
        return jsonify({"success": True})
    return jsonify({"success": False}), 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
