"""
dashboard.py
Network Intrusion Detection System - Alert Dashboard
Parses Suricata eve.json and generates visual charts
Author: Muntaha Ghafoor | CodeAlpha Internship Task 4
"""

import json
import os
from collections import Counter
from datetime import datetime
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

LOG_FILE  = "./eve.json"
OUT_DIR   = "./charts"
os.makedirs(OUT_DIR, exist_ok=True)

# ── Load alerts from eve.json ──────────────────────────────
def load_alerts():
    alerts = []
    with open(LOG_FILE, "r") as f:
        for line in f:
            try:
                e = json.loads(line.strip())
                if e.get("event_type") == "alert":
                    alerts.append(e)
            except:
                continue
    return alerts

# ── Chart 1: Alert Types Bar Chart ────────────────────────
def plot_alert_types(alerts):
    sigs   = [a["alert"]["signature"] for a in alerts]
    counts = Counter(sigs)
    labels = list(counts.keys())
    values = list(counts.values())
    colors = ["#EF4444","#F59E0B","#3B82F6","#10B981","#8B5CF6"][:len(values)]

    fig, ax = plt.subplots(figsize=(12, 5))
    fig.patch.set_facecolor("#0A0F1E")
    ax.set_facecolor("#111827")
    bars = ax.barh(labels, values, color=colors, edgecolor="#1E3A5F", linewidth=0.8)
    for bar, val in zip(bars, values):
        ax.text(val + 0.3, bar.get_y() + bar.get_height()/2,
                str(val), va='center', color='white',
                fontsize=11, fontweight='bold')
    ax.set_xlabel("Number of Alerts", color="white", fontsize=12)
    ax.set_title("🚨 Suricata IDS — Alerts by Attack Type",
                 color="white", fontsize=15, fontweight='bold', pad=15)
    ax.tick_params(colors='white')
    for spine in ax.spines.values():
        spine.set_color('#334155')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.set_xlim(0, max(values) + 5)
    plt.tight_layout()
    path = f"{OUT_DIR}/1_alert_types.png"
    plt.savefig(path, dpi=150, bbox_inches='tight', facecolor="#0A0F1E")
    plt.close()
    print(f"✅ Chart 1 saved: {path}")

# ── Chart 2: Top Source IPs ────────────────────────────────
def plot_top_sources(alerts):
    ips    = [a.get("src_ip","unknown") for a in alerts]
    counts = Counter(ips).most_common(8)
    labels = [ip for ip, _ in counts]
    values = [c  for _, c  in counts]
    colors = ["#EF4444" if v == max(values) else "#3B82F6" for v in values]

    fig, ax = plt.subplots(figsize=(10, 5))
    fig.patch.set_facecolor("#0A0F1E")
    ax.set_facecolor("#111827")
    bars = ax.bar(labels, values, color=colors,
                  edgecolor="#1E3A5F", linewidth=0.8, width=0.5)
    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width()/2,
                bar.get_height() + 0.3,
                str(val), ha='center', color='white',
                fontsize=12, fontweight='bold')
    ax.set_xlabel("Source IP Address", color="white", fontsize=12)
    ax.set_ylabel("Alert Count",       color="white", fontsize=12)
    ax.set_title("🌐 Top Attacking IP Addresses",
                 color="white", fontsize=15, fontweight='bold', pad=15)
    ax.tick_params(colors='white')
    for spine in ax.spines.values():
        spine.set_color('#334155')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    plt.tight_layout()
    path = f"{OUT_DIR}/2_top_sources.png"
    plt.savefig(path, dpi=150, bbox_inches='tight', facecolor="#0A0F1E")
    plt.close()
    print(f"✅ Chart 2 saved: {path}")

# ── Chart 3: Protocol Pie Chart ────────────────────────────
def plot_protocol_pie(alerts):
    protos = [a.get("proto","OTHER") for a in alerts]
    counts = Counter(protos)
    colors = ["#3B82F6","#EF4444","#10B981","#F59E0B","#8B5CF6"]

    fig, ax = plt.subplots(figsize=(7, 7))
    fig.patch.set_facecolor("#0A0F1E")
    ax.set_facecolor("#111827")
    wedges, texts, autotexts = ax.pie(
        counts.values(),
        labels=counts.keys(),
        autopct='%1.1f%%',
        colors=colors[:len(counts)],
        startangle=140,
        wedgeprops=dict(edgecolor='#0A0F1E', linewidth=2)
    )
    for text in texts:
        text.set_color('white')
        text.set_fontsize(13)
    for autotext in autotexts:
        autotext.set_color('white')
        autotext.set_fontsize(11)
        autotext.set_fontweight('bold')
    ax.set_title("📡 Alerts by Protocol",
                 color="white", fontsize=15, fontweight='bold', pad=20)
    plt.tight_layout()
    path = f"{OUT_DIR}/3_protocols.png"
    plt.savefig(path, dpi=150, bbox_inches='tight', facecolor="#0A0F1E")
    plt.close()
    print(f"✅ Chart 3 saved: {path}")

# ── Chart 4: Severity Distribution ────────────────────────
def plot_severity(alerts):
    sigs   = [a["alert"]["signature"] for a in alerts]
    counts = Counter(sigs)
    high_kw   = ["Metasploit","Brute Force","FTP","Telnet","Port Scan"]
    medium_kw = ["Large ICMP","Directory"]
    high = medium = low = 0
    for sig, count in counts.items():
        if any(k in sig for k in high_kw):     high   += count
        elif any(k in sig for k in medium_kw): medium += count
        else:                                   low    += count

    categories = ['🔴 HIGH', '🟡 MEDIUM', '🟢 LOW']
    values     = [high, medium, low]
    colors     = ['#EF4444', '#F59E0B', '#10B981']

    fig, ax = plt.subplots(figsize=(8, 5))
    fig.patch.set_facecolor("#0A0F1E")
    ax.set_facecolor("#111827")
    bars = ax.bar(categories, values, color=colors,
                  edgecolor='#1E3A5F', linewidth=1, width=0.4)
    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width()/2,
                bar.get_height() + 0.3,
                str(val), ha='center', color='white',
                fontsize=18, fontweight='bold')
    ax.set_ylabel("Number of Alerts", color="white", fontsize=12)
    ax.set_title("⚠️ Alert Severity Distribution",
                 color="white", fontsize=15, fontweight='bold', pad=15)
    ax.tick_params(colors='white')
    for spine in ax.spines.values():
        spine.set_color('#334155')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    plt.tight_layout()
    path = f"{OUT_DIR}/4_severity.png"
    plt.savefig(path, dpi=150, bbox_inches='tight', facecolor="#0A0F1E")
    plt.close()
    print(f"✅ Chart 4 saved: {path}")

# ── Print Summary ──────────────────────────────────────────
def print_summary(alerts):
    sigs = Counter([a["alert"]["signature"] for a in alerts])
    ips  = Counter([a.get("src_ip","?")     for a in alerts])
    print(f"\n{'='*55}")
    print(f"  NIDS ALERT SUMMARY — SURICATA IDS")
    print(f"  Author  : Muntaha Ghafoor")
    print(f"  Task    : CodeAlpha Internship — Task 4")
    print(f"  Date    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*55}")
    print(f"  Total Alerts : {len(alerts)}")
    print(f"\n  Alerts by Type:")
    for sig, count in sigs.most_common():
        bar = "█" * min(count, 50)
        print(f"  {count:3d}  {bar}  {sig}")
    print(f"\n  Top Attacking IPs:")
    for ip, count in ips.most_common(5):
        print(f"  {count:3d}  {ip}")
    print(f"\n  Charts saved to: {OUT_DIR}/")
    print(f"{'='*55}\n")

# ── Main ───────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n🔍 Loading Suricata alerts from eve.json ...")
    alerts = load_alerts()
    print(f"📊 Total alerts loaded: {len(alerts)}")
    print("\n📈 Generating charts ...")
    plot_alert_types(alerts)
    plot_top_sources(alerts)
    plot_protocol_pie(alerts)
    plot_severity(alerts)
    print_summary(alerts)
    print("✅ All done! Check the charts/ folder.")
