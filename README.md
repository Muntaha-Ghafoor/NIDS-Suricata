# 🛡️ Network Intrusion Detection System (NIDS)

<div align="center">

![Suricata](https://img.shields.io/badge/Tool-Suricata%208.0.5-orange?style=for-the-badge)
![Kali](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=for-the-badge&logo=kalilinux&logoColor=white)
![Python](https://img.shields.io/badge/Dashboard-Python%203-yellow?style=for-the-badge&logo=python&logoColor=white)
![CodeAlpha](https://img.shields.io/badge/CodeAlpha-Internship%20Task%204-brightgreen?style=for-the-badge)
![Alerts](https://img.shields.io/badge/Alerts%20Detected-59-red?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Completed-success?style=for-the-badge)

**A fully functional Network Intrusion Detection System built using Suricata IDS on Kali Linux — detecting real network attacks with custom rules and visualizing results with a Python dashboard.**

</div>

---

## 📌 Project Overview

This project is **Task 4 — Network Intrusion Detection System** of the **CodeAlpha Cybersecurity Internship Program**.

A fully operational NIDS was set up using **Suricata 8.0.5** on **Kali Linux (VMware)**. Custom Suricata detection rules were written to identify various attack types including port scans, ICMP floods, FTP/Telnet connections, and Metasploit traffic. Real attack traffic was generated using **Nmap** and **ping** tools, and all 59 alerts were captured, analyzed, and visualized using a custom **Python dashboard** with Matplotlib charts.

> 🔒 **Note:** This is a purely defensive, educational project conducted in a controlled local VMware lab environment.

---

## 🎯 Objectives

- ✅ Set up Suricata IDS to monitor live network traffic on eth0
- ✅ Write 8 custom detection rules from scratch
- ✅ Generate real attack traffic to trigger alerts
- ✅ Capture and analyze 59 network intrusion alerts
- ✅ Build a Python dashboard with 4 visualization charts
- ✅ Document all findings in a professional report

---

## 🚨 Alerts Detected

| # | Attack Type | Alerts | Severity | Rule SID |
|---|-------------|--------|----------|----------|
| 1 | Nmap SYN Port Scan | 50 | 🔴 HIGH | 1000002 |
| 2 | ICMP Ping Detected | 6 | 🟡 MEDIUM | 1000001 |
| 3 | FTP Connection Attempt | 1 | 🔴 HIGH | 1000006 |
| 4 | Telnet Connection Attempt | 1 | 🔴 HIGH | 1000005 |
| 5 | Possible Metasploit Connection | 1 | 🔴 HIGH | 1000010 |
| | **TOTAL** | **59** | | |

### Attacking IP Summary

| Source IP | Alerts | Role |
|-----------|--------|------|
| 192.168.137.1 | 56 | Windows Host (attacker simulation) |
| 192.168.137.128 | 3 | Kali Linux (target / IDS sensor) |

---

## 🛠️ Tools Used

| Tool | Version | Purpose |
|------|---------|---------|
| **Suricata** | 8.0.5 | Main IDS engine — monitors eth0 live traffic |
| **Custom Rules** | 8 rules | Written from scratch for specific threat detection |
| **Nmap** | 7.99 | Generate SYN port scan attack traffic |
| **Ping / ICMP** | Built-in | Generate ICMP flood traffic |
| **Python 3** | 3.13 | Dashboard script and log parsing |
| **Matplotlib** | 3.x | Generate 4 professional visualization charts |
| **Kali Linux** | Rolling | Operating system and testing platform |
| **VMware** | Workstation | Virtualization environment |

---

## 📁 Repository Structure

```
NIDS-Suricata/
├── dashboard.py            # Python visualization dashboard
├── custom.rules            # 8 custom Suricata detection rules
├── fast.log                # Suricata alert log (human-readable)
├── eve.json                # Suricata alert log (JSON format)
├── charts/
│   ├── 1_alert_types.png   # Alerts by attack type
│   ├── 2_top_sources.png   # Top attacking IPs
│   ├── 3_protocols.png     # Protocol distribution
│   └── 4_severity.png      # Severity distribution
├── NIDS_Presentation.pptx  # Full presentation
├── NIDS_Presentation.pdf   # PDF version
└── README.md               # This file
```

---

## 📋 Custom Detection Rules

```
# Rule 1: Detect ICMP Ping
alert icmp any any -> $HOME_NET any (msg:"ICMP Ping Detected"; sid:1000001; rev:1;)

# Rule 2: Detect Nmap SYN Port Scan
alert tcp any any -> $HOME_NET any (msg:"Nmap SYN Port Scan Detected"; flags:S; threshold:type threshold, track by_src, count 20, seconds 3; sid:1000002; rev:1;)

# Rule 3: Detect SSH Brute Force
alert tcp any any -> $HOME_NET 22 (msg:"SSH Brute Force Attempt"; threshold:type threshold, track by_src, count 5, seconds 60; sid:1000003; rev:1;)

# Rule 4: Detect Telnet Connection
alert tcp any any -> $HOME_NET 23 (msg:"Telnet Connection Attempt"; sid:1000005; rev:1;)

# Rule 5: Detect FTP Connection
alert tcp any any -> $HOME_NET 21 (msg:"FTP Connection Attempt"; sid:1000006; rev:1;)

# Rule 6: Detect DNS Flood
alert udp any any -> any 53 (msg:"Possible DNS Flood"; threshold:type threshold, track by_src, count 30, seconds 5; sid:1000007; rev:1;)

# Rule 7: Detect Large ICMP Packet
alert icmp any any -> $HOME_NET any (msg:"Large ICMP Packet Detected"; dsize:>800; sid:1000008; rev:1;)

# Rule 8: Detect Metasploit Default Port
alert tcp any any -> $HOME_NET 4444 (msg:"Possible Metasploit Connection"; sid:1000010; rev:1;)
```

---

## ▶️ How to Run

### Step 1 — Install Suricata

```bash
sudo apt update
sudo apt install suricata nmap -y
```

### Step 2 — Add Custom Rules

```bash
sudo cp custom.rules /var/lib/suricata/rules/
```

### Step 3 — Update Suricata Config

```bash
sudo nano /etc/suricata/suricata.yaml
# Set rule-files to only: custom.rules
# Set HOME_NET to your network range
```

### Step 4 — Start Suricata

```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eth0 -v
```

### Step 5 — Generate Test Attack Traffic

```bash
# In a second terminal:
ping -c 50 YOUR_IP
sudo nmap -sS YOUR_IP
sudo nmap -p 21,22,23,4444 YOUR_IP
ping -c 10 -s 1000 YOUR_IP
```

### Step 6 — Check Alerts

```bash
sudo cat /var/log/suricata/fast.log
sudo wc -l /var/log/suricata/fast.log
```

### Step 7 — Run Python Dashboard

```bash
sudo cp /var/log/suricata/eve.json ./eve.json
python3 dashboard.py
ls -lh charts/
```

---

## 📊 Dashboard Charts

| Chart | Type | Shows |
|-------|------|-------|
| `1_alert_types.png` | Horizontal Bar | Count of each attack type detected |
| `2_top_sources.png` | Vertical Bar | Top IP addresses generating alerts |
| `3_protocols.png` | Pie Chart | TCP vs ICMP vs UDP breakdown |
| `4_severity.png` | Vertical Bar | HIGH / MEDIUM / LOW alert counts |

---

## 🔁 Response Mechanisms

| Alert Type | Recommended Response |
|-----------|---------------------|
| Port Scan Detected | Block source IP with iptables firewall |
| SSH Brute Force | Rate limit SSH, enable fail2ban |
| Metasploit Connection | Immediately isolate affected host |
| FTP/Telnet Attempts | Disable legacy protocols, use SFTP/SSH |
| ICMP Flood | Apply ICMP rate limiting rules |

---

## 🏢 Internship Details

| Field | Details |
|-------|---------|
| **Internship** | CodeAlpha |
| **Domain** | Cybersecurity |
| **Task** | Task 4 — Network Intrusion Detection System |
| **IDS Tool** | Suricata 8.0.5 |
| **Platform** | Kali Linux on VMware Workstation |
| **Interface Monitored** | eth0 (192.168.137.128/24) |
| **Total Alerts Detected** | 59 real network alerts |
| **Rules Written** | 8 custom Suricata rules |

---

## 👩‍💻 Author

<div align="center">

### Muntaha Ghafoor
**Cybersecurity Intern @ CodeAlpha**

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Muntaha%20Ghafoor-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/muntaha-ghafoor-2b87a9386)
[![GitHub](https://img.shields.io/badge/GitHub-Muntaha--Ghafoor-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/Muntaha-Ghafoor)

*Passionate about cybersecurity, network security, and building defensive tools.*

</div>

---

## 📄 License

This project is open-source under the [MIT License](LICENSE).
Free to use and adapt for educational purposes with proper attribution.

---

<div align="center">

⭐ **If this project helped you, please give it a star!** ⭐

*Detect early. Respond fast. Stay secure. 🛡️*

</div>
