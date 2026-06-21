"""
Configuration File
Log File Analyzer for Intrusion Detection
"""

import os

# ----------------------------
# Project Directories
# ----------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

LOG_DIR = os.path.join(BASE_DIR, "logs")
REPORT_DIR = os.path.join(BASE_DIR, "reports")
CHART_DIR = os.path.join(BASE_DIR, "charts")
BLACKLIST_DIR = os.path.join(BASE_DIR, "blacklist")

# ----------------------------
# Log Files
# ----------------------------

APACHE_LOG = os.path.join(LOG_DIR, "apache.log")
SSH_LOG = os.path.join(LOG_DIR, "ssh.log")

# ----------------------------
# Output Files
# ----------------------------

CSV_REPORT = os.path.join(REPORT_DIR, "incident_report.csv")
PDF_REPORT = os.path.join(REPORT_DIR, "incident_report.pdf")

ATTACK_GRAPH = os.path.join(CHART_DIR, "attacks_by_ip.png")
TIME_GRAPH = os.path.join(CHART_DIR, "attacks_by_hour.png")
THREAT_GRAPH = os.path.join(CHART_DIR, "threat_levels.png")

# ----------------------------
# Blacklist
# ----------------------------

BLACKLIST_FILE = os.path.join(BLACKLIST_DIR, "blacklist.txt")

# ----------------------------
# Detection Thresholds
# ----------------------------

BRUTE_FORCE_THRESHOLD = 5
DOS_THRESHOLD = 100
PORT_SCAN_THRESHOLD = 20

# ----------------------------
# Threat Levels
# ----------------------------

LOW = "LOW"
MEDIUM = "MEDIUM"
HIGH = "HIGH"
CRITICAL = "CRITICAL"
