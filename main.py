"""
main.py

Log File Analyzer for Intrusion Detection
Main Application
"""

import os

from parser import LogParser
from detector import ThreatDetector
from blacklist import BlacklistChecker
from visualizer import Visualizer
from report_generator import ReportGenerator

from utils import (
    create_directories,
    print_banner,
    divider,
)

from config import (
    APACHE_LOG,
    SSH_LOG,
)


def main():

    print_banner()

    print("\nInitializing Project...")

    create_directories()


    # Parse Logs


    parser = LogParser()

    print("\nReading Apache Log...")

    apache_df = parser.parse_apache_log(APACHE_LOG)

    print("Apache Records :", len(apache_df))

    print("\nReading SSH Log...")

    ssh_df = parser.parse_ssh_log(SSH_LOG)

    print("SSH Records :", len(ssh_df))

    divider()

   
    # Detect Threats


    detector = ThreatDetector()

    brute_force = detector.detect_brute_force(ssh_df)

    dos = detector.detect_dos(apache_df)

    port_scan = detector.detect_port_scan(ssh_df)

    suspicious_status = detector.detect_suspicious_status(apache_df)

    summary = detector.summary(
        apache_df,
        ssh_df
    )

    # Console Summary
   
    print("\nThreat Analysis")

    divider()

    print("Apache Requests :", summary["apache_requests"])

    print("SSH Attempts :", summary["ssh_attempts"])

    print("Brute Force :", summary["brute_force"])

    print("DoS :", summary["dos"])

    print("Port Scan :", summary["port_scan"])

    print("Threat Score :", summary["threat_score"])

    print("Threat Level :", summary["threat_level"])

    divider()

   
    # Suspicious HTTP Status
 

    print("\nSuspicious HTTP Responses")

    if suspicious_status.empty:

        print("No suspicious HTTP responses found.")

    else:

        print(suspicious_status.head(10))

    divider()

  
    # Blacklist Checker


    checker = BlacklistChecker()

    checker.load_blacklist()

    blacklist_report = checker.combined_report(
        apache_df,
        ssh_df
    )

    checker.print_summary(
        blacklist_report
    )
