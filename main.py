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
    
    # Generate Graphs
   

    print("\nGenerating Charts...")

    visualizer = Visualizer()

    visualizer.generate_all(
        apache_df,
        summary
    )

    print("Charts generated successfully.")

    divider()

    # Generate Reports


    print("\nGenerating Reports...")

    report = ReportGenerator()

    report.generate_all(
        brute_force,
        dos,
        port_scan,
        summary
    )

    checker.save_report(
        blacklist_report
    )

    print("Reports generated successfully.")

    divider()

   
    # Final Statistics
 

    print("\n========== FINAL SUMMARY ==========\n")

    print(f"Apache Requests      : {summary['apache_requests']}")
    print(f"SSH Attempts         : {summary['ssh_attempts']}")
    print(f"Brute Force Attacks  : {summary['brute_force']}")
    print(f"DoS Attacks          : {summary['dos']}")
    print(f"Port Scan Attempts   : {summary['port_scan']}")
    print(f"Threat Score         : {summary['threat_score']}")
    print(f"Threat Level         : {summary['threat_level']}")
    print(f"Blacklist Hits       : {blacklist_report['total_hits']}")

    print("\nGenerated Files")

    print("------------------------------")

    print("✔ reports/incident_report.csv")
    print("✔ reports/incident_report.pdf")
    print("✔ reports/blacklist_report.csv")
    print("✔ charts/attacks_by_ip.png")
    print("✔ charts/attacks_by_hour.png")
    print("✔ charts/status_codes.png")
    print("✔ charts/threat_levels.png")

    print("\nProject Completed Successfully.")

    divider()



# Entry Point


if __name__ == "__main__":

    try:

        main()

    except FileNotFoundError as error:

        print("\nFile Not Found")

        print(error)

    except KeyboardInterrupt:

        print("\nExecution Cancelled by User.")

    except Exception as error:

        print("\nUnexpected Error")

        print(error)
