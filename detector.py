"""
detector.py

Threat Detection Engine
Detects suspicious activities from parsed Apache and SSH logs.
"""

import pandas as pd
from collections import Counter

class ThreatDetector:

    def __init__(self,
                 brute_force_threshold=5,
                 dos_threshold=100,
                 port_scan_threshold=20):

        self.brute_force_threshold = brute_force_threshold
        self.dos_threshold = dos_threshold
        self.port_scan_threshold = port_scan_threshold

    def detect_brute_force(self, ssh_df):

        if ssh_df.empty:
            return pd.DataFrame()

        attempts = (
            ssh_df.groupby("ip")
            .size()
            .reset_index(name="attempts")
        )

        attacks = attempts[
            attempts["attempts"] >= self.brute_force_threshold
        ].copy()

        attacks["attack"] = "Brute Force"

        return attacks

    def detect_dos(self, apache_df):

        if apache_df.empty:
            return pd.DataFrame()

        requests = (
            apache_df.groupby("ip")
            .size()
            .reset_index(name="requests")
        )

        dos = requests[
            requests["requests"] >= self.dos_threshold
        ].copy()

        dos["attack"] = "DoS"

        return dos


    def detect_port_scan(self, ssh_df):

        if ssh_df.empty:
            return pd.DataFrame()

        grouped = (
            ssh_df.groupby("ip")["port"]
            .nunique()
            .reset_index(name="unique_ports")
        )

        scans = grouped[
            grouped["unique_ports"] >= self.port_scan_threshold
        ].copy()

        scans["attack"] = "Port Scan"

        return scans

]

    def detect_suspicious_status(self, apache_df):

        if apache_df.empty:
            return pd.DataFrame()

        suspicious = apache_df[
            apache_df["status"] >= 400
        ].copy()

        return suspicious



    def top_ips(self, apache_df):

        if apache_df.empty:
            return pd.DataFrame()

        return (
            apache_df["ip"]
            .value_counts()
            .reset_index()
            .rename(columns={
                "index": "ip",
                "ip": "requests"
            })
        )

  

    def threat_score(self,
                     brute_force_count,
                     dos_count,
                     port_scan_count):

        score = (
            brute_force_count * 5 +
            dos_count * 4 +
            port_scan_count * 3
        )

        return score

   
    def threat_level(self, score):

        if score >= 100:
            return "CRITICAL"

        elif score >= 50:
            return "HIGH"

        elif score >= 20:
            return "MEDIUM"

        return "LOW"

   
    def summary(self,
                apache_df,
                ssh_df):

        brute = self.detect_brute_force(ssh_df)

        dos = self.detect_dos(apache_df)

        scan = self.detect_port_scan(ssh_df)

        score = self.threat_score(
            len(brute),
            len(dos),
            len(scan)
        )

        return {

            "apache_requests": len(apache_df),

            "ssh_attempts": len(ssh_df),

            "brute_force": len(brute),

            "dos": len(dos),

            "port_scan": len(scan),

            "threat_score": score,

            "threat_level": self.threat_level(score)

        }


if __name__ == "__main__":

    print("Threat Detection Module")
