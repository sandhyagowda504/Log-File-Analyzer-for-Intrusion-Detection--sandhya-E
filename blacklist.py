"""
blacklist.py

IP Blacklist Checker
Checks Apache and SSH log IPs against a blacklist.
"""

import os
import pandas as pd


class BlacklistChecker:

    def __init__(self, blacklist_file="blacklist/blacklist.txt"):
        self.blacklist_file = blacklist_file
        self.blacklisted_ips = set()

  
    # Load blacklist from file
  

    def load_blacklist(self):

        if not os.path.exists(self.blacklist_file):
            print(f"[WARNING] Blacklist file not found: {self.blacklist_file}")
            return

        with open(self.blacklist_file, "r") as file:

            for line in file:

                ip = line.strip()

                if ip:
                    self.blacklisted_ips.add(ip)

        print(f"Loaded {len(self.blacklisted_ips)} blacklisted IPs.")

   
    # Check Apache logs
   

    def check_apache(self, apache_df):

        if apache_df.empty:
            return pd.DataFrame()

        flagged = apache_df[
            apache_df["ip"].isin(self.blacklisted_ips)
        ].copy()

        if not flagged.empty:
            flagged["reason"] = "Blacklisted IP"

        return flagged

    # Check SSH logs
   

    def check_ssh(self, ssh_df):

        if ssh_df.empty:
            return pd.DataFrame()

        flagged = ssh_df[
            ssh_df["ip"].isin(self.blacklisted_ips)
        ].copy()

        if not flagged.empty:
            flagged["reason"] = "Blacklisted IP"

        return flagged

   
    # Combined Report


    def combined_report(self, apache_df, ssh_df):

        apache_hits = self.check_apache(apache_df)

        ssh_hits = self.check_ssh(ssh_df)

        return {
            "apache_hits": apache_hits,
            "ssh_hits": ssh_hits,
            "total_hits": len(apache_hits) + len(ssh_hits)
        }

    
    # Print Summary
 
    def print_summary(self, report):

        print("\n========== BLACKLIST REPORT ==========")

        print(f"Apache Matches : {len(report['apache_hits'])}")
        print(f"SSH Matches    : {len(report['ssh_hits'])}")
        print(f"Total Matches  : {report['total_hits']}")

        print("======================================")

    
    # Save Report
   

    def save_report(self, report, output_file="reports/blacklist_report.csv"):

        frames = []

        if not report["apache_hits"].empty:
            frames.append(report["apache_hits"])

        if not report["ssh_hits"].empty:
            frames.append(report["ssh_hits"])

        if len(frames) == 0:
            print("No blacklisted IPs detected.")
            return

        final_df = pd.concat(frames)

        final_df.to_csv(output_file, index=False)

        print(f"Blacklist report saved to {output_file}")



# Testing


if __name__ == "__main__":

    checker = BlacklistChecker()

    checker.load_blacklist()

    print("Blacklist module loaded successfully.")
