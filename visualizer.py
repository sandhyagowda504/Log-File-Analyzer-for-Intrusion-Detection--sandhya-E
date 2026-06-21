"""
visualizer.py

Log File Analyzer for Intrusion Detection

Generates charts for:
1. Top Attacking IPs
2. HTTP Status Codes
3. Threat Levels
4. Hourly Requests
"""

import os
import matplotlib.pyplot as plt
import pandas as pd


class Visualizer:

    def __init__(self, output_dir="charts"):

        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

 
    # Top IP Chart


    def plot_top_ips(self, apache_df, top_n=10):

        if apache_df.empty:
            print("No Apache data available.")
            return

        ip_counts = apache_df["ip"].value_counts().head(top_n)

        plt.figure(figsize=(10, 6))
        ip_counts.plot(kind="bar")

        plt.title("Top Attacking IP Addresses")
        plt.xlabel("IP Address")
        plt.ylabel("Number of Requests")

        plt.xticks(rotation=45)
        plt.tight_layout()

        filename = os.path.join(
            self.output_dir,
            "attacks_by_ip.png"
        )

        plt.savefig(filename)
        plt.close()

        print(f"Saved: {filename}")


    # HTTP Status Code Distribution
  

    def plot_status_codes(self, apache_df):

        if apache_df.empty:
            return

        status = apache_df["status"].value_counts()

        plt.figure(figsize=(8, 5))

        status.plot(kind="bar")

        plt.title("HTTP Status Code Distribution")
        plt.xlabel("Status Code")
        plt.ylabel("Count")

        plt.tight_layout()

        filename = os.path.join(
            self.output_dir,
            "status_codes.png"
        )

        plt.savefig(filename)
        plt.close()

        print(f"Saved: {filename}")

    # Threat Level Pie Chart
   

    def plot_threat_levels(self, summary):

        levels = {
            "LOW": 0,
            "MEDIUM": 0,
            "HIGH": 0,
            "CRITICAL": 0
        }

        level = summary.get("threat_level", "LOW")

        levels[level] = 1

        plt.figure(figsize=(6, 6))

        plt.pie(
            levels.values(),
            labels=levels.keys(),
            autopct="%1.1f%%",
            startangle=90
        )

        plt.title("Threat Level")

        filename = os.path.join(
            self.output_dir,
            "threat_levels.png"
        )

        plt.savefig(filename)
        plt.close()

        print(f"Saved: {filename}")

    # Hourly Requests
    

    def plot_hourly_requests(self, apache_df):

        if apache_df.empty:
            return

        try:

            apache_df["hour"] = apache_df["time"].str.extract(r":(\d{2}):")

            hourly = apache_df["hour"].value_counts().sort_index()

            plt.figure(figsize=(10, 5))

            hourly.plot(marker="o")

            plt.title("Requests by Hour")

            plt.xlabel("Hour")

            plt.ylabel("Requests")

            plt.grid(True)

            plt.tight_layout()

            filename = os.path.join(
                self.output_dir,
                "attacks_by_hour.png"
            )

            plt.savefig(filename)
            plt.close()

            print(f"Saved: {filename}")

        except Exception as e:

            print("Hourly graph error:", e)


    # Generate All Graphs


    def generate_all(self, apache_df, summary):

        self.plot_top_ips(apache_df)

        self.plot_status_codes(apache_df)

        self.plot_hourly_requests(apache_df)

        self.plot_threat_levels(summary)


# Testing


if __name__ == "__main__":

    sample = pd.DataFrame({

        "ip": [
            "192.168.1.1",
            "192.168.1.1",
            "192.168.1.2",
            "10.0.0.1",
            "10.0.0.1",
            "10.0.0.1"
        ],

        "status": [
            200,
            404,
            500,
            200,
            403,
            404
        ],

        "time": [
            "20/Jun/2026:10:00:00 +0000",
            "20/Jun/2026:10:20:00 +0000",
            "20/Jun/2026:11:10:00 +0000",
            "20/Jun/2026:12:15:00 +0000",
            "20/Jun/2026:12:30:00 +0000",
            "20/Jun/2026:13:40:00 +0000"
        ]

    })

    summary = {

        "threat_level": "HIGH"

    }

    graph = Visualizer()

    graph.generate_all(sample, summary)

    print("Charts generated successfully.")
