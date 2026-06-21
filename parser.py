"""
parser.py

Parses Apache access logs and SSH authentication logs
into structured pandas DataFrames.
"""

import re
import pandas as pd
from pathlib import Path

# --------------------------------------------------------------------
# Apache Log Pattern (Common Log Format)
# Example:
# 127.0.0.1 - - [20/Jun/2026:10:15:20 +0000] "GET /index.html HTTP/1.1" 200 1024
# --------------------------------------------------------------------

APACHE_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<time>.*?)\] '
    r'"(?P<method>\S+) (?P<url>\S+) (?P<protocol>.*?)" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
)

# --------------------------------------------------------------------
# SSH Authentication Pattern
# Example:
# Jun 20 10:22:10 server sshd[1234]: Failed password for root from 192.168.1.5 port 53210 ssh2
# --------------------------------------------------------------------

SSH_PATTERN = re.compile(
    r'(?P<month>\w+)\s+'
    r'(?P<day>\d+)\s+'
    r'(?P<time>\d+:\d+:\d+).*?'
    r'Failed password for (?P<user>\S+) from '
    r'(?P<ip>\d+\.\d+\.\d+\.\d+) '
    r'port (?P<port>\d+)'
)


class LogParser:
    """
    Parses Apache and SSH logs.
    """

    def __init__(self):
        self.apache_df = pd.DataFrame()
        self.ssh_df = pd.DataFrame()

    # ---------------------------------------------------------

    def parse_apache_log(self, file_path):
        """
        Parse Apache access log.
        """

        rows = []

        file_path = Path(file_path)

        if not file_path.exists():
            print(f"[ERROR] Apache log not found: {file_path}")
            return pd.DataFrame()

        with open(file_path, "r", encoding="utf-8") as logfile:

            for line in logfile:

                match = APACHE_PATTERN.match(line)

                if match:

                    rows.append({

                        "ip": match.group("ip"),

                        "time": match.group("time"),

                        "method": match.group("method"),

                        "url": match.group("url"),

                        "protocol": match.group("protocol"),

                        "status": int(match.group("status")),

                        "size": match.group("size")

                    })

        self.apache_df = pd.DataFrame(rows)

        return self.apache_df

    # ---------------------------------------------------------

    def parse_ssh_log(self, file_path):
        """
        Parse SSH authentication log.
        """

        rows = []

        file_path = Path(file_path)

        if not file_path.exists():
            print(f"[ERROR] SSH log not found: {file_path}")
            return pd.DataFrame()

        with open(file_path, "r", encoding="utf-8") as logfile:

            for line in logfile:

                match = SSH_PATTERN.search(line)

                if match:

                    rows.append({

                        "month": match.group("month"),

                        "day": int(match.group("day")),

                        "time": match.group("time"),

                        "user": match.group("user"),

                        "ip": match.group("ip"),

                        "port": int(match.group("port"))

                    })

        self.ssh_df = pd.DataFrame(rows)

        return self.ssh_df

    # ---------------------------------------------------------

    def apache_summary(self):

        if self.apache_df.empty:
            return {}

        return {

            "total_requests": len(self.apache_df),

            "unique_ips": self.apache_df["ip"].nunique(),

            "status_codes": self.apache_df["status"].value_counts().to_dict(),

            "top_ips": self.apache_df["ip"].value_counts().head(10).to_dict(),

            "top_urls": self.apache_df["url"].value_counts().head(10).to_dict()

        }

    # ---------------------------------------------------------

    def ssh_summary(self):

        if self.ssh_df.empty:
            return {}

        return {

            "failed_attempts": len(self.ssh_df),

            "unique_ips": self.ssh_df["ip"].nunique(),

            "top_attackers": self.ssh_df["ip"].value_counts().head(10).to_dict(),

            "target_users": self.ssh_df["user"].value_counts().to_dict()

        }

    # ---------------------------------------------------------

    def get_apache_dataframe(self):
        return self.apache_df

    def get_ssh_dataframe(self):
        return self.ssh_df


# --------------------------------------------------------------------

if __name__ == "__main__":

    parser = LogParser()

    apache = parser.parse_apache_log("logs/apache.log")
    ssh = parser.parse_ssh_log("logs/ssh.log")

    print("\nApache Summary")
    print(parser.apache_summary())

    print("\nSSH Summary")
    print(parser.ssh_summary())
