"""
Unit Tests for report_generator.py
"""

import unittest
import pandas as pd
import os

from report_generator import ReportGenerator


class TestReports(unittest.TestCase):

    def setUp(self):

        self.generator = ReportGenerator()

    def test_csv_generation(self):

        brute = pd.DataFrame({

            "ip": ["192.168.1.10"],
            "attempts": [10]

        })

        dos = pd.DataFrame({

            "ip": ["10.0.0.5"],
            "requests": [200]

        })

        port = pd.DataFrame({

            "ip": ["172.16.1.5"],
            "unique_ports": [25]

        })

        self.generator.generate_csv(
            brute,
            dos,
            port
        )

        self.assertTrue(
            os.path.exists(
                "reports/incident_report.csv"
            )
        )

    def test_pdf_generation(self):

        summary = {

            "apache_requests": 100,

            "ssh_attempts": 25,

            "brute_force": 3,

            "dos": 1,

            "port_scan": 1,

            "threat_score": 50,

            "threat_level": "HIGH"

        }

        self.generator.generate_pdf(summary)

        self.assertTrue(
            os.path.exists(
                "reports/incident_report.pdf"
            )
        )


if __name__ == "__main__":
    unittest.main()
