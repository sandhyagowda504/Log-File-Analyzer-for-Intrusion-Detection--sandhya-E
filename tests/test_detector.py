"""
Unit Tests for detector.py
"""

import unittest
import pandas as pd

from detector import ThreatDetector


class TestDetector(unittest.TestCase):

    def setUp(self):

        self.detector = ThreatDetector()

    def test_bruteforce_detection(self):

        ssh = pd.DataFrame({

            "ip": [
                "1.1.1.1",
                "1.1.1.1",
                "1.1.1.1",
                "1.1.1.1",
                "1.1.1.1",
                "2.2.2.2"
            ],

            "port": [
                22,
                22,
                22,
                22,
                22,
                22
            ]

        })

        result = self.detector.detect_brute_force(ssh)

        self.assertEqual(len(result), 1)

    def test_dos_detection(self):

        apache = pd.DataFrame({

            "ip": ["3.3.3.3"] * 120

        })

        result = self.detector.detect_dos(apache)

        self.assertEqual(len(result), 1)

    def test_port_scan(self):

        ports = list(range(20, 45))

        ssh = pd.DataFrame({

            "ip": ["5.5.5.5"] * len(ports),

            "port": ports

        })

        result = self.detector.detect_port_scan(ssh)

        self.assertEqual(len(result), 1)

    def test_threat_level(self):

        self.assertEqual(
            self.detector.threat_level(10),
            "LOW"
        )

        self.assertEqual(
            self.detector.threat_level(25),
            "MEDIUM"
        )

        self.assertEqual(
            self.detector.threat_level(60),
            "HIGH"
        )

        self.assertEqual(
            self.detector.threat_level(120),
            "CRITICAL"
        )


if __name__ == "__main__":
    unittest.main()
