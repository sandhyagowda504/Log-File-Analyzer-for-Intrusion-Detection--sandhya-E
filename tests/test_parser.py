"""
Unit Tests for parser.py
"""

import unittest
import os

from parser import LogParser


class TestParser(unittest.TestCase):

    def setUp(self):

        self.parser = LogParser()

    def test_apache_parser(self):

        if not os.path.exists("logs/apache.log"):
            self.skipTest("Apache log not found.")

        df = self.parser.parse_apache_log("logs/apache.log")

        self.assertFalse(df.empty)

        self.assertIn("ip", df.columns)
        self.assertIn("status", df.columns)

    def test_ssh_parser(self):

        if not os.path.exists("logs/ssh.log"):
            self.skipTest("SSH log not found.")

        df = self.parser.parse_ssh_log("logs/ssh.log")

        self.assertFalse(df.empty)

        self.assertIn("ip", df.columns)
        self.assertIn("user", df.columns)


if __name__ == "__main__":
    unittest.main()
