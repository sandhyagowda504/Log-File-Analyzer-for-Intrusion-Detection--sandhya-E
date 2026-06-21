"""
Utility Functions
"""

import os
from datetime import datetime


def create_directories():
    """
    Create required project folders.
    """

    folders = [
        "logs",
        "reports",
        "charts",
        "blacklist"
    ]

    for folder in folders:
        os.makedirs(folder, exist_ok=True)


def timestamp():
    """
    Current timestamp.
    """
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def print_banner():

    print("=" * 60)
    print(" LOG FILE ANALYZER FOR INTRUSION DETECTION ")
    print("=" * 60)


def divider():
    print("-" * 60)


def save_text(path, text):

    with open(path, "w", encoding="utf-8") as file:
        file.write(text)


def load_blacklist(path):

    if not os.path.exists(path):
        return []

    with open(path, "r") as file:
        return [line.strip() for line in file.readlines()]


def file_exists(path):

    return os.path.exists(path)
