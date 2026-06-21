# 🔐 Log File Analyzer for Intrusion Detection

## 📌 Overview

The **Log File Analyzer for Intrusion Detection** is a Python-based cybersecurity tool designed to analyze Apache and SSH server log files to identify suspicious activities and potential security threats. The application parses log entries, detects common attack patterns such as brute-force login attempts, port scanning, and denial-of-service (DoS) attacks, and generates detailed reports with graphical visualizations.

This project demonstrates practical cybersecurity concepts including log analysis, intrusion detection, data visualization, and automated incident reporting.

---

## 🚀 Features

* Parse Apache Access Logs
* Parse SSH Authentication Logs
* Detect Brute Force Login Attempts
* Detect Port Scanning Activities
* Detect DoS (Denial of Service) Attacks
* Count Requests by IP Address
* Analyze Login Failures
* Threat Level Classification
* IP Address Statistics
* Export Incident Reports (CSV)
* Generate Traffic Analysis Charts
* Modular Python Architecture
* Easy Configuration
* Sample Log Dataset Included

---

## 📂 Project Structure

```text
log-file-analyzer/
│
├── README.md
├── requirements.txt
├── LICENSE
├── .gitignore
│
├── config.py
├── main.py
├── parser.py
├── detector.py
├── blacklist.py
├── visualizer.py
├── report_generator.py
├── utils.py
│
├── logs/
│   ├── apache.log
│   └── ssh.log
│
├── reports/
│   ├── incident_report.csv
│   └── incident_report.pdf
│
├── charts/
│   ├── attacks_by_ip.png
│   ├── attacks_by_hour.png
│   └── threat_levels.png
│
├── blacklist/
│   └── blacklist.txt
│
├── screenshots/
│   ├── dashboard.png
│   ├── graphs.png
│   └── report.png
│
└── tests/
    ├── test_parser.py
    ├── test_detector.py
    └── test_reports.py
```

---

## ⚙️ Technologies Used

* Python 3.11+
* Pandas
* Matplotlib
* Regular Expressions (Regex)
* CSV
* Datetime
* Collections
* OS Module

---

## 🛠 Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/log-file-analyzer.git
```

Navigate to the project directory:

```bash
cd log-file-analyzer
```

Install the required packages:

```bash
pip install -r requirements.txt
```

---

## ▶️ Running the Project

Run the application:

```bash
python main.py
```

---

## 📊 Sample Output

```text
====================================

LOG FILE ANALYZER

====================================

Apache Logs Processed : 1287

SSH Logs Processed : 412

Brute Force Attempts : 14

DoS Attempts : 2

Port Scan Attempts : 7

Unique IP Addresses : 86

Threat Level : HIGH

Incident Report Generated

Charts Saved Successfully

====================================
```

---

## 📈 Generated Reports

The application automatically creates:

* Incident Report (CSV)
* Threat Summary
* Attack Frequency Graph
* Requests by IP Chart
* Hourly Traffic Analysis
* Threat Level Distribution

---

## 📋 Detection Capabilities

The analyzer detects:

* Brute Force Login Attempts
* Multiple Failed SSH Logins
* High Request Rate (DoS)
* Port Scanning Attempts
* Suspicious IP Addresses
* Excessive HTTP Requests
* Unauthorized Login Attempts
* Repeated Authentication Failures

---

## 📊 Workflow

```text
Read Apache Logs
        │
        ▼
Read SSH Logs
        │
        ▼
Parse Log Entries
        │
        ▼
Extract IP Addresses
        │
        ▼
Analyze Events
        │
        ▼
Detect Threats
        │
        ▼
Generate Reports
        │
        ▼
Create Charts
        │
        ▼
Export Results
```

---

## 🎯 Project Objectives

* Learn log parsing techniques
* Detect malicious activities automatically
* Understand intrusion detection concepts
* Visualize cybersecurity events
* Generate security incident reports
* Improve security monitoring skills

---

## 📌 Future Enhancements

* Real-time Log Monitoring
* Machine Learning-based Anomaly Detection
* Email Alert Notifications
* Threat Intelligence API Integration
* Web Dashboard (Flask)
* Elasticsearch Integration
* SIEM Compatibility
* Multi-Server Monitoring
* Interactive Analytics Dashboard

---

## 🧪 Testing

The project includes unit tests for:

* Log Parsing
* Threat Detection
* Report Generation
* Visualization Functions

Run the tests using:

```bash
python -m unittest discover tests
```

---

## 📄 Requirements

* Python 3.11 or later
* Windows
* Minimum 4 GB RAM
* Internet connection (optional, for blacklist updates)

---

## 🤝 Contributing

Contributions are welcome.

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to your branch
5. Open a Pull Request

---

## 📜 License

This project is licensed under the MIT License.

---

## 👨‍💻 Author

**Sandhya E**

Cybersecurity Enthusiast | Python Developer

GitHub: https://github.com/sandhyagowda504


## ⭐ If you found this project useful

Please consider giving the repository a **Star ⭐** on GitHub.

