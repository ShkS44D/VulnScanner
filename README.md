# VulnScanner Demo Vulnerability Scanner (Flask)

## Overview
A modular vulnerability scanner to demonstrate:
- Fast multi-threaded TCP port scanning (sockets + ThreadPool)
- Basic OS fingerprinting (banner heuristics and optional scapy TTL fingerprint)
- CVE lookup via NVD API
- Basic web scanning (headers, robots.txt, directory discovery, simple SQLi/XSS checks)
- Web frontend (Flask + Bootstrap) — professional dark theme
- Logging and error handling

## Requirements
- Python 3.10+
- Linux/macOS recommended for scapy-based fingerprinting (root)
- Install dependencies:
```bash
python -m venv venv
source venv/bin/activate   # windows: venv\Scripts\activate
pip install -r requirements.txt

