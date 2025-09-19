VulnScanner

VulnScanner a modular demo vulnerability scanner built with Python and Flask.
Designed for learning, demonstrations, and portfolio showcase. Not intended for unauthorized scanning always get permission before testing systems you do not own.

Features

Multi-threaded TCP port scanner (socket-based, configurable range & threads)
Service banner capture and basic protocol probing (HTTP/TLS/SSH)
Lightweight OS fingerprinting (banner heuristics + optional Scapy TTL method)
Per-port CVE lookup via the NVD API (keyword-search based)
Basic web scans: headers, robots.txt, simple directory discovery, basic SQLi/XSS checks
Web UI built with Flask + Bootstrap (dark theme, results page)
Logging via rotating file handlers

Quick demo

Run the app locally and visit: http://127.0.0.1:5000
(Choose a small port range for demos — e.g., 1–1024.)

Requirements
Python 3.10+
Recommended: Linux/macOS for Scapy features (root privileges for raw sockets)

Install dependencies:
python -m venv .venv
# Windows (PowerShell):
.venv\Scripts\activate
# Linux / macOS:
source .venv/bin/activate
pip install -r requirements.txt

If you prefer not to create a venv, you can run with system Python, but virtualenvs are recommended.

Run
# inside the activated venv
python app.py
# or run python from venv directly
.venv\Scripts\python.exe app.py

Then open http://127.0.0.1:5000 in your browser.

For production use, run behind a WSGI server (Waitress/Gunicorn) Flask builtin server is for development only.

Example with Waitress:

pip install waitress
waitress-serve --listen=0.0.0.0:5000 app:app

Configuration
Optionally set NVD_API_KEY environment variable for better rate limits when using CVE lookup.
Scapy-based fingerprinting requires libpcap / Npcap on Windows for full functionality.

File structure (recommended)
VulnScanner/
├─ app.py
├─ README.md
├─ requirements.txt
├─ templates/
│  ├─ base.html
│  ├─ index.html
│  └─ results.html
├─ static/
│  └─ css/custom.css
├─ scanner/
│  ├─ port_scanner.py
│  ├─ os_fingerprint.py
│  ├─ web_scanner.py
│  └─ cve_lookup.py
└─ utils/
   ├─ logger.py
   └─ helpers.py

Security & Legal
Do NOT scan systems without explicit authorization. Misuse can be illegal and unethical. Use this project only on hosts you own, on lab environments, or with clear written permission.

Notes & Known Issues
If you see WARNING: No libpcap provider available ! pcap won't be used — install Npcap (Windows) or libpcap (Linux/macOS) to enable Scapy’s packet capture features.
The NVD lookup uses keyword search heuristics and may return noisy results — it’s a helper, not a replacement for targeted vulnerability research.

Contributing
Contributions, bug reports and feature suggestions are welcome. Open an issue or send a PR.

License
Consider adding an open-source license such as MIT. Add a LICENSE file to the repo if you want reuse/redistribution terms.

Contact
Created by ShkS44D 
find me on GitHub: https://github.com/ShkS44D
