from flask import Flask, render_template, request, redirect, url_for
from scanner.port_scanner import PortScanner
from scanner.os_fingerprint import OSFingerprint
from scanner.web_scanner import WebScanner
from scanner.cve_lookup import CVELookup
from utils.logger import get_logger
import os
import threading
from urllib.parse import urlparse
import re

app = Flask(__name__)
logger = get_logger('app')

# Initialize modules (stateless)
cve = CVELookup(api_key=os.getenv('NVD_API_KEY'))
osfp = OSFingerprint()
webscan = WebScanner()

def clean_target(target: str) -> str:
   
    if not target:
        return ''

    t = target.strip()

    # If the input contains a scheme (http:// or ftp:// etc.), use urlparse to get hostname
    if re.match(r'^[a-zA-Z][a-zA-Z0-9+.\-]*://', t):
        parsed = urlparse(t)
        # parsed.hostname will already strip userinfo and port
        host = parsed.hostname or parsed.netloc
        return host or ''

    # Remove any path portion if present (take before first '/')
    if '/' in t:
        t = t.split('/', 1)[0]

    # Remove userinfo if present (user:pass@host)
    if '@' in t:
        t = t.split('@', 1)[-1]

    # Handle IPv6 in brackets [::1]:8080 or [::1]
    if t.startswith('['):
        # if port is present like [::1]:8080 -> keep [::1] (some resolvers accept without brackets; keep as-is)
        if ']:' in t:
            host = t.split(']:', 1)[0] + ']'
            return host
        # no port, return until closing bracket
        if ']' in t:
            host = t.split(']', 1)[0] + ']'
            return host

    # If there's a colon (:) it's likely host:port (IPv4:port). Remove port.
    # This will also remove accidental ports in hostnames — acceptable for scanning host.
    if ':' in t:
        # only split on the first colon to preserve weird cases minimally
        parts = t.split(':', 1)
        return parts[0]

    return t

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        raw_target = request.form.get('target', '').strip()
        port_start = int(request.form.get('port_start', 1))
        port_end = int(request.form.get('port_end', 1024))
        threads = int(request.form.get('threads', 100))

        # sanitize target
        target = clean_target(raw_target)

        # validation
        if not raw_target:
            return render_template('index.html', error='Please provide a target (IP or hostname).')

        if not target:
            return render_template('index.html', error='Could not parse target. Please provide a valid IP or hostname.')

        # Kick off scan synchronously for demo (small ranges); in production use job queue
        try:
            logger.info(f"Starting scan. raw_target='{raw_target}' cleaned_target='{target}' ports={port_start}-{port_end} threads={threads}")

            scanner = PortScanner(target, port_start, port_end, threads)
            open_ports = scanner.scan()
            logger.info(f'Scan finished for {target}: {open_ports}')

            # OS fingerprinting
            os_info = osfp.fingerprint(target, open_ports)

            # CVE lookup: queries by identified services (simple: use banners/services from port scanner)
            service_banners = scanner.service_banners
            cve_results = cve.lookup_services(service_banners)

            # Web scan if HTTP port found
            web_results = None
            if any(p in (80, 443, 8080, 8000) for p in open_ports):
                # webscan.scan_http expects hostname (it should assemble URLs internally)
                web_results = webscan.scan_http(target)

            return render_template('results.html', target=target, open_ports=open_ports,
                                   os_info=os_info, cve_results=cve_results, web_results=web_results)
        except Exception as e:
            logger.exception("Error during scanning")
            return render_template('index.html', error=str(e))
    return render_template('index.html')

if __name__ == '__main__':
    # For dev only; in production run via gunicorn/uwsgi
    app.run(host='0.0.0.0', port=5000, debug=False)
