# scanner/port_scanner.py
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.logger import get_logger

logger = get_logger('port_scanner')

class PortScanner:
    def __init__(self, target, start_port=1, end_port=1024, threads=100, timeout=1.0):
        self.target = target
        self.start_port = max(1, start_port)
        self.end_port = min(65535, end_port)
        self.threads = threads
        self.timeout = timeout
        self.service_banners = {}  # port -> banner string

    def _try_recv(self, sock, total_timeout=1.0):
        """Try to recv from socket with small sleeps to allow server to send banner."""
        sock.settimeout(0.3)
        chunks = []
        start = time.time()
        try:
            while time.time() - start < total_timeout:
                try:
                    data = sock.recv(4096)
                    if not data:
                        break
                    chunks.append(data)
                except socket.timeout:
                    break
        except Exception as e:
            logger.debug("recv error: %s", e)
        try:
            return b''.join(chunks).decode(errors='ignore').strip()
        except Exception:
            return ''

    def _banner_probe_for_port(self, s, port):
        """
        Robust probing:
        - Try recv first (some servers send banner immediately)
        - Try plain HTTP HEAD/GET for common ports
        - If still nothing, attempt SSL wrap (SNI) and probe over TLS
        - Return a single string that can contain server header / cert CN / raw banner
        """
        # 1) Try reading first (some services, like SSH, send banner immediately)
        raw = self._try_recv(s, total_timeout=0.6)
        if raw:
            return raw

        # 2) HTTP style probe for common plain HTTP ports
        try:
            if port in (80, 8080, 8000):
                try:
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % self.target.encode())
                except Exception:
                    pass
                raw = self._try_recv(s, total_timeout=0.9)
                if raw:
                    return raw
        except Exception as e:
            logger.debug("HTTP probe error on port %s: %s", port, e)

        # 3) Generic newline probe
        try:
            s.sendall(b"\r\n")
        except Exception:
            pass
        raw = self._try_recv(s, total_timeout=0.4)
        if raw:
            return raw

        # 4) Try a TLS handshake (SNI) on this connected socket; many apps run TLS on non-standard ports.
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ss = ctx.wrap_socket(s, server_hostname=self.target)
            # extract cert CN if present
            cert_cn = ''
            try:
                cert = ss.getpeercert()
                subj = cert.get('subject', ())
                for tup in subj:
                    for name, val in tup:
                        if name == 'commonName':
                            cert_cn = val
                            break
                    if cert_cn:
                        break
            except Exception:
                cert_cn = ''

            # Try read first on TLS socket
            raw_tls = self._try_recv(ss, total_timeout=0.6)
            if raw_tls:
                combined = f"TLS cert CN: {cert_cn} | {raw_tls}"
                return combined

            # Try HTTP HEAD over TLS
            try:
                ss.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % self.target.encode())
            except Exception:
                pass
            raw_tls = self._try_recv(ss, total_timeout=0.9)
            if raw_tls:
                combined = f"TLS cert CN: {cert_cn} | {raw_tls}"
                return combined

            # Final fallback: GET
            try:
                ss.sendall(b"GET / HTTP/1.0\r\nHost: %b\r\n\r\n" % self.target.encode())
            except Exception:
                pass
            raw_tls = self._try_recv(ss, total_timeout=0.8)
            if raw_tls:
                combined = f"TLS cert CN: {cert_cn} | {raw_tls}"
                return combined

        except ssl.SSLError as e:
            logger.debug("SSL handshake failed on port %s: %s", port, e)
        except Exception as e:
            logger.debug("Generic TLS probe error on port %s: %s", port, e)

        # 5) If everything fails, return empty string
        return ''

    def _scan_port(self, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            start = time.time()
            res = s.connect_ex((self.target, port))
            latency = time.time() - start
            if res == 0:
                # Connected — attempt banner capture using protocol-aware probes
                try:
                    banner = self._banner_probe_for_port(s, port)
                except Exception as e:
                    logger.debug("banner capture failed on port %s: %s", port, e)
                    banner = ''
                logger.debug("Open port %s banner: %s", port, banner)
                return port, True, latency, banner
            return port, False, None, None
        except Exception as e:
            logger.debug("Exception scanning port %s: %s", port, e)
            return port, False, None, None
        finally:
            try:
                s.close()
            except Exception:
                pass

    def scan(self):
        open_ports = []
        logger.info(f"Starting TCP connect scan on {self.target}:{self.start_port}-{self.end_port} with {self.threads} threads")
        with ThreadPoolExecutor(max_workers=self.threads) as exe:
            futures = {exe.submit(self._scan_port, p): p for p in range(self.start_port, self.end_port + 1)}
            for fut in as_completed(futures):
                port, is_open, latency, banner = fut.result()
                if is_open:
                    open_ports.append(port)
                    self.service_banners[port] = banner or ''
        open_ports.sort()
        logger.info(f"Scan complete for {self.target}. Open ports: {open_ports}")
        return open_ports
