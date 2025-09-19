import requests
from bs4 import BeautifulSoup
from utils.logger import get_logger
from urllib.parse import urljoin
import re

logger = get_logger('web_scanner')

COMMON_DIRS = ['admin', 'login', 'dashboard', '.git', 'config', 'backup', 'robots.txt', 'wp-admin', 'uploads']

SQLI_TESTS = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "';--"]
XSS_TEST = "<script>alert(1)</script>"

SQLI_ERROR_PATTERNS = [
    'you have an error in your sql syntax',
    'warning: mysql',
    'unclosed quotation mark after the character string',
    'sqlite error'
]

class WebScanner:
    def __init__(self, timeout=8):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'VulnScanner/1.0 (+https://example.com)'})

    def _norm_url(self, target):
        if not target.startswith('http'):
            return 'http://' + target
        return target

    def scan_http(self, target):
        target = self._norm_url(target)
        results = {'target': target, 'headers': {}, 'robots': None, 'dirs': [], 'sqli': [], 'xss': []}
        try:
            resp = self.session.get(target, timeout=self.timeout, allow_redirects=True, verify=False)
            results['headers'] = dict(resp.headers)
            # robots
            robots_url = urljoin(target, '/robots.txt')
            try:
                r = self.session.get(robots_url, timeout=3, verify=False)
                if r.status_code == 200:
                    results['robots'] = r.text[:2000]
            except Exception:
                pass
            # directory discovery (simple)
            for d in COMMON_DIRS:
                url = urljoin(target, '/' + d)
                try:
                    r = self.session.get(url, timeout=3, allow_redirects=True, verify=False)
                    if r.status_code in (200, 401, 403):
                        results['dirs'].append({'path': d, 'url': r.url, 'status': r.status_code})
                except Exception:
                    pass
            # simple SQLi checks (reflected or error-based)
            # try injecting in query parameter 'q'
            for payload in SQLI_TESTS:
                url = target
                if '?' in url:
                    test_url = url + '&q=' + payload
                else:
                    test_url = url + '?q=' + payload
                try:
                    r = self.session.get(test_url, timeout=5, verify=False)
                    body = r.text.lower()
                    # check for error patterns
                    for pat in SQLI_ERROR_PATTERNS:
                        if pat in body:
                            results['sqli'].append({'payload': payload, 'evidence': pat, 'url': test_url})
                    # reflected
                    if payload.strip("'\"") in body:
                        results['sqli'].append({'payload': payload, 'evidence': 'reflected', 'url': test_url})
                except Exception:
                    pass
            # simple XSS reflection
            test_url = target + ('&' if '?' in target else '?') + 'xss=' + XSS_TEST
            try:
                r = self.session.get(test_url, timeout=5, verify=False)
                if XSS_TEST in r.text:
                    results['xss'].append({'payload': XSS_TEST, 'url': test_url})
            except Exception:
                pass

            return results
        except Exception as e:
            logger.exception("HTTP scan failed: %s", e)
            return results
