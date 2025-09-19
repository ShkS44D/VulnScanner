import requests
from urllib.parse import quote_plus
from utils.logger import get_logger
import time
from dateutil import parser

logger = get_logger('cve_lookup')

class CVELookup:
    NVD_BASE = 'https://services.nvd.nist.gov/rest/json'
    def __init__(self, api_key=None, rate_limit_sleep=1.5):
        self.api_key = api_key
        self.rate_limit_sleep = rate_limit_sleep

    def _nvd_get(self, url, params=None):
        headers = {}
        if self.api_key:
            headers['apiKey'] = self.api_key
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=10)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 429:
                logger.warning("NVD rate limited; sleeping")
                time.sleep(self.rate_limit_sleep)
                return self._nvd_get(url, params)
            else:
                logger.warning("NVD responded %s: %s", resp.status_code, resp.text[:200])
                return None
        except Exception as e:
            logger.exception("Error calling NVD: %s", e)
            return None

    def _build_query_for_product(self, product_name):
        # Naive product -> keyword mapping
        return product_name

    def lookup_services(self, service_banners):
        """
        service_banners: dict port->banner
        returns: dict port -> list of CVEs (summary)
        """
        results = {}
        for port, banner in service_banners.items():
            keyword = banner or ''
            # sanitize and pick a few keywords
            if not keyword:
                results[port] = []
                continue
            # pick top tokens
            tokens = [t for t in keyword.split() if len(t) > 2][:4]
            query = ' '.join(tokens)
            if not query:
                results[port] = []
                continue
            # Search NVD CVE API: use /cves/2.0?keyword=...
            url = f"{self.NVD_BASE}/cves/2.0"
            params = {'keywordSearch': query, 'resultsPerPage': 5}
            data = self._nvd_get(url, params=params)
            cves = []
            if data and 'vulnerabilities' in data:
                for item in data['vulnerabilities']:
                    cve_id = item.get('cve', {}).get('id')
                    desc = ''
                    nodes = item.get('cve', {}).get('descriptions', [])
                    if nodes:
                        desc = nodes[0].get('value', '')
                    # severity info (CVSS) if present
                    metrics = item.get('cve', {}).get('metrics', {})
                    score = None
                    if metrics:
                        # handle v3 or v2
                        if 'cvssMetricV31' in metrics:
                            score = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
                        elif 'cvssMetricV3' in metrics:
                            score = metrics['cvssMetricV3'][0]['cvssData']['baseScore']
                    cves.append({'id': cve_id, 'desc': desc, 'score': score})
            results[port] = cves
            time.sleep(0.2)  # gentle
        return results
