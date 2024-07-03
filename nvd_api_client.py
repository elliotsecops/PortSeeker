import requests
import requests_cache
from config import NVD_API_KEY
from logger import default_logger as logger
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from typing import Dict, Any, Optional, List
import json

# Install cache for requests with different expiration times for different query types
requests_cache.install_cache('nvd_cache', expire_after={
    'search_vulnerabilities': 3600,  # 1 hour for general searches
    'get_cve_details': 86400,  # 24 hours for specific CVE details
})

class NVDAPIClient:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    @retry(stop=stop_after_attempt(3), 
           wait=wait_exponential(multiplier=1, min=4, max=10),
           retry=retry_if_exception_type(requests.exceptions.RequestException))
    def search_vulnerabilities(self, keyword: str, start_date: Optional[str] = None, 
                               end_date: Optional[str] = None, severity: Optional[str] = None, 
                               start_index: int = 0, results_per_page: int = 20) -> Dict[str, Any]:
        # Parameter validation
        if not keyword:
            raise ValueError("Keyword must be provided")
        if start_date and not self._validate_date(start_date):
            raise ValueError("Invalid start_date format. Use YYYY-MM-DD")
        if end_date and not self._validate_date(end_date):
            raise ValueError("Invalid end_date format. Use YYYY-MM-DD")

        params = {
            "keyword": keyword,
            "pubStartDate": start_date,
            "pubEndDate": end_date,
            "cvssV3Severity": severity,
            "startIndex": start_index,
            "resultsPerPage": results_per_page,
            "apiKey": NVD_API_KEY
        }
        try:
            response = requests.get(self.BASE_URL, params=params)
            response.raise_for_status()
            data = response.json()
            logger.info(f"Successfully retrieved vulnerabilities for keyword: {keyword}")
            logger.debug(f"Response data: {json.dumps(data, indent=2)}")
            return data
        except requests.exceptions.RequestException as e:
            logger.error(f"Error retrieving vulnerabilities: {str(e)}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON response: {str(e)}")
            raise

    def parse_vulnerabilities(self, response: Dict[str, Any]) -> List[Dict[str, Any]]:
        vulnerabilities = []
        for vuln in response.get('vulnerabilities', []):
            cve = vuln.get('cve', {})
            try:
                parsed_vuln = {
                    'id': cve.get('id'),
                    'description': cve.get('descriptions', [{}])[0].get('value'),
                    'published': cve.get('published'),
                    'lastModified': cve.get('lastModified'),
                    'cvssScore': cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore')
                }
                vulnerabilities.append(parsed_vuln)
                logger.debug(f"Parsed vulnerability: {json.dumps(parsed_vuln, indent=2)}")
            except Exception as e:
                logger.error(f"Error parsing vulnerability {cve.get('id')}: {str(e)}")
        return vulnerabilities

    @staticmethod
    def _validate_date(date_string: str) -> bool:
        # Basic date validation, could be expanded
        parts = date_string.split('-')
        return len(parts) == 3 and all(part.isdigit() for part in parts)