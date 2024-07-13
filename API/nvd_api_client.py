import os
import requests
import requests_cache
from .config import NVD_API_KEY
from logger import default_logger as logger
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from typing import Dict, Any, Optional, List
import json
from datetime import datetime, timedelta
import re
from .logger import default_logger as logger

class NVDAPIClient:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self):
        if 'TESTING' not in os.environ:
            self.session = requests_cache.CachedSession('nvd_cache', expire_after=timedelta(hours=1))
        else:
            self.session = requests.Session()  # Use a regular session for testing

    @retry(stop=stop_after_attempt(3), 
           wait=wait_exponential(multiplier=1, min=4, max=10),
           retry=retry_if_exception_type(requests.exceptions.RequestException))
    def search_vulnerabilities(self, keyword: str, start_date: Optional[str] = None, 
                               end_date: Optional[str] = None, severity: Optional[str] = None, 
                               start_index: int = 0, results_per_page: int = 20) -> requests.Response:
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
            response = self.session.get(self.BASE_URL, params=params)
            response.raise_for_status()
            logger.info(f"Successfully retrieved vulnerabilities for keyword: {keyword}")
            logger.debug(f"Response data: {json.dumps(response.json(), indent=2)}")
            return response
        except requests.exceptions.RequestException as e:
            logger.error(f"Error retrieving vulnerabilities: {str(e)}")
            raise e  # Re-raise the exception to be handled by the retry mechanism
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON response: {str(e)}")
            raise e  # Re-raise the exception to be handled by the retry mechanism

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
        # Use a regular expression to strictly match YYYY-MM-DD format
        pattern = r'^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])$'
        if not re.match(pattern, date_string):
            return False
        
        try:
            datetime.strptime(date_string, "%Y-%m-%d")
            return True
        except ValueError:
            return False
