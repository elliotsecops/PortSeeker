import os
import requests
import requests_cache
from datetime import datetime, timedelta
from .config import get_config
from .logger import default_logger as logger
from tenacity import retry, stop_after_attempt, wait_fixed, wait_exponential, retry_if_exception_type
from typing import Dict, Any, Optional, List
import json
import re
from logging.handlers import RotatingFileHandler
import logging
import time
from functools import wraps

def rate_limit(calls: int, period: int):
    def decorator(func):
        last_called = [0.0]
        @wraps(func)
        def wrapper(*args, **kwargs):
            elapsed = time.time() - last_called[0]
            left_to_wait = period - elapsed
            if left_to_wait > 0:
                time.sleep(left_to_wait)
            ret = func(*args, **kwargs)
            last_called[0] = time.time()
            return ret
        return wrapper
    return decorator

class NVDAPIClient:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self):
        config = get_config()
        self.api_key = config['NVD_API_KEY']
        if 'TESTING' not in os.environ:
            self.session = requests_cache.CachedSession('nvd_cache', expire_after=timedelta(hours=1))
        else:
            self.session = requests.Session()  # Use a regular session for testing

        # Set up logging
        log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        log_file = "nvd_api_client.log"
        log_handler = RotatingFileHandler(log_file, maxBytes=1024 * 1024, backupCount=5)
        log_handler.setFormatter(log_formatter)
        logger.addHandler(log_handler)
        logger.setLevel(logging.DEBUG)

    @retry(stop=stop_after_attempt(3),
           wait=wait_fixed(2) + wait_exponential(multiplier=1, min=4, max=10),
           retry=retry_if_exception_type(requests.exceptions.RequestException))
    @rate_limit(calls=1, period=6)
    def search_vulnerabilities(self, search_term: str, start_date: Optional[str] = None,
                               end_date: Optional[str] = None, severity: Optional[str] = None,
                               start_index: int = 0, results_per_page: int = 20) -> requests.Response:
        # Parameter validation
        if not search_term:
            raise ValueError("Search term must be provided")
        if start_date and not self._validate_date(start_date):
            raise ValueError("Invalid start_date format. Use YYYY-MM-DD")
        if end_date and not self._validate_date(end_date):
            raise ValueError("Invalid end_date format. Use YYYY-MM-DD")

        params = {
            "keywordSearch": search_term,  # Make sure it's "keywordSearch"
            "pubStartDate": start_date,
            "pubEndDate": end_date,
            "cvssV3Severity": severity,
            "startIndex": start_index,
            "resultsPerPage": results_per_page,
            "apiKey": self.api_key
        }

        headers = {}  # Remove the API key from headers

        masked_api_key = self.api_key[:4] + '*' * (len(self.api_key) - 4)
        logger.debug(f"Requesting URL: {self.BASE_URL}")
        logger.debug(f"Params: {params}")
        logger.debug(f"Headers: {headers}")

        try:
            response = self.session.get(self.BASE_URL, headers=headers, params=params)
            logger.debug(f"Response status code: {response.status_code}")
            logger.debug(f"Response content: {response.text[:500]}...")  # Log first 500 characters
            response.raise_for_status()
            logger.info(f"Successfully retrieved vulnerabilities for search term: {search_term}")
            return response
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error occurred: {e}")
            logger.error(f"Response content: {response.text[:500]}...")  # Log detailed error response
            raise e
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
                    'description': cve.get('descriptions', [{}])[0].get('value', ''),
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

    @rate_limit(calls=1, period=6)
    def get_updates(self, last_update_time: datetime):
        current_time = datetime.utcnow()
        headers = {}  # Remove the API key from headers
        params = {
            "modStartDate": last_update_time.isoformat(),
            "modEndDate": current_time.isoformat(),
            "apiKey": self.api_key  # Move apiKey here
        }
        response = self.session.get(self.BASE_URL, headers=headers, params=params)
        response.raise_for_status()
        return response.json(), current_time
