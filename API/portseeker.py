import argparse
import nmap
import asyncio
from ratelimit import limits, sleep_and_retry
from API.nvd_api_client import NVDAPIClient
from .logger import setup_logger, default_logger as logger
import os
from dotenv import load_dotenv
import time
import requests

load_dotenv()

logger = setup_logger(__name__)

def run_in_executor(func, *args):
    loop = asyncio.get_event_loop()
    return loop.run_in_executor(None, func, *args)

class PortSeeker:
    CALLS = int(os.getenv('NVD_API_CALLS', 50))  # Fallback to default if not set
    RATE_LIMIT = int(os.getenv('NVD_API_RATE_LIMIT', 30))

    def __init__(self):
        self.nvd_client = NVDAPIClient()
        self.nm = nmap.PortScanner()

    async def scan_ports(self, target):
        logger.info(f"Scanning ports for target: {target}")
        try:
            self.nm.scan(target, arguments='-sV')
            services = []
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    lport = self.nm[host][proto].keys()
                    for port in lport:
                        service = self.nm[host][proto][port]
                        services.append({
                            'port': port,
                            'service': service['name'],
                            'version': service['version']
                        })
            return services
        except nmap.PortScannerError as e:
            logger.error(f"Nmap scan error: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error during port scan: {str(e)}")
            return []

    @sleep_and_retry
    @limits(calls=CALLS, period=RATE_LIMIT)
    async def scan_vulnerability(self, service):
        try:
            keyword = f"{service.get('service', '')} {service.get('version', '')}".strip()
            if not keyword:
                logger.warning(f"Skipping vulnerability scan for service with empty keyword: {service}")
                return []
            logger.debug(f"Scanning vulnerabilities for: {keyword}")

            response = await run_in_executor(self.nvd_client.search_vulnerabilities, keyword)
            if response.status_code != 200:
                logger.warning(f"NVD API returned status code {response.status_code} for keyword: {keyword}")
                return []

            parsed_vulns = self.nvd_client.parse_vulnerabilities(response.json())
            return self.associate_vulns_with_ports(parsed_vulns, service['port'])
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error during vulnerability scan: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"Error scanning vulnerabilities for {service}: {str(e)}")
            return []

    def associate_vulns_with_ports(self, parsed_vulns, port):
        for vuln in parsed_vulns:
            vuln['port'] = port
        return parsed_vulns

    async def scan_vulnerabilities(self, services):
        tasks = [self.scan_vulnerability(service) for service in services]
        results = await asyncio.gather(*tasks)
        return results

    async def run(self, target):
        try:
            services = await self.scan_ports(target)
            vulnerabilities = await self.scan_vulnerabilities(services)
            return [vuln for sublist in vulnerabilities for vuln in sublist]
        except Exception as e:
            logger.error(f"Error during scan: {str(e)}")
            return []

async def main():
    parser = argparse.ArgumentParser(description="PortSeeker - Port and Vulnerability Scanner")
    parser.add_argument("target", help="The target IP address or hostname to scan")
    args = parser.parse_args()

    port_seeker = PortSeeker()
    try:
        vulnerabilities = await asyncio.wait_for(port_seeker.run(args.target), timeout=300)
        if not vulnerabilities:
            logger.info("No vulnerabilities found.")
            return

        for vuln in vulnerabilities:
            print(f"Port: {vuln['port']}")
            print(f"CVE ID: {vuln['id']}")
            print(f"Description: {vuln['description']}")
            print(f"CVSS Score: {vuln['cvssScore']}")
            print("---")
    except asyncio.TimeoutError:
        logger.error("Scan timed out after 300 seconds")
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main())
