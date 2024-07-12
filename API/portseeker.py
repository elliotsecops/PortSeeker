import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
import asyncio
from unittest.mock import MagicMock, patch
from API.portseeker import PortSeeker
from tests.helper import run_in_executor

@pytest.fixture
def mock_nvd_client():
    with patch('API.portseeker.NVDAPIClient') as mock:
        yield mock

@pytest.fixture
def mock_nmap():
    with patch('API.portseeker.nmap.PortScanner') as mock:
        mock_instance = mock.return_value
        mock_instance.all_hosts.return_value = ['127.0.0.1']
        mock_instance['127.0.0.1'].all_protocols.return_value = ['tcp']
        mock_instance['127.0.0.1']['tcp'].keys.return_value = [80, 443]
        mock_instance['127.0.0.1']['tcp'][80] = {'name': 'http', 'version': '1.1', 'product': 'Some Server', 'extrainfo': 'Some extra info'}
        mock_instance['127.0.0.1']['tcp'][443] = {'name': 'https', 'version': '1.1', 'product': 'Another Server', 'extrainfo': 'More extra info'}
        yield mock

@pytest.mark.asyncio
async def test_scan_ports(mock_nmap):
    mock_nmap_instance = mock_nmap.return_value
    port_seeker = PortSeeker()
    services = await port_seeker.scan_ports('127.0.0.1')

    assert len(services) == 2
    assert services[0]['port'] == 80
    assert services[0]['service'] == mock_nmap_instance['127.0.0.1']['tcp'][80]['name']
    assert services[0]['version'] == mock_nmap_instance['127.0.0.1']['tcp'][80]['version']
    assert services[1]['port'] == 443
    assert services[1]['service'] == mock_nmap_instance['127.0.0.1']['tcp'][443]['name']
    assert services[1]['version'] == mock_nmap_instance['127.0.0.1']['tcp'][443]['version']

@pytest.mark.asyncio
async def test_scan_vulnerability(mock_nvd_client):
    mock_nvd_client_instance = mock_nvd_client.return_value
    mock_nvd_client_instance.search_vulnerabilities.return_value = MagicMock(json=lambda: {'vulnerabilities': [
        {'cve': {'id': 'CVE-2021-1234', 'descriptions': [{'value': 'Test description'}], 'metrics': {'cvssMetricV31': [{'cvssData': {'baseScore': 7.5}}]}}}
    ]})
    mock_nvd_client_instance.parse_vulnerabilities.return_value = [
        {'id': 'CVE-2021-1234', 'description': 'Test description', 'cvssScore': 7.5}
    ]

    port_seeker = PortSeeker()
    vulns = await port_seeker.scan_vulnerability({'port': 80, 'service': 'http', 'version': '1.1'})

    assert len(vulns) == 1
    assert vulns[0]['port'] == 80
    assert vulns[0]['id'] == 'CVE-2021-1234'
    assert vulns[0]['description'] == 'Test description'
    assert vulns[0]['cvssScore'] == 7.5

@pytest.mark.asyncio
async def test_scan_vulnerabilities(mock_nvd_client):
    # Mock the scan_vulnerability method to return predictable results
    port_seeker = PortSeeker()
    
    async def mock_scan_vulnerability(service):
        if service['port'] == 80:
            return [{'id': 'CVE-2021-1234', 'description': 'Test description', 'cvssScore': 7.5, 'port': 80}]
        elif service['port'] == 443:
            return [{'id': 'CVE-2021-1234', 'description': 'Test description', 'cvssScore': 7.5, 'port': 443}]
    
    port_seeker.scan_vulnerability = MagicMock(side_effect=mock_scan_vulnerability)

    # Run the scan_vulnerabilities method
    vulns = await port_seeker.scan_vulnerabilities([
        {'port': 80, 'service': 'http', 'version': '1.1'},
        {'port': 443, 'service': 'https', 'version': '1.1'}
    ])

    # Assert the results
    assert len(vulns) == 2
    assert any(vuln['port'] == 80 for vuln in vulns)
    assert any(vuln['port'] == 443 for vuln in vulns)
    assert all(vuln['id'] == 'CVE-2021-1234' for vuln in vulns)
    assert all(vuln['description'] == 'Test description' for vuln in vulns)
    assert all(vuln['cvssScore'] == 7.5 for vuln in vulns)

@pytest.mark.asyncio
async def test_run(mock_nmap, mock_nvd_client):
    # Mock the scan_vulnerability method to return predictable results
    port_seeker = PortSeeker()
    
    async def mock_scan_vulnerability(service):
        if service['port'] == 80:
            return [{'id': 'CVE-2021-1234', 'description': 'Test description', 'cvssScore': 7.5, 'port': 80}]
        elif service['port'] == 443:
            return [{'id': 'CVE-2021-1234', 'description': 'Test description', 'cvssScore': 7.5, 'port': 443}]
    
    port_seeker.scan_vulnerability = MagicMock(side_effect=mock_scan_vulnerability)

    # Run the run method
    vulns = await port_seeker.run('127.0.0.1')

    # Assert the results
    assert len(vulns) == 2
    assert any(vuln['port'] == 80 for vuln in vulns)
    assert any(vuln['port'] == 443 for vuln in vulns)
    assert all(vuln['id'] == 'CVE-2021-1234' for vuln in vulns)
    assert all(vuln['description'] == 'Test description' for vuln in vulns)
    assert all(vuln['cvssScore'] == 7.5 for vuln in vulns)
