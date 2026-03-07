import json
import os
import re
from typing import List

import pytest

from illumio.vulnerabilities import Vulnerability

VULNERABILITIES = os.path.join(pytest.DATA_DIR, 'vulnerabilities.json')


@pytest.fixture(scope='module')
def vulnerabilities() -> List[dict]:
    with open(VULNERABILITIES, 'r') as f:
        yield json.loads(f.read())


@pytest.fixture(autouse=True)
def vulnerabilities_mock(pce_object_mock, vulnerabilities):
    pce_object_mock.add_mock_objects(vulnerabilities)


@pytest.fixture(autouse=True)
def mock_requests(requests_mock, get_callback, post_callback, put_callback, delete_callback):
    pattern = re.compile('/vulnerabilities')
    requests_mock.register_uri('GET', pattern, json=get_callback)
    requests_mock.register_uri('POST', pattern, json=post_callback)
    requests_mock.register_uri('PUT', pattern, json=put_callback)
    requests_mock.register_uri('DELETE', pattern, json=delete_callback)


def test_get_vulnerability(pce):
    vuln = pce.vulnerabilities.get_by_reference("/orgs/1/vulnerabilities/CVE-2021-44228")
    assert vuln.name == "Log4Shell"
    assert vuln.score == 10
    assert vuln.cve_ids == ["CVE-2021-44228"]


def test_create_vulnerability(pce):
    vuln = Vulnerability(name="Test Vuln", score=5, severity="medium")
    created = pce.vulnerabilities.create(vuln)
    assert created.href


def test_vulnerability_from_json():
    data = {
        "href": "/orgs/1/vulnerabilities/test",
        "name": "Test",
        "score": 7,
        "cve_ids": ["CVE-2023-1234"],
        "severity": "high"
    }
    vuln = Vulnerability.from_json(data)
    assert vuln.score == 7
    assert vuln.severity == "high"
