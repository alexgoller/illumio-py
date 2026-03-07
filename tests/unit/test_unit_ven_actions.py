import json
import re

import pytest


@pytest.fixture(autouse=True)
def mock_requests(requests_mock):
    requests_mock.register_uri('PUT', re.compile('/vens/'), json=[])
    requests_mock.register_uri('POST', re.compile('/vens/'), json={})
    requests_mock.register_uri('GET', re.compile('/workloads/'), json=[])
    requests_mock.register_uri('POST', re.compile('/workloads/'), json={})
    requests_mock.register_uri('PUT', re.compile('/workloads/'), json=[])
    requests_mock.register_uri('DELETE', re.compile('/workloads/'), status_code=204)


def test_unpair_vens(pce, requests_mock):
    requests_mock.register_uri('PUT', re.compile('/vens/unpair'), json=[{"href": "/orgs/1/vens/uuid-1"}])
    result = pce.unpair_vens(["/orgs/1/vens/uuid-1"])
    assert len(result) == 1


def test_upgrade_vens(pce, requests_mock):
    requests_mock.register_uri('PUT', re.compile('/vens/upgrade'), json=[{"href": "/orgs/1/vens/uuid-1", "status": "pending"}])
    result = pce.upgrade_vens(["/orgs/1/vens/uuid-1"], "22.0.0")
    assert len(result) == 1


def test_ven_remote_action(pce, requests_mock):
    requests_mock.register_uri('PUT', re.compile('/vens/remote_action'), json=[{"status": "ok"}])
    result = pce.ven_remote_action(["/orgs/1/vens/uuid-1"], "suspend")
    assert len(result) == 1


def test_ven_statistics(pce, requests_mock):
    requests_mock.register_uri('POST', re.compile('/vens/statistics'), json={"count": 5})
    result = pce.get_ven_statistics(["/orgs/1/vens/uuid-1"])
    assert result["count"] == 5


def test_get_workload_interfaces(pce, requests_mock):
    interfaces = [{"name": "eth0", "address": "10.0.0.1"}]
    requests_mock.register_uri('GET', re.compile('/interfaces'), json=interfaces)
    result = pce.get_workload_interfaces("/orgs/1/workloads/uuid-1")
    assert len(result) == 1
    assert result[0]["name"] == "eth0"


def test_unpair_workloads(pce, requests_mock):
    requests_mock.register_uri('PUT', re.compile('/workloads/unpair'), json=[{"href": "/orgs/1/workloads/uuid-1"}])
    result = pce.unpair_workloads(["/orgs/1/workloads/uuid-1"])
    assert len(result) == 1


def test_get_label_group_all_labels(pce, requests_mock):
    labels = [{"href": "/orgs/1/labels/1", "key": "env", "value": "Production"}]
    requests_mock.register_uri('GET', re.compile('/all_labels'), json=labels)
    result = pce.get_label_group_all_labels("/orgs/1/sec_policy/draft/label_groups/uuid-1")
    assert len(result) == 1
