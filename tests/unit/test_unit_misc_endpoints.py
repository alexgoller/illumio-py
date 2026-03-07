import json
import re

import pytest


@pytest.fixture(autouse=True)
def mock_requests(requests_mock):
    requests_mock.register_uri('GET', re.compile('/'), json={})
    requests_mock.register_uri('POST', re.compile('/'), json={})
    requests_mock.register_uri('PUT', re.compile('/'), json={})
    requests_mock.register_uri('DELETE', re.compile('/'), status_code=204)


def test_get_product_version(pce, requests_mock):
    version_data = {"version": "23.5.0", "build": "1234"}
    requests_mock.register_uri('GET', re.compile('/product_version'), json=version_data)
    result = pce.get_product_version()
    assert result["version"] == "23.5.0"


def test_get_node_available(pce, requests_mock):
    requests_mock.register_uri('GET', re.compile('/node_available'), json={"available": True})
    result = pce.get_node_available()
    assert result["available"] is True


def test_get_supercluster_leader(pce, requests_mock):
    requests_mock.register_uri('GET', re.compile('/supercluster/leader'), json={"leader": "pce1.example.com"})
    result = pce.get_supercluster_leader()
    assert result["leader"] == "pce1.example.com"


def test_get_app_group_risk_summary(pce, requests_mock):
    requests_mock.register_uri('GET', re.compile('/app_groups/risk_summary'), json={"total_groups": 10})
    result = pce.get_app_group_risk_summary()
    assert result["total_groups"] == 10


def test_get_traffic_flow_db_metrics(pce, requests_mock):
    requests_mock.register_uri('GET', re.compile('/traffic_flows/database_metrics'), json={"total_flows": 1000})
    result = pce.get_traffic_flow_db_metrics()
    assert result["total_flows"] == 1000


def test_get_async_queries(pce, requests_mock):
    queries = [{"href": "/orgs/1/traffic_flows/async_queries/uuid-1", "status": "completed"}]
    requests_mock.register_uri('GET', re.compile('/traffic_flows/async_queries'), json=queries)
    result = pce.get_async_queries()
    assert len(result) == 1


def test_delete_async_query(pce, requests_mock):
    requests_mock.register_uri('DELETE', re.compile('/async_queries/uuid-1'), status_code=204)
    pce.delete_async_query("uuid-1")


def test_get_ven_software_releases(pce, requests_mock):
    releases = [{"release": "22.0.0", "default": True}]
    requests_mock.register_uri('GET', re.compile('/software/ven/releases'), json=releases)
    result = pce.get_ven_software_releases()
    assert len(result) == 1
