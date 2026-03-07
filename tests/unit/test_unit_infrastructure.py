import json
import re

import pytest

from illumio.infrastructure import (
    NetworkDevice,
    NetworkEndpoint,
    NetworkEnforcementNode,
    SLB,
    DiscoveredVirtualServer,
    KubernetesWorkload,
)


@pytest.fixture(autouse=True)
def mock_requests(requests_mock, get_callback, post_callback, put_callback, delete_callback):
    pattern = re.compile('/network_devices|/network_enforcement_nodes|/slbs|/discovered_virtual_servers|/kubernetes_workloads')
    requests_mock.register_uri('GET', pattern, json=get_callback)
    requests_mock.register_uri('POST', pattern, json=post_callback)
    requests_mock.register_uri('PUT', pattern, json=put_callback)
    requests_mock.register_uri('DELETE', pattern, json=delete_callback)


def test_network_device_from_json():
    data = {
        "href": "/orgs/1/network_devices/uuid-1",
        "name": "Switch-01",
        "status": "active",
        "network_enforcement_node": {"href": "/orgs/1/network_enforcement_nodes/uuid-2"}
    }
    nd = NetworkDevice.from_json(data)
    assert nd.name == "Switch-01"
    assert nd.network_enforcement_node.href == "/orgs/1/network_enforcement_nodes/uuid-2"


def test_network_enforcement_node_from_json():
    data = {
        "href": "/orgs/1/network_enforcement_nodes/uuid-1",
        "name": "NEN-01",
        "hostname": "nen01.example.com",
        "status": "active",
        "software_version": "1.0.0"
    }
    nen = NetworkEnforcementNode.from_json(data)
    assert nen.hostname == "nen01.example.com"


def test_discovered_virtual_server_from_json():
    data = {
        "href": "/orgs/1/discovered_virtual_servers/uuid-1",
        "name": "DVS-01",
        "vip_address": "10.0.0.100",
        "vip_port": 443,
        "vip_proto": 6
    }
    dvs = DiscoveredVirtualServer.from_json(data)
    assert dvs.vip_address == "10.0.0.100"
    assert dvs.vip_port == 443


def test_kubernetes_workload_from_json():
    data = {
        "href": "/orgs/1/kubernetes_workloads/uuid-1",
        "name": "nginx-deployment-abc123",
        "namespace": "default",
        "kind": "Deployment",
        "container_cluster": {"href": "/orgs/1/container_clusters/cc-uuid"}
    }
    kw = KubernetesWorkload.from_json(data)
    assert kw.namespace == "default"
    assert kw.kind == "Deployment"


def test_create_network_device(pce):
    nd = NetworkDevice(name="Test-Switch")
    created = pce.network_devices.create(nd)
    assert created.href


def test_enforcement_instructions(pce, requests_mock):
    requests_mock.register_uri('POST', re.compile('/enforcement_instructions'), json={"instructions": []})
    result = pce.request_enforcement_instructions("/orgs/1/network_devices/uuid-1")
    assert "instructions" in result
