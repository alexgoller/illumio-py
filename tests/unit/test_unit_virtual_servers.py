import json
import os
import re
from typing import List

import pytest

from illumio.policyobjects import VirtualServer

VIRTUAL_SERVERS = os.path.join(pytest.DATA_DIR, 'virtual_servers.json')


@pytest.fixture(scope='module')
def virtual_servers() -> List[dict]:
    with open(VIRTUAL_SERVERS, 'r') as f:
        yield json.loads(f.read())


@pytest.fixture(autouse=True)
def virtual_servers_mock(pce_object_mock, virtual_servers):
    pce_object_mock.add_mock_objects(virtual_servers)


@pytest.fixture(autouse=True)
def mock_requests(requests_mock, get_callback, post_callback, put_callback, delete_callback):
    pattern = re.compile('/sec_policy/(draft|active)/virtual_servers')
    requests_mock.register_uri('GET', pattern, json=get_callback)
    requests_mock.register_uri('POST', pattern, json=post_callback)
    requests_mock.register_uri('PUT', pattern, json=put_callback)
    requests_mock.register_uri('DELETE', pattern, json=delete_callback)


def test_get_virtual_server(pce):
    vs = pce.virtual_servers.get_by_reference(
        "/orgs/1/sec_policy/draft/virtual_servers/a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    )
    assert vs.name == "VS-LB-PROD"
    assert vs.dvs_name == "vs-lb-01"


def test_create_virtual_server(pce):
    vs = VirtualServer(name="VS-TEST", mode="unmanaged")
    created = pce.virtual_servers.create(vs)
    assert created.href


def test_virtual_server_from_json():
    data = {
        "href": "/orgs/1/sec_policy/draft/virtual_servers/test",
        "name": "VS-Test",
        "mode": "unmanaged",
        "dvs_identifier": "10.0.0.1:80"
    }
    vs = VirtualServer.from_json(data)
    assert vs.name == "VS-Test"
    assert vs.dvs_identifier == "10.0.0.1:80"
