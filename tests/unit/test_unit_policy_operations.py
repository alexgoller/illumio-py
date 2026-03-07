import json
import re

import pytest
from requests_mock import ANY

from illumio import PolicyComputeEngine
from illumio.secpolicy import FirewallSetting, PolicyDependency, PolicyCheck, ModifiedObject


@pytest.fixture(autouse=True)
def mock_requests(requests_mock):
    requests_mock.register_uri('GET', re.compile('/sec_policy'), json=[])
    requests_mock.register_uri('POST', re.compile('/sec_policy'), json={})
    requests_mock.register_uri('PUT', re.compile('/sec_policy'), json={})
    requests_mock.register_uri('DELETE', re.compile('/sec_policy'), status_code=204)


def test_get_pending_policy_changes(pce, requests_mock):
    pending = [{"href": "/orgs/1/sec_policy/draft/ip_lists/1", "change_type": "create"}]
    requests_mock.register_uri('GET', re.compile('/sec_policy/pending'), json=pending)
    result = pce.get_pending_policy_changes()
    assert len(result) == 1


def test_discard_pending_policy_changes(pce, requests_mock):
    requests_mock.register_uri('DELETE', re.compile('/sec_policy/pending'), status_code=204)
    pce.discard_pending_policy_changes()


def test_get_modified_policy_objects(pce, requests_mock):
    modified = [{"href": "/orgs/1/sec_policy/draft/ip_lists/1", "token": "ip_list", "change_type": "create"}]
    requests_mock.register_uri('GET', re.compile('/sec_policy/draft/modified_objects'), json=modified)
    result = pce.get_modified_policy_objects()
    assert len(result) == 1
    assert isinstance(result[0], ModifiedObject)


def test_check_policy(pce, requests_mock):
    check_result = {"status": "ok", "errors": [], "warnings": []}
    requests_mock.register_uri('GET', re.compile('/policy_check'), json=check_result)
    result = pce.check_policy()
    assert isinstance(result, PolicyCheck)
    assert result.status == "ok"


def test_search_rules(pce, requests_mock):
    rules = [{"href": "/orgs/1/sec_policy/draft/rule_sets/1/sec_rules/1"}]
    requests_mock.register_uri('POST', re.compile('/rule_search'), json=rules)
    result = pce.search_rules({"providers": []})
    assert len(result) == 1


def test_firewall_setting_from_json():
    data = {
        "href": "/orgs/1/sec_policy/draft/firewall_settings/1",
        "allow_dhcp_client": True,
        "log_dropped_multicast": False,
        "network_detection_mode": "single_private_brn"
    }
    fs = FirewallSetting.from_json(data)
    assert fs.allow_dhcp_client is True
    assert fs.network_detection_mode == "single_private_brn"


def test_policy_dependency_from_json():
    data = {
        "href": "/orgs/1/sec_policy/draft/ip_lists/1",
        "type": "ip_list",
        "name": "Test IP List",
        "dependent_type": "rule_set",
        "dependent_href": "/orgs/1/sec_policy/draft/rule_sets/1"
    }
    dep = PolicyDependency.from_json(data)
    assert dep.type == "ip_list"
    assert dep.dependent_type == "rule_set"
