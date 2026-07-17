import json
import os
import re
from typing import List

import pytest

from illumio.rules import Rule

MOCK_RULES = os.path.join(pytest.DATA_DIR, 'rules.json')
MOCK_RULE_SET_HREF = '/orgs/1/sec_policy/draft/rule_sets/1'


@pytest.fixture(scope='module')
def rules() -> List[Rule]:
    with open(MOCK_RULES, 'r') as f:
        yield json.loads(f.read())


@pytest.fixture(autouse=True)
def rules_mock(pce_object_mock, rules):
    pce_object_mock.add_mock_objects(rules)


@pytest.fixture(autouse=True)
def mock_requests(requests_mock, get_callback, post_callback, put_callback, delete_callback):
    pattern = re.compile('/sec_rules')
    requests_mock.register_uri('GET', pattern, json=get_callback)
    requests_mock.register_uri('POST', pattern, json=post_callback)
    requests_mock.register_uri('PUT', pattern, json=put_callback)
    requests_mock.register_uri('DELETE', pattern, json=delete_callback)


@pytest.fixture()
def mock_rule(pce) -> Rule:
    yield pce.rules.get_by_reference('{}/sec_rules/1'.format(MOCK_RULE_SET_HREF))


def test_label_resolution_block(mock_rule):
    json_rule = mock_rule.to_json()
    assert json_rule['resolve_labels_as']['providers'] == ['workloads']


def test_builder():
    rule = Rule.build(
        providers=['/orgs/1/labels/1'],
        consumers=['ams'],
        ingress_services=[{'port': 1234, 'proto': 6}],
        resolve_providers_as=['workloads'],
        resolve_consumers_as=['workloads']
    )
    expected_result = json.loads('''
        {
            "enabled": true,
            "ingress_services": [
                {"port": 1234, "proto": 6}
            ],
            "providers": [
                {"label": {"href": "/orgs/1/labels/1"}}
            ],
            "consumers": [
                {"actors": "ams"}
            ],
            "resolve_labels_as": {
                "providers": ["workloads"],
                "consumers": ["workloads"]
            }
        }
    ''')
    assert rule.to_json() == expected_result


def test_allow_rule_has_no_action_field():
    """Allow rules do not carry an ``action`` field; deny/override-deny are
    separate rule types with their own nested endpoints."""
    rule = Rule.build(
        providers=['/orgs/1/labels/1'],
        consumers=['/orgs/1/labels/2'],
        ingress_services=[{'port': 22, 'proto': 6}],
    )
    field_names = {f.name for f in Rule.__dataclass_fields__.values()}
    assert 'action' not in field_names
    assert 'action' not in rule.to_json()


def test_allow_rule_schema_fields_decode():
    """Fields present on real allow rules decode with correct types.

    all_ips_except_* and use_workload_subnets are in the schema; egress_services
    is present on live-PCE responses (the bundled schema omits it)."""
    rule = Rule.from_json({
        "href": "/orgs/1/sec_policy/draft/rule_sets/1/sec_rules/1",
        "enabled": True,
        "providers": [{"label": {"href": "/orgs/1/labels/1"}}],
        "consumers": [{"actors": "ams"}],
        "ingress_services": [{"port": 22, "proto": 6}],
        "egress_services": [{"href": "/orgs/1/sec_policy/draft/services/3"}],
        "all_ips_except_for_in_consumers": True,
        "all_ips_except_for_in_providers": False,
        "use_workload_subnets": ["providers", "consumers"],
    })
    assert rule.all_ips_except_for_in_consumers is True
    assert rule.all_ips_except_for_in_providers is False
    assert rule.use_workload_subnets == ["providers", "consumers"]
    from illumio.policyobjects import Service
    assert isinstance(rule.egress_services[0], Service)
    assert rule.egress_services[0].href.endswith("/services/3")
    # round-trip preserves the new fields
    j = rule.to_json()
    assert j["all_ips_except_for_in_consumers"] is True
    assert j["use_workload_subnets"] == ["providers", "consumers"]


def test_get_rules(pce):
    rules = pce.rules.get(parent=MOCK_RULE_SET_HREF)
    assert len(rules) > 0
