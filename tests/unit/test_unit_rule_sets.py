import json
import os
import re
from typing import List

import pytest

from illumio.policyobjects import LabelSet
from illumio.rules import RuleSet, DenyRule, OverrideDenyRule
from illumio.util import Reference, DRAFT, ACTIVE

RULESETS = os.path.join(pytest.DATA_DIR, 'rule_sets.json')


@pytest.fixture(scope='module')
def rule_sets() -> List[dict]:
    with open(RULESETS, 'r') as f:
        yield json.loads(f.read())


@pytest.fixture(scope='module')
def new_rule_set() -> RuleSet:
    return RuleSet(
        name="RS-TEST"
    )


@pytest.fixture(autouse=True)
def rule_sets_mock(pce_object_mock, rule_sets):
    pce_object_mock.add_mock_objects(rule_sets)


@pytest.fixture(autouse=True)
def mock_requests(requests_mock, get_callback, post_callback, put_callback, delete_callback):
    pattern = re.compile('/sec_policy/(draft|active)/rule_sets')
    requests_mock.register_uri('GET', pattern, json=get_callback)
    requests_mock.register_uri('POST', pattern, json=post_callback)
    requests_mock.register_uri('PUT', pattern, json=put_callback)
    requests_mock.register_uri('DELETE', pattern, json=delete_callback)


@pytest.fixture()
def mock_rule_set(pce) -> RuleSet:
    yield pce.rule_sets.get_by_reference("/orgs/1/sec_policy/active/rule_sets/1")


@pytest.fixture()
def mock_rule_set_with_deny_rules(pce) -> RuleSet:
    yield pce.rule_sets.get_by_reference("/orgs/1/sec_policy/draft/rule_sets/3")


def test_encoded_scopes(pce):
    rule_set = pce.rule_sets.get_by_reference("/orgs/1/sec_policy/draft/rule_sets/2")
    json_rule_set = rule_set.to_json()
    assert json_rule_set['scopes'] == [[]]


def test_compare_unordered_scopes(mock_rule_set):
    scopes = [
        LabelSet(
            labels=[
                Reference(href="/orgs/1/labels/24"),
                Reference(href="/orgs/1/labels/22"),
                Reference(href="/orgs/1/labels/23")
            ]
        )
    ]
    assert mock_rule_set.scopes == scopes


def test_get_by_partial_name(pce):
    rule_sets = pce.rule_sets.get(params={'name': 'RS-'}, policy_version=DRAFT)
    assert len(rule_sets) >= 2  # At least RS-RINGFENCE, RS-DRAFT, and RS-WITH-DENY-RULES


def test_get_by_name(pce):
    rule_set = pce.rule_sets.get_by_name('RS-RINGFENCE')
    assert rule_set


def test_get_active_rule_sets(pce, mock_rule_set):
    rule_set = pce.rule_sets.get(params={'name': 'RS-RINGFENCE', 'max_results': 1}, policy_version=ACTIVE)[0]
    assert rule_set == mock_rule_set


def test_create_rule_set(pce, new_rule_set):
    created_rule_set = pce.rule_sets.create(new_rule_set)
    assert created_rule_set.href != ''
    rule_set = pce.rule_sets.get_by_reference(created_rule_set.href)
    assert created_rule_set == rule_set


def test_update_rule_set(pce, mock_rule_set):
    pce.rule_sets.update(mock_rule_set.href, {'enabled': False})
    updated_rule_set = pce.rule_sets.get_by_reference(mock_rule_set.href)
    assert updated_rule_set.enabled is False


def test_rule_set_deny_rules_field(mock_rule_set_with_deny_rules):
    """Test that RuleSet includes deny_rules field."""
    assert hasattr(mock_rule_set_with_deny_rules, 'deny_rules')
    assert mock_rule_set_with_deny_rules.deny_rules is not None
    assert len(mock_rule_set_with_deny_rules.deny_rules) == 1
    assert isinstance(mock_rule_set_with_deny_rules.deny_rules[0], DenyRule)


def test_rule_set_override_deny_rules_field(mock_rule_set_with_deny_rules):
    """Test that RuleSet includes override_deny_rules field."""
    assert hasattr(mock_rule_set_with_deny_rules, 'override_deny_rules')
    assert mock_rule_set_with_deny_rules.override_deny_rules is not None
    assert len(mock_rule_set_with_deny_rules.override_deny_rules) == 1
    assert isinstance(mock_rule_set_with_deny_rules.override_deny_rules[0], OverrideDenyRule)


def test_rule_set_with_deny_rules_json(mock_rule_set_with_deny_rules):
    """Test RuleSet JSON encoding includes deny rules."""
    json_result = mock_rule_set_with_deny_rules.to_json()
    
    assert 'deny_rules' in json_result
    assert 'override_deny_rules' in json_result
    assert len(json_result['deny_rules']) == 1
    assert len(json_result['override_deny_rules']) == 1
    
    # Verify deny rule structure
    deny_rule = json_result['deny_rules'][0]
    assert deny_rule['name'] == 'DR-Block-SSH-In-RuleSet'
    assert deny_rule['priority'] == 100
    assert deny_rule['enabled'] == True
    
    # Verify override deny rule structure
    override_rule = json_result['override_deny_rules'][0]
    assert override_rule['name'] == 'ODR-Allow-Admin-In-RuleSet'
    assert override_rule['enabled'] == True
    assert 'overrides' in override_rule


def test_rule_set_deny_rules_decoding():
    """Test RuleSet.from_json decodes deny_rules properly."""
    json_data = {
        "href": "/orgs/1/sec_policy/draft/rule_sets/99",
        "name": "RS-Test-Decode",
        "enabled": True,
        "deny_rules": [
            {
                "href": "/orgs/1/sec_policy/draft/rule_sets/99/sec_deny_rules/1",
                "name": "DR-Test",
                "enabled": True,
                "priority": 50,
                "providers": [{"label": {"href": "/orgs/1/labels/1"}}],
                "consumers": [{"label": {"href": "/orgs/1/labels/2"}}],
                "ingress_services": [{"port": 22, "proto": 6}],
                "resolve_labels_as": {"providers": ["workloads"], "consumers": ["workloads"]}
            }
        ],
        "override_deny_rules": []
    }
    
    ruleset = RuleSet.from_json(json_data)
    
    assert ruleset.name == "RS-Test-Decode"
    assert len(ruleset.deny_rules) == 1
    assert isinstance(ruleset.deny_rules[0], DenyRule)
    assert ruleset.deny_rules[0].name == "DR-Test"
    assert ruleset.deny_rules[0].priority == 50


def test_rule_set_empty_deny_rules():
    """Test RuleSet with empty deny_rules lists."""
    ruleset = RuleSet(
        name="RS-Empty",
        deny_rules=[],
        override_deny_rules=[]
    )
    
    json_result = ruleset.to_json()
    
    assert json_result['name'] == 'RS-Empty'
    assert json_result['deny_rules'] == []
    assert json_result['override_deny_rules'] == []


def test_create_rule_set_with_deny_rules(pce):
    """Test creating a RuleSet that will contain deny rules."""
    ruleset = RuleSet(
        name="RS-NEW-WITH-DENY",
        enabled=True,
        deny_rules=[],
        override_deny_rules=[]
    )
    
    created = pce.rule_sets.create(ruleset)
    assert created.href is not None
    assert 'rule_sets' in created.href
