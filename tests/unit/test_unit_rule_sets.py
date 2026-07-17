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
    """A ruleset exposes a single deny_rules array (holding both kinds)."""
    assert hasattr(mock_rule_set_with_deny_rules, 'deny_rules')
    assert mock_rule_set_with_deny_rules.deny_rules is not None
    assert len(mock_rule_set_with_deny_rules.deny_rules) == 2
    assert all(isinstance(r, DenyRule) for r in mock_rule_set_with_deny_rules.deny_rules)


def test_rule_set_has_no_override_deny_rules_field():
    """A ruleset has no separate override_deny_rules field; override rules
    live in deny_rules with override=True."""
    field_names = {f.name for f in RuleSet.__dataclass_fields__.values()}
    assert 'override_deny_rules' not in field_names


def test_rule_set_override_rule_lives_in_deny_rules(mock_rule_set_with_deny_rules):
    """The override-deny rule is present in deny_rules, flagged by override."""
    overrides = sorted(r.override for r in mock_rule_set_with_deny_rules.deny_rules)
    assert overrides == [False, True]


def test_rule_set_with_deny_rules_json(mock_rule_set_with_deny_rules):
    """Test RuleSet JSON encoding includes deny rules and no invented fields."""
    json_result = mock_rule_set_with_deny_rules.to_json()

    assert 'deny_rules' in json_result
    assert 'override_deny_rules' not in json_result
    assert len(json_result['deny_rules']) == 2

    for deny_rule in json_result['deny_rules']:
        assert deny_rule['enabled'] == True
        assert 'priority' not in deny_rule
        assert 'overrides' not in deny_rule


def test_rule_set_deny_rules_decoding():
    """Test RuleSet.from_json decodes deny_rules properly."""
    json_data = {
        "href": "/orgs/1/sec_policy/draft/rule_sets/99",
        "name": "RS-Test-Decode",
        "enabled": True,
        "deny_rules": [
            {
                "href": "/orgs/1/sec_policy/draft/rule_sets/99/deny_rules/1",
                "enabled": True,
                "override": True,
                "providers": [{"label": {"href": "/orgs/1/labels/1"}}],
                "consumers": [{"label": {"href": "/orgs/1/labels/2"}}],
                "ingress_services": [{"port": 22, "proto": 6}]
            }
        ]
    }

    ruleset = RuleSet.from_json(json_data)

    assert ruleset.name == "RS-Test-Decode"
    assert len(ruleset.deny_rules) == 1
    assert isinstance(ruleset.deny_rules[0], DenyRule)
    assert ruleset.deny_rules[0].override is True
    assert '/rule_sets/99/deny_rules/' in ruleset.deny_rules[0].href


def test_rule_set_empty_deny_rules():
    """Test RuleSet with an empty deny_rules list."""
    ruleset = RuleSet(name="RS-Empty", deny_rules=[])

    json_result = ruleset.to_json()

    assert json_result['name'] == 'RS-Empty'
    assert json_result['deny_rules'] == []
    assert 'override_deny_rules' not in json_result


def test_create_rule_set_with_deny_rules(pce):
    """Test creating a RuleSet that will contain deny rules."""
    ruleset = RuleSet(name="RS-NEW-WITH-DENY", enabled=True, deny_rules=[])

    created = pce.rule_sets.create(ruleset)
    assert created.href is not None
    assert 'rule_sets' in created.href
