# -*- coding: utf-8 -*-

"""Unit tests for DenyRule and OverrideDenyRule.

Deny rules and override-deny rules are rule *types* that live nested under a
ruleset, alongside allow rules. They share the same shape as an allow ``Rule``
(providers, consumers, ingress_services, enabled, resolve_labels_as) and differ
only by which nested endpoint they are posted to. Rule precedence is by type:
override-deny > allow > deny. There is no numeric ``priority`` field and
override-deny rules do not reference specific deny rules.

Copyright:
    © 2024 Illumio

License:
    Apache2, see LICENSE for more details.
"""
import json
import os
import re
from typing import List

import pytest

from illumio.rules import DenyRule, OverrideDenyRule, RuleSet

MOCK_DENY_RULES = os.path.join(pytest.DATA_DIR, 'deny_rules.json')
MOCK_OVERRIDE_DENY_RULES = os.path.join(pytest.DATA_DIR, 'override_deny_rules.json')
MOCK_RULE_SETS = os.path.join(pytest.DATA_DIR, 'rule_sets.json')
MOCK_RULE_SET_HREF = '/orgs/1/sec_policy/draft/rule_sets/3'
MOCK_DENY_RULE_HREF = '/orgs/1/sec_policy/draft/rule_sets/3/deny_rules/1'
MOCK_OVERRIDE_DENY_RULE_HREF = '/orgs/1/sec_policy/draft/rule_sets/3/override_deny_rules/1'


@pytest.fixture(scope='module')
def deny_rules() -> List[dict]:
    with open(MOCK_DENY_RULES, 'r') as f:
        yield json.loads(f.read())


@pytest.fixture(scope='module')
def override_deny_rules() -> List[dict]:
    with open(MOCK_OVERRIDE_DENY_RULES, 'r') as f:
        yield json.loads(f.read())


@pytest.fixture(scope='module')
def rule_sets() -> List[dict]:
    with open(MOCK_RULE_SETS, 'r') as f:
        yield json.loads(f.read())


@pytest.fixture(autouse=True)
def deny_rules_mock(pce_object_mock, deny_rules, override_deny_rules, rule_sets):
    pce_object_mock.add_mock_objects(deny_rules)
    pce_object_mock.add_mock_objects(override_deny_rules)
    pce_object_mock.add_mock_objects(rule_sets)


@pytest.fixture(autouse=True)
def mock_requests(requests_mock, get_callback, post_callback, put_callback, delete_callback):
    deny_pattern = re.compile(r'/deny_rules')
    override_pattern = re.compile(r'/override_deny_rules')
    ruleset_pattern = re.compile(r'/rule_sets')

    requests_mock.register_uri('GET', deny_pattern, json=get_callback)
    requests_mock.register_uri('POST', deny_pattern, json=post_callback)
    requests_mock.register_uri('PUT', deny_pattern, json=put_callback)
    requests_mock.register_uri('DELETE', deny_pattern, json=delete_callback)

    requests_mock.register_uri('GET', override_pattern, json=get_callback)
    requests_mock.register_uri('POST', override_pattern, json=post_callback)
    requests_mock.register_uri('PUT', override_pattern, json=put_callback)
    requests_mock.register_uri('DELETE', override_pattern, json=delete_callback)

    requests_mock.register_uri('GET', ruleset_pattern, json=get_callback)
    requests_mock.register_uri('POST', ruleset_pattern, json=post_callback)
    requests_mock.register_uri('PUT', ruleset_pattern, json=put_callback)
    requests_mock.register_uri('DELETE', ruleset_pattern, json=delete_callback)


class TestDenyRule:
    """Test cases for DenyRule API."""

    def test_get_deny_rule_by_reference(self, pce):
        """A deny rule is fetched by its ruleset-nested href."""
        rule = pce.deny_rules.get_by_reference(MOCK_DENY_RULE_HREF)
        assert rule.href == MOCK_DENY_RULE_HREF
        assert rule.enabled is True
        assert len(rule.ingress_services) == 1
        assert rule.ingress_services[0].port == 22

    def test_deny_rule_has_no_priority_field(self):
        """Deny rules have no numeric priority; precedence is by rule type."""
        assert 'priority' not in {f.name for f in DenyRule.__dataclass_fields__.values()}

    def test_create_deny_rule_in_ruleset(self, pce):
        """A deny rule is created nested under its parent ruleset."""
        deny_rule = DenyRule.build(
            providers=['/orgs/1/labels/1'],
            consumers=['/orgs/1/labels/2'],
            ingress_services=[{'port': 80, 'proto': 6}],
        )
        created = pce.deny_rules.create(deny_rule, parent=MOCK_RULE_SET_HREF)
        assert created.href is not None
        assert '/rule_sets/3/deny_rules' in created.href

    def test_deny_rule_builder(self):
        """DenyRule.build mirrors the allow-rule builder shape."""
        deny_rule = DenyRule.build(
            providers=['/orgs/1/labels/1'],
            consumers=['ams'],
            ingress_services=[{'port': 443, 'proto': 6}],
        )
        assert deny_rule.enabled is True
        assert len(deny_rule.providers) == 1
        assert len(deny_rule.consumers) == 1
        assert len(deny_rule.ingress_services) == 1
        assert deny_rule.resolve_labels_as.providers == ['workloads']

    def test_deny_rule_json_encoding(self):
        """A built deny rule serializes without invented fields."""
        deny_rule = DenyRule.build(
            providers=['/orgs/1/labels/1'],
            consumers=['/orgs/1/labels/2'],
            ingress_services=[{'port': 22, 'proto': 6}],
        )
        json_result = deny_rule.to_json()
        assert json_result['enabled'] is True
        assert 'providers' in json_result
        assert 'consumers' in json_result
        assert 'ingress_services' in json_result
        assert 'priority' not in json_result
        assert 'override' not in json_result

    def test_deny_rule_decoding(self, deny_rules):
        """A deny rule decodes from a real-shaped API response."""
        rule = DenyRule.from_json(deny_rules[0])
        assert rule.href == MOCK_DENY_RULE_HREF
        assert rule.enabled is True
        assert len(rule.ingress_services) == 1
        assert rule.ingress_services[0].port == 22

    def test_update_deny_rule(self, pce):
        """A deny rule is updated by its ruleset-nested href."""
        pce.deny_rules.update(MOCK_DENY_RULE_HREF, {'enabled': False})
        updated = pce.deny_rules.get_by_reference(MOCK_DENY_RULE_HREF)
        assert updated.enabled is False

    def test_delete_deny_rule(self, pce):
        """A deny rule can be deleted (204, no exception)."""
        deny_rule = DenyRule.build(
            providers=['/orgs/1/labels/1'],
            consumers=['/orgs/1/labels/2'],
            ingress_services=[{'port': 8080, 'proto': 6}],
        )
        created = pce.deny_rules.create(deny_rule, parent=MOCK_RULE_SET_HREF)
        pce.deny_rules.delete(created.href)


class TestOverrideDenyRule:
    """Test cases for OverrideDenyRule API."""

    def test_get_override_deny_rule_by_reference(self, pce):
        rule = pce.override_deny_rules.get_by_reference(MOCK_OVERRIDE_DENY_RULE_HREF)
        assert rule.href == MOCK_OVERRIDE_DENY_RULE_HREF
        assert rule.enabled is True

    def test_override_deny_rule_has_no_overrides_field(self):
        """Override-deny rules are a rule type, not a pointer to deny rules."""
        field_names = {f.name for f in OverrideDenyRule.__dataclass_fields__.values()}
        assert 'overrides' not in field_names
        assert 'priority' not in field_names

    def test_create_override_deny_rule_in_ruleset(self, pce):
        override_rule = OverrideDenyRule.build(
            providers=['/orgs/1/labels/10'],
            consumers=['/orgs/1/labels/1'],
            ingress_services=[{'port': 22, 'proto': 6}],
        )
        created = pce.override_deny_rules.create(override_rule, parent=MOCK_RULE_SET_HREF)
        assert created.href is not None
        assert '/rule_sets/3/override_deny_rules' in created.href

    def test_override_deny_rule_builder(self):
        override_rule = OverrideDenyRule.build(
            providers=['/orgs/1/labels/1'],
            consumers=['/orgs/1/labels/2'],
            ingress_services=[{'port': 443, 'proto': 6}],
        )
        assert override_rule.enabled is True
        assert len(override_rule.providers) == 1
        assert len(override_rule.consumers) == 1
        assert override_rule.resolve_labels_as.providers == ['workloads']

    def test_override_deny_rule_json_encoding(self):
        override_rule = OverrideDenyRule.build(
            providers=['/orgs/1/labels/1'],
            consumers=['/orgs/1/labels/2'],
            ingress_services=[{'port': 22, 'proto': 6}],
        )
        json_result = override_rule.to_json()
        assert json_result['enabled'] is True
        assert 'providers' in json_result
        assert 'consumers' in json_result
        assert 'overrides' not in json_result

    def test_override_deny_rule_decoding(self, override_deny_rules):
        rule = OverrideDenyRule.from_json(override_deny_rules[0])
        assert rule.href == MOCK_OVERRIDE_DENY_RULE_HREF
        assert rule.enabled is True

    def test_deny_and_override_share_shape(self):
        """DenyRule and OverrideDenyRule expose the same field set."""
        deny_fields = {f.name for f in DenyRule.__dataclass_fields__.values()}
        override_fields = {f.name for f in OverrideDenyRule.__dataclass_fields__.values()}
        assert deny_fields == override_fields


class TestDenyRulesInRuleSet:
    """Deny rules as fetched/encoded within their parent RuleSet."""

    def test_ruleset_with_deny_rules(self, pce):
        ruleset = pce.rule_sets.get_by_reference(MOCK_RULE_SET_HREF)
        assert ruleset.name == "RS-WITH-DENY-RULES"
        assert ruleset.deny_rules is not None
        assert len(ruleset.deny_rules) == 1
        assert isinstance(ruleset.deny_rules[0], DenyRule)

    def test_ruleset_with_override_deny_rules(self, pce):
        ruleset = pce.rule_sets.get_by_reference(MOCK_RULE_SET_HREF)
        assert ruleset.override_deny_rules is not None
        assert len(ruleset.override_deny_rules) == 1
        assert isinstance(ruleset.override_deny_rules[0], OverrideDenyRule)

    def test_ruleset_nested_deny_rule_href_is_ruleset_scoped(self, pce):
        ruleset = pce.rule_sets.get_by_reference(MOCK_RULE_SET_HREF)
        assert '/rule_sets/3/deny_rules/' in ruleset.deny_rules[0].href
        assert '/rule_sets/3/override_deny_rules/' in ruleset.override_deny_rules[0].href

    def test_ruleset_deny_rules_json_encoding(self, pce):
        ruleset = pce.rule_sets.get_by_reference(MOCK_RULE_SET_HREF)
        json_result = ruleset.to_json()
        assert 'deny_rules' in json_result
        assert 'override_deny_rules' in json_result
        assert 'priority' not in json_result['deny_rules'][0]
        assert 'overrides' not in json_result['override_deny_rules'][0]


class TestRuleSetModel:
    """RuleSet model with deny-rule fields."""

    def test_ruleset_empty_deny_rules(self):
        ruleset = RuleSet(
            name='RS-Empty-Deny',
            deny_rules=[],
            override_deny_rules=[],
        )
        assert ruleset.deny_rules == []
        assert ruleset.override_deny_rules == []
