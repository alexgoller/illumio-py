# -*- coding: utf-8 -*-

"""Unit tests for DenyRule and OverrideDenyRule.

Deny rules live nested under a ruleset. There is a single deny-rule object
type (schema ``deny_rules_get``) whose ``override`` boolean determines its
precedence: ``override=true`` is an "override-deny" rule that takes precedence
over allow rules, ``override=false`` (default) is an ordinary deny rule. The
policy evaluation order is override-deny > allow > deny.

``OverrideDenyRule`` is a thin convenience whose ``build`` defaults
``override=True``; it targets the same ``/deny_rules`` endpoint as ``DenyRule``.

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
from illumio.policyobjects import Service, ServicePort

MOCK_DENY_RULES = os.path.join(pytest.DATA_DIR, 'deny_rules.json')
MOCK_OVERRIDE_DENY_RULES = os.path.join(pytest.DATA_DIR, 'override_deny_rules.json')
MOCK_RULE_SETS = os.path.join(pytest.DATA_DIR, 'rule_sets.json')
MOCK_RULE_SET_HREF = '/orgs/1/sec_policy/draft/rule_sets/3'
MOCK_DENY_RULE_HREF = '/orgs/1/sec_policy/draft/rule_sets/3/deny_rules/1'
MOCK_OVERRIDE_DENY_RULE_HREF = '/orgs/1/sec_policy/draft/rule_sets/3/deny_rules/10'

# Fields defined by the real deny_rules_get schema that must NOT leak invented ones.
INVENTED_FIELDS = {'priority', 'overrides'}


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
    ruleset_pattern = re.compile(r'/rule_sets')

    for verb, cb in (('GET', get_callback), ('POST', post_callback),
                     ('PUT', put_callback), ('DELETE', delete_callback)):
        requests_mock.register_uri(verb, deny_pattern, json=cb)
        requests_mock.register_uri(verb, ruleset_pattern, json=cb)


class TestDenyRuleModel:
    """The DenyRule model matches the deny_rules_get schema."""

    def test_no_invented_fields(self):
        deny_fields = {f.name for f in DenyRule.__dataclass_fields__.values()}
        assert INVENTED_FIELDS.isdisjoint(deny_fields)

    def test_has_schema_fields(self):
        deny_fields = {f.name for f in DenyRule.__dataclass_fields__.values()}
        for field in ('providers', 'consumers', 'ingress_services', 'egress_services',
                      'enabled', 'override', 'network_type', 'unscoped_consumers',
                      'all_ips_except_for_in_consumers', 'all_ips_except_for_in_providers'):
            assert field in deny_fields, field

    def test_deny_has_no_resolve_labels_as(self):
        """resolve_labels_as is an allow-rule field, not a deny-rule field."""
        deny_fields = {f.name for f in DenyRule.__dataclass_fields__.values()}
        assert 'resolve_labels_as' not in deny_fields

    def test_deny_and_override_share_shape(self):
        deny_fields = {f.name for f in DenyRule.__dataclass_fields__.values()}
        override_fields = {f.name for f in OverrideDenyRule.__dataclass_fields__.values()}
        assert deny_fields == override_fields


class TestDenyRule:
    """DenyRule CRUD, nested under a ruleset."""

    def test_get_deny_rule_by_reference(self, pce):
        rule = pce.deny_rules.get_by_reference(MOCK_DENY_RULE_HREF)
        assert rule.href == MOCK_DENY_RULE_HREF
        assert rule.enabled is True
        assert rule.override is False
        assert rule.ingress_services[0].port == 22

    def test_egress_services_decode(self, deny_rules):
        rule = DenyRule.from_json(deny_rules[1])
        assert rule.egress_services is not None
        assert isinstance(rule.egress_services[0], Service)
        assert rule.egress_services[0].href.endswith('/services/3')

    def test_all_ips_except_decode(self, deny_rules):
        rule = DenyRule.from_json(deny_rules[1])
        assert rule.all_ips_except_for_in_consumers is True
        assert rule.unscoped_consumers is True

    def test_create_deny_rule_hits_deny_endpoint(self, pce):
        deny_rule = DenyRule.build(
            providers=['/orgs/1/labels/1'],
            consumers=['/orgs/1/labels/2'],
            ingress_services=[{'port': 80, 'proto': 6}],
        )
        created = pce.deny_rules.create(deny_rule, parent=MOCK_RULE_SET_HREF)
        assert '/rule_sets/3/deny_rules' in created.href

    def test_builder_defaults(self):
        deny_rule = DenyRule.build(
            providers=['/orgs/1/labels/1'],
            consumers=['ams'],
            ingress_services=[{'port': 443, 'proto': 6}],
        )
        assert deny_rule.enabled is True
        # A plain deny rule does not force override; server default is false.
        assert deny_rule.override in (None, False)
        assert len(deny_rule.providers) == 1

    def test_builder_with_override(self):
        deny_rule = DenyRule.build(
            providers=['/orgs/1/labels/1'],
            consumers=['/orgs/1/labels/2'],
            ingress_services=[{'port': 22, 'proto': 6}],
            override=True,
        )
        assert deny_rule.override is True

    def test_json_encoding_has_no_resolve_labels_as(self):
        deny_rule = DenyRule.build(
            providers=['/orgs/1/labels/1'],
            consumers=['/orgs/1/labels/2'],
            ingress_services=[{'port': 22, 'proto': 6}],
        )
        j = deny_rule.to_json()
        assert 'resolve_labels_as' not in j
        assert 'priority' not in j
        assert 'providers' in j and 'consumers' in j and 'ingress_services' in j

    def test_update_deny_rule(self, pce):
        pce.deny_rules.update(MOCK_DENY_RULE_HREF, {'enabled': False})
        updated = pce.deny_rules.get_by_reference(MOCK_DENY_RULE_HREF)
        assert updated.enabled is False


class TestOverrideDenyRule:
    """OverrideDenyRule is a deny rule with override defaulting True."""

    def test_builder_defaults_override_true(self):
        rule = OverrideDenyRule.build(
            providers=['/orgs/1/labels/10'],
            consumers=['/orgs/1/labels/1'],
            ingress_services=[{'port': 22, 'proto': 6}],
        )
        assert rule.override is True

    def test_override_targets_deny_endpoint(self, pce):
        rule = OverrideDenyRule.build(
            providers=['/orgs/1/labels/10'],
            consumers=['/orgs/1/labels/1'],
            ingress_services=[{'port': 22, 'proto': 6}],
        )
        created = pce.override_deny_rules.create(rule, parent=MOCK_RULE_SET_HREF)
        assert '/rule_sets/3/deny_rules' in created.href

    def test_get_override_deny_rule_by_reference(self, pce):
        rule = pce.override_deny_rules.get_by_reference(MOCK_OVERRIDE_DENY_RULE_HREF)
        assert rule.override is True
        assert rule.enabled is True


class TestDenyRulesInRuleSet:
    """Deny rules embedded within their parent RuleSet.

    A real ruleset exposes a single ``deny_rules`` array holding both ordinary
    deny rules (``override=False``) and override-deny rules (``override=True``);
    there is no separate ``override_deny_rules`` array.
    """

    def test_ruleset_deny_rules_array_holds_both_kinds(self, pce):
        ruleset = pce.rule_sets.get_by_reference(MOCK_RULE_SET_HREF)
        assert ruleset.name == "RS-WITH-DENY-RULES"
        assert not hasattr(ruleset, 'override_deny_rules') or \
            'override_deny_rules' not in {f.name for f in RuleSet.__dataclass_fields__.values()}
        assert len(ruleset.deny_rules) == 2
        assert all(isinstance(r, DenyRule) for r in ruleset.deny_rules)
        overrides = sorted(r.override for r in ruleset.deny_rules)
        assert overrides == [False, True]

    def test_ruleset_deny_rules_json_encoding(self, pce):
        ruleset = pce.rule_sets.get_by_reference(MOCK_RULE_SET_HREF)
        j = ruleset.to_json()
        assert 'override_deny_rules' not in j
        for dr in j['deny_rules']:
            assert 'priority' not in dr
            assert 'overrides' not in dr


class TestRuleSetModel:
    def test_ruleset_has_no_override_deny_rules_field(self):
        field_names = {f.name for f in RuleSet.__dataclass_fields__.values()}
        assert 'deny_rules' in field_names
        assert 'override_deny_rules' not in field_names

    def test_ruleset_empty_deny_rules(self):
        ruleset = RuleSet(name='RS-Empty-Deny', deny_rules=[])
        assert ruleset.deny_rules == []
