# -*- coding: utf-8 -*-

"""Unit tests for DenyRule and OverrideDenyRule.

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
    # Match both sec_policy paths and direct rule paths, including ruleset-scoped paths
    deny_pattern = re.compile(r'/(sec_deny_rules|deny_rules)')
    override_pattern = re.compile(r'/(sec_override_deny_rules|override_deny_rules)')
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

    def test_get_deny_rules(self, pce):
        """Test fetching deny rules."""
        rules = pce.deny_rules.get()
        assert len(rules) >= 2
        assert all(isinstance(r, DenyRule) for r in rules)

    def test_get_deny_rule_by_reference(self, pce):
        """Test fetching a single deny rule by href."""
        rule = pce.deny_rules.get_by_reference("/orgs/1/sec_policy/draft/deny_rules/1")
        assert rule.name == "DR-Block-SSH-External"
        assert rule.priority == 100
        assert rule.enabled == True

    def test_get_deny_rule_by_name(self, pce):
        """Test fetching deny rule by name."""
        rule = pce.deny_rules.get_by_name("DR-Block-SSH-External")
        assert rule is not None
        assert rule.priority == 100

    def test_create_deny_rule(self, pce):
        """Test creating a deny rule."""
        deny_rule = DenyRule.build(
            providers=['/orgs/1/labels/1'],
            consumers=['/orgs/1/labels/2'],
            ingress_services=[{'port': 80, 'proto': 6}],
            name='DR-Test-Block-HTTP',
            priority=50
        )
        created = pce.deny_rules.create(deny_rule)
        assert created.href is not None
        assert 'sec_deny_rules' in created.href

    def test_deny_rule_builder(self):
        """Test DenyRule.build() method."""
        deny_rule = DenyRule.build(
            providers=['/orgs/1/labels/1'],
            consumers=['ams'],
            ingress_services=[{'port': 443, 'proto': 6}],
            name='DR-Block-HTTPS',
            priority=100
        )
        
        assert deny_rule.name == 'DR-Block-HTTPS'
        assert deny_rule.priority == 100
        assert deny_rule.enabled == True
        assert len(deny_rule.providers) == 1
        assert len(deny_rule.consumers) == 1
        assert len(deny_rule.ingress_services) == 1

    def test_deny_rule_json_encoding(self):
        """Test DenyRule JSON encoding."""
        deny_rule = DenyRule.build(
            providers=['/orgs/1/labels/1'],
            consumers=['/orgs/1/labels/2'],
            ingress_services=[{'port': 22, 'proto': 6}],
            name='DR-Test',
            priority=75
        )
        
        json_result = deny_rule.to_json()
        
        assert json_result['name'] == 'DR-Test'
        assert json_result['priority'] == 75
        assert json_result['enabled'] == True
        assert 'providers' in json_result
        assert 'consumers' in json_result
        assert 'ingress_services' in json_result
        assert 'resolve_labels_as' in json_result

    def test_deny_rule_decoding(self, deny_rules):
        """Test DenyRule JSON decoding."""
        rule_json = deny_rules[0]
        rule = DenyRule.from_json(rule_json)
        
        assert rule.href == "/orgs/1/sec_policy/draft/deny_rules/1"
        assert rule.name == "DR-Block-SSH-External"
        assert rule.priority == 100
        assert len(rule.ingress_services) == 1
        assert rule.ingress_services[0].port == 22


class TestOverrideDenyRule:
    """Test cases for OverrideDenyRule API."""

    def test_get_override_deny_rules(self, pce):
        """Test fetching override deny rules."""
        rules = pce.override_deny_rules.get()
        assert len(rules) >= 2
        assert all(isinstance(r, OverrideDenyRule) for r in rules)

    def test_get_override_deny_rule_by_reference(self, pce):
        """Test fetching a single override deny rule by href."""
        rule = pce.override_deny_rules.get_by_reference(
            "/orgs/1/sec_policy/draft/override_deny_rules/1"
        )
        assert rule.name == "ODR-Allow-Admin-SSH"
        assert rule.enabled == True

    def test_get_override_deny_rule_by_name(self, pce):
        """Test fetching override deny rule by name."""
        rule = pce.override_deny_rules.get_by_name("ODR-Allow-Admin-SSH")
        assert rule is not None

    def test_create_override_deny_rule(self, pce):
        """Test creating an override deny rule."""
        override_rule = OverrideDenyRule.build(
            providers=['/orgs/1/labels/10'],
            consumers=['/orgs/1/labels/1'],
            ingress_services=[{'port': 22, 'proto': 6}],
            name='ODR-Test-Override'
        )
        created = pce.override_deny_rules.create(override_rule)
        assert created.href is not None
        assert 'override_deny_rules' in created.href

    def test_override_deny_rule_builder(self):
        """Test OverrideDenyRule.build() method."""
        override_rule = OverrideDenyRule.build(
            providers=['/orgs/1/labels/1'],
            consumers=['/orgs/1/labels/2'],
            ingress_services=[{'port': 443, 'proto': 6}],
            name='ODR-Emergency',
            overrides=['/orgs/1/sec_policy/draft/deny_rules/1']
        )
        
        assert override_rule.name == 'ODR-Emergency'
        assert override_rule.enabled == True
        assert len(override_rule.providers) == 1
        assert len(override_rule.consumers) == 1

    def test_override_deny_rule_json_encoding(self):
        """Test OverrideDenyRule JSON encoding."""
        override_rule = OverrideDenyRule.build(
            providers=['/orgs/1/labels/1'],
            consumers=['/orgs/1/labels/2'],
            ingress_services=[{'port': 22, 'proto': 6}],
            name='ODR-Test'
        )
        
        json_result = override_rule.to_json()
        
        assert json_result['name'] == 'ODR-Test'
        assert json_result['enabled'] == True
        assert 'providers' in json_result
        assert 'consumers' in json_result

    def test_override_deny_rule_decoding(self, override_deny_rules):
        """Test OverrideDenyRule JSON decoding."""
        rule_json = override_deny_rules[0]
        rule = OverrideDenyRule.from_json(rule_json)
        
        assert rule.href == "/orgs/1/sec_policy/draft/override_deny_rules/1"
        assert rule.name == "ODR-Allow-Admin-SSH"
        assert len(rule.overrides) == 1

    def test_override_with_multiple_deny_rules(self, override_deny_rules):
        """Test OverrideDenyRule with multiple overrides."""
        rule_json = override_deny_rules[1]  # Has 2 overrides
        rule = OverrideDenyRule.from_json(rule_json)
        
        assert len(rule.overrides) == 2
        assert rule.enabled == False  # This one is disabled


class TestRuleActions:
    """Test rule action field behavior."""
    
    def test_rule_action_allow(self):
        """Test Rule with allow action."""
        from illumio.rules import Rule
        rule = Rule.build(
            providers=['/orgs/1/labels/1'],
            consumers=['/orgs/1/labels/2'],
            ingress_services=[{'port': 80, 'proto': 6}],
            action='allow'
        )
        assert rule.action == 'allow'
    
    def test_rule_action_deny(self):
        """Test Rule with deny action."""
        from illumio.rules import Rule
        rule = Rule.build(
            providers=['/orgs/1/labels/1'],
            consumers=['/orgs/1/labels/2'],
            ingress_services=[{'port': 80, 'proto': 6}],
            action='deny'
        )
        assert rule.action == 'deny'
    
    def test_rule_action_override_deny(self):
        """Test Rule with override_deny action."""
        from illumio.rules import Rule
        rule = Rule.build(
            providers=['/orgs/1/labels/1'],
            consumers=['/orgs/1/labels/2'],
            ingress_services=[{'port': 80, 'proto': 6}],
            action='override_deny'
        )
        assert rule.action == 'override_deny'
    
    def test_rule_invalid_action_raises(self):
        """Test that invalid action raises exception."""
        from illumio.rules import Rule
        from illumio.exceptions import IllumioException
        
        with pytest.raises(IllumioException):
            Rule.build(
                providers=['/orgs/1/labels/1'],
                consumers=['/orgs/1/labels/2'],
                ingress_services=[{'port': 80, 'proto': 6}],
                action='invalid_action'
            )


class TestDenyRulesInRuleSet:
    """Test cases for DenyRule within RuleSet context."""

    def test_ruleset_with_deny_rules(self, pce):
        """Test fetching a ruleset with deny_rules field."""
        ruleset = pce.rule_sets.get_by_reference(MOCK_RULE_SET_HREF)
        assert ruleset.name == "RS-WITH-DENY-RULES"
        assert ruleset.deny_rules is not None
        assert len(ruleset.deny_rules) == 1
        assert isinstance(ruleset.deny_rules[0], DenyRule)
        assert ruleset.deny_rules[0].name == "DR-Block-SSH-In-RuleSet"

    def test_ruleset_with_override_deny_rules(self, pce):
        """Test fetching a ruleset with override_deny_rules field."""
        ruleset = pce.rule_sets.get_by_reference(MOCK_RULE_SET_HREF)
        assert ruleset.override_deny_rules is not None
        assert len(ruleset.override_deny_rules) == 1
        assert isinstance(ruleset.override_deny_rules[0], OverrideDenyRule)
        assert ruleset.override_deny_rules[0].name == "ODR-Allow-Admin-In-RuleSet"

    def test_create_deny_rule_in_ruleset(self, pce):
        """Test creating a deny rule within a ruleset."""
        deny_rule = DenyRule.build(
            providers=['/orgs/1/labels/1'],
            consumers=['/orgs/1/labels/2'],
            ingress_services=[{'port': 3389, 'proto': 6}],
            name='DR-Block-RDP-In-RuleSet',
            priority=50
        )
        created = pce.deny_rules.create(deny_rule, parent=MOCK_RULE_SET_HREF)
        assert created.href is not None
        # When created with a parent, the href should contain the ruleset path
        assert 'sec_deny_rules' in created.href

    def test_create_override_deny_rule_in_ruleset(self, pce):
        """Test creating an override deny rule within a ruleset."""
        override_rule = OverrideDenyRule.build(
            providers=['/orgs/1/labels/10'],
            consumers=['/orgs/1/labels/2'],
            ingress_services=[{'port': 22, 'proto': 6}],
            name='ODR-Emergency-In-RuleSet'
        )
        created = pce.override_deny_rules.create(override_rule, parent=MOCK_RULE_SET_HREF)
        assert created.href is not None
        assert 'override_deny_rules' in created.href

    def test_get_deny_rules_from_ruleset(self, pce):
        """Test getting deny rules from a specific ruleset."""
        deny_rules = pce.deny_rules.get(parent=MOCK_RULE_SET_HREF)
        # Should only return deny rules from that ruleset
        assert isinstance(deny_rules, list)

    def test_get_override_deny_rules_from_ruleset(self, pce):
        """Test getting override deny rules from a specific ruleset."""
        override_rules = pce.override_deny_rules.get(parent=MOCK_RULE_SET_HREF)
        assert isinstance(override_rules, list)

    def test_ruleset_deny_rules_json_encoding(self, pce):
        """Test that a ruleset with deny rules encodes correctly to JSON."""
        ruleset = pce.rule_sets.get_by_reference(MOCK_RULE_SET_HREF)
        json_result = ruleset.to_json()
        
        assert 'deny_rules' in json_result
        assert 'override_deny_rules' in json_result
        assert len(json_result['deny_rules']) == 1
        assert len(json_result['override_deny_rules']) == 1
        
        deny_rule_json = json_result['deny_rules'][0]
        assert deny_rule_json['name'] == 'DR-Block-SSH-In-RuleSet'
        assert deny_rule_json['priority'] == 100
        assert 'ingress_services' in deny_rule_json

    def test_update_deny_rule_in_ruleset(self, pce):
        """Test updating a deny rule within a ruleset context."""
        deny_rule_href = f"{MOCK_RULE_SET_HREF}/sec_deny_rules/1"
        pce.deny_rules.update(deny_rule_href, {'enabled': False, 'priority': 200})
        
        updated = pce.deny_rules.get_by_reference(deny_rule_href)
        assert updated.enabled == False
        assert updated.priority == 200

    def test_delete_deny_rule_from_ruleset(self, pce):
        """Test deleting a deny rule from a ruleset."""
        # First create a deny rule to delete
        deny_rule = DenyRule.build(
            providers=['/orgs/1/labels/1'],
            consumers=['/orgs/1/labels/2'],
            ingress_services=[{'port': 8080, 'proto': 6}],
            name='DR-To-Delete',
            priority=10
        )
        created = pce.deny_rules.create(deny_rule, parent=MOCK_RULE_SET_HREF)
        
        # Now delete it
        pce.deny_rules.delete(created.href)
        # No exception means success (DELETE returns 204)


class TestRuleSetModel:
    """Test RuleSet model with deny rules fields."""
    
    def test_ruleset_empty_deny_rules(self):
        """Test creating a RuleSet with empty deny_rules."""
        ruleset = RuleSet(
            name='RS-Empty-Deny',
            deny_rules=[],
            override_deny_rules=[]
        )
        assert ruleset.deny_rules == []
        assert ruleset.override_deny_rules == []
    
    def test_ruleset_with_deny_rules_objects(self):
        """Test creating a RuleSet with DenyRule objects."""
        deny_rule = DenyRule.build(
            providers=['/orgs/1/labels/1'],
            consumers=['/orgs/1/labels/2'],
            ingress_services=[{'port': 22, 'proto': 6}],
            name='DR-Test',
            priority=100
        )
        ruleset = RuleSet(
            name='RS-With-Deny',
            deny_rules=[deny_rule]
        )
        assert len(ruleset.deny_rules) == 1
        assert ruleset.deny_rules[0].name == 'DR-Test'
    
    def test_ruleset_json_with_deny_rules(self):
        """Test JSON encoding of RuleSet with deny rules."""
        deny_rule = DenyRule.build(
            providers=['/orgs/1/labels/1'],
            consumers=['/orgs/1/labels/2'],
            ingress_services=[{'port': 22, 'proto': 6}],
            name='DR-Test',
            priority=100
        )
        override_rule = OverrideDenyRule.build(
            providers=['/orgs/1/labels/10'],
            consumers=['/orgs/1/labels/1'],
            ingress_services=[{'port': 22, 'proto': 6}],
            name='ODR-Test'
        )
        ruleset = RuleSet(
            name='RS-Full',
            deny_rules=[deny_rule],
            override_deny_rules=[override_rule]
        )
        
        json_result = ruleset.to_json()
        
        assert json_result['name'] == 'RS-Full'
        assert 'deny_rules' in json_result
        assert 'override_deny_rules' in json_result
        assert len(json_result['deny_rules']) == 1
        assert len(json_result['override_deny_rules']) == 1


# Integration test examples (commented out for reference)
# These would be run against a real PCE with --integration flag
#
# class TestDenyRulesIntegration:
#     """Integration tests for deny rules - requires real PCE connection."""
#     
#     @pytest.mark.integration
#     def test_create_deny_rule_in_live_ruleset(self, pce, test_ruleset, test_ip_list, test_label):
#         """Create a deny rule in a live ruleset."""
#         deny_rule = DenyRule.build(
#             providers=[test_ip_list.href],
#             consumers=[test_label.href],
#             ingress_services=[{'port': 22, 'proto': 'tcp'}],
#             name='intg-test-deny-rule',
#             priority=100
#         )
#         created = pce.deny_rules.create(deny_rule, parent=test_ruleset)
#         assert created.href is not None
#         assert 'sec_deny_rules' in created.href
#         
#         # Cleanup
#         pce.deny_rules.delete(created.href)
#     
#     @pytest.mark.integration
#     def test_override_deny_rule_in_live_ruleset(self, pce, test_ruleset, test_label):
#         """Create an override deny rule in a live ruleset."""
#         # First create a deny rule to override
#         deny_rule = DenyRule.build(
#             providers=['/orgs/1/sec_policy/draft/ip_lists/1'],
#             consumers=[test_label.href],
#             ingress_services=[{'port': 22, 'proto': 'tcp'}],
#             name='intg-test-deny-to-override',
#             priority=100
#         )
#         created_deny = pce.deny_rules.create(deny_rule, parent=test_ruleset)
#         
#         # Now create override
#         override_rule = OverrideDenyRule.build(
#             providers=[test_label.href],
#             consumers=[test_label.href],
#             ingress_services=[{'port': 22, 'proto': 'tcp'}],
#             name='intg-test-override',
#             overrides=[created_deny.href]
#         )
#         created_override = pce.override_deny_rules.create(override_rule, parent=test_ruleset)
#         assert created_override.href is not None
#         
#         # Cleanup
#         pce.override_deny_rules.delete(created_override.href)
#         pce.deny_rules.delete(created_deny.href)
