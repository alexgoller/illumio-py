# -*- coding: utf-8 -*-

"""Extended unit tests for Labels and Label Groups.

Tests for label functionality and label group operations.

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

from illumio.policyobjects import Label, LabelGroup, LabelSet, LabelUsage

MOCK_LABEL_GROUPS = os.path.join(pytest.DATA_DIR, 'label_groups.json')


@pytest.fixture(scope='module')
def label_groups() -> List[dict]:
    with open(MOCK_LABEL_GROUPS, 'r') as f:
        yield json.loads(f.read())


@pytest.fixture(autouse=True)
def labels_mock(pce_object_mock, label_groups):
    # Add some test labels
    test_labels = [
        {
            "href": "/orgs/1/labels/1",
            "key": "role",
            "value": "R-Web",
            "created_at": "2024-01-01T00:00:00.000Z",
            "updated_at": "2024-01-01T00:00:00.000Z"
        },
        {
            "href": "/orgs/1/labels/2",
            "key": "app",
            "value": "A-App",
            "created_at": "2024-01-01T00:00:00.000Z",
            "updated_at": "2024-01-01T00:00:00.000Z"
        },
        {
            "href": "/orgs/1/labels/3",
            "key": "env",
            "value": "E-Prod",
            "created_at": "2024-01-01T00:00:00.000Z",
            "updated_at": "2024-01-01T00:00:00.000Z"
        },
        {
            "href": "/orgs/1/labels/4",
            "key": "loc",
            "value": "L-AWS",
            "created_at": "2024-01-01T00:00:00.000Z",
            "updated_at": "2024-01-01T00:00:00.000Z"
        }
    ]
    pce_object_mock.add_mock_objects(test_labels)
    pce_object_mock.add_mock_objects(label_groups)


@pytest.fixture(autouse=True)
def mock_requests(requests_mock, get_callback, post_callback, put_callback, delete_callback):
    label_pattern = re.compile('/labels')
    label_group_pattern = re.compile('/label_groups')
    
    requests_mock.register_uri('GET', label_pattern, json=get_callback)
    requests_mock.register_uri('POST', label_pattern, json=post_callback)
    requests_mock.register_uri('PUT', label_pattern, json=put_callback)
    requests_mock.register_uri('DELETE', label_pattern, json=delete_callback)
    
    requests_mock.register_uri('GET', label_group_pattern, json=get_callback)
    requests_mock.register_uri('POST', label_group_pattern, json=post_callback)
    requests_mock.register_uri('PUT', label_group_pattern, json=put_callback)
    requests_mock.register_uri('DELETE', label_group_pattern, json=delete_callback)


class TestLabel:
    """Test Label model and operations."""

    def test_create_label(self, pce):
        """Test creating a label."""
        label = Label(key='role', value='R-Database')
        created = pce.labels.create(label)
        
        assert created.href is not None
        assert '/labels/' in created.href

    def test_get_labels(self, pce):
        """Test fetching labels."""
        labels = pce.labels.get()
        assert len(labels) >= 1
        assert all(isinstance(l, Label) for l in labels)

    def test_get_label_by_reference(self, pce):
        """Test fetching label by href."""
        label = pce.labels.get_by_reference("/orgs/1/labels/1")
        assert label.key == "role"
        assert label.value == "R-Web"

    def test_get_label_by_name(self, pce):
        """Test fetching label by value (name)."""
        # Note: get_by_name searches by 'name' parameter
        # For labels, we typically filter by key and value
        labels = pce.labels.get(params={'key': 'role', 'value': 'R-Web'})
        assert len(labels) >= 1

    def test_label_keys(self):
        """Test standard label keys."""
        role_label = Label(key='role', value='R-Web')
        app_label = Label(key='app', value='A-App')
        env_label = Label(key='env', value='E-Prod')
        loc_label = Label(key='loc', value='L-AWS')
        
        assert role_label.key == 'role'
        assert app_label.key == 'app'
        assert env_label.key == 'env'
        assert loc_label.key == 'loc'

    def test_label_json_encoding(self):
        """Test Label JSON encoding."""
        label = Label(key='role', value='R-Test')
        json_result = label.to_json()
        
        assert json_result['key'] == 'role'
        assert json_result['value'] == 'R-Test'

    def test_label_with_usage(self):
        """Test Label with usage information."""
        label_json = {
            "href": "/orgs/1/labels/1",
            "key": "role",
            "value": "R-Web",
            "usage": {
                "label_group": True,
                "ruleset": True,
                "rule": True,
                "static_policy_scopes": False,
                "enforcement_boundary": False
            }
        }
        
        label = Label.from_json(label_json)
        
        assert label.usage is not None
        assert label.usage.label_group == True
        assert label.usage.ruleset == True
        assert label.usage.rule == True


class TestLabelGroup:
    """Test LabelGroup model and operations."""

    def test_create_label_group(self, pce):
        """Test creating a label group."""
        label_group = LabelGroup(
            key='env',
            name='LG-PreProd',
            labels=[
                {"href": "/orgs/1/labels/3"}
            ]
        )
        created = pce.label_groups.create(label_group)
        
        assert created.href is not None
        assert '/label_groups/' in created.href

    def test_get_label_groups(self, pce):
        """Test fetching label groups."""
        groups = pce.label_groups.get()
        assert len(groups) >= 1

    def test_label_group_with_sub_groups(self, label_groups):
        """Test LabelGroup with nested sub-groups."""
        # If test data has sub_groups
        for lg_json in label_groups:
            lg = LabelGroup.from_json(lg_json)
            assert lg.key is not None

    def test_label_group_json_encoding(self):
        """Test LabelGroup JSON encoding."""
        label_group = LabelGroup(
            key='env',
            name='LG-Test',
            labels=[
                {"href": "/orgs/1/labels/3"},
                {"href": "/orgs/1/labels/5"}
            ]
        )
        
        json_result = label_group.to_json()
        
        assert json_result['key'] == 'env'
        assert json_result['name'] == 'LG-Test'
        assert len(json_result['labels']) == 2


class TestLabelSet:
    """Test LabelSet functionality."""

    def test_label_set_creation(self):
        """Test creating a LabelSet."""
        from illumio.util import Reference
        
        label_set = LabelSet(labels=[
            Reference(href="/orgs/1/labels/1"),
            Reference(href="/orgs/1/labels/2"),
            Reference(href="/orgs/1/labels/3"),
            Reference(href="/orgs/1/labels/4")
        ])
        
        assert len(label_set.labels) == 4

    def test_label_set_equality(self):
        """Test LabelSet equality (ignores order)."""
        from illumio.util import Reference
        
        set1 = LabelSet(labels=[
            Reference(href="/orgs/1/labels/1"),
            Reference(href="/orgs/1/labels/2")
        ])
        
        set2 = LabelSet(labels=[
            Reference(href="/orgs/1/labels/2"),
            Reference(href="/orgs/1/labels/1")
        ])
        
        # Same labels, different order - should be equal
        assert set1 == set2

    def test_label_set_inequality(self):
        """Test LabelSet inequality."""
        from illumio.util import Reference
        
        set1 = LabelSet(labels=[
            Reference(href="/orgs/1/labels/1")
        ])
        
        set2 = LabelSet(labels=[
            Reference(href="/orgs/1/labels/2")
        ])
        
        assert set1 != set2

    def test_label_set_encoding_with_label_groups(self):
        """Test LabelSet encoding handles label groups."""
        from illumio.util import Reference
        
        label_set = LabelSet(labels=[
            Reference(href="/orgs/1/labels/1"),
            Reference(href="/orgs/1/sec_policy/draft/label_groups/uuid-123")
        ])
        
        encoded = label_set._encode()
        
        # Should have 'label' for regular labels and 'label_group' for groups
        assert len(encoded) == 2

    def test_label_set_from_json(self):
        """Test LabelSet decoding from JSON."""
        json_data = [
            {"label": {"href": "/orgs/1/labels/1"}},
            {"label": {"href": "/orgs/1/labels/2"}},
            {"label_group": {"href": "/orgs/1/sec_policy/draft/label_groups/uuid"}}
        ]
        
        label_set = LabelSet.from_json(json_data)
        
        assert len(label_set.labels) == 3


class TestLabelUsage:
    """Test LabelUsage model."""

    def test_label_usage_decoding(self):
        """Test LabelUsage from JSON."""
        usage_json = {
            "label_group": True,
            "ruleset": True,
            "rule": False,
            "static_policy_scopes": False,
            "containers_inherit_host_policy_scopes": False,
            "blocked_connection_reject_scope": False,
            "enforcement_boundary": True
        }
        
        usage = LabelUsage.from_json(usage_json)
        
        assert usage.label_group == True
        assert usage.ruleset == True
        assert usage.rule == False
        assert usage.enforcement_boundary == True
