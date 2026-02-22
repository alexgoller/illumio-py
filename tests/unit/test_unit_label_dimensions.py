# -*- coding: utf-8 -*-

"""Unit tests for LabelDimension API.

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

from illumio import (
    PolicyComputeEngine,
    LabelDimension,
    LabelDimensionDisplayInfo,
    LabelDimensionUsage,
)

MOCK_LABEL_DIMENSIONS = os.path.join(pytest.DATA_DIR, 'label_dimensions.json')


@pytest.fixture(scope='module')
def label_dimensions_data() -> List[dict]:
    with open(MOCK_LABEL_DIMENSIONS, 'r') as f:
        yield json.loads(f.read())


@pytest.fixture(autouse=True)
def dimensions_mock(pce_object_mock, label_dimensions_data):
    pce_object_mock.add_mock_objects(label_dimensions_data)


@pytest.fixture(autouse=True)
def mock_requests(requests_mock, get_callback, post_callback, put_callback, delete_callback):
    dimension_pattern = re.compile('/label_dimensions')
    
    requests_mock.register_uri('GET', dimension_pattern, json=get_callback)
    requests_mock.register_uri('POST', dimension_pattern, json=post_callback)
    requests_mock.register_uri('PUT', dimension_pattern, json=put_callback)
    requests_mock.register_uri('DELETE', dimension_pattern, json=delete_callback)


class TestLabelDimension:
    """Tests for LabelDimension class."""

    def test_from_json(self, label_dimensions_data):
        """Test creating LabelDimension from JSON."""
        role_dim = LabelDimension.from_json(label_dimensions_data[0])
        assert role_dim.key == 'role'
        assert role_dim.display_name == 'Role'
        assert role_dim.href == '/orgs/1/label_dimensions/6bd4bdbf-6fad-43a3-b75f-da3d385bcb62'

    def test_display_info(self, label_dimensions_data):
        """Test LabelDimensionDisplayInfo parsing."""
        role_dim = LabelDimension.from_json(label_dimensions_data[0])
        assert role_dim.display_info is not None
        assert role_dim.display_info.icon == 'role'
        assert role_dim.display_info.initial == 'R'
        assert role_dim.display_info.sort_ordinal == 1000000
        assert role_dim.display_info.background_color == '#ce93d8'
        assert role_dim.display_info.foreground_color == '#ffffff'
        assert role_dim.display_info.display_name_plural == 'Roles'

    def test_usage(self, label_dimensions_data):
        """Test LabelDimensionUsage parsing."""
        role_dim = LabelDimension.from_json(label_dimensions_data[0])
        assert role_dim.usage is not None
        assert role_dim.usage.labels is True
        assert role_dim.usage.label_groups is False

        app_dim = LabelDimension.from_json(label_dimensions_data[1])
        assert app_dim.usage.labels is True
        assert app_dim.usage.label_groups is True

    def test_caps(self, label_dimensions_data):
        """Test caps (capabilities) field."""
        role_dim = LabelDimension.from_json(label_dimensions_data[0])
        assert role_dim.caps == ['write']

        bu_dim = LabelDimension.from_json(label_dimensions_data[2])
        assert 'write' in bu_dim.caps
        assert 'delete' in bu_dim.caps

    def test_external_data(self, label_dimensions_data):
        """Test external_data_set and external_data_reference fields."""
        role_dim = LabelDimension.from_json(label_dimensions_data[0])
        assert role_dim.external_data_set == 'defaults.illumio.com'
        assert role_dim.external_data_reference == 'role'

        bu_dim = LabelDimension.from_json(label_dimensions_data[2])
        assert bu_dim.external_data_set == ''
        assert bu_dim.external_data_reference == ''

    def test_created_by_updated_by(self, label_dimensions_data):
        """Test created_by and updated_by references."""
        role_dim = LabelDimension.from_json(label_dimensions_data[0])
        assert role_dim.created_by is not None
        assert role_dim.created_by.href == '/users/0'
        assert role_dim.updated_by is not None
        assert role_dim.updated_by.href == '/users/1'

    def test_to_json(self):
        """Test LabelDimension serialization to JSON."""
        display_info = LabelDimensionDisplayInfo(
            icon='servers',
            initial='TD',
            background_color='#ff5722',
            foreground_color='#ffffff',
            display_name_plural='Test Dimensions'
        )
        dim = LabelDimension(
            key='test-dim',
            display_name='Test Dimension',
            display_info=display_info
        )
        json_data = dim.to_json()
        assert json_data['key'] == 'test-dim'
        assert json_data['display_name'] == 'Test Dimension'
        assert json_data['display_info']['icon'] == 'servers'
        assert json_data['display_info']['initial'] == 'TD'

    def test_custom_dimension(self, label_dimensions_data):
        """Test custom label dimension (Business Unit)."""
        bu_dim = LabelDimension.from_json(label_dimensions_data[2])
        assert bu_dim.key == 'bu'
        assert bu_dim.display_name == 'Business Unit'
        assert bu_dim.display_info.icon == 'group'
        assert bu_dim.display_info.initial == 'BU'
        # Custom dimensions should have delete capability
        assert 'delete' in bu_dim.caps


class TestLabelDimensionDisplayInfo:
    """Tests for LabelDimensionDisplayInfo class."""

    def test_from_json(self):
        """Test creating LabelDimensionDisplayInfo from JSON."""
        data = {
            'icon': 'role',
            'initial': 'R',
            'sort_ordinal': 1000000,
            'background_color': '#ce93d8',
            'foreground_color': '#ffffff',
            'display_name_plural': 'Roles'
        }
        display_info = LabelDimensionDisplayInfo.from_json(data)
        assert display_info.icon == 'role'
        assert display_info.initial == 'R'
        assert display_info.sort_ordinal == 1000000

    def test_to_json(self):
        """Test serialization to JSON."""
        display_info = LabelDimensionDisplayInfo(
            icon='app',
            initial='A',
            sort_ordinal=2000000,
            background_color='#42a5f5',
            foreground_color='#ffffff',
            display_name_plural='Applications'
        )
        json_data = display_info.to_json()
        assert json_data['icon'] == 'app'
        assert json_data['sort_ordinal'] == 2000000


class TestLabelDimensionUsage:
    """Tests for LabelDimensionUsage class."""

    def test_from_json(self):
        """Test creating LabelDimensionUsage from JSON."""
        data = {'labels': True, 'label_groups': False}
        usage = LabelDimensionUsage.from_json(data)
        assert usage.labels is True
        assert usage.label_groups is False

    def test_to_json(self):
        """Test serialization to JSON."""
        usage = LabelDimensionUsage(labels=True, label_groups=True)
        json_data = usage.to_json()
        assert json_data['labels'] is True
        assert json_data['label_groups'] is True


class TestLabelDimensionAPI:
    """Tests for LabelDimension PCE API integration."""

    def test_pce_api_registered(self, pce: PolicyComputeEngine):
        """Test that label_dimensions API is registered on PCE."""
        assert hasattr(pce, 'label_dimensions')

    def test_get_all(self, pce: PolicyComputeEngine):
        """Test getting all label dimensions."""
        dims = pce.label_dimensions.get()
        assert len(dims) == 3
        assert dims[0].key == 'role'
        assert dims[1].key == 'app'
        assert dims[2].key == 'bu'

    def test_get_by_params(self, pce: PolicyComputeEngine):
        """Test getting label dimensions with params."""
        dims = pce.label_dimensions.get(params={'key': 'role'})
        assert len(dims) == 1
        assert dims[0].key == 'role'
        assert dims[0].display_name == 'Role'

    def test_get_by_reference(self, pce: PolicyComputeEngine):
        """Test getting a specific label dimension by HREF."""
        dim = pce.label_dimensions.get_by_reference(
            '/orgs/1/label_dimensions/6bd4bdbf-6fad-43a3-b75f-da3d385bcb62'
        )
        assert dim.key == 'role'
        assert dim.display_name == 'Role'

    def test_create(self, pce: PolicyComputeEngine):
        """Test creating a label dimension."""
        display_info = LabelDimensionDisplayInfo(
            icon='group',
            initial='TD',
            background_color='#ff5722',
            foreground_color='#ffffff',
            display_name_plural='Test Dimensions'
        )
        dim = LabelDimension(
            key='test-dim',
            display_name='Test Dimension',
            display_info=display_info
        )
        created = pce.label_dimensions.create(dim)
        assert created.href is not None
        assert '/label_dimensions/' in created.href

    def test_update(self, pce: PolicyComputeEngine):
        """Test updating a label dimension."""
        href = '/orgs/1/label_dimensions/d99389c9-f501-4d0f-951c-1d546c140905'
        
        update_body = LabelDimension(display_name='BU Updated')
        pce.label_dimensions.update(href, update_body)
        
        updated = pce.label_dimensions.get_by_reference(href)
        assert updated.display_name == 'BU Updated'

    def test_delete(self, pce: PolicyComputeEngine):
        """Test deleting a label dimension."""
        href = '/orgs/1/label_dimensions/d99389c9-f501-4d0f-951c-1d546c140905'
        
        # Should not raise
        pce.label_dimensions.delete(href)
        
        # Verify deleted
        dims = pce.label_dimensions.get()
        assert all(d.href != href for d in dims)
