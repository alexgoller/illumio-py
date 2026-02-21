# -*- coding: utf-8 -*-

"""Unit tests for VEN model updates.

Tests for VEN fields and operations added in recent PCE versions.

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

from illumio.workloads import VEN
from illumio.util import VENType

VENS = os.path.join(pytest.DATA_DIR, 'vens.json')


@pytest.fixture(scope='module')
def vens() -> List[dict]:
    with open(VENS, 'r') as f:
        yield json.loads(f.read())


@pytest.fixture(autouse=True)
def vens_mock(pce_object_mock, vens):
    pce_object_mock.add_mock_objects(vens)


@pytest.fixture(autouse=True)
def mock_requests(requests_mock, get_callback):
    pattern = re.compile('/vens')
    requests_mock.register_uri('GET', pattern, json=get_callback)


class TestVENModel:
    """Test VEN model fields."""

    def test_ven_type_server(self):
        """Test VEN with type='server'."""
        ven = VEN(
            hostname="server01.example.com",
            ven_type=VENType.SERVER
        )
        assert ven.ven_type in VENType

    def test_ven_type_endpoint(self):
        """Test VEN with type='endpoint'."""
        ven = VEN(
            hostname="laptop01.example.com",
            ven_type=VENType.ENDPOINT
        )
        assert ven.ven_type == 'endpoint'

    def test_ven_type_containerized(self):
        """Test VEN with type='containerized'."""
        ven = VEN(
            hostname="container01.example.com",
            ven_type=VENType.CONTAINERIZED
        )
        assert ven.ven_type == 'containerized'

    def test_ven_decoding_from_json(self, vens):
        """Test VEN decoding from JSON response."""
        ven_json = vens[0]
        ven = VEN.from_json(ven_json)
        
        assert ven.href == "/orgs/1/vens/ec38510d-e4fd-41a1-a6ba-8b0bb4ce9ae9"
        assert ven.hostname == "WIN-CK9JH7R07NB"
        assert ven.status == "active"
        assert ven.os_platform == "windows"

    def test_ven_with_conditions(self, vens):
        """Test VEN with conditions (warnings/errors)."""
        # Third VEN in test data has conditions
        ven_json = vens[2]
        ven = VEN.from_json(ven_json)
        
        assert ven.conditions is not None
        assert len(ven.conditions) >= 1
        
        # Check condition structure
        condition = ven.conditions[0]
        assert condition.first_reported_timestamp is not None
        assert condition.latest_event is not None

    def test_ven_interfaces(self, vens):
        """Test VEN interfaces decoding."""
        ven_json = vens[0]
        ven = VEN.from_json(ven_json)
        
        assert ven.interfaces is not None
        assert len(ven.interfaces) >= 1
        
        iface = ven.interfaces[0]
        assert iface.name is not None
        assert iface.address is not None

    def test_ven_labels(self, vens):
        """Test VEN labels decoding."""
        ven_json = vens[0]
        ven = VEN.from_json(ven_json)
        
        assert ven.labels is not None
        assert len(ven.labels) >= 1
        
        for label in ven.labels:
            assert label.href is not None
            assert '/labels/' in label.href

    def test_ven_workloads(self, vens):
        """Test VEN workloads reference."""
        ven_json = vens[0]
        ven = VEN.from_json(ven_json)
        
        assert ven.workloads is not None
        assert len(ven.workloads) >= 1
        assert '/workloads/' in ven.workloads[0].href

    def test_ven_caps(self, vens):
        """Test VEN capabilities."""
        ven_json = vens[0]
        ven = VEN.from_json(ven_json)
        
        assert ven.caps is not None
        assert 'write' in ven.caps


class TestVENOperations:
    """Test VEN read operations."""

    def test_get_vens(self, pce):
        """Test fetching VENs."""
        vens = pce.vens.get()
        assert len(vens) >= 1
        assert all(isinstance(v, VEN) for v in vens)

    def test_get_ven_by_reference(self, pce):
        """Test fetching VEN by href."""
        ven = pce.vens.get_by_reference("/orgs/1/vens/ec38510d-e4fd-41a1-a6ba-8b0bb4ce9ae9")
        assert ven.hostname == "WIN-CK9JH7R07NB"

    def test_filter_vens_by_hostname(self, pce):
        """Test filtering VENs by hostname."""
        vens = pce.vens.get(params={'hostname': 'WIN-CK9JH7R07NB'})
        assert len(vens) >= 1
        assert vens[0].hostname == "WIN-CK9JH7R07NB"

    def test_filter_vens_by_status(self, pce, vens):
        """Test filtering VENs by status."""
        active_vens = pce.vens.get(params={'status': 'active'})
        # All test VENs should be active
        assert all(v.status == 'active' for v in active_vens)


class TestVENValidation:
    """Test VEN validation."""

    def test_invalid_ven_type_raises(self):
        """Test that invalid ven_type raises exception."""
        from illumio.exceptions import IllumioException
        
        with pytest.raises(IllumioException):
            ven = VEN(
                hostname="test.example.com",
                ven_type="invalid_type"
            )
            ven._validate()


class TestVENNewFields:
    """Test new VEN fields from recent API versions."""

    def test_ven_with_activation_type(self, vens):
        """Test VEN activation_type field."""
        ven_json = vens[0]
        ven = VEN.from_json(ven_json)
        
        assert ven.activation_type == "pairing_key"

    def test_ven_unpair_allowed(self, vens):
        """Test VEN unpair_allowed field."""
        ven_json = vens[0]
        ven = VEN.from_json(ven_json)
        
        assert ven.unpair_allowed == True

    def test_ven_heartbeat_timestamps(self, vens):
        """Test VEN heartbeat timestamp fields."""
        ven_json = vens[0]
        ven = VEN.from_json(ven_json)
        
        assert ven.last_heartbeat_at is not None
        # last_goodbye_at can be None if VEN hasn't said goodbye

    def test_ven_version(self, vens):
        """Test VEN version field."""
        ven_json = vens[0]
        ven = VEN.from_json(ven_json)
        
        assert ven.version is not None
        assert '.' in ven.version  # Version should be like "21.5.30-8527"

    def test_ven_os_details(self, vens):
        """Test VEN OS detail fields."""
        ven_json = vens[0]
        ven = VEN.from_json(ven_json)
        
        assert ven.os_id is not None
        assert ven.os_detail is not None
        assert ven.os_platform in ['windows', 'linux']
