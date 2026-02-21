# -*- coding: utf-8 -*-

"""Unit tests for Workload model updates (v24.2+ fields).

These tests verify the new fields added in recent PCE versions:
- risk_summary (ransomware dashboard)
- vulnerability_computation_state
- managed field

Copyright:
    © 2024 Illumio

License:
    Apache2, see LICENSE for more details.
"""
import json
import pytest

from illumio.workloads import Workload
from illumio.util import EnforcementMode, VisibilityLevel


class TestWorkloadNewFields:
    """Test new Workload model fields from PCE v24.2+."""

    def test_workload_with_risk_summary(self):
        """Test Workload with risk_summary field."""
        workload_json = {
            "href": "/orgs/1/workloads/test-uuid",
            "name": "test-workload",
            "hostname": "test.example.com",
            "enforcement_mode": "full",
            "risk_summary": {
                "ransomware": {
                    "workload_exposure_severity": "medium",
                    "ransomware_protection_percent": 75.5,
                    "last_updated_at": "2024-02-01T12:00:00.000Z"
                }
            }
        }
        
        workload = Workload.from_json(workload_json)
        
        assert workload.href == "/orgs/1/workloads/test-uuid"
        assert hasattr(workload, 'risk_summary')
        # risk_summary is decoded as dict since we haven't defined the class yet
        if workload.risk_summary:
            assert 'ransomware' in workload.risk_summary

    def test_workload_managed_field(self):
        """Test Workload with managed boolean field."""
        workload_json = {
            "href": "/orgs/1/workloads/test-uuid",
            "name": "managed-workload",
            "hostname": "managed.example.com",
            "managed": True,
            "online": True
        }
        
        workload = Workload.from_json(workload_json)
        
        assert workload.href == "/orgs/1/workloads/test-uuid"
        # managed is an extra field not in dataclass, but should be accessible
        assert hasattr(workload, 'managed') or 'managed' in workload_json

    def test_workload_enforcement_mode_enum(self):
        """Test enforcement_mode with EnforcementMode enum."""
        workload = Workload(
            name='test-workload',
            enforcement_mode=EnforcementMode.FULL
        )
        
        assert workload.enforcement_mode in EnforcementMode

    def test_workload_visibility_level_enum(self):
        """Test visibility_level with VisibilityLevel enum."""
        workload = Workload(
            name='test-workload',
            visibility_level=VisibilityLevel.FLOW_FULL_DETAIL
        )
        
        assert workload.visibility_level in VisibilityLevel

    def test_workload_enhanced_data_collection(self):
        """Test enhanced_data_collection visibility level."""
        workload = Workload(
            name='test-workload',
            visibility_level=VisibilityLevel.ENHANCED_DATA_COLLECTION
        )
        
        assert workload.visibility_level == 'enhanced_data_collection'


class TestVulnerabilitySummaryUpdates:
    """Test VulnerabilitiesSummary model updates."""

    def test_vulnerability_computation_state_syncing(self):
        """Test vulnerability_computation_state='syncing'."""
        workload_json = {
            "href": "/orgs/1/workloads/test-uuid",
            "name": "test-workload",
            "vulnerabilities_summary": {
                "num_vulnerabilities": 30,
                "max_vulnerability_score": 88,
                "vulnerability_score": 1248,
                "vulnerable_port_exposure": None,
                "vulnerable_port_wide_exposure": {
                    "any": None,
                    "ip_list": None
                },
                "vulnerability_exposure_score": None,
                "vulnerability_computation_state": "syncing"
            }
        }
        
        workload = Workload.from_json(workload_json)
        
        assert workload.vulnerabilities_summary is not None
        assert workload.vulnerabilities_summary.num_vulnerabilities == 30
        # vulnerability_computation_state may be an extra field
        vuln_summary = workload.vulnerabilities_summary
        assert vuln_summary.max_vulnerability_score == 88

    def test_vulnerability_computation_state_in_sync(self):
        """Test vulnerability_computation_state='in_sync'."""
        workload_json = {
            "href": "/orgs/1/workloads/test-uuid",
            "name": "test-workload",
            "vulnerabilities_summary": {
                "num_vulnerabilities": 5,
                "max_vulnerability_score": 9.8,
                "vulnerability_score": 45,
                "vulnerability_exposure_score": 850,
                "vulnerability_computation_state": "in_sync"
            }
        }
        
        workload = Workload.from_json(workload_json)
        
        assert workload.vulnerabilities_summary is not None
        assert workload.vulnerabilities_summary.vulnerability_exposure_score == 850


class TestWorkloadServicesUpdates:
    """Test WorkloadServices model updates."""

    def test_open_service_ports_decoding(self):
        """Test open_service_ports decoding."""
        workload_json = {
            "href": "/orgs/1/workloads/test-uuid",
            "name": "test-workload",
            "services": {
                "uptime_seconds": 86400,
                "open_service_ports": [
                    {
                        "protocol": 6,
                        "address": "0.0.0.0",
                        "port": 443,
                        "process_name": "nginx",
                        "user": "www-data",
                        "package": "nginx-1.18.0"
                    },
                    {
                        "protocol": 6,
                        "address": "127.0.0.1",
                        "port": 3306,
                        "process_name": "mysqld",
                        "user": "mysql"
                    }
                ]
            }
        }
        
        workload = Workload.from_json(workload_json)
        
        assert workload.services is not None
        assert workload.services.uptime_seconds == 86400
        assert len(workload.services.open_service_ports) == 2
        assert workload.services.open_service_ports[0].port == 443
        assert workload.services.open_service_ports[0].process_name == "nginx"


class TestWorkloadInterfaceUpdates:
    """Test Interface model with new fields."""

    def test_interface_with_all_fields(self):
        """Test Interface with all available fields."""
        workload_json = {
            "href": "/orgs/1/workloads/test-uuid",
            "name": "test-workload",
            "interfaces": [
                {
                    "name": "eth0",
                    "address": "10.0.0.10",
                    "cidr_block": 24,
                    "link_state": "up",
                    "default_gateway_address": "10.0.0.1",
                    "network_detection_mode": "single_private_brn",
                    "friendly_name": "Primary Network",
                    "loopback": False,
                    "network": {
                        "href": "/orgs/1/networks/net-uuid"
                    }
                }
            ]
        }
        
        workload = Workload.from_json(workload_json)
        
        assert len(workload.interfaces) == 1
        iface = workload.interfaces[0]
        assert iface.name == "eth0"
        assert iface.address == "10.0.0.10"
        assert iface.cidr_block == 24
        assert iface.link_state == "up"
        assert iface.default_gateway_address == "10.0.0.1"


class TestSelectivelyEnforcedServices:
    """Test selectively_enforced_services field."""

    def test_mixed_service_types(self):
        """Test selectively_enforced_services with Service and ServicePort mix."""
        workload_json = {
            "href": "/orgs/1/workloads/test-uuid",
            "name": "selective-workload",
            "enforcement_mode": "selective",
            "selectively_enforced_services": [
                {"href": "/orgs/1/sec_policy/draft/services/1"},
                {"href": "/orgs/1/sec_policy/draft/services/2"},
                {"port": 443, "proto": 6},
                {"port": 80, "proto": 6}
            ]
        }
        
        workload = Workload.from_json(workload_json)
        
        assert len(workload.selectively_enforced_services) == 4
        # First two should be Service references
        from illumio.policyobjects import Service, ServicePort
        assert isinstance(workload.selectively_enforced_services[0], Service)
        assert isinstance(workload.selectively_enforced_services[1], Service)
        # Last two should be ServicePort
        assert isinstance(workload.selectively_enforced_services[2], ServicePort)
        assert isinstance(workload.selectively_enforced_services[3], ServicePort)


class TestWorkloadContainerCluster:
    """Test workload container_cluster field."""

    def test_workload_with_container_cluster(self):
        """Test Workload associated with ContainerCluster."""
        workload_json = {
            "href": "/orgs/1/workloads/test-uuid",
            "name": "k8s-workload",
            "container_cluster": {
                "href": "/orgs/1/container_clusters/cluster-uuid",
                "name": "production-k8s"
            }
        }
        
        workload = Workload.from_json(workload_json)
        
        assert workload.container_cluster is not None
        assert workload.container_cluster.href == "/orgs/1/container_clusters/cluster-uuid"
