# -*- coding: utf-8 -*-

"""This module provides classes related to organization settings.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
from dataclasses import dataclass
from typing import List

from illumio.util import Reference, IllumioObject, MutableObject, pce_api


@dataclass
@pce_api('org_settings', endpoint='/settings')
class OrgSettings(Reference):
    """Represents organization-level settings in the PCE."""
    num_assets_requiring_ransomware_protection: int = None
    automatic_label_application_on_ven_activation: bool = None
    rule_based_label_maker_schedule_enabled: bool = None
    rule_based_label_maker_schedule: dict = None
    max_explorer_query_timespan_days: int = None
    max_api_key_expiration_in_seconds: int = None
    expired_api_keys_retention_in_seconds: int = None
    advanced_ruleset_display: bool = None
    label_display: str = None
    ven_maintenance_token_required: bool = None
    clone_detection_enabled: bool = None
    automatic_clone_reactivation: str = None
    use_census_permissions: bool = None
    format: dict = None
    cloud_secure_tenant_id: str = None
    max_rule_search_provider_consumer_entities: int = None
    total_internet_address_space: int = None
    total_lateral_address_space: int = None


@dataclass
@pce_api('event_settings', endpoint='/settings/events')
class EventSettings(Reference):
    """Represents event settings in the PCE."""
    audit_event_retention_seconds: int = None
    audit_event_min_severity: str = None
    format: str = None


@dataclass
@pce_api('report_settings', endpoint='/settings/reports')
class ReportSettings(Reference):
    """Represents report settings in the PCE.

    ``max_report_size`` is retained as a deprecated field; the current API
    exposes ``max_queued_reports`` and ``report_retention_days``.
    """
    max_queued_reports: int = None
    report_retention_days: int = None
    max_report_size: int = None  # deprecated / not returned by current PCEs


@dataclass
@pce_api('syslog_destinations', endpoint='/settings/syslog/destinations')
class SyslogDestination(MutableObject):
    """Represents a syslog destination in the PCE."""
    type: str = None
    pce_scope: bool = None
    remote_syslog: dict = None
    audit_event_logger: dict = None
    traffic_event_logger: dict = None
    node_status_logger: dict = None


@dataclass
@pce_api('traffic_collector_settings', endpoint='/settings/traffic_collector')
class TrafficCollectorSetting(IllumioObject):
    """Represents a traffic collector setting in the PCE.

    Uses IllumioObject base instead of MutableObject because the PCE
    returns created_by/updated_by as integer IDs rather than Reference objects.
    """
    transmission: str = None
    action: str = None
    target: dict = None
    data_source: str = None
    network: str = None
    created_at: str = None
    updated_at: str = None
    created_by: int = None
    updated_by: int = None


@dataclass
@pce_api('trusted_proxy_ips', endpoint='/settings/trusted_proxy_ips')
class TrustedProxyIPs(Reference):
    """Represents trusted proxy IP settings in the PCE."""
    trusted_proxy_ips: List[str] = None


@dataclass
@pce_api('workload_settings', endpoint='/settings/workloads')
class WorkloadSettings(Reference):
    """Represents workload settings in the PCE."""
    workload_disconnected_timeout_seconds: List[dict] = None
    workload_goodbye_timeout_seconds: int = None


@dataclass
@pce_api('optional_features')
class OptionalFeature(Reference):
    """Represents optional feature flags in the PCE."""
    name: str = None
    enabled: bool = None


__all__ = [
    'OrgSettings',
    'EventSettings',
    'ReportSettings',
    'SyslogDestination',
    'TrafficCollectorSetting',
    'TrustedProxyIPs',
    'WorkloadSettings',
    'OptionalFeature',
]
