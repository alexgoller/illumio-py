# -*- coding: utf-8 -*-

"""This module provides classes related to organization settings.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
from dataclasses import dataclass
from typing import List

from illumio.util import Reference, MutableObject, pce_api


@dataclass
@pce_api('org_settings', endpoint='/settings')
class OrgSettings(Reference):
    """Represents organization-level settings in the PCE."""
    format: dict = None


@dataclass
@pce_api('event_settings', endpoint='/settings/events')
class EventSettings(Reference):
    """Represents event settings in the PCE."""
    syslog_enabled: bool = None
    retention_period_days: int = None


@dataclass
@pce_api('report_settings', endpoint='/settings/reports')
class ReportSettings(Reference):
    """Represents report settings in the PCE."""
    max_report_size: int = None


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
class TrafficCollectorSetting(MutableObject):
    """Represents a traffic collector setting in the PCE."""
    transmission: str = None
    action: str = None
    target: dict = None


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
