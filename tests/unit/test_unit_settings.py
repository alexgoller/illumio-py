import json
import re

import pytest

from illumio.settings import (
    OrgSettings,
    EventSettings,
    ReportSettings,
    SyslogDestination,
    TrafficCollectorSetting,
    TrustedProxyIPs,
    WorkloadSettings,
    OptionalFeature,
)


def test_syslog_destination_from_json():
    data = {
        "href": "/orgs/1/settings/syslog/destinations/1",
        "name": "Splunk",
        "type": "remote_syslog",
        "pce_scope": True,
        "remote_syslog": {
            "address": "splunk.example.com",
            "port": 514,
            "protocol": 6
        }
    }
    sd = SyslogDestination.from_json(data)
    assert sd.type == "remote_syslog"
    assert sd.pce_scope is True


def test_traffic_collector_setting_from_json():
    data = {
        "href": "/orgs/1/settings/traffic_collector/1",
        "transmission": "broadcast",
        "action": "drop"
    }
    tc = TrafficCollectorSetting.from_json(data)
    assert tc.transmission == "broadcast"


def test_workload_settings_from_json():
    data = {
        "href": "/orgs/1/settings/workloads",
        "workload_goodbye_timeout_seconds": 3600
    }
    ws = WorkloadSettings.from_json(data)
    assert ws.workload_goodbye_timeout_seconds == 3600


def test_optional_feature_from_json():
    data = {
        "href": "/orgs/1/optional_features/1",
        "name": "edge_enforcement",
        "enabled": True
    }
    of = OptionalFeature.from_json(data)
    assert of.name == "edge_enforcement"
    assert of.enabled is True
