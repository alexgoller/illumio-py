# -*- coding: utf-8 -*-

"""Unit tests for settings & reporting model fields (Tier-2 spec-conformance).

Field sets validated against the Illumio schemas and, where data exists, against
live PCE responses (org settings, report settings, report templates).

Copyright:
    © 2026 Illumio and contributors

License:
    Apache2, see LICENSE for more details.
"""
from illumio.settings import OrgSettings, ReportSettings
from illumio.reporting import Report, ReportSchedule, ReportTemplate


def _fields(cls):
    return {f.name for f in cls.__dataclass_fields__.values()}


class TestOrgSettings:
    def test_missing_fields_added(self):
        for field in ('cloud_secure_tenant_id', 'max_rule_search_provider_consumer_entities',
                      'total_internet_address_space', 'total_lateral_address_space'):
            assert field in _fields(OrgSettings), field

    def test_decode_live_shaped(self):
        s = OrgSettings.from_json({
            'href': '/orgs/1/settings',
            'cloud_secure_tenant_id': 'tenant-abc',
            'max_rule_search_provider_consumer_entities': 500,
            'total_internet_address_space': 42,
            'total_lateral_address_space': 7,
            'clone_detection_enabled': True,
        })
        assert s.cloud_secure_tenant_id == 'tenant-abc'
        assert s.max_rule_search_provider_consumer_entities == 500
        assert s.clone_detection_enabled is True


class TestReportSettings:
    def test_missing_fields_added(self):
        for field in ('max_queued_reports', 'report_retention_days'):
            assert field in _fields(ReportSettings), field

    def test_decode_live_shaped(self):
        s = ReportSettings.from_json({
            'href': '/orgs/1/settings/reports',
            'max_queued_reports': 10,
            'report_retention_days': 30,
        })
        assert s.max_queued_reports == 10
        assert s.report_retention_days == 30


class TestReport:
    def test_missing_fields_added(self):
        for field in ('generated_at', 'progress_percentage', 'send_by_email'):
            assert field in _fields(Report), field

    def test_decode(self):
        r = Report.from_json({
            'href': '/orgs/1/reports/1',
            'generated_at': '2026-01-01T00:00:00.000Z',
            'progress_percentage': 100,
            'send_by_email': True,
        })
        assert r.progress_percentage == 100
        assert r.send_by_email is True
        assert r.generated_at.startswith('2026')


class TestReportSchedule:
    def test_missing_fields_added(self):
        for field in ('report_generation_frequency', 'scheduled_at', 'send_by_email'):
            assert field in _fields(ReportSchedule), field


class TestReportTemplate:
    def test_missing_fields_added(self):
        for field in ('enabled', 'report_parameters', 'show_in_ui'):
            assert field in _fields(ReportTemplate), field

    def test_decode_live_shaped(self):
        t = ReportTemplate.from_json({
            'href': '/orgs/1/report_templates/1',
            'name': 'Executive Summary',
            'enabled': True,
            'show_in_ui': True,
            'report_parameters': {'time_range': 'last_30_days'},
        })
        assert t.enabled is True
        assert t.show_in_ui is True
        assert t.report_parameters['time_range'] == 'last_30_days'
