import json
import re

import pytest

from illumio.reporting import (
    Job,
    Report,
    ReportSchedule,
    ReportTemplate,
    CoreServiceType,
    DetectedCoreService,
    SupportBundleRequest,
    SystemEvent,
)


@pytest.fixture(autouse=True)
def mock_requests(requests_mock, get_callback, post_callback, put_callback, delete_callback):
    pattern = re.compile('/jobs|/reports|/report_schedules|/report_templates|/core_service|/detected_core|/support_bundle|/system_events')
    requests_mock.register_uri('GET', pattern, json=get_callback)
    requests_mock.register_uri('POST', pattern, json=post_callback)
    requests_mock.register_uri('PUT', pattern, json=put_callback)
    requests_mock.register_uri('DELETE', pattern, json=delete_callback)


def test_job_from_json():
    data = {
        "href": "/orgs/1/jobs/uuid-1",
        "status": "completed",
        "job_type": "collection",
        "result": {"href": "/orgs/1/datafiles/uuid-2"}
    }
    job = Job.from_json(data)
    assert job.status == "completed"


def test_report_from_json():
    data = {
        "href": "/orgs/1/reports/uuid-1",
        "name": "Monthly Report",
        "report_type": "traffic_summary",
        "status": "completed"
    }
    report = Report.from_json(data)
    assert report.report_type == "traffic_summary"


def test_create_report(pce):
    report = Report(name="Test Report", report_type="traffic_summary")
    created = pce.reports.create(report)
    assert created.href


def test_system_event_from_json():
    data = {
        "href": "/system_events/uuid-1",
        "event_type": "system.startup",
        "severity": "info",
        "status": "success",
        "timestamp": "2023-01-01T00:00:00Z"
    }
    event = SystemEvent.from_json(data)
    assert event.event_type == "system.startup"


def test_download_report(pce, requests_mock):
    requests_mock.register_uri('GET', re.compile('/download'), content=b'csv,data')
    result = pce.download_report("/orgs/1/reports/uuid-1")
    assert result == b'csv,data'


def test_risk_summary(pce, requests_mock):
    requests_mock.register_uri('GET', re.compile('/risk_summary'), json={"total_risk": 42})
    result = pce.get_risk_summary()
    assert result["total_risk"] == 42
