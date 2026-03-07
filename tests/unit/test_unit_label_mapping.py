import json
import os
import re
from typing import List

import pytest

from illumio.labelmapping import LabelMappingRule

LABEL_MAPPING_RULES = os.path.join(pytest.DATA_DIR, 'label_mapping_rules.json')


@pytest.fixture(scope='module')
def label_mapping_rules() -> List[dict]:
    with open(LABEL_MAPPING_RULES, 'r') as f:
        yield json.loads(f.read())


@pytest.fixture(autouse=True)
def label_mapping_rules_mock(pce_object_mock, label_mapping_rules):
    pce_object_mock.add_mock_objects(label_mapping_rules)


@pytest.fixture(autouse=True)
def mock_requests(requests_mock, get_callback, post_callback, put_callback, delete_callback):
    pattern = re.compile('/label_mapping_rules')
    requests_mock.register_uri('GET', pattern, json=get_callback)
    requests_mock.register_uri('POST', pattern, json=post_callback)
    requests_mock.register_uri('PUT', pattern, json=put_callback)
    requests_mock.register_uri('DELETE', pattern, json=delete_callback)


def test_get_label_mapping_rule(pce):
    rule = pce.label_mapping_rules.get_by_reference("/orgs/1/label_mapping_rules/1")
    assert rule.name == "Map production servers"
    assert rule.enabled is True
    assert rule.order == 1


def test_create_label_mapping_rule(pce):
    rule = LabelMappingRule(
        name="Test Rule",
        enabled=True,
        match_criteria=[{"property": "hostname", "operator": "contains", "value": "test"}]
    )
    created = pce.label_mapping_rules.create(rule)
    assert created.href


def test_label_mapping_rule_from_json():
    data = {
        "href": "/orgs/1/label_mapping_rules/2",
        "name": "Dev Rule",
        "enabled": False,
        "order": 2,
        "match_criteria": [
            {"property": "hostname", "operator": "starts_with", "value": "dev-"}
        ],
        "label_assignments": [{"href": "/orgs/1/labels/5"}]
    }
    rule = LabelMappingRule.from_json(data)
    assert rule.name == "Dev Rule"
    assert rule.enabled is False


def test_run_label_mapping_rules(pce, requests_mock):
    requests_mock.register_uri('POST', re.compile('/label_mapping_rules/run'), json={"job_uuid": "test-uuid"})
    result = pce.run_label_mapping_rules({"workload_hrefs": ["/orgs/1/workloads/uuid-1"]})
    assert result["job_uuid"] == "test-uuid"


def test_reorder_label_mapping_rule(pce, requests_mock):
    requests_mock.register_uri('PUT', re.compile('/reorder'), status_code=204)
    pce.reorder_label_mapping_rule("/orgs/1/label_mapping_rules/1", 3)
