import json
import os
import re
from typing import List

import pytest

from illumio.accessmanagement import (
    AccessRestriction,
    AuthSecurityPrincipal,
    Permission,
    Role,
    ServiceAccount,
)

SERVICE_ACCOUNTS = os.path.join(pytest.DATA_DIR, 'service_accounts.json')


@pytest.fixture(scope='module')
def service_accounts() -> List[dict]:
    with open(SERVICE_ACCOUNTS, 'r') as f:
        yield json.loads(f.read())


@pytest.fixture(autouse=True)
def service_accounts_mock(pce_object_mock, service_accounts):
    pce_object_mock.add_mock_objects(service_accounts)


@pytest.fixture(autouse=True)
def mock_requests(requests_mock, get_callback, post_callback, put_callback, delete_callback):
    pattern = re.compile('/service_accounts|/access_restrictions|/auth_security_principals|/permissions|/roles')
    requests_mock.register_uri('GET', pattern, json=get_callback)
    requests_mock.register_uri('POST', pattern, json=post_callback)
    requests_mock.register_uri('PUT', pattern, json=put_callback)
    requests_mock.register_uri('DELETE', pattern, json=delete_callback)


def test_get_service_account(pce):
    sa = pce.service_accounts.get_by_reference(
        "/orgs/1/service_accounts/a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    )
    assert sa.name == "SA-Terraform"


def test_create_service_account(pce):
    sa = ServiceAccount(name="SA-Test", description="Test SA")
    created = pce.service_accounts.create(sa)
    assert created.href


def test_access_restriction_from_json():
    data = {
        "href": "/orgs/1/access_restrictions/1",
        "name": "Office Only",
        "ips": ["10.0.0.0/8"],
        "type": "allow"
    }
    ar = AccessRestriction.from_json(data)
    assert ar.ips == ["10.0.0.0/8"]


def test_auth_security_principal_from_json():
    data = {
        "href": "/orgs/1/auth_security_principals/test-uuid",
        "display_name": "Engineering Group",
        "sid": "S-1-5-21-123456",
        "type": "group"
    }
    asp = AuthSecurityPrincipal.from_json(data)
    assert asp.display_name == "Engineering Group"


def test_permission_from_json():
    data = {
        "href": "/orgs/1/permissions/perm-uuid",
        "role": {"href": "/orgs/1/roles/owner"},
        "scope": [{"href": "/orgs/1/labels/1"}],
        "auth_security_principal": {"href": "/orgs/1/auth_security_principals/test"}
    }
    perm = Permission.from_json(data)
    assert perm.role.href == "/orgs/1/roles/owner"


def test_role_from_json():
    data = {
        "href": "/orgs/1/roles/owner",
        "display_name": "Organization Owner",
        "access_level": "owner"
    }
    role = Role.from_json(data)
    assert role.display_name == "Organization Owner"
