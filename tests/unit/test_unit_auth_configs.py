# -*- coding: utf-8 -*-

"""Unit tests for authentication config models (Tier-2 spec-conformance).

Field sets validated against the real Illumio schemas and, for SAML and the
password policy, against live PCE responses.

Copyright:
    © 2026 Illumio and contributors

License:
    Apache2, see LICENSE for more details.
"""
from illumio.authentication import LDAPConfig, SAMLConfig, PasswordPolicy


def _fields(cls):
    return {f.name for f in cls.__dataclass_fields__.values()}


class TestSAMLConfig:
    def test_real_schema_fields_present(self):
        for field in (
            'authn_context', 'cluster_fqdn', 'consumer_logout_url', 'consumer_service_url',
            'force_authn', 'idp_cert', 'idp_slo_target_url', 'idp_sso_target_url', 'issuer',
            'name_identifier_format', 'sign_authn_request', 'pce_signing_cert',
            'pce_signing_cert_expires_at',
        ):
            assert field in _fields(SAMLConfig), field

    def test_decode_live_shaped(self):
        cfg = SAMLConfig.from_json({
            'href': '/orgs/1/authentication_settings/saml_configs/1',
            'issuer': 'https://idp.example.com/metadata',
            'idp_sso_target_url': 'https://idp.example.com/sso',
            'idp_slo_target_url': 'https://idp.example.com/slo',
            'idp_cert': '-----BEGIN CERTIFICATE-----',
            'cluster_fqdn': 'pce.example.com',
            'force_authn': True,
            'sign_authn_request': False,
            'name_identifier_format': 'urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress',
            'created_at': '2026-01-01T00:00:00.000Z',
        })
        assert cfg.issuer == 'https://idp.example.com/metadata'
        assert cfg.idp_sso_target_url.endswith('/sso')
        assert cfg.force_authn is True
        assert cfg.sign_authn_request is False
        assert cfg.created_at.startswith('2026')  # from MutableObject


class TestPasswordPolicy:
    def test_real_schema_fields_present(self):
        for field in (
            'expire_time_days', 'min_changed_characters', 'min_characters_per_type',
            'require_type_lowercase', 'require_type_number', 'require_type_symbol',
            'require_type_uppercase',
        ):
            assert field in _fields(PasswordPolicy), field

    def test_decode_live_shaped(self):
        pp = PasswordPolicy.from_json({
            'href': '/orgs/1/authentication_settings/password_policy',
            'expire_time_days': 90,
            'history_count': 5,
            'min_length': 12,
            'min_changed_characters': 3,
            'min_characters_per_type': 1,
            'require_type_lowercase': True,
            'require_type_number': True,
            'require_type_symbol': False,
            'require_type_uppercase': True,
            'updated_at': '2026-01-01T00:00:00.000Z',
        })
        assert pp.expire_time_days == 90
        assert pp.require_type_lowercase is True
        assert pp.require_type_symbol is False
        assert pp.min_changed_characters == 3


class TestLDAPConfig:
    def test_real_schema_fields_present(self):
        for field in (
            'authentication_method', 'bind_distinguished_name', 'full_name_attribute',
            'insecure_disable_tls_certificate_verification', 'is_bind_password_set',
            'pce_fqdn', 'request_timeout_seconds', 'tls_ca_bundle',
            'user_base_distinguished_name', 'user_base_filter',
            'user_distinguished_name_pattern', 'user_memberof_attribute', 'username_attribute',
        ):
            assert field in _fields(LDAPConfig), field

    def test_decode_schema_shaped(self):
        cfg = LDAPConfig.from_json({
            'href': '/orgs/1/authentication_settings/ldap_configs/1',
            'name': 'corp-ldap',
            'authentication_method': 'simple',
            'bind_distinguished_name': 'cn=svc,dc=example,dc=com',
            'user_base_distinguished_name': 'ou=users,dc=example,dc=com',
            'username_attribute': 'uid',
            'request_timeout_seconds': 30,
            'is_bind_password_set': True,
            'insecure_disable_tls_certificate_verification': False,
        })
        assert cfg.bind_distinguished_name.startswith('cn=svc')
        assert cfg.username_attribute == 'uid'
        assert cfg.request_timeout_seconds == 30
        assert cfg.is_bind_password_set is True
