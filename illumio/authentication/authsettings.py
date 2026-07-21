# -*- coding: utf-8 -*-

"""This module provides classes related to authentication settings.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
from dataclasses import dataclass
from typing import List

from illumio.util import Reference, MutableObject, pce_api


@dataclass
@pce_api('authentication_settings', is_global=True)
class AuthenticationSettings(Reference):
    """Represents authentication settings in the PCE.

    Global singleton object. Supports GET and PUT only.
    """
    session_timeout_minutes: int = None
    mfa_config: dict = None


@dataclass
@pce_api('ldap_configs', endpoint='/authentication_settings/ldap_configs', is_global=True)
class LDAPConfig(MutableObject):
    """Represents an LDAP configuration in the PCE.

    Field names follow the current PCE API. The ``base_dn``, ``user_dn``,
    ``password``, ``request_timeout``, ``tls_enabled``, ``authentication_type``,
    and ``bind_type`` fields are retained as deprecated aliases for backwards
    compatibility; prefer ``user_base_distinguished_name``,
    ``bind_distinguished_name``, ``bind_password``, ``request_timeout_seconds``,
    ``insecure_disable_tls_certificate_verification``, and
    ``authentication_method``.

    Note that ``bind_password`` is write-only: the PCE accepts it on create and
    update but never returns it; ``is_bind_password_set`` indicates whether one
    is configured.
    """
    address: str = None
    port: int = None
    authentication_method: str = None
    bind_distinguished_name: str = None
    bind_password: str = None  # write-only; not returned on GET
    user_base_distinguished_name: str = None
    user_base_filter: str = None
    user_distinguished_name_pattern: str = None
    username_attribute: str = None
    full_name_attribute: str = None
    user_memberof_attribute: str = None
    request_timeout_seconds: int = None
    tls_ca_bundle: str = None
    insecure_disable_tls_certificate_verification: bool = None
    is_bind_password_set: bool = None
    pce_fqdn: str = None
    # deprecated aliases (pre-1.2.0 field names)
    base_dn: str = None
    user_dn: str = None
    password: str = None
    tls_enabled: bool = None
    request_timeout: int = None
    authentication_type: str = None
    bind_type: str = None


@dataclass
@pce_api('saml_configs', endpoint='/authentication_settings/saml_configs', is_global=True)
class SAMLConfig(MutableObject):
    """Represents a SAML configuration in the PCE.

    The ``issuer_url``, ``sso_url``, ``slo_url``, ``certificate``, and
    ``pce_fqdn`` fields are retained as deprecated aliases; prefer ``issuer``,
    ``idp_sso_target_url``, ``idp_slo_target_url``, ``idp_cert``, and
    ``cluster_fqdn``.
    """
    issuer: str = None
    idp_sso_target_url: str = None
    idp_slo_target_url: str = None
    idp_cert: str = None
    cluster_fqdn: str = None
    consumer_service_url: str = None
    consumer_logout_url: str = None
    name_identifier_format: str = None
    authn_context: str = None
    force_authn: bool = None
    sign_authn_request: bool = None
    pce_signing_cert: str = None
    pce_signing_cert_expires_at: str = None
    # deprecated aliases (pre-1.2.0 field names)
    issuer_url: str = None
    sso_url: str = None
    slo_url: str = None
    certificate: str = None
    pce_fqdn: str = None


@dataclass
@pce_api('password_policy', endpoint='/authentication_settings/password_policy', is_global=True)
class PasswordPolicy(MutableObject):
    """Represents the password policy settings in the PCE.

    ``require_type_count`` and ``min_characters_for_change_of_password`` are
    retained as deprecated aliases; prefer the ``require_type_*`` booleans and
    ``min_changed_characters``.
    """
    min_length: int = None
    expire_time_days: int = None
    history_count: int = None
    min_changed_characters: int = None
    min_characters_per_type: int = None
    require_type_lowercase: bool = None
    require_type_uppercase: bool = None
    require_type_number: bool = None
    require_type_symbol: bool = None
    session_timeout_minutes: int = None
    # deprecated aliases (pre-1.2.0 field names)
    require_type_count: int = None
    min_characters_for_change_of_password: int = None


__all__ = [
    'AuthenticationSettings',
    'LDAPConfig',
    'SAMLConfig',
    'PasswordPolicy',
]
