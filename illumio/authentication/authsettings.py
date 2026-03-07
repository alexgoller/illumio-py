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
    """Represents an LDAP configuration in the PCE."""
    address: str = None
    port: int = None
    base_dn: str = None
    user_dn: str = None
    password: str = None
    tls_enabled: bool = None
    request_timeout: int = None
    authentication_type: str = None
    bind_type: str = None


@dataclass
@pce_api('saml_configs', endpoint='/authentication_settings/saml_configs', is_global=True)
class SAMLConfig(Reference):
    """Represents a SAML configuration in the PCE."""
    issuer_url: str = None
    sso_url: str = None
    slo_url: str = None
    certificate: str = None
    pce_fqdn: str = None


@dataclass
@pce_api('password_policy', endpoint='/authentication_settings/password_policy', is_global=True)
class PasswordPolicy(Reference):
    """Represents the password policy settings in the PCE."""
    min_length: int = None
    require_type_count: int = None
    session_timeout_minutes: int = None
    history_count: int = None
    min_characters_for_change_of_password: int = None


__all__ = [
    'AuthenticationSettings',
    'LDAPConfig',
    'SAMLConfig',
    'PasswordPolicy',
]
