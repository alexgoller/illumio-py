# -*- coding: utf-8 -*-

"""This module provides classes related to auth security principals.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
from dataclasses import dataclass
from typing import List

from illumio.util import Reference, MutableObject, pce_api


@dataclass
@pce_api('auth_security_principals')
class AuthSecurityPrincipal(MutableObject):
    """Represents an auth security principal in the PCE.

    Auth security principals map external identity provider groups
    to PCE permissions.
    """
    display_name: str = None
    sid: str = None
    type: str = None


__all__ = [
    'AuthSecurityPrincipal',
]
