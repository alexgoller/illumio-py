# -*- coding: utf-8 -*-

"""This module provides classes related to RBAC permissions.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
from dataclasses import dataclass
from typing import List

from illumio.util import Reference, MutableObject, pce_api


@dataclass
@pce_api('permissions')
class Permission(MutableObject):
    """Represents an RBAC permission in the PCE.

    Permissions define access control bindings between auth security principals,
    roles, and scopes.
    """
    role: Reference = None
    scope: List[Reference] = None
    auth_security_principal: Reference = None


__all__ = [
    'Permission',
]
