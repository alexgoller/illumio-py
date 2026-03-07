# -*- coding: utf-8 -*-

"""This module provides classes related to RBAC roles.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
from dataclasses import dataclass
from typing import List

from illumio.util import Reference, JsonObject, pce_api


@dataclass
@pce_api('roles')
class Role(Reference):
    """Represents a role in the PCE.

    Roles are read-only and define sets of capabilities.
    """
    display_name: str = None
    access_level: str = None


__all__ = [
    'Role',
]
