# -*- coding: utf-8 -*-

"""This module provides classes related to access restrictions.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
from dataclasses import dataclass
from typing import List

from illumio.util import Reference, MutableObject, pce_api


@dataclass
@pce_api('access_restrictions')
class AccessRestriction(MutableObject):
    """Represents an access restriction in the PCE.

    Access restrictions limit what IP ranges can access the PCE management API.
    """
    ips: List[str] = None
    type: str = None


__all__ = [
    'AccessRestriction',
]
