# -*- coding: utf-8 -*-

"""This module provides classes related to server load balancers.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
from dataclasses import dataclass
from typing import List

from illumio.util import Reference, MutableObject, pce_api


@dataclass
@pce_api('slbs')
class SLB(MutableObject):
    """Represents a server load balancer in the PCE."""
    dvs: Reference = None
    nfc: Reference = None
    devices: List[Reference] = None


__all__ = [
    'SLB',
]
