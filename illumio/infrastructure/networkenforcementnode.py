# -*- coding: utf-8 -*-

"""This module provides classes related to network enforcement nodes.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
from dataclasses import dataclass
from typing import List

from illumio.util import Reference, MutableObject, pce_api


@dataclass
@pce_api('network_enforcement_nodes')
class NetworkEnforcementNode(MutableObject):
    """Represents a network enforcement node (NEN) in the PCE.

    NENs manage enforcement on network switches.
    """
    status: str = None
    conditions: List[dict] = None
    software_version: str = None
    hostname: str = None
    network_devices_count: int = None


__all__ = [
    'NetworkEnforcementNode',
]
