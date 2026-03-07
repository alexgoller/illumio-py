# -*- coding: utf-8 -*-

"""This module provides classes related to discovered virtual servers.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
from dataclasses import dataclass
from typing import List

from illumio.util import Reference, pce_api


@dataclass
@pce_api('discovered_virtual_servers')
class DiscoveredVirtualServer(Reference):
    """Represents a discovered virtual server in the PCE.

    These are read-only objects discovered by NENs.
    """
    name: str = None
    vip_address: str = None
    vip_port: int = None
    vip_proto: int = None
    network_enforcement_node: Reference = None
    created_at: str = None
    updated_at: str = None


__all__ = [
    'DiscoveredVirtualServer',
]
