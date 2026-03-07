# -*- coding: utf-8 -*-

"""This module provides classes related to network devices.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
from dataclasses import dataclass
from typing import List

from illumio.util import Reference, MutableObject, pce_api


@dataclass
@pce_api('network_devices')
class NetworkDevice(MutableObject):
    """Represents a network device (switch) in the PCE."""
    config: dict = None
    supported_endpoint_type: str = None
    network_enforcement_node: Reference = None
    status: str = None
    rules_href: str = None


@dataclass
@pce_api('network_endpoints')
class NetworkEndpoint(MutableObject):
    """Represents a network endpoint on a network device."""
    workload: Reference = None
    network_device: Reference = None
    endpoint_type: str = None
    port_id: str = None
    vlan_id: int = None


__all__ = [
    'NetworkDevice',
    'NetworkEndpoint',
]
