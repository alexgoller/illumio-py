# -*- coding: utf-8 -*-

"""This module provides classes related to virtual servers.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
from dataclasses import dataclass
from typing import List

from illumio.util import JsonObject, Reference, MutableObject, pce_api

from .service import ServicePort


@dataclass
class DVSVirtualServer(JsonObject):
    """Represents a discovered virtual server entry within a VirtualServer."""
    href: str = None
    name: str = None
    vip_port: int = None
    vip_proto: int = None


@dataclass
@pce_api('virtual_servers', is_sec_policy=True)
class VirtualServer(MutableObject):
    """Represents a virtual server object in the PCE.

    Virtual servers are used to model load-balanced services.
    They exist under the security policy and require provisioning.
    """
    discovered_virtual_server: Reference = None
    dvs_name: str = None
    dvs_identifier: str = None
    labels: List[Reference] = None
    service: Reference = None
    providers: List[Reference] = None
    mode: str = None


__all__ = [
    'DVSVirtualServer',
    'VirtualServer',
]
