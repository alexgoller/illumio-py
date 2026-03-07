# -*- coding: utf-8 -*-

"""This module provides classes related to core services.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
from dataclasses import dataclass
from typing import List

from illumio.util import Reference, MutableObject, pce_api


@dataclass
@pce_api('core_service_types')
class CoreServiceType(MutableObject):
    """Represents a core service type in the PCE."""
    num_workloads: int = None
    port: int = None
    protocol: int = None


@dataclass
@pce_api('detected_core_services')
class DetectedCoreService(MutableObject):
    """Represents a detected core service in the PCE."""
    core_service_type: Reference = None
    workload: Reference = None
    ip_address: str = None
    port: int = None
    protocol: int = None
    detected_at: str = None


__all__ = [
    'CoreServiceType',
    'DetectedCoreService',
]
