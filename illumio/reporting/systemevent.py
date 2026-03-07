# -*- coding: utf-8 -*-

"""This module provides classes related to system events.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
from dataclasses import dataclass
from typing import List

from illumio.util import Reference, pce_api


@dataclass
@pce_api('system_events', endpoint='/system_events', is_global=True)
class SystemEvent(Reference):
    """Represents a system event in the PCE.

    System events are global (not scoped to an org) and read-only.
    """
    event_type: str = None
    severity: str = None
    status: str = None
    timestamp: str = None
    pce_fqdn: str = None
    created_by: dict = None
    info: dict = None
    notifications: List[dict] = None


__all__ = [
    'SystemEvent',
]
