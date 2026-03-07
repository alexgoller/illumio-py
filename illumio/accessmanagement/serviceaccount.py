# -*- coding: utf-8 -*-

"""This module provides classes related to service accounts.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
from dataclasses import dataclass
from typing import List

from illumio.util import Reference, MutableObject, pce_api


@dataclass
@pce_api('service_accounts')
class ServiceAccount(MutableObject):
    """Represents a service account in the PCE.

    Service accounts provide API access credentials for automated systems.
    """
    permissions: List[Reference] = None
    api_key_id: str = None
    api_key_secret: str = None
    last_login: str = None


__all__ = [
    'ServiceAccount',
]
