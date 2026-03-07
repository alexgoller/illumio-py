# -*- coding: utf-8 -*-

"""This module provides classes related to support bundle requests.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
from dataclasses import dataclass
from typing import List

from illumio.util import Reference, pce_api


@dataclass
@pce_api('support_bundle_requests')
class SupportBundleRequest(Reference):
    """Represents a support bundle request in the PCE."""
    status: str = None
    vens: List[Reference] = None
    requested_at: str = None
    requested_by: Reference = None
    result: dict = None
    created_at: str = None


__all__ = [
    'SupportBundleRequest',
]
