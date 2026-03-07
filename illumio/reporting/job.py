# -*- coding: utf-8 -*-

"""This module provides classes related to async jobs.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
from dataclasses import dataclass

from illumio.util import Reference, pce_api


@dataclass
@pce_api('jobs')
class Job(Reference):
    """Represents an async job in the PCE.

    Jobs are read-only and track the status of async operations.
    """
    status: str = None
    job_type: str = None
    description: str = None
    result: dict = None
    requested_at: str = None
    terminated_at: str = None
    requested_by: Reference = None
    created_at: str = None


__all__ = [
    'Job',
]
