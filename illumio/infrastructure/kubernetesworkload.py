# -*- coding: utf-8 -*-

"""This module provides classes related to Kubernetes workloads.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
from dataclasses import dataclass
from typing import List

from illumio.util import Reference, pce_api


@dataclass
@pce_api('kubernetes_workloads')
class KubernetesWorkload(Reference):
    """Represents a Kubernetes workload in the PCE.

    Read-only objects representing containerized workloads.
    """
    name: str = None
    namespace: str = None
    kind: str = None
    container_cluster: Reference = None
    labels: List[Reference] = None
    created_at: str = None
    updated_at: str = None


__all__ = [
    'KubernetesWorkload',
]
