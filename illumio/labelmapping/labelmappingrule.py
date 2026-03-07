# -*- coding: utf-8 -*-

"""This module provides classes related to label mapping rules.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
from dataclasses import dataclass
from typing import List

from illumio.util import Reference, MutableObject, pce_api


@dataclass
@pce_api('label_mapping_rules')
class LabelMappingRule(MutableObject):
    """Represents a label mapping rule in the PCE.

    Label mapping rules automatically assign labels to workloads
    based on hostname patterns and other criteria.
    """
    enabled: bool = None
    match_criteria: List[dict] = None
    label_assignments: List[Reference] = None
    order: int = None


__all__ = [
    'LabelMappingRule',
]
