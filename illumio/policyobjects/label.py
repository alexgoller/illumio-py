# -*- coding: utf-8 -*-

"""This module provides classes related to labels and label groups.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
import json
from dataclasses import dataclass
from typing import List

from illumio.util import JsonObject, Reference, MutableObject, pce_api


@dataclass
class LabelUsage(JsonObject):
    """Represents how a label object is being used in the PCE."""
    label_group: bool = None
    ruleset: bool = None
    rule: bool = None
    static_policy_scopes: bool = None
    containers_inherit_host_policy_scopes: bool = None
    blocked_connection_reject_scope: bool = None
    enforcement_boundary: bool = None


@dataclass
class LabelDimensionUsage(JsonObject):
    """Represents usage information for a label dimension."""
    labels: bool = None
    label_groups: bool = None


@dataclass
class LabelDimensionDisplayInfo(JsonObject):
    """Display configuration for a label dimension in the UI.

    Args:
        icon (str, optional): Icon name (e.g., 'role', 'app', 'env', 'loc', 'group', 'servers').
        initial (str, optional): Short initial(s) displayed in labels (e.g., 'R', 'A', 'BU').
        sort_ordinal (int, optional): Sort order in UI (lower = higher priority).
        background_color (str, optional): Hex color for label background (e.g., '#ce93d8').
        foreground_color (str, optional): Hex color for label text (e.g., '#ffffff').
        display_name_plural (str, optional): Plural form of display name.
    """
    icon: str = None
    initial: str = None
    sort_ordinal: int = None
    background_color: str = None
    foreground_color: str = None
    display_name_plural: str = None


@dataclass
@pce_api('label_dimensions')
class LabelDimension(MutableObject):
    """Represents a label dimension (label type) in the PCE.

    Label dimensions define the types of labels available in the PCE.
    The default dimensions are Role, Application, Environment, and Location,
    but custom dimensions can be created (e.g., 'Business Unit', 'Tenant').

    Available since PCE v24.5.

    See https://docs.illumio.com/core/24.5/Content/Guides/security-policy/security-policy-objects/labels-and-label-groups.htm

    Usage:
        >>> import illumio
        >>> pce = illumio.PolicyComputeEngine('pce.company.com', port=443, org_id=1)
        >>> pce.set_credentials('api_key', 'api_secret')
        >>> # List all label dimensions
        >>> dimensions = pce.label_dimensions.get()
        >>> for dim in dimensions:
        ...     print(f"{dim.key}: {dim.display_name}")
        role: Role
        app: Application
        env: Environment
        loc: Location
        >>> # Create a custom label dimension
        >>> dimension = illumio.LabelDimension(
        ...     key='bu',
        ...     display_name='Business Unit',
        ...     display_info=illumio.LabelDimensionDisplayInfo(
        ...         icon='group',
        ...         initial='BU',
        ...         background_color='#ebbb0f',
        ...         foreground_color='#000000',
        ...         display_name_plural='Business Units'
        ...     )
        ... )
        >>> dimension = pce.label_dimensions.create(dimension)
        >>> dimension
        LabelDimension(
            href='/orgs/1/label_dimensions/...',
            key='bu',
            display_name='Business Unit',
            ...
        )
    """
    key: str = None
    display_name: str = None
    display_info: LabelDimensionDisplayInfo = None
    deleted: bool = None
    deleted_at: str = None
    usage: LabelDimensionUsage = None
    caps: List[str] = None
    external_data_set: str = None
    external_data_reference: str = None
    created_by: Reference = None
    updated_by: Reference = None
    deleted_by: Reference = None


@dataclass
@pce_api('labels')
class Label(MutableObject):
    """Represents a label in the PCE.

    Labels help to configure the reach of policy rules in a dynamic way,
    without relying on precise identifiers like IP addresses.

    When fetching Labels from the PCE, a breakdown of the labels' usage can be
    optionally included.

    See https://docs.illumio.com/core/21.5/Content/Guides/security-policy/security-policy-objects/labels-and-label-groups.htm

    Usage:
        >>> import illumio
        >>> pce = illumio.PolicyComputeEngine('pce.company.com', port=443, org_id=1)
        >>> pce.set_credentials('api_key', 'api_secret')
        >>> label = illumio.Label(key='role', value='R-DB')
        >>> label = pce.labels.create(label)
        >>> label
        Label(
            href='/orgs/1/labels/18',
            key='role',
            value='R-DB',
            ...
        )
    """
    key: str = None
    value: str = None
    deleted: bool = None
    usage: LabelUsage = None


@dataclass
@pce_api('label_groups', is_sec_policy=True)
class LabelGroup(Label):
    """Represents a label group in the PCE.

    Label groups can contain labels and other sub-groups to define broader
    categories that are often grouped when writing rules or otherwise
    referencing multiple labels.

    See https://docs.illumio.com/core/21.5/Content/Guides/security-policy/security-policy-objects/labels-and-label-groups.htm

    Usage:
        >>> import illumio
        >>> pce = illumio.PolicyComputeEngine('pce.company.com', port=443, org_id=1)
        >>> pce.set_credentials('api_key', 'api_secret')
        >>> dev_label = pce.labels.create({'key': 'env', 'value': 'E-Dev'})
        >>> stage_label = pce.labels.create({'key': 'env', 'value': 'E-Stage'})
        >>> label_group = illumio.LabelGroup(
        ...     key='role',
        ...     name='LG-E-PreProd',
        ...     labels=[dev_label, stage_label]
        ... )
        >>> label_group = pce.label_groups.create(label_group)
        >>> label_group
        LabelGroup(
            href='/orgs/1/sec_policy/draft/label_groups/5704a6f4-e051-4f88-9149-713ee22b5d41',
            key='role',
            value='R-DB',
            ...
        )
    """
    labels: List[Reference] = None
    sub_groups: List['LabelGroup'] = None


@dataclass
class LabelSet(JsonObject):
    """Represents a set of labels with distinct keys.

    Used to define rule set scopes.

    Args:
        labels (List[Reference], optional): list of label and label group
            references in the set.
    """
    labels: List[Reference] = None

    def __eq__(self, o) -> bool:
        """Compares LabelSet instances based on label HREFs, ignoring list order"""
        if not isinstance(o, LabelSet):
            return False
        return len(self.labels) == len(o.labels) and \
            set([label.href for label in self.labels]) == set([label.href for label in o.labels])

    def _encode(self):
        json_array = []
        for label in self.labels:
            key = 'label_group' if '/label_groups/' in label.href else 'label'
            json_array.append({key: Reference(href=label.href).to_json()})
        return json_array

    @classmethod
    def from_json(cls, data) -> 'LabelSet':
        data = json.loads(data) if type(data) is str else data
        labels = []
        for label_entry in data:
            key = 'label' if 'label' in label_entry else 'label_group'
            labels.append(Label.from_json(label_entry[key]))
        return LabelSet(labels=labels)


__all__ = [
    'LabelUsage',
    'Label',
    'LabelGroup',
    'LabelSet',
    'LabelDimensionUsage',
    'LabelDimensionDisplayInfo',
    'LabelDimension',
]
