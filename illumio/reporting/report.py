# -*- coding: utf-8 -*-

"""This module provides classes related to reports and report schedules.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
from dataclasses import dataclass
from typing import List

from illumio.util import Reference, MutableObject, pce_api


@dataclass
@pce_api('reports')
class Report(MutableObject):
    """Represents a report in the PCE."""
    report_type: str = None
    status: str = None
    report_template: Reference = None
    report_parameters: dict = None
    send_to: List[str] = None
    send_by_email: bool = None
    generated_at: str = None
    progress_percentage: int = None


@dataclass
@pce_api('report_schedules')
class ReportSchedule(MutableObject):
    """Represents a report schedule in the PCE."""
    report_type: str = None
    schedule: dict = None
    report_parameters: dict = None
    report_template: Reference = None
    send_to: List[str] = None
    enabled: bool = None
    report_generation_frequency: str = None
    scheduled_at: str = None
    send_by_email: bool = None


@dataclass
@pce_api('report_templates')
class ReportTemplate(Reference):
    """Represents a report template in the PCE.

    Read-only. Templates define the structure and parameters for reports.
    """
    name: str = None
    description: str = None
    enabled: bool = None
    report_parameters: dict = None
    show_in_ui: bool = None
    template_type: str = None
    format: str = None
    created_at: str = None
    updated_at: str = None


__all__ = [
    'Report',
    'ReportSchedule',
    'ReportTemplate',
]
