# -*- coding: utf-8 -*-

"""The illumio library provides a simple interface for interacting with PCE APIs.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
from .events import *
from .exceptions import *
from .secpolicy import *
from .util import *
from .accessmanagement import *
from .authentication import *
from .policyobjects import *
from .infrastructure import *
from .vulnerabilities import *
from .workloads import *
from .rules import *
from .explorer import *
from .reporting import *
from .settings import *
from .labelmapping import *
from .pce import *
from .appgroups import *

from types import ModuleType

# avoid name conflicts with package modules when using
# `from illumio import *` by excluding them here
__all__ = [
    export for export, o in globals().items()
        if not (export.startswith('_') or isinstance(o, ModuleType))
]
