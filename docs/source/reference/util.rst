.. currentmodule:: illumio

Utilities
=========


.. _util:

Utilities
---------

Contains global constants, helper functions, and internal structures.

Constants
#########

.. autodata:: illumio.util.constants.ACTIVE
.. autodata:: illumio.util.constants.DRAFT
.. autodata:: illumio.util.constants.AMS
.. autodata:: illumio.util.constants.RESOLVE_AS_WORKLOADS
.. autodata:: illumio.util.constants.RESOLVE_AS_VIRTUAL_SERVICES
.. autodata:: illumio.util.constants.ANY_IP_LIST_NAME
.. autodata:: illumio.util.constants.ALL_SERVICES_NAME
.. autodata:: illumio.util.constants.PORT_MAX
.. autodata:: illumio.util.constants.ICMP_CODE_MAX
.. autodata:: illumio.util.constants.ICMP_TYPE_MAX
.. autodata:: illumio.util.constants.BULK_CHANGE_LIMIT

.. autoenum:: illumio.util.constants.EnforcementMode
    :members:

.. autoenum:: illumio.util.constants.LinkState
    :members:

.. autoenum:: illumio.util.constants.VisibilityLevel
    :members:

.. autoenum:: illumio.util.constants.Transmission
    :members:

.. autoenum:: illumio.util.constants.FlowDirection
    :members:

.. autoenum:: illumio.util.constants.TrafficState
    :members:

.. autoenum:: illumio.util.constants.ApplyTo
    :members:

.. autoenum:: illumio.util.constants.VENType
    :members:

.. autoenum:: illumio.util.constants.ChangeType
    :members:

.. autoenum:: illumio.util.constants.EventSeverity
    :members:

.. autoenum:: illumio.util.constants.EventStatus
    :members:

Helper Functions
################

.. autofunction:: illumio.util.functions.convert_active_href_to_draft
.. autofunction:: illumio.util.functions.convert_draft_href_to_active
.. autofunction:: illumio.util.functions.convert_protocol
.. autofunction:: illumio.util.functions.deprecated
.. autofunction:: illumio.util.functions.ignore_empty_keys
.. autofunction:: illumio.util.functions.parse_url
.. autofunction:: illumio.util.functions.pce_api

.. autofunction:: illumio.util.jsonutils.href_from

Base Classes
############

.. autoclass:: illumio.util.jsonutils.JsonObject
.. autoclass:: illumio.util.jsonutils.IllumioObject
.. autoclass:: illumio.util.jsonutils.Reference
