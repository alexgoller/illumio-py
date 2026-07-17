.. currentmodule:: illumio

Core client
===========


.. _pce:

PCE Interface
-------------

PolicyComputeEngine
###################

The ``PolicyComputeEngine`` object provides the core interface for interacting
with PCE API endpoints.

.. autoclass:: PolicyComputeEngine
    :inherited-members:

PCE Object API
##############

This internal class is used to represent API objects within the PCE, and provides
a common CRUD interface for them.

.. autoclass:: illumio.pce::PolicyComputeEngine._PCEObjectAPI
    :inherited-members:

.. _apiattributes:

PolicyComputeEngine API Attributes
##################################

The :class:`PolicyComputeEngine <PolicyComputeEngine>` class provides the following attributes:

|APIList|

Each represents a corresponding PCE API endpoint, implemented as a
:class:`_PCEObjectAPI <illumio.pce.PolicyComputeEngine._PCEObjectAPI>` instance.


.. _exceptions:

Exceptions
----------

The library uses two exception types to capture errors returned from the API or
encountered in other library functions.

.. autoexception:: IllumioException
.. autoexception:: IllumioApiException
.. autoexception:: IllumioIntegerValidationException
