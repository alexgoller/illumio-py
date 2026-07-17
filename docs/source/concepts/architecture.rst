.. _concept-architecture:

Client architecture
===================

This page explains how the ``illumio`` client is put together, so the rest of
the library feels predictable rather than magical.

The registry: ``@pce_api``
--------------------------

Every PCE resource is a dataclass decorated with :func:`@pce_api <illumio.util.pce_api>`,
which registers it in a global ``PCE_APIS`` mapping:

.. code-block:: python

    @dataclass
    @pce_api('labels', endpoint='/labels')
    class Label(MutableObject):
        ...

The decorator records the API *name* (``labels``), its *endpoint*, and two
scoping flags — ``is_sec_policy`` and ``is_global`` (see
:ref:`concept-policy-versioning` and :ref:`concept-org-scoping`).

Dynamic dispatch: ``pce.<name>``
--------------------------------

:class:`PolicyComputeEngine <illumio.PolicyComputeEngine>` has no hand-written
``labels`` attribute. Instead, ``PolicyComputeEngine.__getattr__`` looks the name
up in ``PCE_APIS`` and returns a ``_PCEObjectAPI`` instance bound to that
resource:

.. code-block:: python

    pce.labels          # -> _PCEObjectAPI for the Label type
    pce.labels.get()    # GET  /orgs/{org_id}/labels
    pce.labels.create(Label(key='role', value='web'))

Because dispatch is data-driven, **adding a resource is just adding a decorated
dataclass** — no changes to ``PolicyComputeEngine`` are required.

Generic CRUD: ``_PCEObjectAPI``
-------------------------------

``_PCEObjectAPI`` provides the uniform CRUD surface every registered resource
shares: ``get``, ``get_by_reference``, ``get_by_name``, ``get_all``,
``get_async``, ``create``, ``update``, ``delete``, and the ``bulk_*`` variants.
It builds the request path from the resource's endpoint and scoping flags, then
encodes/decodes objects with the shared JSON machinery (see
:ref:`concept-object-model`).

Custom methods
--------------

Operations that go beyond CRUD — provisioning, VEN lifecycle actions, traffic
queries, sub-resources like workload interfaces — are plain methods on
:class:`PolicyComputeEngine <illumio.PolicyComputeEngine>`. Reach for a custom
method when a resource needs an action the generic CRUD interface doesn't model.

.. seealso::

   :ref:`concept-object-model` for the dataclass hierarchy, and
   :ref:`api` for the full reference.
