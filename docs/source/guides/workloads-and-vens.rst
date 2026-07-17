.. _guide-workloads-vens:

.. currentmodule:: illumio

Workloads & VENs
================

VEN Lifecycle Management
------------------------

Virtual Enforcement Nodes (VENs) are the agents installed on workloads to
enforce security policy. The **illumio** library provides methods for
managing VEN lifecycle operations including unpairing, upgrading, and
monitoring.

.. rubric:: Unpairing VENs

Remove VENs from workloads. The ``firewall_restore`` parameter controls
what happens to the host firewall after unpairing:

.. code-block:: python

    >>> pce.unpair_vens(
    ...     ven_hrefs=[ven1.href, ven2.href],
    ...     firewall_restore='default'
    ... )

.. rubric:: Upgrading VENs

Upgrade VENs to a specific software release:

.. code-block:: python

    >>> pce.upgrade_vens(ven_hrefs=[ven1.href], release='22.5.0')

.. rubric:: VEN Statistics

Retrieve statistics for one or more VENs:

.. code-block:: python

    >>> stats = pce.get_ven_statistics(ven_hrefs=[ven.href])

.. rubric:: Software Releases

Query available VEN software releases and set the default:

.. code-block:: python

    >>> releases = pce.get_ven_software_releases()
    >>> pce.set_default_ven_release('22.5.0')

.. note::
    VEN upgrade operations are asynchronous. The PCE will schedule the
    upgrade and the VEN will apply it during its next heartbeat cycle.

Workload Operations
-------------------

In addition to the standard CRUD operations available through
``pce.workloads``, several sub-endpoints provide additional workload
management capabilities.

.. rubric:: Network Interfaces

Retrieve network interface details for a specific workload:

.. code-block:: python

    >>> interfaces = pce.get_workload_interfaces(workload.href)

.. rubric:: Bulk Import

Import a large number of workloads in a single operation:

.. code-block:: python

    >>> pce.bulk_import_workloads(data=[...])

.. rubric:: Unpairing Workloads

Unpair multiple workloads at once:

.. code-block:: python

    >>> pce.unpair_workloads(workload_hrefs=[w.href for w in workloads])

.. rubric:: Risk Details

Get vulnerability and risk information for a specific workload:

.. code-block:: python

    >>> risk = pce.get_workload_risk_details(workload.href)
