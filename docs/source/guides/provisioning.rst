.. _guide-provisioning:

.. currentmodule:: illumio

Provisioning security policy
============================

Security Policy Operations
--------------------------

The PCE uses a draft/active policy model where changes must be provisioned
before they take effect. The **illumio** library provides several methods
to manage the security policy lifecycle, from reviewing pending changes to
provisioning or discarding them.

.. rubric:: Reviewing Pending Changes

Before provisioning, you can inspect what changes are queued:

.. code-block:: python

    >>> pending = pce.get_pending_policy_changes()

.. rubric:: Policy Check

Run a policy check to validate the current draft policy configuration:

.. code-block:: python

    >>> from illumio import PolicyCheck
    >>> result = pce.check_policy()

.. rubric:: Searching Rules

Search for rules matching specific criteria:

.. code-block:: python

    >>> rules = pce.search_rules({'key': 'value'})

.. rubric:: Impact Analysis

Before provisioning changes, analyze the impact they will have on your
environment:

.. code-block:: python

    >>> impact = pce.analyze_policy_impact(hrefs=[rule_set.href])

.. rubric:: Discarding Changes

If pending changes are no longer needed, discard them:

.. code-block:: python

    >>> pce.discard_pending_policy_changes()

.. rubric:: Bulk Deletion

Remove multiple policy objects in a single operation:

.. code-block:: python

    >>> pce.bulk_delete_policy_objects(hrefs=[ip_list.href, service.href])

.. note::
    Bulk deletion of policy objects will create pending changes that must be
    provisioned before the objects are removed from active policy.
