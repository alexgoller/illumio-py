.. _migrating:

Migrating from ``illumio``
==========================

``illumio-py-open`` is a community-maintained fork of
`illumio/illumio-py <https://github.com/illumio/illumio-py>`_, updated to track
current Illumio Core REST APIs. It is **not an official Illumio product and is
not endorsed by Illumio.**

Installation & imports
----------------------

The distribution name changes, but the **import name does not**. Existing code
keeps working unchanged:

.. code-block:: sh

    pip uninstall illumio        # the orphaned upstream distribution (optional)
    pip install illumio-py-open

.. code-block:: python

    from illumio import PolicyComputeEngine   # unchanged

Behavioral changes to be aware of
---------------------------------

Most of the fork is additive. The changes below are the ones that can affect
existing code.

Deny rules
~~~~~~~~~~

The deny-rule model was corrected to match the real PCE API (see
:ref:`Deny and override-deny rules <denyrules>`):

- There is a single :class:`DenyRule <illumio.rules.DenyRule>` object with an
  ``override`` flag (``override=True`` is an override-deny rule). Both
  :class:`DenyRule <illumio.rules.DenyRule>` and
  :class:`OverrideDenyRule <illumio.rules.OverrideDenyRule>` post to the same
  nested ``/deny_rules`` endpoint via ``parent=ruleset``.
- Removed fields that never existed in the API: ``DenyRule.priority``,
  ``OverrideDenyRule.overrides``, and the ``Rule.action`` / ``RuleAction``
  machinery.
- ``RuleSet.override_deny_rules`` was removed; a rule set exposes a single
  ``deny_rules`` array holding both ordinary and override-deny rules.

Settings & authentication field names
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The settings, authentication, and reporting models were reconciled with the
current API. New field names were added; the previous names are retained as
**deprecated aliases**, so existing code continues to work. Prefer the new
names — for example ``SAMLConfig.issuer`` over ``issuer_url``, and
``LDAPConfig.user_base_distinguished_name`` over ``base_dn``.

What stays the same
-------------------

- The ``PolicyComputeEngine`` client, the ``pce.<resource>`` CRUD interface, and
  the dataclass object model are unchanged.
- ``RuleAction`` remains importable from ``illumio.util`` (now unused internally).
