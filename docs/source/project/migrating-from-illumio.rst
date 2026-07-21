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

    pip uninstall illumio        # REQUIRED — see the warning below
    pip install illumio-py-open

.. code-block:: python

    from illumio import PolicyComputeEngine   # unchanged

.. warning::

    ``illumio-py-open`` installs the **same** ``illumio`` import package as the
    upstream ``illumio`` distribution. The two cannot be installed side by side:
    which files win is install-order dependent, and uninstalling one can remove
    or leave stale shared modules. **Uninstall the upstream** ``illumio``
    **distribution before installing** ``illumio-py-open``, and do not list both
    in the same requirements set.

Behavioral changes to be aware of
---------------------------------

Most of the fork is additive. The changes below are the ones that can affect
existing code.

Deny rules
~~~~~~~~~~

The deny-rule model was corrected to match the real PCE API (see
:ref:`Deny and override-deny rules <denyrules>`):

- There is a single :class:`DenyRule <illumio.rules.DenyRule>` object with an
  ``override`` flag (``override=True`` is an override-deny rule), managed through
  ``pce.deny_rules``. :class:`OverrideDenyRule <illumio.rules.OverrideDenyRule>`
  is now only a convenience builder (its ``build`` defaults ``override=True``);
  create it via ``pce.deny_rules.create(OverrideDenyRule.build(...), parent=ruleset)``.
  There is no ``pce.override_deny_rules`` collection — a rule set exposes a single
  ``deny_rules`` array holding both kinds, distinguished by ``override``.
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
