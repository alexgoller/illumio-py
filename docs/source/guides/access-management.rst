.. _guide-access-management:

.. currentmodule:: illumio

Access management & API keys
============================

Access Management & Authentication
-----------------------------------

The PCE supports API key-based authentication for both user accounts and
service accounts. The **illumio** library provides methods for managing
these keys as well as verifying external authentication configurations.

.. rubric:: Service Account API Keys

Create and delete API keys for service accounts:

.. code-block:: python

    >>> key = pce.create_service_account_api_key(service_account.href)
    >>> pce.delete_service_account_api_key(
    ...     service_account.href, key_id='abc123'
    ... )

.. rubric:: User API Keys

Manage API keys for individual user accounts:

.. code-block:: python

    >>> keys = pce.get_user_api_keys(user_id=1)
    >>> new_key = pce.create_user_api_key(user_id=1)

.. rubric:: Organization API Keys

Retrieve all API keys across the organization:

.. code-block:: python

    >>> all_keys = pce.get_org_api_keys()

.. rubric:: LDAP Verification

Verify connectivity to an LDAP authentication server:

.. code-block:: python

    >>> pce.verify_ldap_connection(ldap_config.href)

.. note::
    API keys should be stored securely and rotated regularly. When a new
    key is created, the secret is only available in the creation response
    and cannot be retrieved again.
