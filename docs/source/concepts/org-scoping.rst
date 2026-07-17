.. _concept-org-scoping:

Org scoping & global endpoints
==============================

Most PCE resources belong to an **organization**, so their paths are prefixed
with ``/orgs/{org_id}/``. You set the org when constructing the client:

.. code-block:: python

    pce = PolicyComputeEngine('my.pce.com', port='443', org_id='1')
    pce.labels.get()   # GET /orgs/1/labels

A few resources are **global** — they belong to the PCE cluster rather than a
single org (users, authentication settings, LDAP/SAML configs, system events).
These are registered with ``is_global=True`` and are *not* org-prefixed:

.. code-block:: python

    pce.users.get()             # GET /users
    pce.ldap_configs.get()      # GET /authentication_settings/ldap_configs

When making a raw request, the ``include_org`` flag controls the prefix:

.. code-block:: python

    pce.get('/settings', include_org=True)                       # /orgs/{org}/settings
    pce.get('/authentication_settings/password_policy',
            include_org=False)                                   # global

Combined with the security-policy prefix (see
:ref:`concept-policy-versioning`), a request path is built from three parts:
the optional ``/orgs/{org_id}``, the optional ``/sec_policy/{version}``, and the
resource endpoint.
