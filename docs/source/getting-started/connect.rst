.. _pceconnect:

.. currentmodule:: illumio

Connecting to the PCE
=====================

The first step for any application is connecting to the Policy Compute Engine.
Make sure you have the library :ref:`installed <install>`, then read on.

Create a client
---------------

The :class:`PolicyComputeEngine <PolicyComputeEngine>` class is the entry point
for everything:

.. code-block:: python

    >>> from illumio import PolicyComputeEngine
    >>> pce = PolicyComputeEngine('my.pce.com', port=443, org_id=1)

.. note::
    The first parameter can be a full URL — useful if your PCE does not have TLS
    certificates configured — or an FQDN as shown above. When you pass just the
    domain name, the scheme defaults to ``https://``.

Authenticate
------------

Provide credentials to authorize the client. Both an API key/secret pair and a
username/password can be passed to
:meth:`set_credentials <PolicyComputeEngine.set_credentials>`:

.. code-block:: python

    >>> pce.set_credentials('api_key', 'api_secret')

Confirm the connection
----------------------

.. code-block:: python

    >>> pce.check_connection()
    True

With a few lines of code you now have a working, persistent connection to the
PCE. If your PCE uses self-signed or internal certificates, see
:ref:`Connecting to the PCE <guide-connecting>` for TLS and proxy options.

Next, build your first policy in :ref:`Your first policy <apiendpoints>`.

.. note::

    This guide assumes some familiarity with the PCE APIs. See the
    `Illumio PCE REST API Developer Guide <https://docs.illumio.com/core/21.5/Content/LandingPages/Guides/rest-api.htm>`_
    for a fuller introduction to API usage and schema.
