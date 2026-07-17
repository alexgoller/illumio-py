.. illumio-py documentation master file, created by
   sphinx-quickstart on Fri Mar 11 17:22:37 2022.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

.. module:: illumio

Illumio Core Python API Client
==============================

.. image:: https://img.shields.io/github/v/release/alexgoller/illumio-py?label=Latest%20Release
   :target: https://github.com/alexgoller/illumio-py/releases/latest
   :alt: Latest Release Badge

.. image:: https://img.shields.io/pypi/v/illumio-py-open.svg
    :target: https://pypi.org/project/illumio-py-open/
    :alt: PyPI Version Badge

.. image:: https://img.shields.io/pypi/pyversions/illumio-py-open.svg
    :target: https://pypi.org/project/illumio-py-open/
    :alt: Python Version Support Badge

The **illumio** python library exposes Policy Compute Engine API endpoints
through an easy-to-use interface. It is a community-maintained fork of
`illumio/illumio-py <https://github.com/illumio/illumio-py>`_ (the import package
is still ``illumio``), compatible with Illumio Core PCE versions 21.2 and up.

Install it and take advantage of the PCE's APIs in just a few lines of code::

   $ python -m pip install illumio-py-open

.. code-block:: python

   >>> from illumio import PolicyComputeEngine
   >>> pce = PolicyComputeEngine('my.pce.com', port='443', org_id='1')
   >>> pce.set_credentials('api_key', 'api_secret')
   >>> workloads = pce.workloads.get(
   ...     params={'managed': True, 'enforcement_mode': 'visibility_only'}
   ... )

----------------------------------

How the docs are organized
--------------------------

The documentation is split by what you're trying to do:

- **Getting started** — install the client and follow a hands-on path from your
  first connection to your first policy. Start here if you're new.
- **Guides** — task-focused recipes for building segmentation policy, working
  with deny rules, provisioning, and more.
- **Concepts** — how the client is designed: the object model, the ``@pce_api``
  registry, policy versioning, and org scoping.
- **Reference** — the complete, generated API for every class and method.

.. toctree::
   :caption: Getting started
   :maxdepth: 2

   getting-started/install
   getting-started/quickstart

.. toctree::
   :caption: Guides
   :maxdepth: 1

   guides/security-policy
   guides/connecting
   guides/reading-collections
   guides/provisioning
   guides/workloads-and-vens
   guides/virtual-services
   guides/containers
   guides/traffic-analysis
   guides/access-management
   guides/monitoring-and-reporting

.. toctree::
   :caption: Concepts
   :maxdepth: 1

   concepts/architecture
   concepts/object-model
   concepts/policy-versioning
   concepts/org-scoping

.. toctree::
   :caption: Reference
   :maxdepth: 2

   reference/index

.. toctree::
   :caption: Project
   :maxdepth: 1

   project/changelog

* :ref:`genindex`
