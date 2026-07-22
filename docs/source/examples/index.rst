.. _examples:

.. currentmodule:: illumio

Examples
========

Runnable example scripts live in the
`examples/ <https://github.com/alexgoller/illumio-py/tree/main/examples>`_
directory of the repository (and ship in the source distribution). Each is a
small, standalone program you can read top-to-bottom and run against a PCE.

Running an example
------------------

Install the client, then provide connection details via environment variables or
a ``.env`` file (copy ``examples/.env.example``):

.. code-block:: sh

    pip install illumio-py-open

.. code-block:: ini

    PCE_HOST=my.pce.com
    PCE_PORT=443
    PCE_ORG_ID=1
    API_KEY=api_xxxxxxxx
    API_SECRET=xxxxxxxx

Run an example from inside the ``examples/`` directory (they share
``_common.py`` for the connection):

.. code-block:: sh

    cd examples
    python 01_connect.py

.. note::

    Write examples create clearly-named ``Example*`` objects and clean up after
    themselves. Security-policy objects are created in *draft* and are not
    enforced until provisioned. In Illumio rules, *consumers* are the sources
    that initiate connections to *providers* (the destinations).

The scripts
-----------

.. list-table::
   :header-rows: 1
   :widths: 30 55 15

   * - Script
     - What it shows
     - Writes?
   * - `01_connect.py <https://github.com/alexgoller/illumio-py/blob/main/examples/01_connect.py>`_
     - Connect and read basic facts
     - read-only
   * - `02_labels.py <https://github.com/alexgoller/illumio-py/blob/main/examples/02_labels.py>`_
     - Labels CRUD + label groups
     - creates/deletes
   * - `03_ip_lists_and_services.py <https://github.com/alexgoller/illumio-py/blob/main/examples/03_ip_lists_and_services.py>`_
     - IP lists and services
     - creates/deletes
   * - `04_workloads.py <https://github.com/alexgoller/illumio-py/blob/main/examples/04_workloads.py>`_
     - Query workloads; create one; enforcement mode
     - creates/deletes
   * - `05_allow_rules.py <https://github.com/alexgoller/illumio-py/blob/main/examples/05_allow_rules.py>`_
     - Build an allow policy: labels → ruleset → rule
     - creates/deletes
   * - `06_deny_rules.py <https://github.com/alexgoller/illumio-py/blob/main/examples/06_deny_rules.py>`_
     - Deny and override-deny rules
     - creates/deletes
   * - `07_traffic_analysis.py <https://github.com/alexgoller/illumio-py/blob/main/examples/07_traffic_analysis.py>`_
     - Explorer async traffic query
     - read-only
   * - `08_provisioning.py <https://github.com/alexgoller/illumio-py/blob/main/examples/08_provisioning.py>`_
     - draft → active provisioning workflow
     - creates + provisions
   * - `09_vens.py <https://github.com/alexgoller/illumio-py/blob/main/examples/09_vens.py>`_
     - Inspect VENs, statistics, software releases
     - read-only
   * - `10_bulk_operations.py <https://github.com/alexgoller/illumio-py/blob/main/examples/10_bulk_operations.py>`_
     - Bulk create/delete workloads
     - creates/deletes
   * - `11_settings_and_reporting.py <https://github.com/alexgoller/illumio-py/blob/main/examples/11_settings_and_reporting.py>`_
     - Org settings, password policy, reports
     - read-only
   * - `12_pairing_profiles.py <https://github.com/alexgoller/illumio-py/blob/main/examples/12_pairing_profiles.py>`_
     - Pairing profile + pairing key
     - creates/deletes
   * - `13_onboard_unmanaged_workloads.py <https://github.com/alexgoller/illumio-py/blob/main/examples/13_onboard_unmanaged_workloads.py>`_
     - Bulk-onboard unmanaged workloads + labels, rate-limit-safe
     - creates/deletes

Selected examples
-----------------

Connecting to the PCE (``01_connect.py``):

.. literalinclude:: ../../../examples/01_connect.py
   :language: python

Building an allow policy (``05_allow_rules.py``):

.. literalinclude:: ../../../examples/05_allow_rules.py
   :language: python

Deny and override-deny rules (``06_deny_rules.py``):

.. literalinclude:: ../../../examples/06_deny_rules.py
   :language: python

Onboarding unmanaged workloads at scale (``13_onboard_unmanaged_workloads.py``).
This is the common "sync" pattern — prefetch the label map once, get-or-create
labels from it, and ``bulk_create`` the workloads — which avoids the per-label
``GET`` loop that causes :ref:`HTTP 429 rate-limit errors <guide-retries>`:

.. literalinclude:: ../../../examples/13_onboard_unmanaged_workloads.py
   :language: python
