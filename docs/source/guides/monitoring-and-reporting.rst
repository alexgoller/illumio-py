.. _guide-monitoring:

.. currentmodule:: illumio

Monitoring, reporting & settings
================================

Reporting & Monitoring
----------------------

The PCE provides several reporting and monitoring endpoints for tracking
risk, detecting core services, and reviewing system events.

.. rubric:: Reports

Retrieve and download generated reports:

.. code-block:: python

    >>> reports = pce.reports.get()
    >>> pce.download_report(report.href)

.. rubric:: Risk Summary

Get an overview of vulnerability risk across the environment:

.. code-block:: python

    >>> risk = pce.get_risk_summary()

.. rubric:: Core Services Detection

Retrieve a summary of detected core services:

.. code-block:: python

    >>> summary = pce.get_detected_core_services_summary()

.. rubric:: System Events

Query system-wide events. System events use a global endpoint and are not
scoped to a specific organization:

.. code-block:: python

    >>> events = pce.system_events.get()

Organization Settings
---------------------

The PCE exposes several settings endpoints for configuring organization-wide
behavior, event handling, logging, and traffic collection.

.. rubric:: Organization Settings

Read the current organization settings:

.. code-block:: python

    >>> settings = pce.org_settings.get()

.. rubric:: Event Settings

View and manage event configuration:

.. code-block:: python

    >>> event_settings = pce.event_settings.get()

.. rubric:: Syslog Destinations

Manage syslog forwarding destinations:

.. code-block:: python

    >>> destinations = pce.syslog_destinations.get()

.. rubric:: Traffic Collector Settings

View and manage traffic collector configuration:

.. code-block:: python

    >>> tc = pce.traffic_collector_settings.get()

Label Mapping
-------------

Label mapping rules allow you to automatically assign labels to workloads
based on hostname patterns, IP addresses, or other attributes. The
**illumio** library provides full CRUD support for label mapping rules
as well as methods for running and monitoring label mapping jobs.

.. rubric:: Managing Label Mapping Rules

Create and retrieve label mapping rules:

.. code-block:: python

    >>> rules = pce.label_mapping_rules.get()
    >>> rule = pce.label_mapping_rules.create(
    ...     LabelMappingRule(name='My Rule', ...)
    ... )

.. rubric:: Reordering Rules

Label mapping rules are evaluated in order. You can reorder them by
specifying a new position:

.. code-block:: python

    >>> pce.reorder_label_mapping_rule(rule.href, position=1)

.. rubric:: Running Label Mapping

Execute label mapping rules and track job progress:

.. code-block:: python

    >>> job = pce.run_label_mapping_rules(data={...})
    >>> status = pce.get_label_mapping_job(job_uuid='...')
    >>> results = pce.download_label_mapping_results(job_uuid='...')

.. note::
    Label mapping jobs run asynchronously. Use the job UUID returned from
    ``run_label_mapping_rules`` to poll for status and download results
    once the job completes.

PCE System Information
----------------------

The **illumio** library provides access to various PCE system-level
endpoints for querying version information, node status, and managing
async operations.

.. rubric:: Product Version

Retrieve the PCE software version:

.. code-block:: python

    >>> version = pce.get_product_version()

.. rubric:: Node Availability

Check whether the PCE node is available and ready to serve requests:

.. code-block:: python

    >>> available = pce.get_node_available()

.. rubric:: Supercluster Leader

In a supercluster deployment, determine which PCE is the current leader:

.. code-block:: python

    >>> leader = pce.get_supercluster_leader()

.. rubric:: Application Group Risk

Query risk information at the application group level:

.. code-block:: python

    >>> risk_summary = pce.get_app_group_risk_summary()
    >>> risk_details = pce.get_app_group_risk_details(app_group_id='...')

.. rubric:: Traffic Flow Metrics

Retrieve metrics about the traffic flow database:

.. code-block:: python

    >>> metrics = pce.get_traffic_flow_db_metrics()

.. rubric:: Async Query Management

Manage asynchronous queries that have been submitted to the PCE:

.. code-block:: python

    >>> queries = pce.get_async_queries()
    >>> pce.delete_async_query(uuid='...')
    >>> results = pce.download_async_query(uuid='...')
