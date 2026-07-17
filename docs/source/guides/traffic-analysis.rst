.. _guide-traffic-analysis:

.. currentmodule:: illumio

Traffic analysis
================

Traffic Queries
---------------

You can use the PCE API to search the traffic database for flows matching
specific criteria. The traffic query endpoints provide the same interface
as the `Explorer <https://docs.illumio.com/core/21.1/Content/Guides/visualization/explorer/about-explorer.htm>`_
feature in the PCE.

.. note::
    The synchronous traffic query endpoint and :meth:`get_traffic_flows <PolicyComputeEngine.get_traffic_flows>`
    function are deprecated - use the async endpoint and :meth:`get_traffic_flows_async <PolicyComputeEngine.get_traffic_flows_async>`
    function instead. See the `Explorer REST API docs <https://docs.illumio.com/core/21.2/Content/Guides/rest-api/visualization/explorer.htm#Asynchro>`_
    for details.

::

    >>> traffic_query = TrafficQuery.build(
    ...     start_date="2022-07-01T00:00:00Z",
    ...     end_date="2022-08-01T00:00:00Z",
    ...     include_services=[
    ...         {'port': 3389, 'proto': 'tcp'},
    ...         {'port': 3389, 'proto': 'udp'},
    ...     ],
    ...     policy_decisions=['blocked', 'potentially_blocked', 'unknown']
    ... )
    >>> blocked_rdp_traffic = pce.get_traffic_flows_async(
    ...     query_name='blocked-rdp-traffic-july-22',
    ...     traffic_query=traffic_query
    ... )
