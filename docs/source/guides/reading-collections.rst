.. _guide-collections:

.. currentmodule:: illumio

Reading large collections
=========================

Asynchronous Collection Requests
--------------------------------

The PCE provides dedicated endpoints for reading large object collections through
the API. These collection requests kick off asynchronous jobs on the PCE, and
return the job status URL to be polled until the job is completed.
See the `REST API async overview <https://docs.illumio.com/core/21.5/Content/Guides/rest-api/async-get-collections/overview-of-async-get-requests.htm>`_
for details.

The :meth:`get_async <PolicyComputeEngine._PCEObjectAPI.get_async>`
and :meth:`get_collection <PolicyComputeEngine.get_collection>` methods abstract
the async job poll-wait loop from the caller in order to provide a simpler
synchronous interface for collection requests. If your implementation requires
control over job polling, you can set the poll/wait loop up manually::

    >>> resp = pce.get(headers={'Prefer': 'respond-async'})
    >>> job_poll_url = resp.headers['Location']
    >>> poll_interval = resp.headers['Retry-After']
    >>> while True:
    >>>     resp = pce.get(job_poll_url)
    >>>     poll_result = resp.json()
    >>>     poll_status = poll_result['status']
    >>>     if poll_status == 'done':
    >>>         collection_href = poll_result['result']['href']
    >>>         break
    >>>     elif poll_status == 'failed':
    >>>         raise IllumioException("Job failed: {}".format(poll_result))
    >>>     time.sleep(poll_interval)
    >>> resp = pce.get(collection_href)
    >>> job_results = resp.json()
