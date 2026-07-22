.. _guide-connecting:

.. currentmodule:: illumio

Connecting to the PCE
=====================

Proxy Settings
--------------

If you need to use a proxy to communicate with the PCE, HTTP/S proxies can be
configured using the :meth:`set_proxies <PolicyComputeEngine.set_proxies>`
function::

    >>> pce.set_proxies(
    ...     http_proxy='http://my.proxyserver.com:8080',
    ...     https_proxy='http://my.proxyserver.com:8080'
    ... )

If not set in the session, the ``requests`` library will pull proxy settings
from environment variables, see the ``requests`` `proxy documentation <https://requests.readthedocs.io/en/latest/user/advanced/#proxies>`_
for details.

.. note::
    Proxy values set with ``set_proxies`` will apply to the session, and will
    be overwritten by proxy values set in the executing shell environment. If
    you need to override environment proxy settings, you can specify the
    ``proxies`` parameter directly as a keyword argument::

        >>> pce.ip_lists.get(proxies={'http': 'http://proxy.server:8080', 'https': 'http://proxy.server:8080'})

TLS Certificates
----------------

If you're using the **illumio** library with an on-prem PCE, you may be using
self-signed or internal ceriticate chains for your instance.

Requests through the :class:`PolicyComputeEngine <PolicyComputeEngine>` can
leverage the ``requests`` library ``verify`` and ``cert`` parameters to specify
CA certificates and cert/key pairs respectively.

See `the requests documentation <https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification>`_
for details.

Disable TLS verification::

    >>> pce.labels.get(verify=False)

Verify using custom CA bundle::

    >>> pce.labels.get(verify='/path/to/ca/bundle')

Verify using a local client-side cert pair::

    >>> pce.labels.get(verify=True, cert='/path/to/keypair.pem')
    >>> pce.labels.get(verify=True, cert=('/path/to/client.crt', '/path/to/client.key'))

.. _guide-retries:

Retries and rate limiting (HTTP 429)
------------------------------------

The PCE enforces API rate limits. When you exceed them it responds with
**HTTP 429 (Too Many Requests)**. The client retries automatically, but if the
request *rate* stays too high the retries are eventually exhausted and you'll
see an error like::

    illumio.exceptions.IllumioApiException: HTTPSConnectionPool(host='...', port=443):
    Max retries exceeded with url: /api/v2/orgs/.../labels?key=app&value=AID011
    (Caused by ResponseError('too many 429 error responses'))

Default retry behavior
~~~~~~~~~~~~~~~~~~~~~~~~

Every :class:`PolicyComputeEngine <PolicyComputeEngine>` mounts a ``requests``
retry adapter with these defaults:

- ``total`` = ``retry_count`` (default **5**)
- ``backoff_factor`` = **2** — waits of ~1, 2, 4, 8, 16 seconds between retries
- ``status_forcelist`` = ``[429, 500, 502, 503, 504]``
- the PCE's ``Retry-After`` header is honored

Tuning what's exposed
~~~~~~~~~~~~~~~~~~~~~~~

The number of retries and the per-request timeout are constructor arguments;
the timeout can also be changed later:

.. code-block:: python

    pce = PolicyComputeEngine('my.pce.com', port=443, org_id=1,
                              retry_count=10,       # Retry(total=10)
                              request_timeout=60)   # seconds
    pce.set_timeout(90)                             # change the timeout afterwards

``backoff_factor`` and ``status_forcelist`` are **not** exposed through the
public API and there is no ``set_retries`` method. To change them, mount your
own adapter on the session:

.. code-block:: python

    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    pce = PolicyComputeEngine('my.pce.com', port=443, org_id=1)
    pce.set_credentials(key, secret)

    retry = Retry(
        total=10,
        backoff_factor=3,                 # 3, 6, 12, 24, ... seconds
        status_forcelist=[429, 500, 502, 503, 504],
        respect_retry_after_header=True,  # obey the PCE's Retry-After
        # backoff_max=120,                # cap the wait (urllib3 >= 2)
    )
    adapter = HTTPAdapter(max_retries=retry)
    pce._session.mount("https://", adapter)
    pce._session.mount("http://", adapter)

Prefer fixing the request rate
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

More retries only wait *longer* between the same volume of requests — they treat
the symptom. A 429 storm usually comes from calling the API in a tight loop, for
example resolving labels one at a time. Fetch the collection once and resolve
in memory instead:

.. code-block:: python

    # one request instead of thousands
    labels = pce.labels.get_all()
    label_map = {(l.key, l.value): l for l in labels}

    app_label = label_map.get(('app', 'AID011'))   # no API call

For large collections, the async interface
(:meth:`get_async <PolicyComputeEngine._PCEObjectAPI.get_async>` /
``get_all``) has the PCE build the result as a single job rather than many paged
GETs. If you issue requests concurrently, reduce the concurrency and add a small
delay between batches.
