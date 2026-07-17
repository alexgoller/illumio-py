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
