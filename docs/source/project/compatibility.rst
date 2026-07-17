.. _compatibility:

Compatibility
=============

Python
------

``illumio-py-open`` supports **Python 3.6 through 3.12**. Its only runtime
dependency is `requests <https://requests.readthedocs.io/>`_ (plus the
``dataclasses`` backport on Python 3.6).

Illumio Core PCE
----------------

The client's core functionality is compatible with Illumio Core PCE **21.2 and
up**. Object field coverage is validated against the current Illumio Core REST
API schemas (25.x / 26.x) and, where possible, against live PCE responses.

Because the client is *forwards-compatible* — unknown response fields are
preserved rather than rejected (see :ref:`concept-object-model`) — a newer PCE
returning fields this version does not yet model will not break decoding. You
can always fall back to the raw :meth:`get <PolicyComputeEngine.get>` /
:meth:`post <PolicyComputeEngine.post>` methods for endpoints or fields the
typed models do not cover yet.

Deprecated fields
-----------------

Some models carry deprecated field aliases retained for backwards compatibility
with pre-1.2.0 code (see :ref:`Migrating from illumio <migrating>`). These
continue to work but may be removed in a future major release; prefer the
current field names.
