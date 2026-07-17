.. _concept-object-model:

The object model
================

Every PCE resource is a Python ``dataclass`` with shared JSON serialization. The
classes form a small hierarchy:

.. code-block:: text

    JsonObject          (abstract: to_json / from_json)
    └── Reference        (+ href)
        └── IllumioObject (+ name, description, external_data_*, caps)
            ├── MutableObject   (+ created_at/by, updated_at/by, deleted_at/by, update_type)
            └── ImmutableObject (+ created_at)

- **JsonObject** — the base contract: :meth:`to_json` and :meth:`from_json`.
- **Reference** — an object identified by its ``href``. Many fields are typed as
  references (e.g. a rule's ``providers`` reference labels or IP lists).
- **IllumioObject** — a named object with a description and external-data hooks.
- **MutableObject** — most read/write resources; adds audit timestamps.

Encoding and decoding
---------------------

``from_json`` builds an object from a dict (or JSON string). ``to_json`` returns
a JSON-compatible dict. Two properties matter in day-to-day use:

- **Empty fields are dropped.** ``to_json`` omits ``None``/empty values, so you
  only send the fields you actually set — safe for ``PUT``/``POST``.
- **Unknown keys are preserved.** ``from_json`` accepts keys it doesn't have a
  field for and sets them as attributes. This makes the client
  *forwards-compatible*: a newer PCE can return fields this version doesn't model
  yet without breaking decoding.

Nested types
------------

Fields annotated with a nested :class:`JsonObject` type (or ``List[T]`` of one)
are decoded recursively. When a field can hold more than one shape — e.g. a
service reference *or* an inline port/protocol — the class overrides
``_decode_complex_types`` to choose the right type per element.

.. note::

   Use ``typing.List[T]`` (not a bare ``list``) for fields that need nested
   decoding; a bare ``list`` annotation skips the recursive decode.

Validation
----------

Classes override ``_validate`` to enforce enum membership and range constraints
(for example, a workload's ``enforcement_mode`` must be a valid
:class:`EnforcementMode <illumio.util.EnforcementMode>`). Validation runs on
construction and on decode.

.. seealso::

   :ref:`concept-architecture` for how these objects are wired to endpoints.
