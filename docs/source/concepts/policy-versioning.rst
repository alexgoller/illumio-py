.. _concept-policy-versioning:

Policy versioning & provisioning
================================

Security policy objects — rule sets, rules, deny rules, IP lists, services,
label groups, virtual services, enforcement boundaries, firewall settings —
exist in two versions: **draft** and **active**.

- **Draft** is your editable working copy. Creating or updating a policy object
  changes the draft.
- **Active** is what the PCE actually enforces. Draft changes become active only
  when you **provision** them.

Endpoints for these objects are prefixed with ``/sec_policy/{draft|active}/``.
Resources registered with ``is_sec_policy=True`` get this prefix automatically;
``get`` takes a ``policy_version`` argument (``'draft'`` by default):

.. code-block:: python

    pce.rule_sets.get(policy_version='active')   # GET /sec_policy/active/rule_sets
    pce.rule_sets.get()                          # GET /sec_policy/draft/rule_sets

Nested policy objects
---------------------

Some policy objects live *under* a parent. Rules and deny rules, for example,
belong to a rule set. Pass the parent with the ``parent`` argument, and the
client builds the nested path for you:

.. code-block:: python

    pce.rules.create(rule, parent=rule_set)
    # POST /orgs/{org}/sec_policy/draft/rule_sets/{id}/sec_rules

Provisioning
------------

Newly created draft objects are **not enforced** until provisioned. Provision by
passing the hrefs of the draft objects to apply:

.. code-block:: python

    pce.provision_policy_changes(
        'Apply new segmentation policy',
        hrefs=[rule_set.href, ip_list.href]
    )

Related helpers make the workflow manageable:

- ``get_pending_policy_changes`` / ``discard_pending_policy_changes``
- ``get_policy_dependencies`` — what else must be provisioned alongside an object
- ``analyze_policy_impact`` — the effect of provisioning a set of changes
- ``check_policy`` — validate the policy before provisioning
- ``restore_policy`` — roll back to a prior version

.. seealso::

   The :ref:`Deny and override-deny rules <denyrules>` tutorial for an
   end-to-end draft-then-provision example.
