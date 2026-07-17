.. _guide-virtual-services:

.. currentmodule:: illumio

Virtual services
================

Virtual Services
----------------

Sometimes workloads may run multiple services or processes, making it difficult
to fit them into the typical labelling workflow. Container cluster nodes are a
good example. For these cases, :class:`VirtualService <illumio.policyobjects.VirtualService>`
objects provide an abstraction for a given service that can be labelled and
bound to one or more workloads. The virtual service object can then be referenced
in rule definitions through the ``resolve_labels_as`` block to apply policy
for the service across all bound workloads.

See the `virtual services section <https://docs.illumio.com/core/21.5/Content/Guides/security-policy/security-policy-objects/virtual-services.htm>`_
of the Illumio Policy Guide for details.

In the following example, we define two virtual services for a RabbitMQ cluster
serving channels for multiple applications. We'll explore how they can be used
in the sections below.

::

    >>> rabbitmq_svc = pce.services.create(Service(
    ...     name='S-RabbitMQ',
    ...     service_ports=[
    ...         ServicePort(port=5671, to_port=5672, proto='tcp'),   # AMQP/S listeners
    ...         ServicePort(port=15671, to_port=15672, proto='tcp'), # mgmt API/UI, rmqadmin
    ...     ]
    ... ))
    >>> rmq_role_label = pce.labels.create(Label(key='role', value='R-RabbitMQ'))
    >>> notifier_app_label = pce.labels.create(Label(key='app', value='A-Notifier'))
    >>> newsfeed_app_label = pce.labels.create(Label(key='app', value='A-NewsFeed'))
    >>> prod_env_label = pce.labels.create(Label(key='env', value='E-Prod'))
    >>> aws_loc_label = pce.labels.create(Label(key='loc', value='L-AWS'))
    >>> notifier_virtual_service = pce.virtual_services.create(
    ...     VirtualService(
    ...         name='VS-Notifier-RabbitMQ',
    ...         apply_to=ApplyTo.HOST_ONLY,
    ...         service=rabbitmq_svc,
    ...         labels=[rmq_role_label, notifier_app_label, prod_env_label, aws_loc_label]
    ...     )
    ... )
    >>> newsfeed_virtual_service = pce.virtual_services.create(
    ...     VirtualService(
    ...         name='VS-NewsFeed-RabbitMQ',
    ...         apply_to=ApplyTo.HOST_ONLY,
    ...         service=rabbitmq_svc,
    ...         labels=[rmq_role_label, newsfeed_app_label, prod_env_label, aws_loc_label]
    ...     )
    ... )

Service Bindings
################

To associate workloads with a virtual service, you will need to create a :class:`ServiceBinding <illumio.policyobjects.ServiceBinding>`
object. Service bindings link one or more workloads to a virtual service so
they can be referenced in rules, as we'll show in the next section.

.. note::
    Virtual services must be :ref:`provisioned to active state <provisioning>`
    before service bindings can be applied. The example below shows two ways of
    referencing the active HREF, first using a :class:`Reference <illumio.util.Reference>`
    object, and second by updating the virtual service object's ``href`` field
    directly.

We'll extend the example above by binding the RabbitMQ server workload to both
virtual services::

    >>> rmq_workload = pce.workloads.create(Workload(
    ...     name='RabbitMQ Prod', hostname='rmq0.company.com', public_ip='10.0.129.44'
    ... ))
    >>> policy_version = pce.provision_policy_changes(
    ...     change_description="Create RabbitMQ virtual services",
    ...     hrefs=[rabbitmq_svc.href, notifier_virtual_service.href, newsfeed_virtual_service.href]
    ... )
    >>> notifier_vs_active_ref = Reference(
    ...     href=convert_draft_href_to_active(notifier_virtual_service.href)
    ... )
    >>> notifier_binding = ServiceBinding(
    ...     virtual_service=notifier_vs_active_ref,
    ...     workload=rmq_workload,
    ...     port_overrides=[
    ...         PortOverride(
    ...             port=5671, new_port=5673, new_to_port=5674, proto='tcp'
    ...         )
    ...     ]
    ... )
    >>> newsfeed_virtual_service.href = convert_draft_href_to_active(newsfeed_virtual_service.href)
    >>> newsfeed_binding = ServiceBinding(
    ...     virtual_service=newsfeed_virtual_service,
    ...     workload=rmq_workload,
    ...     port_overrides=[
    ...         PortOverride(
    ...             port=5671, new_port=5675, new_to_port=5676, proto='tcp'
    ...         )
    ...     ]
    ... )
    >>> pce.service_bindings.create([notifier_binding, newsfeed_binding])

Writing Rules for Virtual Services
##################################

When using virtual services, your security policy rules will need to be written
slightly differently. Since the virtual service already contains the service
definition, the rule's ``ingress_services`` parameter is left blank. The rule
must also explicitly be configured to resolve labels as virtual services.

See the `virtual service rule writing guide <https://docs.illumio.com/core/21.5/Content/Guides/security-policy/security-policy-objects/virtual-services.htm#VirtualServicesinRuleWriting>`_
for details.

To illustrate the concept, we'll create a rule set for the NewsFeed application
and add a rule allowing all workloads to reach the RabbitMQ server using the
virtual service we created above::

    >>> newsfeed_rule_set = pce.rule_sets.create(
    ...     RuleSet(
    ...         name='RS-NewsFeed-Prod',
    ...         scopes=[
    ...             LabelSet(labels=[newsfeed_app_label, prod_env_label, aws_loc_label])
    ...         ]
    ...     )
    ... )
    >>> newsfeed_rmq_rule = Rule.build(
    ...     consumers=[AMS],
    ...     providers=[rmq_role_label],
    ...     ingress_services=[],
    ...     resolve_providers_as=[RESOLVE_AS_VIRTUAL_SERVICES]
    ... )
    >>> pce.rules.create(newsfeed_rmq_rule, parent=newsfeed_rule_set)
