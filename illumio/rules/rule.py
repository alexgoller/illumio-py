# -*- coding: utf-8 -*-

"""This module provides classes related to policy rules.

Copyright:
    © 2022 Illumio

License:
    Apache2, see LICENSE for more details.
"""
from dataclasses import dataclass
from typing import List, Union

from illumio.util import (
    JsonObject,
    Reference,
    MutableObject,
    pce_api,
    RESOLVE_AS_WORKLOADS,
)
from illumio.policyobjects import Service, ServicePort

from .actor import Actor


@dataclass
class BaseRule(Reference):
    ingress_services: List[Union[Service, ServicePort]] = None
    providers: List[Actor] = None
    consumers: List[Actor] = None

    @classmethod
    def build(cls, providers: List[Union[str, Reference, dict]], consumers: List[Union[str, Reference, dict]],
            ingress_services: List[Union[JsonObject, dict, str]], **kwargs) -> 'BaseRule':
        services = []
        for service in ingress_services:
            if isinstance(service, JsonObject):
                services.append(service)
            elif type(service) is str:
                services.append(Service(href=service))
            else:
                service_type = Service if 'href' in service else ServicePort
                services.append(service_type.from_json(service))
        return cls(
            providers=[Actor.from_reference(provider) for provider in providers],
            consumers=[Actor.from_reference(consumer) for consumer in consumers],
            ingress_services=services,
            **kwargs
        )

    def _decode_complex_types(self):
        decoded_ingress_services = []
        if self.ingress_services:
            for service in self.ingress_services:
                service_type = Service if 'href' in service else ServicePort
                decoded_ingress_services.append(service_type.from_json(service))
        self.ingress_services = decoded_ingress_services
        super()._decode_complex_types()


@dataclass
class LabelResolutionBlock(JsonObject):
    providers: List[str] = None
    consumers: List[str] = None


@dataclass
@pce_api('rules', endpoint='/sec_rules')
class Rule(BaseRule, MutableObject):
    """Represents a security rule in the PCE.

    Each security rule defines one or more services on which traffic will be
    allowed from the defined providers to the defined consumers.

    Providers and consumers can be defined using static (workload HREF) or
    dynamic (label, IP list) references. By default, providers and consumers
    are resolved as workloads.

    ``Rule`` represents an *allow* rule. Deny and override-deny rules are
    distinct rule types with their own nested endpoints; see
    :class:`DenyRule` and :class:`OverrideDenyRule`.

    See https://docs.illumio.com/core/21.5/Content/Guides/security-policy/create-security-policy/rules.htm

    Usage:
        >>> import illumio
        >>> pce = illumio.PolicyComputeEngine('pce.company.com', port=443, org_id=1)
        >>> pce.set_credentials('api_key', 'api_secret')
        >>> any_ip_list = pce.get_default_ip_list()
        >>> role_label = pce.labels.create({'key': 'role', 'value': 'R-Web'})
        >>> app_label = pce.labels.create({'key': 'app', 'value': 'A-App'})
        >>> env_label = pce.labels.create({'key': 'env', 'value': 'E-Prod'})
        >>> loc_label = pce.labels.create({'key': 'loc', 'value': 'L-AWS'})
        >>> ruleset = illumio.RuleSet(
        ...     name='RS-LAB-ALLOWLIST',
        ...     scopes=[
        ...         illumio.LabelSet(
        ...             labels=[app_label, env_label, loc_label]
        ...         )
        ...     ]
        ... )
        >>> ruleset = pce.rule_sets.create(ruleset)
        >>> rule = illumio.Rule.build(
        ...     providers=[role_label],
        ...     consumers=[any_ip_list],
        ...     ingress_services=[
        ...         {'port': 80, 'proto': 'tcp'},
        ...         {'port': 443, 'proto': 'tcp'}
        ...     ],
        ...     unscoped_consumers=True,  # creates an extra-scope rule
        ... )
        >>> rule = pce.rules.create(rule, parent=ruleset)
        >>> rule
        Rule(
            href='/orgs/1/sec_policy/rule_sets/19/rules/sec_rules/34',
            enabled=True,
            providers=[
                Actor(
                    label=Reference(
                        href='/orgs/1/labels/21'
                    ),
                    ...
                )
            ],
            consumers=[
                Actor(
                    ip_list=Reference(
                        href='/orgs/1/sec_policy/draft/ip_lists/1'
                    ),
                    ...
                )
            ],
            ingress_services=[
                ServicePort(port=80, proto=6, ...),
                ServicePort(port=443, proto=6, ...)
            ],
            resolve_labels_as=LabelResolutionBlock(
                providers=['workloads'],
                consumers=['workloads']
            ),
            unscoped_consumers=True,
            ...
        )
    """
    enabled: bool = None
    resolve_labels_as: LabelResolutionBlock = None
    sec_connect: bool = None
    stateless: bool = None
    machine_auth: bool = None
    consuming_security_principals: List[Reference] = None
    unscoped_consumers: bool = None
    network_type: str = None

    @classmethod
    def build(cls, providers: List[Union[str, Reference, dict]], consumers: List[Union[str, Reference, dict]],
            ingress_services: List[Union[JsonObject, dict, str]],
            resolve_providers_as: List[str]=None, resolve_consumers_as: List[str]=None, enabled=True, **kwargs) -> 'Rule':
        resolve_labels_as = LabelResolutionBlock(
            providers=resolve_providers_as or [RESOLVE_AS_WORKLOADS],
            consumers=resolve_consumers_as or [RESOLVE_AS_WORKLOADS]
        )
        return super().build(providers, consumers, ingress_services, resolve_labels_as=resolve_labels_as, enabled=enabled, **kwargs)


@dataclass
class _DenyRuleBase(BaseRule, MutableObject):
    """Shared shape for deny and override-deny rules.

    Deny rules and override-deny rules are rule *types* that live nested under
    a ruleset, alongside allow rules. They share the same fields as an allow
    :class:`Rule` and differ only by the nested endpoint they are posted to.
    Rule precedence is determined by type — override-deny > allow > deny — so
    there is no numeric ``priority`` field, and override-deny rules do not
    reference specific deny rules.
    """
    enabled: bool = None
    resolve_labels_as: LabelResolutionBlock = None
    unscoped_consumers: bool = None
    network_type: str = None

    @classmethod
    def build(cls, providers: List[Union[str, Reference, dict]], consumers: List[Union[str, Reference, dict]],
            ingress_services: List[Union[JsonObject, dict, str]],
            resolve_providers_as: List[str]=None, resolve_consumers_as: List[str]=None, enabled=True, **kwargs):
        resolve_labels_as = LabelResolutionBlock(
            providers=resolve_providers_as or [RESOLVE_AS_WORKLOADS],
            consumers=resolve_consumers_as or [RESOLVE_AS_WORKLOADS]
        )
        return super().build(providers, consumers, ingress_services, resolve_labels_as=resolve_labels_as, enabled=enabled, **kwargs)


@dataclass
@pce_api('deny_rules', endpoint='/deny_rules')
class DenyRule(_DenyRuleBase):
    """Represents a deny rule in the PCE.

    Deny rules explicitly block traffic from the defined providers to the
    defined consumers on the specified services. In the policy evaluation
    order (override-deny > allow > deny), a deny rule is applied last and can
    be overridden by an allow or override-deny rule.

    Deny rules live nested under a ruleset and are created, fetched, updated,
    and deleted with the ruleset passed as ``parent``.

    Usage:
        >>> import illumio
        >>> pce = illumio.PolicyComputeEngine('pce.company.com', port=443, org_id=1)
        >>> pce.set_credentials('api_key', 'api_secret')
        >>> ruleset = pce.rule_sets.get_by_name('RS-APP')
        >>> external_ip_list = pce.ip_lists.get(name='External-IPs')[0]
        >>> internal_label = pce.labels.get(key='role', value='internal')[0]
        >>> deny_rule = illumio.DenyRule.build(
        ...     providers=[external_ip_list],
        ...     consumers=[internal_label],
        ...     ingress_services=[
        ...         {'port': 22, 'proto': 'tcp'},
        ...         {'port': 3389, 'proto': 'tcp'}
        ...     ]
        ... )
        >>> deny_rule = pce.deny_rules.create(deny_rule, parent=ruleset)
    """


@dataclass
@pce_api('override_deny_rules', endpoint='/override_deny_rules')
class OverrideDenyRule(_DenyRuleBase):
    """Represents an override-deny rule in the PCE.

    Override-deny rules block traffic and have the highest precedence in the
    policy evaluation order (override-deny > allow > deny): they cannot be
    overridden by allow rules. Structurally they are identical to
    :class:`DenyRule`, differing only by the nested endpoint they use.

    Override-deny rules live nested under a ruleset and are created, fetched,
    updated, and deleted with the ruleset passed as ``parent``.

    Usage:
        >>> import illumio
        >>> pce = illumio.PolicyComputeEngine('pce.company.com', port=443, org_id=1)
        >>> pce.set_credentials('api_key', 'api_secret')
        >>> ruleset = pce.rule_sets.get_by_name('RS-APP')
        >>> admin_label = pce.labels.get(key='role', value='admin')[0]
        >>> internal_label = pce.labels.get(key='role', value='internal')[0]
        >>> override_rule = illumio.OverrideDenyRule.build(
        ...     providers=[admin_label],
        ...     consumers=[internal_label],
        ...     ingress_services=[
        ...         {'port': 22, 'proto': 'tcp'}
        ...     ]
        ... )
        >>> override_rule = pce.override_deny_rules.create(override_rule, parent=ruleset)
    """


__all__ = [
    'BaseRule',
    'Rule',
    'DenyRule',
    'OverrideDenyRule',
    'LabelResolutionBlock',
]
