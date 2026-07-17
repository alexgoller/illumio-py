.. currentmodule:: illumio

Security policy
===============


.. _securitypolicy:

Security Policy
---------------

Rule Sets
#########

.. autoclass:: illumio.rules.RuleSet

Rules
#####

.. autoclass:: illumio.rules.Rule
    :members: build

Deny Rules
##########

.. autoclass:: illumio.rules.DenyRule
    :members: build

Override Deny Rules
###################

.. autoclass:: illumio.rules.OverrideDenyRule
    :members: build

Enforcement Boundaries
######################

.. autoclass:: illumio.rules.EnforcementBoundary
    :members: build

Firewall Settings
#################

.. autoclass:: illumio.secpolicy.FirewallSetting

Policy Dependencies
####################

.. autoclass:: illumio.secpolicy.PolicyDependency

Policy Checks
##############

.. autoclass:: illumio.secpolicy.PolicyCheck

Modified Objects
################

.. autoclass:: illumio.secpolicy.ModifiedObject
