.. _api:

.. currentmodule:: illumio

Developer Interface v\ |version|
================================

.. _pce:

PCE Interface
-------------

PolicyComputeEngine
###################

The ``PolicyComputeEngine`` object provides the core interface for interacting
with PCE API endpoints.

.. autoclass:: PolicyComputeEngine
    :inherited-members:

PCE Object API
##############

This internal class is used to represent API objects within the PCE, and provides
a common CRUD interface for them.

.. autoclass:: illumio.pce::PolicyComputeEngine._PCEObjectAPI
    :inherited-members:

.. _apiattributes:

PolicyComputeEngine API Attributes
##################################

The :class:`PolicyComputeEngine <PolicyComputeEngine>` class provides the following attributes:

|APIList|

Each represents a corresponding PCE API endpoint, implemented as a
:class:`_PCEObjectAPI <illumio.pce.PolicyComputeEngine._PCEObjectAPI>` instance.

.. _exceptions:

Exceptions
----------

The library uses two exception types to capture errors returned from the API or
encountered in other library functions.

.. autoexception:: IllumioException
.. autoexception:: IllumioApiException
.. autoexception:: IllumioIntegerValidationException

.. _events:

Events
------

.. autoclass:: Event

.. _workloads:

Workloads and VENs
------------------

Workloads
#########

.. autoclass:: illumio.workloads.Workload

VENs
####

.. autoclass:: illumio.workloads.VEN

Pairing Profiles
################

.. autoclass:: illumio.workloads.PairingProfile

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

.. _policyobjects:

Policy Objects
--------------

IP Lists
########

.. autoclass:: illumio.policyobjects.IPList

Labels
######

.. autoclass:: illumio.policyobjects.Label
.. autoclass:: illumio.policyobjects.LabelGroup
.. autoclass:: illumio.policyobjects.LabelSet

Label Dimensions
################

.. autoclass:: illumio.policyobjects.LabelDimension

Services
########

.. autoclass:: illumio.policyobjects.Service

Virtual Services
################

.. autoclass:: illumio.policyobjects.VirtualService

.. autoclass:: illumio.policyobjects.ServiceBinding

Virtual Servers
###############

.. autoclass:: illumio.policyobjects.VirtualServer

.. autoclass:: illumio.policyobjects.DVSVirtualServer

.. _infrastructure:

Infrastructure
--------------

Container Clusters
##################

.. autoclass:: illumio.infrastructure.ContainerCluster

.. autoclass:: illumio.infrastructure.ContainerWorkloadProfile

Network Devices
###############

.. autoclass:: illumio.infrastructure.NetworkDevice

Network Endpoints
#################

.. autoclass:: illumio.infrastructure.NetworkEndpoint

Network Enforcement Nodes
#########################

.. autoclass:: illumio.infrastructure.NetworkEnforcementNode

SLBs
#####

.. autoclass:: illumio.infrastructure.SLB

Discovered Virtual Servers
##########################

.. autoclass:: illumio.infrastructure.DiscoveredVirtualServer

Kubernetes Workloads
####################

.. autoclass:: illumio.infrastructure.KubernetesWorkload

.. _explorer:

Explorer
--------

Traffic Analysis
################

.. autoclass:: illumio.explorer.TrafficQuery
    :members: build

.. autoclass:: illumio.explorer.TrafficFlow

.. _accessmanagement:

Access Management
-----------------

Users
#####

.. autoclass:: illumio.accessmanagement.User

Roles
#####

.. autoclass:: illumio.accessmanagement.Role

Permissions
###########

.. autoclass:: illumio.accessmanagement.Permission

Service Accounts
################

.. autoclass:: illumio.accessmanagement.ServiceAccount

Auth Security Principals
########################

.. autoclass:: illumio.accessmanagement.AuthSecurityPrincipal

Access Restrictions
###################

.. autoclass:: illumio.accessmanagement.AccessRestriction

.. _vulnerabilities:

Vulnerabilities
---------------

Vulnerability
#############

.. autoclass:: illumio.vulnerabilities.Vulnerability

Vulnerability Instances
#######################

.. autoclass:: illumio.vulnerabilities.VulnerabilityInstance

Vulnerability Reports
#####################

.. autoclass:: illumio.vulnerabilities.VulnerabilityReport

.. _authentication:

Authentication
--------------

Authentication Settings
#######################

.. autoclass:: illumio.authentication.AuthenticationSettings

LDAP Configuration
##################

.. autoclass:: illumio.authentication.LDAPConfig

SAML Configuration
##################

.. autoclass:: illumio.authentication.SAMLConfig

Password Policy
################

.. autoclass:: illumio.authentication.PasswordPolicy

.. _reporting:

Reporting
---------

Jobs
####

.. autoclass:: illumio.reporting.Job

Reports
#######

.. autoclass:: illumio.reporting.Report

Report Schedules
################

.. autoclass:: illumio.reporting.ReportSchedule

Report Templates
################

.. autoclass:: illumio.reporting.ReportTemplate

Core Service Types
##################

.. autoclass:: illumio.reporting.CoreServiceType

Detected Core Services
######################

.. autoclass:: illumio.reporting.DetectedCoreService

Support Bundle Requests
#######################

.. autoclass:: illumio.reporting.SupportBundleRequest

System Events
#############

.. autoclass:: illumio.reporting.SystemEvent

.. _settings:

Settings
--------

Organization Settings
#####################

.. autoclass:: illumio.settings.OrgSettings

Event Settings
##############

.. autoclass:: illumio.settings.EventSettings

Report Settings
###############

.. autoclass:: illumio.settings.ReportSettings

Syslog Destinations
####################

.. autoclass:: illumio.settings.SyslogDestination

Traffic Collector Settings
##########################

.. autoclass:: illumio.settings.TrafficCollectorSetting

Trusted Proxy IPs
##################

.. autoclass:: illumio.settings.TrustedProxyIPs

Workload Settings
#################

.. autoclass:: illumio.settings.WorkloadSettings

Optional Features
#################

.. autoclass:: illumio.settings.OptionalFeature

.. _labelmapping:

Label Mapping
-------------

Label Mapping Rules
###################

.. autoclass:: illumio.labelmapping.LabelMappingRule

.. _util:

Utilities
---------

Contains global constants, helper functions, and internal structures.

Constants
#########

.. autodata:: illumio.util.constants.ACTIVE
.. autodata:: illumio.util.constants.DRAFT
.. autodata:: illumio.util.constants.AMS
.. autodata:: illumio.util.constants.RESOLVE_AS_WORKLOADS
.. autodata:: illumio.util.constants.RESOLVE_AS_VIRTUAL_SERVICES
.. autodata:: illumio.util.constants.ANY_IP_LIST_NAME
.. autodata:: illumio.util.constants.ALL_SERVICES_NAME
.. autodata:: illumio.util.constants.PORT_MAX
.. autodata:: illumio.util.constants.ICMP_CODE_MAX
.. autodata:: illumio.util.constants.ICMP_TYPE_MAX
.. autodata:: illumio.util.constants.BULK_CHANGE_LIMIT

.. autoenum:: illumio.util.constants.EnforcementMode
    :members:

.. autoenum:: illumio.util.constants.LinkState
    :members:

.. autoenum:: illumio.util.constants.VisibilityLevel
    :members:

.. autoenum:: illumio.util.constants.Transmission
    :members:

.. autoenum:: illumio.util.constants.FlowDirection
    :members:

.. autoenum:: illumio.util.constants.TrafficState
    :members:

.. autoenum:: illumio.util.constants.ApplyTo
    :members:

.. autoenum:: illumio.util.constants.VENType
    :members:

.. autoenum:: illumio.util.constants.ChangeType
    :members:

.. autoenum:: illumio.util.constants.EventSeverity
    :members:

.. autoenum:: illumio.util.constants.EventStatus
    :members:

Helper Functions
################

.. autofunction:: illumio.util.functions.convert_active_href_to_draft
.. autofunction:: illumio.util.functions.convert_draft_href_to_active
.. autofunction:: illumio.util.functions.convert_protocol
.. autofunction:: illumio.util.functions.deprecated
.. autofunction:: illumio.util.functions.ignore_empty_keys
.. autofunction:: illumio.util.functions.parse_url
.. autofunction:: illumio.util.functions.pce_api

.. autofunction:: illumio.util.jsonutils.href_from

Base Classes
############

.. autoclass:: illumio.util.jsonutils.JsonObject
.. autoclass:: illumio.util.jsonutils.IllumioObject
.. autoclass:: illumio.util.jsonutils.Reference
