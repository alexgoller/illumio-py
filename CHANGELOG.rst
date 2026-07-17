Changelog
=========

Version 1.2.1 (2026-07-17)
--------------------------

.. rubric:: IMPROVEMENTS

* Tier-2 spec-conformance: reconciled the settings, authentication, and reporting
  models with the current PCE API. All additive — pre-1.2.0 field names are kept
  as deprecated aliases. Live-validated against a real PCE where data was available.

    * ``SAMLConfig``: ``issuer``, ``idp_sso_target_url``, ``idp_slo_target_url``, ``idp_cert``, ``cluster_fqdn``, ``consumer_service_url``, ``consumer_logout_url``, ``name_identifier_format``, ``authn_context``, ``force_authn``, ``sign_authn_request``, ``pce_signing_cert``, ``pce_signing_cert_expires_at``
    * ``PasswordPolicy``: ``expire_time_days``, ``min_changed_characters``, ``min_characters_per_type``, ``require_type_lowercase``, ``require_type_uppercase``, ``require_type_number``, ``require_type_symbol``
    * ``LDAPConfig``: ``authentication_method``, ``bind_distinguished_name``, ``user_base_distinguished_name``, ``user_base_filter``, ``user_distinguished_name_pattern``, ``username_attribute``, ``full_name_attribute``, ``user_memberof_attribute``, ``request_timeout_seconds``, ``tls_ca_bundle``, ``insecure_disable_tls_certificate_verification``, ``is_bind_password_set``, ``pce_fqdn``
    * ``OrgSettings``: ``cloud_secure_tenant_id``, ``max_rule_search_provider_consumer_entities``, ``total_internet_address_space``, ``total_lateral_address_space``
    * ``ReportSettings``: ``max_queued_reports``, ``report_retention_days``
    * ``Report``: ``send_by_email``, ``generated_at``, ``progress_percentage``
    * ``ReportSchedule``: ``report_generation_frequency``, ``scheduled_at``, ``send_by_email``
    * ``ReportTemplate``: ``enabled``, ``report_parameters``, ``show_in_ui``

* ``SAMLConfig`` and ``PasswordPolicy`` now extend ``MutableObject`` (gain ``created_at``/``updated_at``/``created_by``/``updated_by``).

.. rubric:: DOCUMENTATION

* Documentation now builds and publishes to GitHub Pages on every push to ``main``.
* Added a "Deny and override-deny rules" use-case section to the user guide.
* Modernized the Sphinx toolchain (``sphinx>=7.2``); fixed the distribution-name version lookup and landing-page badges for the fork.

Version 1.2.0 (2026-07-17)
--------------------------

.. rubric:: NEW FEATURES

* full API coverage for Illumio PCE REST API (OpenAPI v25.2.10)
    * 56 registered CRUD API endpoints (up from 20)
    * 67 custom methods on ``PolicyComputeEngine`` for specialized operations
* new ``illumio.authentication`` subpackage
    * ``AuthenticationSettings``, ``LDAPConfig``, ``SAMLConfig``, ``PasswordPolicy``
* new ``illumio.reporting`` subpackage
    * ``Job``, ``Report``, ``ReportSchedule``, ``ReportTemplate``
    * ``CoreServiceType``, ``DetectedCoreService``
    * ``SupportBundleRequest``, ``SystemEvent``
* new ``illumio.settings`` subpackage
    * ``OrgSettings``, ``EventSettings``, ``ReportSettings``
    * ``SyslogDestination``, ``TrafficCollectorSetting``, ``TrustedProxyIPs``
    * ``WorkloadSettings``, ``OptionalFeature``
* new ``illumio.labelmapping`` subpackage
    * ``LabelMappingRule`` with bulk operations and mapping job management
* expanded ``illumio.accessmanagement`` subpackage
    * ``Role``, ``Permission``, ``ServiceAccount``, ``AuthSecurityPrincipal``, ``AccessRestriction``
* expanded ``illumio.infrastructure`` subpackage
    * ``NetworkDevice``, ``NetworkEndpoint``, ``NetworkEnforcementNode``
    * ``SLB``, ``DiscoveredVirtualServer``, ``KubernetesWorkload``
* security policy operations: ``get_pending_policy_changes``, ``discard_pending_policy_changes``, ``check_policy``, ``search_rules``, ``analyze_policy_impact``, ``restore_policy``, ``bulk_delete_policy_objects``
* VEN lifecycle management: ``unpair_vens``, ``upgrade_vens``, ``ven_remote_action``, ``ven_auth_recovery``, ``get_ven_statistics``, VEN software release management
* workload operations: ``get_workload_interfaces``, ``create_workload_interface``, ``delete_workload_interface``, ``get_workload_risk_details``, ``unpair_workloads``, ``bulk_import_workloads``
* access management: API key management for service accounts, users, and orgs; LDAP verification; user authentication
* reporting: ``download_report``, ``get_risk_summary``, ``get_detected_core_services_summary``
* PCE system info: ``get_product_version``, ``get_node_available``, ``get_supercluster_leader``
* app group risk: ``get_app_group_risk_summary``, ``get_app_group_risk_details``
* async query management: ``get_async_queries``, ``delete_async_query``, ``download_async_query``, ``update_async_query_rules``
* traffic flow database metrics: ``get_traffic_flow_db_metrics``
* registered ``VirtualServer``, ``FirewallSetting``, ``Vulnerability``, ``VulnerabilityReport`` as CRUD endpoints
* added ``PolicyDependency``, ``PolicyCheck``, ``ModifiedObject`` dataclasses
* spec-conformance audit tool (``tools/spec_audit.py``) diffing every registered model against the official Illumio JSON schemas
* added schema-accurate model fields (validated against a live PCE where possible):
    * ``Rule``: ``all_ips_except_for_in_consumers``, ``all_ips_except_for_in_providers``, ``use_workload_subnets``, ``egress_services``
    * ``Workload``: ``managed``, ``datacenter_nat_1to1``, ``risk_summary`` (``RiskSummary``/``Ransomware``), ``container_policy_convergence_status``
    * ``VEN``: ``authentication_recovery``, ``golden_image``, ``upgrade_target_version``, ``upgrade_expires_at``

.. rubric:: BUG FIXES

* corrected the deny-rule model to match the real Illumio API (schema- and live-PCE-validated):
    * a single ``DenyRule`` object carries an ``override`` flag (``override=True`` is an override-deny rule); precedence is override-deny > allow > deny
    * ``OverrideDenyRule`` is now a convenience whose ``build`` defaults ``override=True``; both use the nested ``/deny_rules`` endpoint (there is no separate override-deny endpoint)
    * removed fields that do not exist in the API: ``DenyRule.priority``, ``OverrideDenyRule.overrides``, and the ``Rule.action`` / ``RuleAction`` conflation
    * removed ``RuleSet.override_deny_rules``; a ruleset exposes a single ``deny_rules`` array holding both ordinary and override-deny rules

.. rubric:: IMPROVEMENTS

* comprehensive Sphinx documentation updates covering all new APIs and usage examples
* updated CLAUDE.md with full API coverage reference

.. rubric:: PACKAGING

* released as the community-maintained fork ``illumio-py-open`` (the import package remains ``illumio``)
* tag-triggered PyPI release workflow (``.github/workflows/release.yml``) using trusted publishing; final ``vX.Y.Z`` tags publish to PyPI
* development and API-reference material excluded from the built distribution

Version 1.1.3 (2023-02-10)
--------------------------

.. rubric:: NEW FEATURES

* add `PolicyComputeEngine.set_tls_settings` function to update verify and cert values for PCE requests session
* add `PolicyComputeEngine.must_connect` function to complement `check_connection`, raising the exception on failure rather than suppressing it

.. rubric:: BUG FIXES

* fix issue where PCE request could throw NoneType exception if incorrectly configured

Version 1.1.2 (2022-10-17)
--------------------------

.. rubric:: BUG FIXES

* fix check_connection call to avoid 404s on some PCEs

.. rubric:: NEW FEATURES

* add default timeout to `PolicyComputeEngine` requests session
    * add `PolicyComputeEngine.set_timeout` function to update timeout
* add `_PCEAPIObject.get_by_name` function as a convenience method for finding an exact name match

Version 1.1.1 (2022-09-02)
--------------------------

.. rubric:: BUG FIXES

* fix check_connection call to work with SaaS PCEs

Version 1.1.0 (2022-08-18)
--------------------------

.. rubric:: NEW FEATURES

* readthedocs documentation generated with Sphinx
    * API documentation
    * install guide
    * user guide
    * common use-cases
    * advanced usage
* add `illumio.events` module
    * adds `/events` PCE API endpoint
* add `PolicyComputeEngine.get_default_service` function
* added constant values to `illumio.util.constants`
    * `ALL_SERVICES_NAME` - default `All Services` Service object name
    * `RESOLVE_AS_WORKLOADS` - rule label resolution as workloads
    * `RESOLVE_AS_VIRTUAL_SERVICES` - rule label resolution as virtual services
    * `ICMP_CODE_MAX` - ICMP Code max value
    * `ICMP_TYPE_MAX` - ICMP Type max value
* add enumerations to `illumio.util.constants`
    * `ApplyTo` - enum in place of Virtual Service module constants
    * `VENType` - enum for `VEN.ven_type` field
    * `ChangeType` - enum for `ResourceEvent.change_type` field
    * `EventSeverity` - enum for `BaseEvent.severity` field
    * `EventStatus` - enum for `BaseEvent.status` field

* add `illumio.util.jsonutils.Error` dataclass to capture API error responses

.. rubric:: IMPROVEMENTS

* update `illumio.rules.Rule.build` function to use `['workloads']` as consumer/provider label resolution default
* broad improvements to pydoc
* add `__all__` to all modules
* bug fixes and type hint improvements

Version 1.0.4 (2022-08-16)
--------------------------

.. rubric:: BUG FIXES

* add `FirewallCoexistence` object to fix decoded `Workload.firewall_coexistence` data type

Version 1.0.3 (2022-08-13)
--------------------------

.. rubric:: DEPRECATIONS

* `PolicyComputeEngine.base_url` is DEPRECATED and will be removed in version 2.0.0. The URL is built on each request instead for more flexibility

.. rubric:: NEW FEATURES

* add `PORT_MAX` constant to `illumio.util.constants`
* add `IllumioIntegerValidationException` class
* add int validation helper function

.. rubric:: IMPROVEMENTS

* validate `PolicyComputeEngine` org_id and port values on init
* build URL for each request `PolicyComputeEngine`
* add private member vars for scheme/hostname/port/version
* update `PolicyComputeEngine.check_connection` to make a second call to validate org_id

Version 1.0.2 (2022-07-06)
--------------------------

.. rubric:: IMPROVEMENTS

* `illumio.workloads.pairingprofile.PairingProfile` - add custom encoder to enforce strict type checking for `key_lifespan` and `allowed_uses_per_key` fields
* improve unit and integration tests
    * `illumio.policyobjects.service.Service` - add unit test suite for `/services` API
* `illumio.policyobjects.label.LabelSet` - add custom equality function that ignores labels list ordering

Version 1.0.1 (2022-06-25)
--------------------------

.. rubric:: NEW FEATURES

* `illumio.infrastructure.containercluster.ContainerWorkloadProfiles` - add container clusters workload profiles API
* add stub for `/users` api
* make the `include_org` default configurable as a `PolicyComputeEngine` class attribute

.. rubric:: IMPROVEMENTS

* flesh out and document `/container_clusters` API
* move flatten_ref and resolve_enum functions to JSON encoding to avoid side-effects when creating JsonObject instances
* add sweeper module for integration test teardown
* add unit and integration tests for container clusters and workload profiles
* add unit tests to validate different request paths and include_org values

Version 1.0.0 (2022-06-16)
--------------------------

.. rubric:: MAJOR CHANGES

* change PolicyComputeEngine CRUD interfaces from static functions to a generic internal class (`illumio.pce._PCEObjectAPI`) that checks against dynamically registered endpoints

.. rubric:: NEW FEATURES

* CRUD operations for new model
    * `illumio.pce._PCEObjectAPI::create`
    * `illumio.pce._PCEObjectAPI::get`
    * `illumio.pce._PCEObjectAPI::update`
    * `illumio.pce._PCEObjectAPI::delete`
* `illumio.pce._PCEObjectAPI::get_by_reference` - given a type that can be decomposed in an HREF, get the single object it represents
* `illumio.pce._PCEObjectAPI::get_async` - async collection get
* `illumio.pce._PCEObjectAPI::get_all` - fetch all objects of the specified type by checking X-Total-Count
* add bulk operation functions
    * `illumio.pce._PCEObjectAPI::bulk_create` - can be used with workloads, virtual services, and security principals
    * `illumio.pce._PCEObjectAPI::bulk_update` - can be used with workloads and virtual services
    * `illumio.pce._PCEObjectAPI::bulk_delete` - can be used with workloads

.. rubric:: REMOVED

* `illumio.util.constants.Mode` - deprecated in PCE . replaced by `illumio.util.constants.EnforcementMode` in later versions of the PCE
* `illumio.rules.Ruleset` - renamed `illumio.rules.RuleSet` for internal consistency
* `illumio.pce.PolicyComputeEngine` functions
    * `_get_policy_objects` - change /sec_policy request behaviour for new functions to only return draft or active objects based on policy_version parameter
    * `get_virtual_service` - replaced by `PolicyComputeEngine.virtual_services::get_by_reference`
    * `get_virtual_services` - replaced by `PolicyComputeEngine.virtual_services::get`
    * `get_virtual_services_by_name` - deprecated in v0.8.0
    * `create_virtual_service` - replaced by `PolicyComputeEngine.virtual_services::create`
    * `create_service_binding` - deprecated in v0.8.2
    * `create_service_bindings` - replaced by `PolicyComputeEngine.service_bindings::create`
    * `get_ip_list` - replaced by `PolicyComputeEngine.ip_lists::get_by_reference`
    * `get_ip_lists` - replaced by `PolicyComputeEngine.ip_lists::get`
    * `get_ip_lists_by_name` - deprecated in v0.8.0
    * `create_ip_list` - replaced by `PolicyComputeEngine.ip_lists::create`
    * `get_ruleset` - replaced by `PolicyComputeEngine.rule_sets::get_by_reference`
    * `get_rulesets` - replaced by `PolicyComputeEngine.rule_sets::get`
    * `get_rulesets_by_name` - deprecated in v0.8.0
    * `create_ruleset` - replaced by `PolicyComputeEngine.rule_sets::create`
    * `create_rule` - replaced by `PolicyComputeEngine.rules::create`
    * `get_enforcement_boundary` - replaced by `PolicyComputeEngine.enforcement_boundaries::get_by_reference`
    * `get_enforcement_boundaries` - replaced by `PolicyComputeEngine.enforcement_boundaries::get`
    * `get_enforcement_boundaries_by_name` - deprecated in v0.8.0
    * `create_enforcement_boundary` - replaced by `PolicyComputeEngine.enforcement_boundaries::create`
    * `get_pairing_profile` - replaced by `PolicyComputeEngine.pairing_profiles::get_by_reference`
    * `get_pairing_profiles` - replaced by `PolicyComputeEngine.pairing_profiles::get`
    * `get_pairing_profiles_by_name` - deprecated in v0.8.0
    * `create_pairing_profile` - replaced by `PolicyComputeEngine.pairing_profiles::create`
    * `update_pairing_profile` - replaced by `PolicyComputeEngine.pairing_profiles::update`
    * `delete_pairing_profile` - replaced by `PolicyComputeEngine.pairing_profiles::delete`
    * `get_workload` - replaced by `PolicyComputeEngine.workloads::get_by_reference`
    * `get_workloads` - replaced by `PolicyComputeEngine.workloads::get`
    * `update_workload_enforcement_modes` - replaced with a more generic `bulk_update`
* `illumio.util.jsonutils.ModifiableObject` - changed name to `MutableObject`
* `illumio.util.jsonutils.UnmodifiableObject` - changed name to `ImmutableObject`

.. rubric:: IMPROVEMENTS

* update core JsonObject logic to perform type-based validation
* improve handling of reference types for JSON encoding
* improve URL building to be less strict
* improve tests and add integration test suite

.. rubric:: NOTES

* remove deprecation warning from `illumio.util.functions::convert_protocol`

Version 0.8.4 (2022-05-27)
--------------------------

* add CRUD operation functions for pairing profile objects to the PCE interface
* add pairing profile tests
* improve mock test scaffolding
* change IllumioEnum to metaclass and replace has_value with contains builtin

Version 0.8.3 (2022-05-16)
--------------------------

* add retry logic to PCE requests session

Version 0.8.2 (2022-03-14)
--------------------------

* add tests for PCE URL parsing
* improve documentation
    * add README and CONTRIBUTING docs
    * add copyright and license header to all modules
    * add docstrings for PolicyComputeEngine functions, improve URL parsing
* add UnmodifiableObject class for PolicyVersion (create only)
* change IllumioObject to inherit from Reference
* update parsing in traffic query blocks to simplify builder
* raise IllumioException if invalid protocol name is passed to BaseService subclass
* deprecate convert_protocol function in favour of baking proto conversion into service post_init
* add PolicyObjectType enum
* add parse_url function to improve handling of PCE url arg
* default to draft version of rulesets when creating rules

Version 0.8.1 (2022-03-09)
--------------------------

* overhaul complex type decoding by centralizing logic in JsonObject
* update test cases
* add changelog

Version 0.8.0 (2022-03-03)
--------------------------

* add deprecation decorator
* deprecate get_by_name in favor of broader collection get logic
* add get_ruleset function
* add create_ip_list function
* add ip list tests
* overhaul tests to improve mock logic
* remove duplication in async job calls

Version 0.7.3 (2022-02-22)
--------------------------

* fix get_workloads to correctly use max_results
* update_workload_enforcement_modes can now batch process any number of requested workloads
* fix LabelSet internal type as workload repr can use full Label objects
* improve logic for traffic analysis timestamp conversion
* add classifiers to setup config
* fix license copyright

Version 0.7.2 (2022-01-25)
--------------------------

* update dependencies to remove dataclass req for python versions above 3.6
* fix exception thrown when HTTP error responses don't contain content-type header

Version 0.7.1 (2022-01-07)
--------------------------

* update core json decode functionality to allow for arbitrary parameters not represented in the dataclass definitions for forward compatibility
* change builder function to properly represent traffic query blocks for src/dst/services
* fix representation of selectively_enforced_services param and add num_enforcement_boundaries

Version 0.7.0 (2022-01-06)
--------------------------

* add basic test shells for rules/rulesets
* fix type of service binding workload param
* change json encode default behaviour to improve recursive encoding in cases with complex nested objects
* change connection check to use /health endpoint

Version 0.6.5 (2021-12-20)
--------------------------

* improve get_workloads logic and add check_connection function
* fix traffic flow state error message and incorrect value for timeout state

Version 0.6.4 (2021-11-29)
--------------------------

* add get_workloads function and refactor how default header/params are set

Version 0.6.3 (2021-11-21)
--------------------------

* update Rule builder to allow multiple ingress_service input types

Version 0.6.2 (2021-11-20)
--------------------------

* add set_proxies function to set request session proxies

Version 0.6.1 (2021-11-19)
--------------------------

* allow unix timestamps as valid inputs for start/end dates in traffic analysis queries
* fix x_by reference nesting

Version 0.6.0 (2021-11-18)
--------------------------

* add Rule object builder function and improve HREF regex
* add helper function to convert draft href to active
* move base classes to jsonutils module to avoid circular refs
* fix get_by_name function and improve request error logic
* ignore DS_Store files on mac

Version 0.5.5 (2021-11-18)
--------------------------

* remove get_by_name duplication and simplify calls by working around active/draft duplicate results
* add submodule shortcuts back to root imports
* add update_workload_enforcement_modes function

Version 0.5.4 (2021-11-17)
--------------------------

* add enforcement boundary PCE functions and fix issues with get_by_name and create_service_binding functions
* update rule ingress_services decoding to correctly identify between Service/ServicePort
* add draft and active policy version constants
* improve create_service_binding logic and add create_service_bindings function for batch creation

Version 0.5.3 (2021-11-17)
--------------------------

* separate out base rule class for use with enforcement boundaries
* flesh out Service object structure
* fix IP list convenience functions
* move caps property to ModifiableObject class; add missing type decoding to Rules

Version 0.5.2 (2021-11-16)
--------------------------

* add Reference class for simple href representations in more complex objects
* add IP list convenience methods and create_rule PCE function
* add actor submodule to rules module exports

Version 0.5.1 (2021-11-16)
--------------------------

* fix test imports
* move secpolicy to package root and remove root shortcuts for submodule imports; clean up project imports

Version 0.5.0 (2021-11-16)
--------------------------

* flesh out rules and rulesets and add create_ruleset PCE function
* add SecurityPrincipal policy object skeleton

Version 0.4.2 (2021-11-16)
--------------------------

* remove UserObject in favour of the more generic ModifiableObject as workloads and other objects can be created/modified by non-user entities (e.g. agents)

Version 0.4.1 (2021-11-16)
--------------------------

* add missing fields needed to decode workload objects; implement get_workload PCE function
* remove custom fields for workload open_service_ports objects in favour of new class
* change Network class to IllumioObject subtype
* add VisibilityLevel enum

Version 0.4.0 (2021-11-16)
--------------------------

* fix policy provisioning and add PolicyVersion object
* flesh out IPList class and add get_ip_list PCE function
* move common external_data_set and external_data_reference params into IllumioObject base class
* move modification params to UserObject
* add missing fields for ServiceBinding and PortOverride classes
* add create_service_binding function and dependent objects
* fix PCE functions to send objects rather than JSON strings
* provide more detailed error messages in case of API exceptions
* remove name requirement for virtual service init; change apply_to default to None
* fix broken build function and add error case
* add policy provision API call and dependent objects
* add LabelSet object type
* move enums to constants util module and improve validation logic

Version 0.3.0 (2021-11-11)
--------------------------

* create more descriptive modules and move submodules from policyobjects
* change core object structure to use IllumioObject base class
* move JsonObject class to jsonutils
* standardize formatting for complex type decoding
* use IllumioEncoder rather than directly calling to_json

Version 0.2.0 (2021-11-10)
--------------------------

* add async traffic flow function and builder function for traffic queries
* flesh out traffic analysis flow objects and add decode test
* flesh out workload object definition and subclasses
* add containercluster and vulnerabilityreport module stubs
* define extendable base enum class for package-wide use
* add Network and Vulnerability stubs for workloads
* add params to Service to accommodate Workload open_service_ports object definition
* add delete_type param to base PolicyObject
* add _validate function called from post_init in base JsonObject class
* add virtualserver stub module
* shift date validation to the API so we don't have to worry about ISO format conversion (fromisoformat isn't introduced until 3.9) or timezones
* simplify creation of query objects
* add validation for start and end dates
* add query_name field for async queries
* add traffic analysis query structure dataclasses
* add workload and iplist module stubs
* use UserObject base class and simplify init logic for simple reference cases
* combine service objects into single module and simplify class structures
* add User object and separate UserObject base class for user-created policy objects
* use socket lib function rather than custom protocol enum for conversion to int
* move JsonObject base class into policyobject module
* add pytest cache to gitignore

Version 0.1.1 (2021-11-07)
--------------------------

* improve virtual service tests
* overhaul policy object structures and improve json encoding/decoding
* remove api module

Version 0.1.0 (2021-11-04)
--------------------------

* initial commit
