# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

illumio-py is a Python REST API client library for the Illumio Policy Compute Engine (PCE). It provides a typed, dataclass-based object model for all PCE resources with CRUD operations, bulk actions, policy provisioning, traffic analysis (Explorer), access management, authentication, reporting, settings, label mapping, and VEN lifecycle management.

The library covers **56 registered API endpoints** with automatic CRUD and **67 custom methods** for specialized operations across 14 subpackages.

## Common Commands

```bash
make init                  # Install dependencies
make test                  # Run tox tests across Python 3.6-3.11
make coverage              # Run pytest with coverage
make docs                  # Build Sphinx docs
pytest tests/unit/         # Run unit tests only
pytest tests/unit/test_label.py  # Run a single test file
pytest -k "test_name"      # Run a specific test by name
pytest --integration       # Run integration tests (requires env vars below)
```

### Integration Test Environment Variables
```
ILLUMIO_PCE_HOST, ILLUMIO_PCE_PORT, ILLUMIO_PCE_ORG_ID,
ILLUMIO_API_KEY_USERNAME, ILLUMIO_API_KEY_SECRET
```

## Architecture

### Object Model Hierarchy (illumio/util/jsonutils.py)

All PCE objects are dataclasses with custom JSON serialization:

```
JsonObject (ABC - to_json/from_json)
├── Reference (just an href)
└── IllumioObject (+ name/description)
    ├── MutableObject (+ created_at/updated_at/deleted_at) — most PCE objects
    └── ImmutableObject (+ created_at)
```

Each object overrides `_validate()` for custom validation and `_decode_complex_types()` for nested object deserialization.

### Dynamic API Registration (illumio/util/functions.py -> illumio/pce.py)

The `@pce_api()` decorator registers dataclass types as API endpoints in a global `PCE_APIS` dict:

```python
@dataclass
@pce_api('labels', endpoint='/labels')
class Label(MutableObject): ...
```

When you access `pce.labels`, `PolicyComputeEngine.__getattr__` looks up the registered API and returns a `_PCEObjectAPI` instance that provides generic CRUD: `.get()`, `.create()`, `.update()`, `.delete()`, `.bulk_create()`, etc.

### Policy Versioning

Security policy objects (rules, rulesets, enforcement boundaries, virtual services, virtual servers, firewall settings) exist in ACTIVE or DRAFT versions. Endpoints are prefixed with `/sec_policy/{active|draft}/`. The `is_sec_policy=True` flag in `@pce_api()` controls this. Helper functions convert between active/draft hrefs.

### Organization Scoping

Most endpoints are scoped to `/orgs/{org_id}/...`. Global endpoints (users, authentication settings, system events) set `is_global=True` in `@pce_api()`.

### Nested Endpoints

Some endpoints are nested under parent paths. The `endpoint` parameter in `@pce_api()` specifies the full path:

```python
@pce_api('event_settings', endpoint='/settings/events')    # /orgs/{id}/settings/events
@pce_api('ldap_configs', endpoint='/authentication_settings/ldap_configs', is_global=True)
```

---

## Registered API Endpoints (56 total)

All registered APIs get automatic CRUD via `pce.<api_name>.get()`, `.create()`, `.update()`, `.delete()`.

### Policy Objects (`is_sec_policy=True`)

| Class | API Name | Notes |
|---|---|---|
| `Label` | `labels` | endpoint='/labels' |
| `LabelGroup` | `label_groups` | |
| `IPList` | `ip_lists` | |
| `Service` | `services` | |
| `VirtualService` | `virtual_services` | |
| `VirtualServer` | `virtual_servers` | |
| `RuleSet` | `rule_sets` | |
| `EnforcementBoundary` | `enforcement_boundaries` | |
| `FirewallSetting` | `firewall_settings` | GET/PUT only |

### Rules (under RuleSets)

| Class | API Name | Notes |
|---|---|---|
| `Rule` | `rules` | endpoint='/sec_rules' |
| `DenyRule` | `deny_rules` | endpoint='/deny_rules', nested under a ruleset via `parent=`. Single deny-rule object; `override=True` makes it an override-deny rule (precedence: override-deny > allow > deny) |
| `OverrideDenyRule` | _(not registered)_ | Builder convenience only (`build()` defaults `override=True`); created via `pce.deny_rules.create(OverrideDenyRule.build(...), parent=ruleset)`. No separate `pce.override_deny_rules` collection |

### Workloads & VENs

| Class | API Name |
|---|---|
| `Workload` | `workloads` |
| `VEN` | `vens` |
| `PairingProfile` | `pairing_profiles` |
| `SecurityPrincipal` | `security_principals` |
| `ServiceBinding` | `service_bindings` |

### Infrastructure

| Class | API Name |
|---|---|
| `ContainerCluster` | `container_clusters` |
| `ContainerWorkloadProfile` | `container_workload_profiles` |
| `NetworkDevice` | `network_devices` |
| `NetworkEndpoint` | `network_endpoints` |
| `NetworkEnforcementNode` | `network_enforcement_nodes` |
| `SLB` | `slbs` |
| `DiscoveredVirtualServer` | `discovered_virtual_servers` |
| `KubernetesWorkload` | `kubernetes_workloads` |

### Vulnerabilities

| Class | API Name |
|---|---|
| `Vulnerability` | `vulnerabilities` |
| `VulnerabilityReport` | `vulnerability_reports` |

### Reporting & Monitoring

| Class | API Name | Notes |
|---|---|---|
| `Event` | `events` | |
| `Job` | `jobs` | |
| `Report` | `reports` | |
| `ReportSchedule` | `report_schedules` | |
| `ReportTemplate` | `report_templates` | |
| `CoreServiceType` | `core_service_types` | |
| `DetectedCoreService` | `detected_core_services` | |
| `SupportBundleRequest` | `support_bundle_requests` | |
| `SystemEvent` | `system_events` | `is_global=True` |

### Settings

| Class | API Name | Endpoint |
|---|---|---|
| `OrgSettings` | `org_settings` | `/settings` |
| `EventSettings` | `event_settings` | `/settings/events` |
| `ReportSettings` | `report_settings` | `/settings/reports` |
| `SyslogDestination` | `syslog_destinations` | `/settings/syslog/destinations` |
| `TrafficCollectorSetting` | `traffic_collector_settings` | `/settings/traffic_collector` |
| `TrustedProxyIPs` | `trusted_proxy_ips` | `/settings/trusted_proxy_ips` |
| `WorkloadSettings` | `workload_settings` | `/settings/workloads` |
| `OptionalFeature` | `optional_features` | (default) |

### Access Management

| Class | API Name | Notes |
|---|---|---|
| `User` | `users` | `is_global=True` |
| `Role` | `roles` | |
| `Permission` | `permissions` | |
| `ServiceAccount` | `service_accounts` | |
| `AuthSecurityPrincipal` | `auth_security_principals` | |
| `AccessRestriction` | `access_restrictions` | |

### Authentication (`is_global=True`)

| Class | API Name | Endpoint |
|---|---|---|
| `AuthenticationSettings` | `authentication_settings` | (default) |
| `LDAPConfig` | `ldap_configs` | `/authentication_settings/ldap_configs` |
| `SAMLConfig` | `saml_configs` | `/authentication_settings/saml_configs` |
| `PasswordPolicy` | `password_policy` | `/authentication_settings/password_policy` |

### Label Mapping & App Groups

| Class | API Name |
|---|---|
| `LabelMappingRule` | `label_mapping_rules` |
| `AppGroupSummary` | `app_group_summary` |

---

## Custom Methods on PolicyComputeEngine (67 total)

These are methods on `PolicyComputeEngine` (in `illumio/pce.py`) for operations that go beyond standard CRUD.

### Core Operations

| Method | Description |
|---|---|
| `check_connection()` | Tests connectivity to the PCE |
| `get_default_ip_list()` | Gets the "Any (0.0.0.0/0 and ::/0)" IP list |
| `get_default_service()` | Gets the "All Services" service |
| `generate_pairing_key(pairing_profile_href)` | Generates a pairing key |
| `provision_policy_changes(change_description, hrefs)` | Provisions draft policy objects |
| `get_traffic_flows_async(query_name, traffic_query)` | Async Explorer traffic flow query |

### Security Policy Operations

| Method | Description |
|---|---|
| `get_pending_policy_changes()` | Gets unprovisioned policy changes |
| `discard_pending_policy_changes()` | Discards all pending changes |
| `get_policy_dependencies(hrefs, policy_version)` | Gets dependencies for policy objects |
| `get_modified_policy_objects(policy_version)` | Gets objects modified since last provisioning |
| `check_policy(policy_version)` | Runs policy validation check |
| `get_policy_allow(policy_version)` | Gets allowed policy for a version |
| `analyze_policy_impact(hrefs)` | Analyzes impact of provisioning |
| `restore_policy(policy_version)` | Restores a policy version |
| `bulk_delete_policy_objects(hrefs)` | Bulk deletes policy objects |
| `search_rules(query, policy_version)` | Searches rules by query |

### Access Management & Authentication

| Method | Description |
|---|---|
| `create_service_account_api_key(sa_href)` | Creates API key for service account |
| `delete_service_account_api_key(sa_href, key_id)` | Deletes service account API key |
| `get_user_api_keys(user_id)` | Gets API keys for a user |
| `create_user_api_key(user_id)` | Creates API key for a user |
| `delete_user_api_key(user_id, key_id)` | Deletes a user API key |
| `get_org_api_keys()` | Gets all org API keys |
| `delete_org_api_key(key_id)` | Deletes an org API key |
| `verify_ldap_connection(ldap_href)` | Verifies LDAP server connectivity |
| `login_user(username, password)` | Authenticates a user |

### Infrastructure & Network Devices

| Method | Description |
|---|---|
| `request_enforcement_instructions(device_href)` | Requests enforcement instructions |
| `apply_enforcement_instructions(device_href, data)` | Reports applied enforcement instructions |
| `multi_enforcement_instructions_request(data)` | Bulk enforcement instructions request |
| `multi_enforcement_instructions_applied(data)` | Bulk enforcement instructions applied |
| `get_container_service_backends(cluster_href)` | Gets container service backends |

### Reporting

| Method | Description |
|---|---|
| `download_report(report_href)` | Downloads a completed report |
| `get_risk_summary()` | Gets risk summary report |
| `get_detected_core_services_summary()` | Gets detected core services summary |

### VEN Lifecycle Actions

| Method | Description |
|---|---|
| `unpair_vens(ven_hrefs, firewall_restore)` | Unpairs VENs from PCE |
| `upgrade_vens(ven_hrefs, release)` | Upgrades VENs to a release |
| `ven_remote_action(ven_hrefs, action)` | Remote action on VENs |
| `ven_auth_recovery(ven_hrefs)` | VEN authentication recovery |
| `get_ven_statistics(ven_hrefs)` | Gets VEN statistics |
| `get_ven_software_releases()` | Lists VEN software releases |
| `get_ven_software_release(release)` | Gets a specific release |
| `delete_ven_software_release(release)` | Deletes a release |
| `set_default_ven_release(release)` | Sets default VEN release |
| `get_ven_release_images(release)` | Gets images for a release |

### Workload Operations

| Method | Description |
|---|---|
| `get_workload_interfaces(workload_href)` | Gets workload network interfaces |
| `create_workload_interface(workload_href, interface)` | Creates a workload interface |
| `delete_workload_interface(workload_href, iface_name)` | Deletes a workload interface |
| `get_workload_risk_details(workload_href)` | Gets workload risk details |
| `unpair_workloads(workload_hrefs, firewall_restore)` | Unpairs workloads from PCE |
| `bulk_import_workloads(data)` | Bulk imports workloads |

### Label Group Sub-queries

| Method | Description |
|---|---|
| `get_label_group_all_labels(lg_href)` | Gets all labels recursively |
| `get_label_group_member_of(lg_href)` | Gets parent label groups |

### Label Mapping Operations

| Method | Description |
|---|---|
| `reorder_label_mapping_rule(rule_href, position)` | Reorders a mapping rule |
| `bulk_delete_label_mapping_rules(hrefs)` | Bulk deletes mapping rules |
| `bulk_update_label_mapping_rules(rules)` | Bulk updates mapping rules |
| `run_label_mapping_rules(data)` | Runs label mapping rules |
| `get_label_mapping_job(job_uuid)` | Gets mapping job status |
| `assign_label_mapping_labels(job_uuid, data)` | Assigns labels from mapping job |
| `download_label_mapping_results(job_uuid)` | Downloads mapping results |

### Miscellaneous

| Method | Description |
|---|---|
| `get_product_version()` | Gets PCE product version |
| `get_node_available()` | Checks PCE node availability |
| `get_supercluster_leader()` | Gets supercluster leader |
| `get_app_group_risk_summary()` | App group risk summary |
| `get_app_group_risk_details(app_group_id)` | App group risk details |
| `get_traffic_flow_db_metrics()` | Traffic flow DB metrics |
| `get_async_queries()` | Lists async traffic queries |
| `delete_async_query(uuid)` | Deletes an async query |
| `download_async_query(uuid)` | Downloads async query results |
| `update_async_query_rules(uuid, data)` | Updates async query rules |

---

## Key Modules

| Module | Purpose |
|---|---|
| `illumio/pce.py` | Core `PolicyComputeEngine` client, `_PCEObjectAPI` CRUD, 67 custom methods |
| `illumio/util/jsonutils.py` | Base dataclass hierarchy, JSON encoding/decoding |
| `illumio/util/functions.py` | `@pce_api` decorator, `validate_int`, `deprecated` |
| `illumio/util/constants.py` | Enums (`EnforcementMode`, `Visibility`, etc.) and constants |
| `illumio/secpolicy.py` | `FirewallSetting`, `PolicyDependency`, `PolicyCheck`, `ModifiedObject` |
| `illumio/policyobjects/` | Label, LabelGroup, IPList, Service, VirtualService, VirtualServer |
| `illumio/rules/` | Rule, DenyRule, OverrideDenyRule, RuleSet, EnforcementBoundary |
| `illumio/workloads/` | Workload, VEN, PairingProfile |
| `illumio/explorer/` | TrafficQuery, TrafficFlow, TrafficNode (Explorer API) |
| `illumio/infrastructure/` | ContainerCluster, NetworkDevice, NetworkEndpoint, NEN, SLB, DVS, K8s |
| `illumio/vulnerabilities/` | Vulnerability, VulnerabilityInstance, VulnerabilityReport |
| `illumio/accessmanagement/` | User, Role, Permission, ServiceAccount, AuthSecurityPrincipal, AccessRestriction |
| `illumio/authentication/` | AuthenticationSettings, LDAPConfig, SAMLConfig, PasswordPolicy |
| `illumio/reporting/` | Job, Report, ReportSchedule, ReportTemplate, CoreServiceType, DetectedCoreService, SupportBundleRequest, SystemEvent |
| `illumio/settings/` | OrgSettings, EventSettings, ReportSettings, SyslogDestination, TrafficCollectorSetting, TrustedProxyIPs, WorkloadSettings, OptionalFeature |
| `illumio/labelmapping/` | LabelMappingRule |
| `illumio/appgroups/` | AppGroupSummary |
| `illumio/events.py` | Event |

## Code Conventions

- **Style**: Google Python Style Guide. UTF-8 encoding marker at top of files. Google-style docstrings.
- **Dataclass defaults**: All fields default to `None` for optional fields.
- **Decorator order**: `@dataclass` first, then `@pce_api(...)`.
- **Type annotations**: Use `typing.List[T]` (not bare `list`) for dataclass fields that need nested decoding. Bare `list` breaks `_decode_complex_types()` on Python 3.14+.
- **Exports**: Each module defines `__all__`. Main `__init__.py` re-exports everything.
- **Enums**: Custom `IllumioEnumMeta` metaclass for string-based enums.
- **Exceptions**: `IllumioException` (base), `IllumioApiException` (API errors with parsed PCE messages).
- **Testing**: pytest + requests-mock for HTTP mocking. Test data in `tests/data/`. Integration tests gated behind `--integration` marker.
- **Versioning**: `setuptools_scm` generates `illumio/_version.py` from git tags.

## Adding a New API Resource

1. Create/update dataclass in the appropriate module under `illumio/`:
   - Inherit from `MutableObject` (read-write) or `JsonObject`/`Reference` (read-only)
   - Add `@dataclass` then `@pce_api('api_name', endpoint='/path', is_sec_policy=?, is_global=?)` decorators
   - Define fields with `= None` defaults
   - Override `_decode_complex_types()` for nested objects
   - Override `_validate()` for enum/range constraints
2. Update the subpackage `__init__.py` to export the new class
3. Update `illumio/__init__.py` if adding a new subpackage
4. Add test data JSON fixture in `tests/data/`
5. Add unit test in `tests/unit/`
6. Add custom `pce.py` methods only for non-CRUD operations (sub-endpoints, actions)

**Key reference files:**
- Pattern template: `illumio/policyobjects/label.py`
- Complex example: `illumio/policyobjects/virtualservice.py`
- Decorator impl: `illumio/util/functions.py` (`@pce_api`)
- Generic CRUD: `illumio/pce.py` (`_PCEObjectAPI`)
- Dynamic lookup: `illumio/pce.py` (`PolicyComputeEngine.__getattr__`)
