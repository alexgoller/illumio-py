## Summary

The spec-conformance audit (`tools/spec_audit.py`, report in `tasks/spec-audit-report.md`)
found that the **settings & authentication models** diverge from the authoritative
Illumio schemas by *field renames* — they show both missing **and** extra fields for the
same model. Unlike the Tier‑1 additions (purely additive, already merged), these need
careful field-by-field reconciliation and should be validated against live PCE responses.

This issue tracks that "Tier 2" work. Not started yet — logged for later.

## Approach

For each model below:
1. Map each schema property to the existing model field (identify true renames vs genuinely
   new fields vs stale fields).
2. Add missing fields (additive). For renames, add the new schema name; keep the old name as
   a deprecated alias where feasible to preserve backwards compatibility.
3. Validate against real GET responses from a live PCE (settings/auth endpoints return data
   even on an empty tenant).
4. TDD: strengthen/extend unit tests; keep the full suite green.
5. Re-run `python tools/spec_audit.py` to confirm the model no longer diverges (or record
   intentional differences in a KNOWN_DEVIATIONS allowlist).

## Affected models & fields

### `ldap_configs`
- **missing from model** (add): `authentication_method`, `bind_distinguished_name`, `full_name_attribute`, `insecure_disable_tls_certificate_verification`, `is_bind_password_set`, `pce_fqdn`, `request_timeout_seconds`, `tls_ca_bundle`, `user_base_distinguished_name`, `user_base_filter`, `user_distinguished_name_pattern`, `user_memberof_attribute`, `username_attribute`
- **extra in model** (verify — likely rename/deprecate): `authentication_type`, `base_dn`, `bind_type`, `password`, `request_timeout`, `tls_enabled`, `user_dn`

### `saml_configs`
- **missing from model** (add): `authn_context`, `cluster_fqdn`, `consumer_logout_url`, `consumer_service_url`, `created_at`, `created_by`, `force_authn`, `idp_cert`, `idp_slo_target_url`, `idp_sso_target_url`, `issuer`, `name_identifier_format`, `pce_signing_cert`, `pce_signing_cert_expires_at`, `sign_authn_request`, `updated_at`, `updated_by`
- **extra in model** (verify — likely rename/deprecate): `certificate`, `issuer_url`, `pce_fqdn`, `slo_url`, `sso_url`

### `password_policy`
- **missing from model** (add): `expire_time_days`, `min_changed_characters`, `min_characters_per_type`, `require_type_lowercase`, `require_type_number`, `require_type_symbol`, `require_type_uppercase`, `updated_at`, `updated_by`
- **extra in model** (verify — likely rename/deprecate): `min_characters_for_change_of_password`, `require_type_count`

### `org_settings`
- **missing from model** (add): `cloud_secure_tenant_id`, `max_rule_search_provider_consumer_entities`, `total_internet_address_space`, `total_lateral_address_space`
- **extra in model** (verify — likely rename/deprecate): `automatic_clone_reactivation`, `clone_detection_enabled`, `format`, `label_display`

### `report_settings`
- **missing from model** (add): `max_queued_reports`, `report_retention_days`
- **extra in model** (verify — likely rename/deprecate): `max_report_size`

### `report_schedules`
- **missing from model** (add): `report_generation_frequency`, `scheduled_at`, `send_by_email`
- **extra in model** (verify — likely rename/deprecate): `enabled`, `report_type`, `schedule`, `send_to`

### `report_templates`
- **missing from model** (add): `enabled`, `report_parameters`, `show_in_ui`
- **extra in model** (verify — likely rename/deprecate): `format`, `template_type`

### `reports`
- **missing from model** (add): `generated_at`, `progress_percentage`, `send_by_email`
- **extra in model** (verify — likely rename/deprecate): `report_type`, `send_to`
## Context / references

- Design: `docs/superpowers/specs/2026-07-17-spec-conformance-audit-design.md`
- Audit tool + report: `tools/spec_audit.py`, `tasks/spec-audit-report.md`
- Authoritative schemas: `webservices-v2-experimental-26.3.0/` (v2/ + common/)
- Prior context: an earlier commit ("Fix settings dataclasses to match actual PCE API
  responses") partially addressed settings — this reconciles the rest against the schema.

**Constraint:** backwards-compatible (deprecate rather than remove; keep public names).
