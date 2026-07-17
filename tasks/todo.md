# Deny / Override-Deny Rules — Correctness Fix

Part of the spec-conformance audit (`docs/superpowers/specs/2026-07-17-spec-conformance-audit-design.md`).
Branch: `spec-conformance-audit`.

## Problem

The Feb-2026 fork addition modeled deny rules incorrectly (never released, never
validated against a real PCE):

- Deny rules placed at a bogus top-level `/sec_policy/draft/deny_rules/N`.
  Real Illumio: deny rules live **only** nested under a ruleset
  (`/sec_policy/{pversion}/rule_sets/{id}/deny_rules`).
- Invented `priority` field on deny rules (Illumio precedence is by rule *type*).
- Invented `overrides` href-list on override-deny rules (it's a rule *type*, not a pointer).
- Invented `Rule.action` (allow/deny/override_deny) conflating three separate endpoints.

Enforcement boundaries are dead (per user); everything is Rulesets and Rules.

## Correct model

`DenyRule` and `OverrideDenyRule` are plain ruleset-nested rule types, identical in
shape to an allow `Rule`: providers, consumers, ingress_services, enabled,
resolve_labels_as (+ inherited name/description/timestamps). They differ only by
which nested endpoint they post to (`deny_rules` vs `override_deny_rules`).

## Tasks (TDD: red → green)

- [x] Rewrite mock fixtures to the correct model (ruleset-nested hrefs, no priority/overrides)
      - [x] `tests/data/deny_rules.json`
      - [x] `tests/data/override_deny_rules.json`
      - [x] `tests/data/rule_sets.json` (nested rules sanitized)
- [x] Rewrite `tests/unit/test_unit_deny_rules.py` to assert correct model (RED)
      - [x] deny/override rules created & fetched via `parent=ruleset`
      - [x] assert NO `priority` / `overrides` fields
      - [x] drop `TestRuleActions` (action removed)
- [x] Update `tests/unit/test_unit_rules.py` — remove `action` expectations (RED)
- [x] Update `tests/unit/test_unit_rule_sets.py` — remove priority/overrides assertions
- [x] Implement (GREEN):
      - [x] `illumio/rules/rule.py`: remove `Rule.action` + RuleAction usage;
            rewrite DenyRule/OverrideDenyRule to shared `_DenyRuleBase`; fix docstrings
      - [x] keep `RuleAction` enum exported in constants (unused, compat)
- [x] Full unit suite green + doctests (333 passed)
- [x] Update CLAUDE.md deny-rule notes

## Review

**Outcome:** Deny and override-deny rules now model the real Illumio API.

Behavioral proof (captured request bodies/URLs via requests_mock):
- `pce.deny_rules.create(rule, parent=ruleset)` → `POST /orgs/1/sec_policy/draft/rule_sets/3/deny_rules`
- `pce.override_deny_rules.create(rule, parent=ruleset)` → `.../rule_sets/3/override_deny_rules`
- Bodies contain only real fields (providers, consumers, ingress_services, enabled,
  resolve_labels_as) — no `priority`, `overrides`, `override`, or `action`.

**Removed (Feb-2026 hallucinations, never released):** `DenyRule.priority`,
`DenyRule.override`, `OverrideDenyRule.overrides`, `Rule.action` + its RuleAction
validation, and the bogus top-level `/sec_policy/draft/deny_rules/N` hrefs.

**Kept for compatibility:** the `RuleAction` enum stays exported from
`illumio.util.constants` (now unused by the library).

**Deferred to Phase 2 (live PCE):** confirm the exact deny-rule field set
(e.g. whether `network_type` / `unscoped_consumers` apply) against real responses.

**Note:** `tests/unit/mocks.py` still lists unused `sec_deny_rules`/
`sec_override_deny_rules` entries in `OBJECT_TYPE_REF_MAP` — harmless, left as-is.

---

## Second pass — validated against authoritative schema files (user-provided)

The user supplied `webservices-v2-experimental-26.3.0/` with the real JSON schema
files. Validating against `common/deny_rules_get.schema.json` showed my first pass
had the *endpoint* right but several *fields* wrong. Corrected:

- **`override` (bool) is a REAL field** — it is what makes an override-deny rule.
  Re-added. (My first pass wrongly removed it.)
- **`resolve_labels_as` is NOT a deny-rule field** — removed (it's allow-rule only).
- **Added** schema fields: `egress_services` (List[Service]),
  `all_ips_except_for_in_consumers`, `all_ips_except_for_in_providers`.
- Kept: enabled, network_type, unscoped_consumers (+ inherited href/description/
  timestamps/caps).

**Model shape (user-approved):** one `DenyRule` object with an `override` flag;
`OverrideDenyRule` is a thin convenience whose `build()` defaults `override=True`.
Both register the same `/deny_rules` nested endpoint.

**Schema conformance proof:** every one of the 20 `deny_rules_get` properties maps
to a `DenyRule` field (0 missing). `Rule.action` removal also confirmed correct —
the real allow `sec_rule` schema has no `action` field.

**Behavioral proof:** `DenyRule` → `POST …/rule_sets/3/deny_rules` (override=false);
`OverrideDenyRule` → same endpoint (override=true).

---

## Third pass — LIVE PCE validation (read-only)

User provided `.env` with real PCE access (SaaS, poc4.illum.io). Read-only GET probes
confirmed the model is 100% correct:

- `GET …/rule_sets/{id}/deny_rules` → 200; real keys EXACTLY match the DenyRule model
  (`override`, `egress_services`, `all_ips_except_*`, network_type, unscoped_consumers,
  ... — no priority/name/resolve_labels_as/overrides).
- `GET …/rule_sets/{id}/override_deny_rules` → **404** — confirms there is NO separate
  override-deny endpoint; OverrideDenyRule correctly routes to `/deny_rules`.
- Real ruleset embeds a single `deny_rules` array (holds both kinds) and has **no
  `override_deny_rules` field** → removed `RuleSet.override_deny_rules`; deny_rules now
  holds override rules (flagged by `override`).
- `pce.deny_rules.get(parent=ruleset)` returns typed DenyRule objects; round-trip leaks
  no invented fields. `enforcement_boundaries` endpoint exists but is empty (dead).

Full unit suite: 333 passed. Deny rules are DONE and live-validated.

**Env note:** venv has a stale non-editable `illumio` in site-packages shadowing the
working tree for out-of-repo scripts; use PYTHONPATH or `pip install -e .`.

---

## Tier 1 audit fixes (backwards-compatible, additive) — DONE

From `tasks/spec-audit-report.md`. All additive; full suite: 336 passed.

- **`labels` duplicate** — FALSE POSITIVE (audit regex matched the `@pce_api`
  example inside the decorator's docstring). No code change; fixed the audit tool
  to only match column-0 decorators.
- **`Rule`** — added `all_ips_except_for_in_consumers`, `all_ips_except_for_in_providers`,
  `use_workload_subnets` (schema) + `egress_services` (present on live PCE though the
  bundled schema omits it). **Live-validated** against real allow rules.
- **`Workload`** — added `managed`, `datacenter_nat_1to1`, and typed nested
  `risk_summary` (RiskSummary/Ransomware) + `container_policy_convergence_status`
  (ContainerPolicyConvergenceStatus). Strengthened the previously-weak
  "decoded as dict" tests to assert typed decoding. Schema-validated + decode tests
  (this PCE tenant has 0 workloads, so no live sample).
- **`VEN`** — added `authentication_recovery`, `golden_image`,
  `upgrade_target_version`, `upgrade_expires_at`. Schema-validated + decode tests
  (0 VENs on this tenant).

Re-run audit confirms rules/workloads/vens have no remaining missing Tier-1 fields.
