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
