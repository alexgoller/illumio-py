# illumio-py Spec-Conformance Audit & Test Hardening — Design

**Date:** 2026-07-17
**Author:** Alex Goller (with Claude Code)
**Status:** Draft — awaiting review

---

## 1. Context

`illumio-py` is a typed, dataclass-based REST client for the Illumio PCE. A recent
bulk expansion (commits `4403c74`, `104263a`, `8a456fd`) added broad coverage of the
OpenAPI **25.2.10** spec but appears partly machine-generated and imperfectly correct:

- A **duplicate `labels` registration** (`@pce_api('labels')` and `@pce_api('labels', endpoint='/labels')`).
- **`deny_rules` / `override_deny_rules` registered at bogus top-level paths** (`/deny_rules`,
  `/override_deny_rules`) instead of the real nested ruleset sub-endpoint — and even the
  CLAUDE.md docs (`/sec_deny_rules`) disagree with the code.
- A commit (`8a456fd`) that had to hand-fix settings dataclasses because the generated
  models did not match **actual PCE responses** — evidence the spec/generation can drift
  from reality.

Baseline is healthy: **345 unit tests pass**, 57 registered `@pce_api` endpoints, 79 public
`PolicyComputeEngine` methods. The vendored spec (`illumio-v2-openapi-experimental-25.2.10.json`)
has **186 paths / 304 operations** and **208 component schemas**.

## 2. Goal

Two objectives, chosen by the user:

1. **Correctness audit** — validate every dataclass field, enum, and endpoint registration
   against the OpenAPI 25.2.10 schemas; fix mismatches, wrong paths, and duplicate/incorrect
   registrations.
2. **Test hardening** — add spec-driven tests that make conformance *provable* and guard
   against future drift.

**Constraint: preserve backwards compatibility.** This is a published fork. Additive and
corrective changes only. Deprecate rather than remove. No public class/method renames, no
dropping Python 3.6.

## 3. Non-goals

- No architecture rewrite; keep the `@pce_api` / `_PCEObjectAPI` pattern.
- No building out missing endpoints beyond what correctness requires (coverage gaps are
  *reported*, not built — the user decides later).
- No public API renames or packaging/Python-version changes.

## 4. First-class requirement: Deny & Override-Deny Rules

The user explicitly needs `DenyRule` and `OverrideDenyRule` working correctly. These are
**absent from the experimental spec**, so they cannot be validated against it. They will be
resolved authoritatively via:

- **Now:** public Illumio REST API documentation (web research) + the existing `Rule`
  pattern. `Rule` registers `endpoint='/sec_rules'` and is created with `parent=ruleset`,
  yielding `/orgs/{org}/sec_policy/{pversion}/rule_sets/{id}/sec_rules`. Deny rules must
  mirror this: correct the endpoint name (expected `/sec_deny_rules` /
  `/sec_override_deny_rules`, to be confirmed) and ensure they are created nested under a
  ruleset — not at a top-level path.
- **Later (Phase 2):** confirmed against the live PCE (see §8).

The fix removes the bogus top-level registration paths; the public attribute names
(`pce.deny_rules`, `pce.override_deny_rules`) are preserved, so this is corrective, not
breaking.

## 5. Approach — Spec-driven audit tooling + human-judged fixes

Rejected alternatives: manual per-module review (slow, unrepeatable, misses fields across
57 models); full codegen (would erase intentional deviations like the hand-fixed settings
and the deny rules, and breaks compatibility). Chosen approach keeps human judgment while
mechanizing the exhaustive diff and leaving a permanent regression guard.

### 5.1 Audit engine — `tools/spec_audit.py`

- Load the spec; resolve `$ref`s.
- **Normalizer:** map each `@pce_api(name, endpoint, is_sec_policy, is_global)` registration
  to its spec path(s), accounting for the `/orgs/{org_id}` and `/sec_policy/{pversion}`
  prefixes and `is_global` (no org scope). Confirmed feasible against `labels`, `services`,
  `workloads`, `sec_rules` during design.
- **Schema resolution:** for each resource pick the canonical schema (instance-GET 200
  response body). Introspect the dataclass's fields (names, annotated types, nested types).
- **Diff → classified findings:**
  - `missing_field` — spec property absent from the dataclass (→ additive fix, safe)
  - `extra_field` — dataclass field not in spec (→ keep; flag; may be real/deprecated/experimental)
  - `type_mismatch` — annotated type disagrees with schema type
  - `enum_mismatch` — dataclass/validator enum values differ from schema `enum`
  - `endpoint_mismatch` — registration path can't be resolved to a real spec path
  - `duplicate_registration` — same API name registered twice
  - `spec_resource_uncovered` — spec path group with no registered API (reported only)
- **Output:** structured JSON + a human-readable markdown report.

### 5.2 Fix phase

Work module-by-module (parallel subagents, one subpackage each, to keep main context clean).
Rules:

- Add missing fields with `None` defaults; add nested decoding + `_validate()` where needed.
- Fix wrong types/enums; fix wrong endpoint paths; remove duplicate decorators (same public
  attribute → non-breaking).
- **Never delete** a library feature merely because it is absent from the *experimental*
  spec (e.g. deny rules).
- Every intentional difference is recorded in an explicit **`KNOWN_DEVIATIONS`** allowlist
  with a one-line reason — nothing is silently ignored.

### 5.3 Test hardening

- `tests/unit/test_spec_conformance.py` — permanent, parametrized over all registered APIs:
  - every registration resolves to a real spec path (deny rules exempted via allowlist);
  - no duplicate registrations;
  - every spec-`required` property has a corresponding dataclass field;
  - enum values match the schema.
  - Any deviation must appear in `KNOWN_DEVIATIONS` (with reason) or the test fails.
- **Round-trip tests** from spec `example`s where present: `from_json(ex).to_json()`
  preserves keys.
- Dedicated `DenyRule` / `OverrideDenyRule` tests (endpoint resolution via `parent=ruleset`,
  build/validate, nesting under RuleSet).
- All 345 existing tests + doctests (`--doctest-modules`) stay green.

## 6. Classification & the KNOWN_DEVIATIONS allowlist

The audit distinguishes three truths, not one:

1. Library **missing** spec content → fix additively.
2. Library **diverges** (wrong type/enum/path/dup) → fix correctively.
3. Library has content **not in spec** (deny rules, hand-fixed settings) → keep, and record
   in `KNOWN_DEVIATIONS` with rationale so the conformance test passes deliberately, not
   accidentally.

## 7. Deliverables

- Corrected models and `@pce_api` registrations (backwards-compatible).
- `tools/spec_audit.py` (repeatable) + `tests/unit/test_spec_conformance.py` (regression guard).
- Correct, tested `DenyRule` / `OverrideDenyRule`.
- An **audit report** (`tasks/spec-audit-report.md`) listing every finding and its disposition.
- Updated CLAUDE.md API tables if counts/paths change.

## 8. Two-phase execution

- **Phase 1 — now (offline):** everything above, resolving deny rules from public docs.
- **Phase 2 — later (live PCE, read-only):** when the user has PCE access, validate models
  against real GET responses and confirm the deny-rule endpoint, via the existing
  `--integration` harness. Any real-vs-spec differences get folded into `KNOWN_DEVIATIONS`.

## 9. Risks & mitigations

- **Experimental spec diverges from real PCE** (already seen with settings, deny rules). →
  The tool *reports*; humans decide. `KNOWN_DEVIATIONS` captures intentional differences.
  Phase 2 live validation is the backstop.
- **Backwards-compat regressions.** → Additive fields only; corrective path fixes keep public
  names; full existing test suite must stay green; changes reviewed module-by-module.
- **Type-annotation mapping ambiguity** (bare `list` vs `List[T]`, `$ref` unions). → Normalizer
  handles known cases; ambiguous ones are reported for human review rather than auto-fixed.

## 10. Success criteria

- Audit report enumerates every registration and its conformance status.
- Conformance test passes with an explicit, reasoned `KNOWN_DEVIATIONS` list.
- Deny/override-deny rules resolve to the correct nested ruleset endpoint and are tested.
- Duplicate `labels` registration removed; no bogus endpoint paths remain.
- All pre-existing tests + doctests still pass; new tests added.
