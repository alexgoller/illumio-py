#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Build an allow policy end to end: labels -> ruleset -> rule.

WRITES: creates draft labels, a ruleset, and an allow rule, then deletes them.
Direction reminder: consumers are the *sources* that initiate connections to
providers (the *destinations*).
"""
from illumio import Label, LabelSet, RuleSet, Rule

from _common import connect


def main():
    pce = connect()

    # Scope labels for the ruleset (app / env / loc define where it applies).
    app = pce.labels.create(Label(key="app", value="A-Example-Shop"))
    env = pce.labels.create(Label(key="env", value="E-Example-Prod"))
    loc = pce.labels.create(Label(key="loc", value="L-Example-AWS"))
    web = pce.labels.create(Label(key="role", value="R-Example-Web"))
    db = pce.labels.create(Label(key="role", value="R-Example-DB"))

    ruleset = pce.rule_sets.create(
        RuleSet(name="RS-Example-Shop", scopes=[LabelSet(labels=[app, env, loc])])
    )
    print("Created ruleset:", ruleset.href)

    # Allow the web tier (consumers/source) to reach the DB tier (providers/dest)
    # on PostgreSQL.
    rule = Rule.build(
        providers=[db],
        consumers=[web],
        ingress_services=[{"port": 5432, "proto": "tcp"}],
    )
    rule = pce.rules.create(rule, parent=ruleset)
    print("Created allow rule:", rule.href)

    # (To enforce, provision the ruleset — see 10_provisioning.py.)

    # Clean up the drafts.
    pce.rule_sets.delete(ruleset)
    for label in (web, db, app, env, loc):
        pce.labels.delete(label)
    print("Cleaned up example ruleset, rule, and labels.")


if __name__ == "__main__":
    main()
