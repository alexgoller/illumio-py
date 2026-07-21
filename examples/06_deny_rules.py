#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Create deny and override-deny rules within a ruleset.

WRITES: creates a draft ruleset with two deny rules, then deletes them.

There is a single deny-rule object with an ``override`` flag. Precedence is
override-deny > allow > deny. Override-deny rules are created through
``pce.deny_rules`` (there is no separate override_deny_rules collection).
Direction: consumers (sources) are blocked from reaching providers (destinations).
"""
from illumio import RuleSet, LabelSet, DenyRule, OverrideDenyRule, AMS

from _common import connect


def main():
    pce = connect()

    ruleset = pce.rule_sets.create(
        RuleSet(name="RS-Example-Deny", scopes=[LabelSet(labels=[])])  # empty scope = all
    )
    any_ip = pce.get_default_ip_list()
    print("Created ruleset:", ruleset.href)

    # Ordinary deny rule: block SSH from anywhere to all workloads.
    deny = DenyRule.build(
        providers=[AMS],               # all workloads (destinations)
        consumers=[any_ip.href],       # any source
        ingress_services=[{"port": 22, "proto": "tcp"}],
    )
    deny = pce.deny_rules.create(deny, parent=ruleset)
    print("Created deny rule (override={}): {}".format(deny.override, deny.href))

    # Override-deny rule: highest precedence, block RDP even if an allow rule exists.
    override = OverrideDenyRule.build(
        providers=[AMS],
        consumers=[any_ip.href],
        ingress_services=[{"port": 3389, "proto": "tcp"}],
    )
    override = pce.deny_rules.create(override, parent=ruleset)
    print("Created override-deny rule (override={}): {}".format(override.override, override.href))

    # A ruleset exposes both kinds in a single deny_rules array.
    fetched = pce.rule_sets.get_by_reference(ruleset.href)
    for r in (fetched.deny_rules or []):
        print("  deny_rules entry override={}  {}".format(r.override, r.href))

    # Clean up.
    pce.rule_sets.delete(ruleset)
    print("Cleaned up example ruleset and deny rules.")


if __name__ == "__main__":
    main()
