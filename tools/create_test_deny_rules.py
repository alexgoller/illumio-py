#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Create a test deny rule and override-deny rule on a DRAFT ruleset.

Safe to run against a test PCE: everything is created in *draft* policy, which
is NOT enforced until you explicitly provision it. Nothing here provisions.

    python tools/create_test_deny_rules.py           # create the test rules
    python tools/create_test_deny_rules.py --cleanup # delete them again
    python tools/create_test_deny_rules.py --env /path/to/.env

Reads PCE connection info from a .env file (default: ./.env) with keys:
    PCE_HOST, PCE_PORT, PCE_ORG_ID, API_KEY, API_SECRET

Requires the client:  pip install illumio-py-open
"""
import argparse
import os
import sys

import illumio

RULESET_NAME = "TEST-illumio-py-open-deny-rules"


def load_env(path):
    env = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                env[key.strip()] = value.strip().strip('"').strip("'")
    missing = [k for k in ("PCE_HOST", "API_KEY", "API_SECRET") if not env.get(k)]
    if missing:
        sys.exit("Missing required keys in {}: {}".format(path, ", ".join(missing)))
    return env


def connect(env):
    pce = illumio.PolicyComputeEngine(
        env["PCE_HOST"], port=env.get("PCE_PORT", "443"), org_id=env.get("PCE_ORG_ID", "1")
    )
    pce.set_credentials(env["API_KEY"], env["API_SECRET"])
    if not pce.check_connection():
        sys.exit("Could not connect to the PCE at {}".format(env["PCE_HOST"]))
    return pce


def find_test_ruleset(pce):
    for rs in pce.rule_sets.get(policy_version="draft", params={"name": RULESET_NAME}):
        if rs.name == RULESET_NAME:
            return rs
    return None


def create(pce):
    ruleset = find_test_ruleset(pce)
    if ruleset:
        print("Reusing existing test ruleset: {}".format(ruleset.href))
    else:
        ruleset = pce.rule_sets.create(
            illumio.RuleSet(
                name=RULESET_NAME,
                description="Temporary ruleset created by the illumio-py-open test script.",
                scopes=[illumio.LabelSet(labels=[])],  # empty scope == applies to all
            )
        )
        print("Created draft ruleset: {}".format(ruleset.href))

    any_ip = pce.get_default_ip_list()  # the built-in "Any (0.0.0.0/0 and ::/0)" list

    # 1) A plain deny rule (override=False): block SSH (tcp/22) from anywhere to all workloads.
    deny = illumio.DenyRule.build(
        providers=[illumio.AMS],               # AMS == all workloads
        consumers=[any_ip.href],
        ingress_services=[{"port": 22, "proto": "tcp"}],
    )
    deny = pce.deny_rules.create(deny, parent=ruleset)
    print("Created deny rule          override={!s:<5} {}".format(deny.override, deny.href))

    # 2) An override-deny rule (override=True): highest precedence; block RDP (tcp/3389).
    override = illumio.OverrideDenyRule.build(
        providers=[illumio.AMS],
        consumers=[any_ip.href],
        ingress_services=[{"port": 3389, "proto": "tcp"}],
    )
    # override-deny rules are created through pce.deny_rules (no separate collection)
    override = pce.deny_rules.create(override, parent=ruleset)
    print("Created override-deny rule override={!s:<5} {}".format(override.override, override.href))

    print("\nDeny rules now in the ruleset (fetched back from the PCE):")
    for rule in pce.deny_rules.get(parent=ruleset, policy_version="draft"):
        kind = "override-deny" if rule.override else "deny"
        svcs = ", ".join(
            "{}/{}".format(getattr(s, "port", "?"), getattr(s, "proto", "?"))
            for s in (rule.ingress_services or [])
        )
        print("  - {:<14} enabled={!s:<5} services=[{}]  {}".format(kind, rule.enabled, svcs, rule.href))

    print("\nThese are DRAFT objects and are NOT enforced until the policy is provisioned.")
    print("Clean up with:  python {} --cleanup".format(sys.argv[0]))


def cleanup(pce):
    ruleset = find_test_ruleset(pce)
    if not ruleset:
        print("No test ruleset named '{}' found; nothing to clean up.".format(RULESET_NAME))
        return
    for rule in pce.deny_rules.get(parent=ruleset, policy_version="draft"):
        pce.deny_rules.delete(rule.href)
        print("Deleted rule    {}".format(rule.href))
    pce.rule_sets.delete(ruleset.href)
    print("Deleted ruleset {}".format(ruleset.href))


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--env", default=".env", help="path to the .env file (default: ./.env)")
    parser.add_argument("--cleanup", action="store_true", help="delete the test ruleset and its rules")
    args = parser.parse_args()

    if not os.path.exists(args.env):
        sys.exit(".env file not found at {} (use --env to point elsewhere)".format(args.env))

    pce = connect(load_env(args.env))
    print("Connected to PCE (org {}).\n".format(pce.org_id))

    if args.cleanup:
        cleanup(pce)
    else:
        create(pce)


if __name__ == "__main__":
    main()
