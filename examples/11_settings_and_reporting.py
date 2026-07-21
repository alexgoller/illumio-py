#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Read organization settings, security posture, and reporting endpoints. Read-only."""
from _common import connect


def _one(result):
    """Settings endpoints may return a singleton or a one-item list."""
    return result[0] if isinstance(result, list) and result else result


def main():
    pce = connect()

    org = _one(pce.org_settings.get())
    print("Org settings:")
    print("  clone_detection_enabled:", getattr(org, "clone_detection_enabled", None))
    print("  max_rule_search_provider_consumer_entities:",
          getattr(org, "max_rule_search_provider_consumer_entities", None))

    policy = _one(pce.password_policy.get())
    print("Password policy:")
    print("  min_length:", getattr(policy, "min_length", None))
    print("  expire_time_days:", getattr(policy, "expire_time_days", None))
    print("  require_type_number:", getattr(policy, "require_type_number", None))

    reports = _one(pce.report_settings.get())
    print("Report settings: retention_days={}, max_queued={}".format(
        getattr(reports, "report_retention_days", None),
        getattr(reports, "max_queued_reports", None)))

    templates = pce.report_templates.get()
    print("Report templates:", [t.name for t in (templates or [])])


if __name__ == "__main__":
    main()
