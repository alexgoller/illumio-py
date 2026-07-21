#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Connect to the PCE and read a few basic facts. Read-only."""
from _common import connect


def main():
    pce = connect()
    print("Connected to the PCE (org {}).".format(pce.org_id))

    # A cheap read to confirm the API works end to end.
    labels = pce.labels.get(params={"max_results": 5})
    print("First few labels:")
    for label in labels:
        print("  {}={}  {}".format(label.key, label.value, label.href))

    # Count workloads without pulling them all back.
    workloads = pce.workloads.get(params={"max_results": 1})
    print("Workloads reachable:", "yes" if workloads is not None else "no")


if __name__ == "__main__":
    main()
