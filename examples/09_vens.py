#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Inspect VENs (the agents on workloads) and their software releases. Read-only.

The commented-out calls at the end perform VEN lifecycle actions (unpair,
upgrade) — uncomment only against VENs you intend to change.
"""
from _common import connect


def main():
    pce = connect()

    vens = pce.vens.get(params={"max_results": 10})
    print("VENs (first 10):", len(vens))
    for ven in vens:
        print("  {}  status={}  version={}  {}".format(
            ven.hostname, ven.status, ven.version, ven.href))

    # Available VEN software releases and the current default.
    releases = pce.get_ven_software_releases()
    print("VEN software releases:", releases if releases else "(none)")

    # Statistics for a batch of VENs.
    if vens:
        stats = pce.get_ven_statistics(ven_hrefs=[vens[0].href])
        print("Stats for first VEN:", stats)

    # --- Lifecycle actions (destructive — uncomment deliberately) ---
    # pce.upgrade_vens(ven_hrefs=[vens[0].href], release="23.5.0")
    # pce.unpair_vens(ven_hrefs=[vens[0].href], firewall_restore="default")


if __name__ == "__main__":
    main()
