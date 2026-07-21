#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Bulk create/update/delete for high-volume changes.

WRITES: bulk-creates a handful of unmanaged workloads, then bulk-deletes them.
Bulk operations return a list of results (one per item), including any errors.
"""
from illumio import Workload

from _common import connect


def main():
    pce = connect()

    # Build a batch of unmanaged workloads.
    batch = [
        Workload(name="Example Host {}".format(i),
                 hostname="host{}.example.com".format(i),
                 public_ip="10.20.0.{}".format(i))
        for i in range(1, 6)
    ]

    # bulk_create returns per-item results; check for errors.
    results = pce.workloads.bulk_create(batch)
    print("bulk_create results:", len(results))
    created_hrefs = [r.get("href") for r in results if isinstance(r, dict) and r.get("href")]
    errors = [r for r in results if isinstance(r, dict) and r.get("errors")]
    print("  created:", len(created_hrefs), " errors:", len(errors))

    # Bulk delete them again by HREF.
    if created_hrefs:
        del_results = pce.workloads.bulk_delete(created_hrefs)
        print("bulk_delete results:", len(del_results))


if __name__ == "__main__":
    main()
