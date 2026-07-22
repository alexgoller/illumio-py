#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Onboard many unmanaged workloads and label them — the rate-limit-safe way.

This is the common "sync" use case: you have a list of things (load balancers,
network devices, cloud instances) to represent in the PCE as unmanaged workloads,
each with a set of labels.

The efficient, rate-limit-safe pattern is:

  1. Fetch all existing labels ONCE and build a {(key, value): Label} map.
  2. Resolve/create each workload's labels from that map (only create the
     missing ones) — no per-label GET in a loop.
  3. Create the workloads with ``bulk_create`` (one call for the whole batch).

Doing a ``GET /labels?key=..&value=..`` for every label of every workload is what
triggers HTTP 429 rate-limit errors at scale — this avoids it entirely.

WRITES: creates labels (only missing ones) and a batch of unmanaged workloads,
then cleans up the workloads it created.
"""
from illumio import Label, Workload

from _common import connect


# The inventory you want to represent as unmanaged workloads. In a real job this
# comes from your CMDB / config files / cloud API.
INVENTORY = [
    {"name": "lb-web-01",   "hostname": "lb-web-01.example.com",   "public_ip": "10.30.0.11",
     "labels": {"role": "R-LoadBalancer", "app": "A-Shop", "env": "E-Prod", "loc": "L-AWS"}},
    {"name": "lb-web-02",   "hostname": "lb-web-02.example.com",   "public_ip": "10.30.0.12",
     "labels": {"role": "R-LoadBalancer", "app": "A-Shop", "env": "E-Prod", "loc": "L-AWS"}},
    {"name": "lb-api-01",   "hostname": "lb-api-01.example.com",   "public_ip": "10.30.1.11",
     "labels": {"role": "R-LoadBalancer", "app": "A-API",  "env": "E-Prod", "loc": "L-AWS"}},
    {"name": "cache-01",    "hostname": "cache-01.example.com",    "public_ip": "10.30.2.11",
     "labels": {"role": "R-Cache", "app": "A-Shop", "env": "E-Prod", "loc": "L-AWS"}},
]


def build_label_caches(pce):
    """Fetch every label once and build two caches for O(1) lookups both ways:

    - ``by_href``: ``{href: Label}``          — href -> key/value (label.key, label.value)
    - ``by_kv``:   ``{(key, value): Label}``   — (key, value) -> href (label.href)

    One request instead of one per label lookup. For very large orgs,
    ``pce.labels.get_async()`` runs it as a single PCE job.
    """
    all_labels = pce.labels.get(params={"max_results": 100000})
    by_href = {label.href: label for label in all_labels}
    by_kv = {(label.key, label.value): label for label in all_labels}
    return by_href, by_kv


def get_or_create_label(pce, by_href, by_kv, key, value):
    """Resolve a label from the (key, value) cache, creating it only if missing.
    Keeps both caches current so later lookups stay accurate."""
    label = by_kv.get((key, value))
    if label is None:
        label = pce.labels.create(Label(key=key, value=value))
        by_kv[(key, value)] = label
        by_href[label.href] = label
    return label


def main():
    pce = connect()

    # 1) Prefetch labels once into two caches (href<->key/value).
    by_href, by_kv = build_label_caches(pce)
    print("Prefetched {} existing labels.".format(len(by_kv)))

    # Example lookups both directions:
    #   (key, value) -> href :  by_kv[('role', 'R-Web')].href
    #   href -> value        :  by_href['/orgs/1/labels/1'].value

    # 2) Build the workload objects, resolving labels from the caches. Note we
    #    attach full Label objects directly to Workload(labels=...); the client
    #    flattens each Reference to {"href": ...} when serializing.
    workloads = []
    for item in INVENTORY:
        label_refs = [
            get_or_create_label(pce, by_href, by_kv, key, value)
            for key, value in item["labels"].items()
        ]
        workloads.append(Workload(
            name=item["name"],
            hostname=item["hostname"],
            public_ip=item["public_ip"],
            labels=label_refs,
        ))

    # 3) Create the whole batch in one call. bulk_create returns per-item results;
    #    check for errors rather than assuming success.
    results = pce.workloads.bulk_create(workloads)
    created = [r.get("href") for r in results if isinstance(r, dict) and r.get("href")]
    errors = [r for r in results if isinstance(r, dict) and r.get("errors")]
    print("Created {} unmanaged workloads; {} error(s).".format(len(created), len(errors)))
    for href in created:
        print("  ", href)
    for err in errors:
        print("  ERROR:", err.get("errors"))

    # Clean up the workloads this example created (leaves labels in place).
    if created:
        pce.workloads.bulk_delete(created)
        print("Cleaned up example workloads.")


if __name__ == "__main__":
    main()
