#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Query workloads and create/label/enforce an unmanaged workload.

WRITES: creates one unmanaged workload and deletes it at the end.
"""
from illumio import Label, Workload
from illumio.util import EnforcementMode

from _common import connect


def main():
    pce = connect()

    # Filtered read: managed workloads in visibility-only mode.
    managed = pce.workloads.get(params={"managed": True, "enforcement_mode": "visibility_only",
                                        "max_results": 5})
    print("Managed, visibility-only workloads (first 5):", len(managed))
    for w in managed:
        print("  {}  {}".format(w.hostname, w.href))

    # Create an unmanaged workload to represent something the PCE doesn't have a
    # VEN on (a network device, a SaaS endpoint, etc.).
    role = pce.labels.create(Label(key="role", value="R-Example-NTP"))
    ntp = pce.workloads.create(
        Workload(
            name="Example NTP",
            hostname="ntp0.example.com",
            public_ip="10.9.0.5",
            labels=[role],
        )
    )
    print("Created unmanaged workload:", ntp.href)

    # Move it into full enforcement.
    pce.workloads.update(ntp, Workload(enforcement_mode=EnforcementMode.FULL))
    print("Set enforcement_mode=full.")

    # Clean up.
    pce.workloads.delete(ntp)
    pce.labels.delete(role)
    print("Cleaned up example workload and label.")


if __name__ == "__main__":
    main()
