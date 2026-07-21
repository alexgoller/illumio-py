#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Query the traffic database (Explorer) for flows matching criteria. Read-only."""
from illumio.explorer import TrafficQuery

from _common import connect


def main():
    pce = connect()

    # Find potentially-blocked RDP/SSH flows in a time window.
    query = TrafficQuery.build(
        start_date="2024-01-01T00:00:00Z",
        end_date="2024-02-01T00:00:00Z",
        include_services=[
            {"port": 22, "proto": "tcp"},
            {"port": 3389, "proto": "tcp"},
        ],
        policy_decisions=["blocked", "potentially_blocked", "unknown"],
    )

    # The async endpoint runs the query as a PCE job and polls until complete.
    flows = pce.get_traffic_flows_async(
        query_name="example-blocked-admin-traffic",
        traffic_query=query,
    )
    print("Matching flows:", len(flows))
    for flow in flows[:10]:
        src = getattr(flow.src, "ip", None) if flow.src else None
        dst = getattr(flow.dst, "ip", None) if flow.dst else None
        print("  {} -> {}  {}".format(src, dst, getattr(flow, "policy_decision", "")))


if __name__ == "__main__":
    main()
