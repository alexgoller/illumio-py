#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Create IP lists and services (the building blocks for rules).

WRITES: creates draft IP list and service policy objects, then deletes them.
Note: these are draft security-policy objects — they are not enforced until
provisioned (see 10_provisioning.py).
"""
from illumio import IPList, IPRange, FQDN, Service, ServicePort

from _common import connect


def main():
    pce = connect()

    # An IP list groups CIDRs / ranges / FQDNs for use as a rule actor.
    ip_list = pce.ip_lists.create(
        IPList(
            name="IPL-Example-Corp",
            description="Example corporate ranges",
            ip_ranges=[
                IPRange(from_ip="10.0.0.0/8"),
                IPRange(from_ip="172.16.0.0", to_ip="172.31.255.255"),
            ],
            fqdns=[FQDN(fqdn="api.example.com")],
        )
    )
    print("Created IP list:", ip_list.href)

    # A service defines port/protocol combinations.
    service = pce.services.create(
        Service(
            name="S-Example-Web",
            service_ports=[
                ServicePort(port=80, proto="tcp"),
                ServicePort(port=443, proto="tcp"),
                ServicePort(port=8080, to_port=8089, proto="tcp"),  # a port range
            ],
        )
    )
    print("Created service:", service.href)

    # The PCE also ships built-in defaults you can reference directly.
    print("Default 'Any' IP list:", pce.get_default_ip_list().href)
    print("Default 'All Services':", pce.get_default_service().href)

    # Clean up the drafts.
    pce.services.delete(service)
    pce.ip_lists.delete(ip_list)
    print("Cleaned up example IP list and service.")


if __name__ == "__main__":
    main()
