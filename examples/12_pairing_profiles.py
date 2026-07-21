#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Create a pairing profile and generate a pairing key to onboard VENs.

WRITES: creates a pairing profile and generates one pairing key, then deletes
the profile. A pairing key is a short-lived secret used to pair a new VEN.
"""
from illumio import PairingProfile

from _common import connect


def main():
    pce = connect()

    # A pairing profile defines the default labels/enforcement for VENs paired
    # with its key.
    profile = pce.pairing_profiles.create(
        PairingProfile(
            name="PP-Example-Servers",
            enabled=True,
            enforcement_mode="visibility_only",
        )
    )
    print("Created pairing profile:", profile.href)

    # Generate a one-time pairing key from the profile.
    key = pce.generate_pairing_key(profile.href)
    token = key.get("activation_code") if isinstance(key, dict) else key
    print("Generated pairing key (use it in the VEN pairing script):",
          (str(token)[:8] + "...") if token else key)

    # Clean up. (Do NOT print/store real pairing keys in logs.)
    pce.pairing_profiles.delete(profile)
    print("Cleaned up example pairing profile.")


if __name__ == "__main__":
    main()
