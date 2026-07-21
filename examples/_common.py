# -*- coding: utf-8 -*-

"""Shared connection helper for the illumio-py-open examples.

Reads PCE connection details from environment variables or a ``.env`` file in
the current directory:

    PCE_HOST, PCE_PORT (default 443), PCE_ORG_ID (default 1),
    API_KEY, API_SECRET

Usage in an example::

    from _common import connect
    pce = connect()
"""
import os
import sys

from illumio import PolicyComputeEngine


def load_env(path=".env"):
    """Merge a simple KEY=VALUE .env file into a dict, with os.environ winning."""
    values = {}
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    values[key.strip()] = value.strip().strip('"').strip("'")
    # environment variables take precedence over the .env file
    for key in ("PCE_HOST", "PCE_PORT", "PCE_ORG_ID", "API_KEY", "API_SECRET"):
        if os.environ.get(key):
            values[key] = os.environ[key]
    return values


def connect(env_path=".env"):
    """Return an authenticated PolicyComputeEngine, or exit with a helpful error."""
    env = load_env(env_path)
    missing = [k for k in ("PCE_HOST", "API_KEY", "API_SECRET") if not env.get(k)]
    if missing:
        sys.exit(
            "Missing required connection settings: {}.\n"
            "Set them as environment variables or in a .env file "
            "(PCE_HOST, PCE_PORT, PCE_ORG_ID, API_KEY, API_SECRET).".format(", ".join(missing))
        )
    pce = PolicyComputeEngine(
        env["PCE_HOST"], port=env.get("PCE_PORT", "443"), org_id=env.get("PCE_ORG_ID", "1")
    )
    pce.set_credentials(env["API_KEY"], env["API_SECRET"])
    if not pce.check_connection():
        sys.exit("Could not connect to the PCE at {}".format(env["PCE_HOST"]))
    return pce
