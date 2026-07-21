#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Create, read, update, and delete labels, and group them.

WRITES: creates labels and a label group, then deletes them again.
"""
from illumio import Label, LabelGroup

from _common import connect


def main():
    pce = connect()

    # Create labels across a couple of dimensions (role/app/env/loc).
    role = pce.labels.create(Label(key="role", value="R-Example-Web"))
    app = pce.labels.create(Label(key="app", value="A-Example-Shop"))
    print("Created:", role.href, app.href)

    # Look one up by its key/value.
    found = pce.labels.get(params={"key": "role", "value": "R-Example-Web"})
    print("Lookup by key/value returned:", len(found), "label(s)")

    # Update a label's value.
    pce.labels.update(role, {"value": "R-Example-Web-Tier"})
    print("Updated role label value.")

    # Group labels of the same dimension for reuse in policy scopes/rules.
    env_a = pce.labels.create(Label(key="env", value="E-Example-Staging"))
    env_b = pce.labels.create(Label(key="env", value="E-Example-Dev"))
    group = pce.label_groups.create(
        LabelGroup(name="LG-Example-NonProd", key="env", labels=[env_a, env_b])
    )
    print("Created label group:", group.href)

    # Clean up.
    pce.label_groups.delete(group)
    for label in (role, app, env_a, env_b):
        pce.labels.delete(label)
    print("Cleaned up example labels and group.")


if __name__ == "__main__":
    main()
