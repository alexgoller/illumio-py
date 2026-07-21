#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""The draft -> active provisioning workflow.

WRITES: creates a draft label group, reviews pending changes, then provisions
it to active policy. (Provisioning applies changes to enforced policy.)
"""
from illumio import Label, LabelGroup

from _common import connect


def main():
    pce = connect()

    # Create a draft policy object.
    env = pce.labels.create(Label(key="env", value="E-Example-QA"))
    group = pce.label_groups.create(
        LabelGroup(name="LG-Example-QA", key="env", labels=[env])
    )
    print("Created draft label group:", group.href)

    # Review what's pending before committing.
    pending = pce.get_pending_policy_changes()
    print("Pending policy changes:", len(pending) if pending is not None else 0)

    # See what else must be provisioned alongside it.
    deps = pce.get_policy_dependencies([group.href])
    print("Dependencies:", deps)

    # Provision the draft to active. Returns the new policy version.
    version = pce.provision_policy_changes(
        change_description="Add QA environment label group (example)",
        hrefs=[group.href],
    )
    print("Provisioned. Policy version:", getattr(version, "href", version))

    # (To roll back the example, delete the group and re-provision, or use
    #  pce.discard_pending_policy_changes() before provisioning.)


if __name__ == "__main__":
    main()
