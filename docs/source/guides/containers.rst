.. _guide-containers:

.. currentmodule:: illumio

Container clusters
==================

Container Clusters and Workloads
--------------------------------

The PCE can provide visibility and enforcement for Kubernetes and OpenShift
container orchestration clusters, representing them as :class:`ContainerCluster <illumio.infrastructure.ContainerCluster>`
objects. Container clusters in turn are made up of ``ContainerWorkload`` objects,
which are governed by :class:`ContainerWorkloadProfile <illumio.infrastructure.ContainerWorkloadProfile>`
objects.

While `Kubelink <https://docs.illumio.com/core/21.5/Content/Guides/kubernetes-and-openshift/deployment/deploy-kubelink-in-your-cluster.htm>`_
and `CVEN <https://docs.illumio.com/core/21.5/Content/Guides/kubernetes-and-openshift/deployment/deploy-c-vens-in-your-cluster.htm>`_
deployments must be installed in your Kubernetes or OpenShift cluster
separately, container cluster objects can be created using the **illumio**
library and used to pair these deployments.

.. note::
    When a container cluster is created through the API, the `container_cluster_token`
    is returned in the POST response. This token is only available after the
    object is created and cannot be retrieved via the API: make sure to store
    it in a secure, persistent form such as a Kubernetes or OpenShift Secret.

.. code-block:: python

    >>> container_cluster = ContainerCluster(
    ...     name='CC-GKE-Prod',
    ...     description='Production Kubernetes cluster on GCP'
    ... )
    >>> container_cluster = pce.container_clusters.create(container_cluster)
    >>> container_cluster
    ContainerCluster(
        href='/orgs/1/container_clusters/bba0aa4d-9613-4cf0-b51c-eeb598f2b0f4',
        name='CC-GKE-Prod',
        description='Production Kubernetes cluster on GCP',
        container_cluster_token='1_b7abea42cdade009ab68df7d8e2422749ea38cdbb31d5230bb08258358e58647',
        ...
    )
