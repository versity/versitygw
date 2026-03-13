# versitygw Helm Chart

Versity is an S3-compatible storage gateway that proxies S3 API requests to a variety of backend storage systems.

> **Note**: the chart is currently in development state and breaking changes (with regards to the Helm values structure or the chart behavior) may occur until we reach a 1.0 release of the Helm chart.

## Overview

[versitygw](https://github.com/versity/versitygw) is an S3-compatible gateway that fronts POSIX filesystems, ScoutFS, S3, Azure Blob Storage, or custom plugin backends. This chart deploys versitygw on Kubernetes as a Deployment and Service, with optional support for TLS termination, Ingress, HTTPRoutes, certificate provisioning (via `cert-manager` CRDs), IAM, an Admin API, a browser-based WebUI, persistent storage, and NetworkPolicy.

## Prerequisites

- Kubernetes **1.19+**
- Helm **3.8+** (OCI registry support)
- optional: [cert-manager](https://cert-manager.io/) (only required if `certificate.create=true`)

## Installation

Basic installation (single user mode) with [posix backend](https://github.com/versity/versitygw/wiki/POSIX-Backend):

```bash
helm install my-versitygw oci://ghcr.io/versity/versitygw/charts/versitygw \
  --set auth.accessKey=myaccesskey \
  --set auth.secretKey=mysecretkey \
  --set gateway.backend.type=posix \
  --set persistence.enabled=true
```

> **Production note:** Passing credentials via `--set` stores them in Helm's release history. For production deployments, create a Kubernetes Secret in advance and reference it with `auth.existingSecret=<secret-name>`. The Secret must contain the keys `rootAccessKeyId` and `rootSecretAccessKey`.

## Upgrading

The versioning of this Helm chart and of `versitygw` itself are currently not coupled to each other.

By default, the Helm chart uses the `latest` tag for the versitygw container image.
For production and multi-replica deployment, it is strongly recommended to always pin a specific version, like so:

```yaml
# values.yaml

image:
  repository: ghcr.io/versity/versitygw
  tag: "v1.2.0"
```

To upgrade the `versitygw` version, only the `image.tag` value needs to be adjusted and the Helm charts needs to be re-deployed (with the same values), e.g.:

```sh
helm upgrade my-versitygw oci://ghcr.io/versity/versitygw/charts/versitygw \
  --reuse-values \
  --set image.tag=v1.3.1
```

To upgrade only the Helm chart, use the following command:

```sh
helm upgrade my-versitygw oci://ghcr.io/versity/versitygw/charts/versitygw \
  --reuse-values \
  --version 0.2.0
```

You can find the list of available Helm chart versions in the [GitHub packages page](https://github.com/versity/versitygw/pkgs/container/versitygw%2Fcharts%2Fversitygw/versions?filters%5Bversion_type%5D=tagged).

## Backend Storage

The `gateway.backend.type` value selects the storage backend. Use `gateway.backend.args` to pass backend-specific arguments.

| Backend | Description | Example `gateway.backend.args` |
|---------|-------------|--------------------------------|
| [posix](https://github.com/versity/versitygw/wiki/POSIX-Backend) | POSIX-compatible local or network filesystem (default) | `/mnt/data` |
| [scoutfs](https://github.com/versity/versitygw/wiki/ScoutFS-Backend) | [ScoutFS](https://scoutfs.org/) high-performance filesystem | `/mnt/scoutfs` |
| [s3](https://github.com/versity/versitygw/wiki/S3-Backend) | Proxy to an existing S3-compatible object store | `--access KEY --secret SECRET --endpoint https://s3.example.com` |
| [azure](https://github.com/versity/versitygw/wiki/AzureBlob-Backend) | Azure Blob Storage | `--account myaccount --key mykey` |
| [plugin](https://github.com/versity/versitygw/wiki/Plugin-Backend) | Custom backend via shared library plugin | `/path/to/plugin.so` |

## Optional Features

| Feature | Key values |
|---------|------------|
| **TLS** | `tls.enabled=true` — serve HTTPS; supply a TLS Secret via `certificate.secretName` or let cert-manager provision one |
| **cert-manager** | `certificate.create=true`, `certificate.issuerRef`, `certificate.dnsNames` |
| **Ingress** | `ingress.enabled=true`, `ingress.className`, `ingress.hosts`, `ingress.tls` |
| **HTTPRoute** | `httpRoute.enabled=true` — Gateway API successor to Ingress for S3 API; also `admin.httpRoute.enabled=true` and `webui.httpRoute.enabled=true` to expose the admin API and/or WebUI |
| **Admin API** | `admin.enabled=true` — exposes a separate management API on `admin.port` (default `7071`) |
| **WebUI** | `webui.enabled=true` — browser-based management UI on `webui.port` (default `8080`); set `webui.apiGateways` and `webui.adminGateways` to your externally reachable endpoints |
| **IAM** | `iam.enabled=true` — flat-file identity and access management stored alongside backend data |
| **Persistence** | `persistence.enabled=true` — provisions a PVC for backend data and IAM storage; defaults to `10Gi`, or uses a hostPath volume specified by `persistence.hostPath` |
| **NetworkPolicy** | `networkPolicy.enabled=true` — restricts ingress to selected pods/namespaces; allows all egress |

## Scaling and Persistence

By default, this chart enables persistence via a `PersistentVolumeClaim` (PVC) to ensure data consistency and prevent data loss. 

Alternatively, you may use [hostPath volume](https://kubernetes.io/docs/concepts/storage/volumes/#hostpath) by setting the `persistence.hostPath` value.
As a general rule, this setup should only be used if all nodes in the cluster have access to the same data (e.g. NFS share is mounted on all nodes) or for single-node use cases.
Special care must be taken particularly when using multiple replicas with such a setup, since Versity does not perform internal data replication ("clustering").

### Horizontal Scaling (replicas > 1)

When scaling `versitygw` horizontally by setting `replicaCount` greater than 1, special care must be taken regarding the storage backend:

- **POSIX or Internal IAM**: These backends store state locally on the filesystem.
    - Using **ReadWriteOnce (RWO)**: All replicas must be scheduled on the **same Kubernetes node** to share the same volume. This is useful for process-level concurrency (e.g., when using high-performance local block storage) but limits high availability across nodes.
    - Using **ReadWriteMany (RWX)**: Replicas can be distributed across **multiple nodes** in the cluster. This is the recommended approach for true horizontal scaling and high availability. When using RWX, it is also recommended to use pod anti-affinity (via `affinity` in `values.yaml`) to ensure pods are distributed across nodes/zones.
- **Stateless Backends (S3, Azure)**: If you are using a stateless storage backend (e.g. proxying to another S3 store) **and** you are either not using IAM or using an external IAM provider (e.g. LDAP, Vault), persistence can be safely disabled by setting `persistence.enabled=false`.

## Configuration

See [`values.yaml`](./values.yaml) for the full list of parameters and their defaults.
