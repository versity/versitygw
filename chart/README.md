# versitygw Helm Chart

Versity is an S3-compatible storage gateway that proxies S3 API requests to a variety of backend storage systems.

> **Note**: the chart is currently in development state and breaking changes (with regards to the Helm values structure or the chart behavior) may occur until we reach a 1.0 release of the Helm chart.

## Overview

[versitygw](https://github.com/versity/versitygw) is an S3-compatible gateway that fronts POSIX filesystems, ScoutFS, S3, Azure Blob Storage, or custom plugin backends. This chart deploys versitygw on Kubernetes as a Deployment and Service, with optional support for TLS termination, Ingress, HTTPRoutes, certificate provisioning (via `cert-manager` CRDs), IAM, an Admin API, a browser-based WebUI, persistent storage, and NetworkPolicy.

## Prerequisites

- Kubernetes **1.19+**
- Helm **3.8+** (OCI registry support)
- optional: [cert-manager](https://cert-manager.io/) (required when any of `certificate.create`, `iam.standalone.certificate.create`, or `iamServer.private.certificate.create` is enabled)

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

The `gateway.backend.type` value selects the storage backend. Use `gateway.backend.args` to pass backend-specific arguments. For the POSIX sidecar metadata store and POSIX/ScoutFS object versioning, prefer `gateway.backend.sidecarDir` and `gateway.backend.versioningDir`; the chart mounts those directories from persistent storage and wires the corresponding backend environment variables automatically.

| Backend | Description | Example `gateway.backend.args` |
|---------|-------------|--------------------------------|
| [posix](https://github.com/versity/versitygw/wiki/POSIX-Backend) | POSIX-compatible local or network filesystem (default) | `/mnt/data` |
| [scoutfs](https://github.com/versity/versitygw/wiki/ScoutFS-Backend) | [ScoutFS](https://scoutfs.org/) high-performance filesystem | `/mnt/scoutfs` |
| [s3](https://github.com/versity/versitygw/wiki/S3-Backend) | Proxy to an existing S3-compatible object store | `--access KEY --secret SECRET --endpoint https://s3.example.com` |
| [azure](https://github.com/versity/versitygw/wiki/AzureBlob-Backend) | Azure Blob Storage | `--account myaccount --key mykey` |
| [plugin](https://github.com/versity/versitygw/wiki/Plugin-Backend) | Custom backend via shared library plugin | `/path/to/plugin.so` |

Example for POSIX with sidecar metadata:

```yaml
gateway:
  backend:
    type: posix
    args: /mnt/data
    sidecarDir: /mnt/metadata
```

Example for POSIX or ScoutFS with object versioning enabled:

```yaml
gateway:
  backend:
    type: posix
    args: /mnt/data
    versioningDir: /mnt/versioning
```

## Optional Features

| Feature | Key values |
|---------|------------|
| **TLS** | `tls.enabled=true` — serve HTTPS; supply a TLS Secret via `certificate.secretName` or let cert-manager provision one |
| **cert-manager** | `certificate.create=true`, `certificate.issuerRef`, `certificate.dnsNames` |
| **Ingress** | `ingress.enabled=true`, `ingress.className`, `ingress.hosts`, `ingress.tls` |
| **HTTPRoute** | `httpRoute.enabled=true` — Gateway API successor to Ingress for S3 API; also `admin.httpRoute.enabled=true` and `webui.httpRoute.enabled=true` to expose the admin API and/or WebUI |
| **Admin API** | `admin.enabled=true` — exposes a separate management API on `admin.port` (default `7071`) |
| **WebUI** | `webui.enabled=true` — browser-based management UI on `webui.port` (default `8080`); set `webui.apiGateways` and `webui.adminGateways` to your externally reachable endpoints, and `webui.iamGateways` when `iam.type=standalone` so the login page offers the IAM service (the WebUI then ignores the admin API entirely — the IAM service manages users, and buckets are managed over the S3 API) |
| **Website Hosting** | `website.enabled=true` — static website hosting endpoint on `website.port` (default `8090`); optionally set `website.domain` for virtual-host routing (e.g. `example.com`), or omit it for catch-all mode where the full hostname is the bucket name |
| **IAM** | `iam.enabled=true` — identity and access management. `iam.type=internal` (default) stores accounts in a flat file alongside backend data; `iam.type=standalone` delegates to a separate standalone IAM API service — see [Standalone IAM Service](#standalone-iam-service) below |
| **Persistence** | `persistence.enabled=true` — provisions a PVC for backend data and IAM storage; defaults to `10Gi`, or uses a hostPath volume specified by `persistence.hostPath` |
| **NetworkPolicy** | `networkPolicy.enabled=true` — restricts ingress to selected pods/namespaces; allows all egress |
| **Debug logging** | `gateway.logLevel` — `silent` (default), `debug` (request/response logging, secrets masked), or `unsafe` (unmasked, local troubleshooting only) |
| **Scheduling** | `nodeSelector`, `affinity`, `tolerations`, and `topologySpreadConstraints` — control pod placement and spread replicas across nodes/zones for high availability |

## Standalone IAM Service

In addition to `iam.type=internal` (flat-file IAM stored inside the gateway pod), the chart can deploy the standalone IAM API server — an AWS-compatible IAM Query API — as its own Deployment with separate public and private Services, and configure one or more gateways to use it via `iam.type=standalone`.

```yaml
iam:
  enabled: true
  type: standalone
  standalone:
    # Left empty here: auto-targets the in-chart private IAM Service below.
    certificate:
      create: true
      issuerRef:
        kind: ClusterIssuer
        name: internal-ca

iamServer:
  enabled: true
  storage:
    type: internal   # or vault
  private:
    certificate:
      create: true
      issuerRef:
        kind: ClusterIssuer
        name: internal-ca
```

Key points:

- **Independent scaling**: `iamServer` is a separate Deployment (`iamServer.replicaCount`), so it can be centralized and scaled independently of the gateway. Manage users/roles/policies against its public control-plane API (`iamServer.port`, default `7070`) using the AWS CLI/SDK. It reuses the gateway root Secret by default; set `iamServer.auth.existingSecret` to separate the control-plane identity, and point `iam.standalone.credentials.existingSecret` at the corresponding client identity.
- **Storage**: `iamServer.storage.type` is `internal` (file-backed, needs `iamServer.persistence`, is limited to one replica, and always uses a `Recreate` rollout) or `vault` (`iamServer.storage.vault.*`, centralized and required if `iamServer.replicaCount > 1`).
- **Separate Services**: `iamServer.service.type` applies only to the public control-plane Service. The private listener is exposed by a separate, always-`ClusterIP` Service, so selecting `NodePort` or `LoadBalancer` does not publish the private port. Enable `iamServer.tls` before exposing the public API outside a trusted network.
- **Private mTLS endpoint**: gateways reach the standalone IAM service over a private endpoint (`iamServer.private.port`, default `7443`) that always requires mutual TLS on TCP. Provide certificates either via `existingSecret` (bring your own `tls.crt`/`tls.key`/`ca.crt`) or `certificate.create=true` to auto-provision via cert-manager.
- **Shared CA requirement**: when using cert-manager auto-provisioning, `iamServer.private.certificate.issuerRef` and `iam.standalone.certificate.issuerRef` **must reference the same CA-type issuer** (an `Issuer`/`ClusterIssuer` of kind `CA`, or a Vault issuer) — one that populates `ca.crt` in the resulting Secret. Both sides verify their peer using their own certificate's `ca.crt`, which only works when both certificates share the same issuing CA.
- **External IAM service**: to point a gateway at a standalone IAM service deployed outside this chart (or by a separate chart release), set `iam.standalone.endpoint` to its `host:port` and provide the mTLS material via `iam.standalone.certificate.existingSecret`.
- **WebUI access**: to manage IAM users from the WebUI, set `webui.iamGateways` to the URL a browser can reach `iamServer` on, and `iamServer.corsAllowOrigin` to the WebUI's own origin. Every WebUI call to the IAM API is cross-origin, so without `corsAllowOrigin` the browser blocks it and the WebUI's IAM navigation silently never appears.
- **Secret rotation**: the processes load mTLS material and environment-based credentials at startup. After a referenced Secret rotates, restart both Deployments or configure a Secret-reloader controller through `deploymentAnnotations` and `iamServer.deploymentAnnotations`.

## Scaling and Persistence

By default, this chart enables persistence via a `PersistentVolumeClaim` (PVC) to ensure data consistency and prevent data loss. 

Alternatively, you may use [hostPath volume](https://kubernetes.io/docs/concepts/storage/volumes/#hostpath) by setting the `persistence.hostPath` value.
As a general rule, this setup should only be used if all nodes in the cluster have access to the same data (e.g. NFS share is mounted on all nodes) or for single-node use cases.
Special care must be taken particularly when using multiple replicas with such a setup, since Versity does not perform internal data replication ("clustering").

### Horizontal Scaling (replicas > 1)

When scaling `versitygw` horizontally by setting `replicaCount` greater than 1, special care must be taken regarding the storage backend:

- **POSIX**: This backend stores state on the filesystem.
    - Using **ReadWriteOnce (RWO)**: All replicas must be scheduled on the **same Kubernetes node** to share the same volume. This is useful for process-level concurrency (e.g., when using high-performance local block storage) but limits high availability across nodes.
    - Using **ReadWriteMany (RWX)**: Replicas can be distributed across **multiple nodes** in the cluster. This is the recommended approach for true horizontal scaling and high availability. When using RWX, it is also recommended to use pod anti-affinity (via `affinity` in `values.yaml`) or topology spread constraints (via `topologySpreadConstraints` in `values.yaml`) to ensure pods are distributed across nodes/zones.
- **IAM**: `iam.type=internal` is limited to a single gateway replica because its file store does not coordinate concurrent writers. Use standalone IAM with Vault storage, LDAP, Vault-direct, or another external IAM backend before scaling the gateway above one replica.
- **Stateless Backends (S3, Azure)**: If you are using a stateless storage backend (e.g. proxying to another S3 store) **and** you are either not using IAM or using an external IAM provider (e.g. LDAP, Vault), persistence can be safely disabled by setting `persistence.enabled=false`.

### Deployment Strategy

By default, the `RollingUpdate` [strategy](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#strategy) is used.
If **ReadWriteOnce (RWO)** volumes are used and pods may be scheduled onto different nodes, rollouts may become 
stuck because the replacement pod cannot start. Consider setting `strategy.type=Recreate` in this case.

## Configuration

See [`values.yaml`](./values.yaml) for the full list of parameters and their defaults.
