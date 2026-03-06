# versitygw Helm Chart

Versity is an S3-compatible storage gateway that proxies S3 API requests to a variety of backend storage systems.

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

## Backend Storage

The `gateway.backend.type` value selects the storage backend. Use `gateway.backend.args` to pass backend-specific arguments.

| Backend | Description | Example `gateway.backend.args` |
|---------|-------------|-------------------------------|
| `posix` | POSIX-compatible local or network filesystem (default) | `/mnt/data` |
| `scoutfs` | [ScoutFS](https://scoutfs.org/) high-performance filesystem | `/mnt/scoutfs` |
| `s3` | Proxy to an existing S3-compatible object store | `--access KEY --secret SECRET --endpoint https://s3.example.com` |
| `azure` | Azure Blob Storage | `--account myaccount --key mykey` |
| `plugin` | Custom backend via shared library plugin | `/path/to/plugin.so` |

## Optional Features

| Feature | Key values |
|---------|-----------|
| **TLS** | `tls.enabled=true` — serve HTTPS; supply a TLS Secret via `certificate.secretName` or let cert-manager provision one |
| **cert-manager** | `certificate.create=true`, `certificate.issuerRef`, `certificate.dnsNames` |
| **Ingress** | `ingress.enabled=true`, `ingress.className`, `ingress.hosts`, `ingress.tls` |
| **HTTPRoute** | `httpRoute.enabled=true` — Gateway API successor to Ingress for S3 API; also `admin.httpRoute.enabled=true` and `webui.httpRoute.enabled=true` to expose the admin API and/or WebUI |
| **Admin API** | `admin.enabled=true` — exposes a separate management API on `admin.port` (default `7071`) |
| **WebUI** | `webui.enabled=true` — browser-based management UI on `webui.port` (default `8080`); set `webui.apiGateways` and `webui.adminGateways` to your externally reachable endpoints |
| **IAM** | `iam.enabled=true` — flat-file identity and access management stored alongside backend data |
| **Persistence** | `persistence.enabled=true` — provisions a PVC for backend data and IAM storage; defaults to `10Gi` |
| **NetworkPolicy** | `networkPolicy.enabled=true` — restricts ingress to selected pods/namespaces; allows all egress |

## Multi-Replica Deployments

When setting `replicaCount` greater than 1, the underlying storage must support concurrent access. Set `persistence.accessMode=ReadWriteMany` and use a storage class that supports it (e.g. NFS, CephFS, or a cloud-managed `RWX` provisioner).

## Configuration

See [`values.yaml`](./values.yaml) for the full list of parameters and their defaults.
