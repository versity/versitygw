# VersityGW Multi-Backend Fork

> **Fork of [versity/versitygw](https://github.com/versity/versitygw)** with multi-backend S3 gateway support and automatic fallback.

**English Documentation** | **[Documentação em Português](README.pt-BR.md)**

## What's New in This Fork

### Multi-Backend S3 Gateway with Automatic Fallback

This fork adds transparent multi-backend architecture that enables:

- **Automatic Fallback Across Backends**: Read operations (GET/HEAD/LIST) try all configured backends sequentially until object is found
- **Multiple S3-Compatible Backends**: Works with Cloudflare R2, MinIO, AWS S3, Azure, and any S3-compatible storage
- **Smart Write Operations**: PUT/DELETE always target the primary backend only
- **Presigned URLs**: Full AWS SigV4 signing with configurable expiration (leverages existing Versity feature)
- **Robust Error Detection**: Distinguishes NoSuchKey (404) from other errors to ensure proper fallback behavior
- **🔐 Random Credentials**: Auto-generates secure gateway credentials if not provided (crypto/rand based)

### New Files Added

- `backend/multibackend.go` (623 lines) - Multi-backend wrapper with fallback logic
- `cmd/versitygw/s3multi.go` (261 lines) - New CLI command for multi-backend mode
- `examples/README-s3-multi.md` - Complete usage documentation
- `examples/s3-multi-config.json` - Configuration template
- `multibackend-implementation.patch` - Patch file for easy upstream application

### Quick Start with Multi-Backend

```bash
# Create configuration file
cat > config.json << 'EOF'
{
  "backends": [
    {
      "name": "primary-r2",
      "access": "YOUR_R2_ACCESS_KEY",
      "secret": "YOUR_R2_SECRET_KEY",
      "endpoint": "https://account.r2.cloudflarestorage.com/primary-bucket",
      "region": "us-east-1"
    },
    {
      "name": "fallback-r2",
      "access": "YOUR_R2_ACCESS_KEY",
      "secret": "YOUR_R2_SECRET_KEY",
      "endpoint": "https://account.r2.cloudflarestorage.com/fallback-bucket",
      "region": "us-east-1"
    }
  ]
}
EOF

# Important: Use region "us-east-1" for Cloudflare R2
# AWS CLI must also use: export AWS_DEFAULT_REGION=us-east-1

# Build
make build

# Run with automatic random credentials (easiest!)
./bin/versitygw --port :7070 s3-multi --config config.json
# ⚠️  Generated random ACCESS KEY: kNnIst0KOxuyBbozuF-l
# ⚠️  Generated random SECRET KEY: mZA4WE4HFydNcBubWCozuXkG8-Z03afd5KWlFAp1

# Or provide your own gateway credentials
./bin/versitygw --port :7070 --access admin --secret password s3-multi --config config.json
```

**Note:** Backend credentials (in JSON) are for connecting to R2/S3. Gateway credentials (--access/--secret) are what S3 clients use to connect to VersityGW. If omitted, they're auto-generated.

### Use Cases for Multi-Backend

- **High Availability**: Automatic failover to backup storage if primary is unavailable
- **Data Migration**: Access data from multiple sources during migration periods
- **Multi-Region Access**: Read from nearest/fastest available backend
- **Cost Optimization**: Store hot data in premium storage, archive in cheaper backends

### Testing Status

Fully tested with Cloudflare R2 dual-bucket setup:
- ✅ List buckets across multiple backends
- ✅ Upload/Download with integrity verification
- ✅ Presigned URL generation and validation
- ✅ Automatic fallback to secondary backend
- ✅ 404 error handling

See [`examples/README-s3-multi.md`](examples/README-s3-multi.md) for complete documentation.

---

# The Versity S3 Gateway:<br/>A High-Performance S3 Translation Service

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/versity/versitygw/blob/assets/assets/logo-white.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://github.com/versity/versitygw/blob/assets/assets/logo.svg">
  <a href="https://www.versity.com"><img alt="Versity Software logo image." src="https://github.com/versity/versitygw/blob/assets/assets/logo.svg"></a>
</picture>

 [![Apache V2 License](https://img.shields.io/badge/license-Apache%20V2-blue.svg)](https://github.com/versity/versitygw/blob/main/LICENSE) [![Go Report Card](https://goreportcard.com/badge/github.com/versity/versitygw)](https://goreportcard.com/report/github.com/versity/versitygw) [![Go Reference](https://pkg.go.dev/badge/github.com/versity/versitygw.svg)](https://pkg.go.dev/github.com/versity/versitygw)

### Binary release builds
Download [latest release](https://github.com/versity/versitygw/releases)
 | Linux/amd64 | Linux/arm64 | MacOS/amd64 | MacOS/arm64 | BSD/amd64 | BSD/arm64 |
 |:-----------:|:-----------:|:-----------:|:-----------:|:---------:|:---------:|
 |    ✔️    |  ✔️  |   ✔️   |  ✔️   |  ✔️   |  ✔️   |
 
### Use Cases
* Turn your local filesystem into an S3 server with a single command!
* Proxy S3 requests to S3 storage
* Simple to deploy S3 server with a single command
* Protocol compatibility in `posix` allows common access to files via posix or S3
* Simplified interface for adding new storage system support

### News
Check out latest wiki articles: [https://github.com/versity/versitygw/wiki/Articles](https://github.com/versity/versitygw/wiki/Articles)

### Mailing List
Keep up to date with latest gateway announcements by signing up to the [versitygw mailing list](https://www.versity.com/products/versitygw#signup).

### Documentation
See project [documentation](https://github.com/versity/versitygw/wiki) on the wiki.

### Need help?
Ask questions in the [community discussions](https://github.com/versity/versitygw/discussions).
<br>
Contact [Versity Sales](https://www.versity.com/contact/) to discuss enterprise support.

### Overview
Versity Gateway, a simple to use tool for seamless inline translation between AWS S3 object commands and storage systems. The Versity Gateway bridges the gap between S3-reliant applications and other storage systems, enabling enhanced compatibility and integration while offering exceptional scalability.

The server translates incoming S3 API requests and transforms them into equivalent operations to the backend service. By leveraging this gateway server, applications can interact with the S3-compatible API on top of already existing storage systems. This project enables leveraging existing infrastructure investments while seamlessly integrating with S3-compatible systems, offering increased flexibility and compatibility in managing data storage.

The Versity Gateway is focused on performance, simplicity, and expandability. The Versity Gateway is designed with modularity in mind, enabling future extensions to support additional backend storage systems. At present, the Versity Gateway supports any generic POSIX file backend storage, Versity’s open source ScoutFS filesystem, Azure Blob Storage, and other S3 servers.  

The gateway is completely stateless. Multiple Versity Gateway instances may be deployed in a cluster to increase aggregate throughput. The Versity Gateway’s stateless architecture allows any request to be serviced by any gateway thereby distributing workloads and enhancing performance. Load balancers may be used to evenly distribute requests across the cluster of gateways for optimal performance. 

The S3 HTTP(S) server and routing is implemented using the [Fiber](https://gofiber.io) web framework.  This framework is actively developed with a focus on performance.  S3 API compatibility leverages the official [aws-sdk-go-v2](https://github.com/aws/aws-sdk-go-v2) whenever possible for maximum service compatibility with AWS S3. 

## Getting Started
See the [Quickstart](https://github.com/versity/versitygw/wiki/Quickstart) documentation.

### Run the gateway with posix backend:

```
mkdir /tmp/vgw
ROOT_ACCESS_KEY="testuser" ROOT_SECRET_KEY="secret" ./versitygw --port :10000 posix /tmp/vgw
```
This will enable an S3 server on the current host listening on port 10000 and hosting the directory `/tmp/vgw`.

To get the usage output, run the following:

```
./versitygw --help
```

The command format is

```
versitygw [global options] command [command options] [arguments...]
```
The [global options](https://github.com/versity/versitygw/wiki/Global-Options) are specified before the backend type and the backend options are specified after.

### Run the gateway in Docker

Use the published image like the native binary by passing CLI arguments:

```bash
docker run --rm versity/versitygw:latest --version
```

When no command arguments are supplied, the container looks for `VGW_BACKEND` and optional `VGW_BACKEND_ARG`/`VGW_BACKEND_ARGS` environment variables to determine which backend to start. Backend-specific configuration continues to come from the existing environment flags (for example `ROOT_ACCESS_KEY`, `VGW_PORT`, and others).

```bash
docker run --rm \
  -e ROOT_ACCESS_KEY=testuser \
  -e ROOT_SECRET_KEY=secret \
  -e VGW_BACKEND=posix \
  -e VGW_BACKEND_ARG=/data \
  -p 10000:7070 \
  -v $(pwd)/data:/data \
  versity/versitygw:latest
```

If you need to pass additional CLI options, set `VGW_ARGS` with a space-delimited list, or continue passing arguments directly to `docker run`.

***

#### Versity gives you clarity and control over your archival storage, so you can allocate more resources to your core mission.

### Contact
![versity logo](https://www.versity.com/wp-content/uploads/2022/12/cropped-android-chrome-512x512-1-32x32.png)
info@versity.com <br />
+1 844 726 8826

### @versitysoftware 
[![linkedin](https://github.com/versity/versitygw/blob/assets/assets/linkedin.jpg)](https://www.linkedin.com/company/versity/) &nbsp; 
[![twitter](https://github.com/versity/versitygw/blob/assets/assets/twitter.jpg)](https://twitter.com/VersitySoftware) &nbsp;
[![facebook](https://github.com/versity/versitygw/blob/assets/assets/facebook.jpg)](https://www.facebook.com/versitysoftware) &nbsp;
[![instagram](https://github.com/versity/versitygw/blob/assets/assets/instagram.jpg)](https://www.instagram.com/versitysoftware/) &nbsp;

