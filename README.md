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

### WebGUI
Get more details about the new (optional) WebGUI management/explorer here: [https://github.com/versity/versitygw/wiki/WebGUI](https://github.com/versity/versitygw/wiki/WebGUI)

![admin-explorer](https://github.com/user-attachments/assets/e99db171-2c72-4d0f-8c8d-480a56e1c8a1)

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
mkdir /tmp/vgw /tmp/vers
ROOT_ACCESS_KEY="testuser" ROOT_SECRET_KEY="secret" ./versitygw --port :10000 --iam-dir /tmp/vgw posix --versioning-dir /tmp/vers /tmp/vgw
```
This will enable an S3 server on the current host listening on port 10000 and hosting the directory `/tmp/vgw` with older object versions in `/tmp/vers`. It's fine if both of these directories are within the same filesystem. The `--iam-dir` option enables simple JSON flat file accounts for testing.

To get the usage output, run the following:

```
./versitygw --help
```

The command format is

```
versitygw [global options] command [command options] [arguments...]
```
The [global options](https://github.com/versity/versitygw/wiki/Global-Options) are specified before the backend type and the backend options are specified after.

### Testing & Production Readiness

VersityGW is **battle-tested and production-ready**. Every pull request must pass our comprehensive test suite before it can be reviewed or merged. All code reviews are done by at least one human in the loop. LLMs may be used to augment the review process, but are never the sole reviewer or decision maker. See [Testing](https://github.com/versity/versitygw/wiki/Testing) for high level testing documentation.

#### Comprehensive Test Coverage

Our multi-layered testing strategy includes:

- **Go Unit Test Files** - Extensive unit tests with race detection and code coverage analysis covering core functionality, edge cases, and error handling.
- **Integration Test Scripts** - Real-world scenario testing across multiple backends (POSIX, S3, Azure) and configurations.
- **Functional/Regression Tests** - End-to-end SDK tests validating complete workflows including full-flow operations, POSIX-specific behavior, and IAM functionality populated with regression tests as issues are addressed.
- **Static Analysis** - Static Analysis checks using [staticcheck](https://staticcheck.dev).
- **System Tests** - Protocol-level validation using industry-standard S3 clients:
  - AWS CLI - Official AWS command-line tools
  - s3cmd - Popular S3 client
  - MinIO mc - Modern S3-compatible client
  - Direct REST API testing with curl for request/response validation
- **Security Testing** - Both HTTP and HTTPS configurations tested. Vulnerability scanning with govulncheck. And regular dependency updates with dependabot.
- **Compatibility Testing** - Multiple backends, versioning scenarios, static bucket modes, and various authentication methods.

### Run the gateway in Docker

Use the published image like the native binary by passing CLI arguments:

```bash
docker run --rm versity/versitygw:latest --version
```

See [Docker](https://github.com/versity/versitygw/wiki/Docker) for more
documentation for running within Docker.

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

