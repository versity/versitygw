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

