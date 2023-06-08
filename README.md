# The Versity Gateway: A High-Performance Open Source S3 to File Translation Tool

[![Versity Logo](https://www.versity.com/wp-content/themes/versity-theme/assets/img/svg/logo.svg)](https://www.versity.com)

 [![Apache V2 License](https://img.shields.io/badge/license-Apache%20V2-blue.svg)](https://github.com/versity/versitygw/blob/main/LICENSE)  

The Versity Gateway: A High-Performance Open Source S3 to File Translation Tool

Versity Gateway, an innovative tool for seamless inline translation between AWS S3 object commands and file-based storage systems. The Versity Gateway bridges the gap between S3-reliant applications and file storage systems, enabling enhanced compatibility and integration with file based systems while offering exceptional scalability.

The server translates incoming S3 API requests and transforms them into equivalent operations to the backend service. By leveraging this gateway server, applications can interact with the S3-compatible API on top of already existing storage systems. This project enables leveraging existing infrastructure investments while seamlessly integrating with S3-compatible systems, offering increased flexibility and compatibility in managing data storage.

The Versity Gateway is focused on performance, simplicity, and expandability. The Versity Gateway is designed with modularity in mind, enabling future extensions to support additional backend storage systems. At present, the Versity Gateway supports any generic POSIX file backend storage and Versity’s open source ScoutFS filesystem.  

The gateway is completely stateless. Multiple Versity Gateway instances may be deployed in a cluster to increase aggregate throughput. The Versity Gateway’s stateless architecture allows any request to be serviced by any gateway thereby distributing workloads and enhancing performance. Load balancers may be used to evenly distribute requests across the cluster of gateways for optimal performance. 

The S3 HTTP(S) server and routing is implemented using the [Fiber](https://gofiber.io) web framework.  This framework is actively developed with a focus on performance.  S3 API compatibility leverages the official [aws-sdk-go-v2](https://github.com/aws/aws-sdk-go-v2) whenever possible for maximum service compatibility with AWS S3. 

## Getting Started

### Run the gateway with posix backend:

```
mkdir /tmp/vgw
ADMIN_ACCESS_KEY="testuser" ADMIN_SECRET_KEY="secret" ./versitygw --port :10000 posix /tmp/vgw
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
The global options are specified before the backend type and the backend options are specified after.
