# noop backend plugin

The noop backend is a `/dev/null`-style backend for testing. It accepts all S3
API requests and discards any data written to it. Read operations return empty
but valid responses (empty bucket lists, empty object lists, empty object
bodies, etc.).

This backend is useful for:
- Load and performance testing the gateway without storage I/O as a bottleneck
- Verifying gateway configuration and middleware behavior

## Building

From this directory:

```sh
make
```

This produces `noop.so`. To place the output elsewhere use the `OUTPUT` variable:

```sh
make OUTPUT=/usr/local/lib/versitygw/noop.so
```

Note: You will likely need to build versitygw binary at the same time as the
plugin. See warnings: [plugin-warnings](https://pkg.go.dev/plugin#hdr-Warnings),
notably:
- Plugins are currently supported only on Linux, FreeBSD, and macOS, making them unsuitable for applications intended to be portable.
- Runtime crashes are likely to occur unless all parts of the program (the application and all its plugins) are compiled using exactly the same version of the toolchain, the same build tags, and the same values of certain flags and environment variables.

## Usage

Pass the path to the compiled plugin to the `plugin` subcommand of `versitygw`:

```sh
versitygw <global-flags> plugin /path/to/noop.so
```

The noop backend requires no configuration file. If one is passed via `-c` /
`--config`, it is silently ignored.

### Example

```sh
versitygw --access myaccesskey --secret mysecretkey plugin ./noop.so
```

The gateway will then respond to S3 API requests on the default port, accepting
all operations without persisting any data.
