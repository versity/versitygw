# Distributed Tracing

versitygw supports distributed tracing via [OpenTelemetry](https://opentelemetry.io/).
Every S3 API request produces a trace that flows through the middleware stack and into the backend, giving you end-to-end latency breakdowns, error attribution, and per-operation metrics.

## How it works

### Initialization (`tracing/tracing.go`)

When the `--otel-endpoint` flag (or `VGW_OTEL_ENDPOINT` / `OTEL_EXPORTER_OTLP_ENDPOINT` env var) is set, `main` calls `tracing.InitTracer`, which:

1. Creates an **OTLP HTTP exporter** pointed at the given endpoint (e.g. `http://localhost:4318`).
2. Builds an OTel `Resource` containing the service name (`versitygw` by default, overridable via `--otel-service-name` / `VGW_OTEL_SERVICE_NAME`), process info, and OS attributes.
3. Installs the `TracerProvider` and a W3C **Trace Context + Baggage** propagator as global OTel objects.
4. Returns a `Shutdown` function that is `defer`-ed in `main` to flush in-flight spans on exit.

If the flag is not set, no tracer is installed and all OTel calls are no-ops — there is zero overhead.

### Request span (`s3api/middlewares/tracing.go`)

`OtelTracing()` is the first Fiber middleware registered on the server when tracing is enabled. For every incoming request it:

1. **Extracts** any parent `traceparent` / `tracestate` / `baggage` headers from the request, enabling trace context propagation from upstream callers (e.g. an AWS SDK client that sets W3C headers).
2. **Starts a server span** scoped to the full request lifetime, initially named `METHOD /path`.
3. **Injects the span context** into the Fiber `UserContext` so all downstream code can access it via `c.UserContext()`.
4. After the handler chain returns:
   - Renames the span to the resolved **S3 action** (e.g. `s3_ListObjectsV2`) and records it as the `s3.action` attribute. If no action could be resolved, falls back to the low-cardinality route pattern.
   - Records `http.response.status_code`.
   - Sets span status to **Error** for any HTTP ≥ 400 or handler error, otherwise **Ok**.

### Middleware child spans

Each middleware that does non-trivial work creates a **child span** parented to the request span:

| Source file | Span name |
|---|---|
| `middlewares/authentication.go` | `middleware.VerifyV4Signature`, `iam.GetUserAccount` |
| `middlewares/presign-auth.go` | `middleware.VerifyPresignedV4Signature`, `iam.GetUserAccount` |
| `middlewares/acl-parser.go` | `middleware.ParseAcl` |
| `middlewares/public-bucket.go` | `middleware.AuthorizePublicBucketAccess` |
| `middlewares/checksum.go` | `middleware.VerifyChecksums` |

Errors in any of these spans call `span.RecordError(err)` and set the span status to Error, so failures are clearly visible in the trace waterfall.

### Backend span (`s3api/controllers/base.go`)

`ProcessController` wraps every backend call with a `backend.<s3action>` child span (e.g. `backend.s3_GetObject`). This lets you see exactly how much of the total request latency was spent inside the storage backend vs. the middleware stack.

### Span hierarchy for a typical request

```
s3_PutObject                              (server span — OtelTracing middleware)
├── middleware.VerifyV4Signature           (auth middleware)
│   └── iam.GetUserAccount
├── middleware.ParseAcl
├── middleware.VerifyChecksums
└── backend.s3_PutObject                  (storage backend)
```

## Local observability stack

The `tracing/` directory ships a Docker Compose file that runs the full local stack:

| Service | Port | Purpose |
|---|---|---|
| [Grafana Tempo](https://grafana.com/oss/tempo/) | 4317 (gRPC), 4318 (HTTP) | Receives OTLP spans from versitygw |
| [Prometheus](https://prometheus.io/) | 9090 | Receives spanmetrics remote-written from Tempo |
| [Grafana](https://grafana.com/) | 3000 | Dashboards and trace explorer |

Tempo is configured (via `tempo.yaml`) to run the **spanmetrics** metrics generator, which derives RED metrics (rate, error rate, latency percentiles) from the incoming spans and remote-writes them to Prometheus. The pre-built Grafana dashboard (`grafana-provisioning/dashboards/versitygw.json`) visualises these metrics alongside raw trace data.

### Starting the stack

```sh
make -C tracing up
# or from the tracing/ directory:
make up
```

### Stopping the stack

```sh
make -C tracing down
```

### Running versitygw with tracing enabled

```sh
./versitygw --otel-endpoint http://localhost:4318 [other flags…]
```

Spans are exported over OTLP HTTP to Tempo. Open Grafana at <http://localhost:3000> (credentials: `admin` / `admin`).

### Exploring traces

1. In Grafana, go to **Explore** and select the **Tempo** datasource.
2. Use the **Search** tab to filter by service name `versitygw`, span name, or attributes such as `s3.action`.
3. Use **TraceQL** for programmatic queries, for example:
   ```
   { span.s3.action = "s3_GetObject" && status = error }
   ```

### Viewing metrics

Open the **versitygw** dashboard from the Grafana home page. It shows:

- Total requests, request rate, internal server error rate, and p50/p95/p99 latency (top-of-page stats)
- Per-operation request rate and error bars
- Authentication error rate (401/403) over time
- Full RED metrics table per operation with drill-through links into Tempo
- Middleware overhead breakdown — absolute latency and percentage of total request time for each middleware layer

### Reloading the dashboard after edits

```sh
make -C tracing reload
```

This calls the Grafana provisioning reload API without restarting any containers.

## Adding new spans

To instrument a new codepath, retrieve the span context from the Fiber `UserContext` and start a child span:

```go
import (
    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/codes"
)

ctx, span := otel.Tracer("github.com/versity/versitygw").Start(c.UserContext(), "my.operation")
defer span.End()

if err := doWork(ctx); err != nil {
    span.RecordError(err)
    span.SetStatus(codes.Error, "")
    return err
}
```

The new span automatically becomes a child of the current request span and appears in the Tempo waterfall view.
