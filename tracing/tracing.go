// Copyright 2023 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package tracing

import (
	"context"
	"fmt"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// InitTracer configures the global OpenTelemetry tracer provider with an OTLP
// HTTP exporter. endpointURL is a full URL such as "http://localhost:4318" or
// "https://otel-collector:4318"; if no scheme is present, "http://" is assumed.
//
// Returns a shutdown function that flushes and stops the provider. Call it
// before process exit (typically via defer in main/runGateway).
func InitTracer(ctx context.Context, serviceName, endpointURL string) (func(context.Context) error, error) {
	if !strings.HasPrefix(endpointURL, "http://") && !strings.HasPrefix(endpointURL, "https://") {
		endpointURL = "http://" + endpointURL
	}

	exp, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpointURL(endpointURL),
	)
	if err != nil {
		return nil, fmt.Errorf("create OTLP trace exporter: %w", err)
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(semconv.ServiceName(serviceName)),
		resource.WithProcess(),
		resource.WithOS(),
	)
	if err != nil {
		// resource.New can return a partially-populated resource alongside a
		// non-fatal partial error; use it anyway.
		fmt.Printf("WARNING: OTel resource detection: %v\n", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return tp.Shutdown, nil
}
