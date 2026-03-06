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

package middlewares

import (
	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
	"github.com/versity/versitygw/s3api/utils"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

const tracerName = "github.com/versity/versitygw"

// fasthttpCarrier adapts a *fasthttp.RequestHeader to the OTel TextMapCarrier
// interface so that W3C Trace Context headers can be extracted from incoming
// requests in the Fiber / fasthttp stack.
type fasthttpCarrier struct {
	header *fasthttp.RequestHeader
}

func (c fasthttpCarrier) Get(key string) string {
	return string(c.header.Peek(key))
}

func (c fasthttpCarrier) Set(key, value string) {
	c.header.Set(key, value)
}

func (c fasthttpCarrier) Keys() []string {
	keys := make([]string, 0, 8)
	c.header.VisitAll(func(k, _ []byte) {
		keys = append(keys, string(k))
	})
	return keys
}

// OtelTracing returns a Fiber middleware that:
//  1. Extracts an incoming W3C Trace Context / Baggage from the request headers.
//  2. Starts a server-side span for the request.
//  3. Stores the span context in the Fiber user context so downstream handlers
//     can create child spans via otel.Tracer(...).Start(c.UserContext(), ...).
//  4. After the handler chain returns, updates the span name to the matched
//     route pattern (low-cardinality), records the HTTP status code, and sets
//     the span status.
func OtelTracing() fiber.Handler {
	tracer := otel.Tracer(tracerName)
	propagator := otel.GetTextMapPropagator()

	return func(c *fiber.Ctx) error {
		// Extract parent trace context from incoming HTTP headers.
		parentCtx := propagator.Extract(
			c.UserContext(),
			fasthttpCarrier{&c.Request().Header},
		)

		// Start a server span.  Use method+path as initial name; it is
		// replaced below with the low-cardinality route pattern once routing
		// has resolved.
		ctx, span := tracer.Start(
			parentCtx,
			c.Method()+" "+c.Path(),
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				semconv.HTTPRequestMethodKey.String(c.Method()),
				semconv.URLPathKey.String(c.Path()),
				semconv.ServerAddressKey.String(c.Hostname()),
			),
		)
		defer span.End()

		// Make the span context available to handlers.
		c.SetUserContext(ctx)

		err := c.Next()

		// Prefer the resolved S3 action name (e.g. "s3_ListAllMyBuckets") as
		// the span name; fall back to the low-cardinality route pattern.
		spanName := ""
		if action, ok := c.Locals(string(utils.ContextKeyS3Action)).(string); ok && action != "" {
			spanName = action
			span.SetAttributes(attribute.String("s3.action", action))
		} else if r := c.Route(); r != nil && r.Path != "" {
			spanName = c.Method() + " " + r.Path
		}
		if spanName != "" {
			span.SetName(spanName)
		}

		statusCode := c.Response().StatusCode()
		span.SetAttributes(semconv.HTTPResponseStatusCodeKey.Int(statusCode))

		if err != nil || statusCode >= 400 {
			span.SetStatus(codes.Error, "")
		} else {
			span.SetStatus(codes.Ok, "")
		}

		return err
	}
}
