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

package utils

import (
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/debuglogger"
)

// ConditionalHeaders holds the conditional header values
type ConditionalHeaders struct {
	IfMatch       *string
	IfNoneMatch   *string
	IfModSince    *time.Time
	IfUnmodeSince *time.Time
}

type precondtionCfg struct {
	withCopySource bool
}

type preconditionOpt func(*precondtionCfg)

func WithCopySource() preconditionOpt {
	return func(o *precondtionCfg) { o.withCopySource = true }
}

// ParsePreconditionHeaders parses the precondition headers:
// - If-Match
// - If-None-Match
// - If-Modified-Since
// - If-Unmodified-Since
func ParsePreconditionHeaders(ctx *fiber.Ctx, opts ...preconditionOpt) ConditionalHeaders {
	ifMatch, ifNoneMatch := ParsePreconditionMatchHeaders(ctx, opts...)
	ifModSince, ifUnmodeSince := ParsePreconditionDateHeaders(ctx, opts...)

	return ConditionalHeaders{
		IfMatch:       ifMatch,
		IfNoneMatch:   ifNoneMatch,
		IfModSince:    ifModSince,
		IfUnmodeSince: ifUnmodeSince,
	}
}

// ParsePreconditionMatchHeaders extracts "If-Match" and "If-None-Match" headers from fiber Ctx
func ParsePreconditionMatchHeaders(ctx *fiber.Ctx, opts ...preconditionOpt) (*string, *string) {
	cfg := new(precondtionCfg)
	for _, opt := range opts {
		opt(cfg)
	}
	prefix := ""
	if cfg.withCopySource {
		prefix = "X-Amz-Copy-Source-"
	}
	return GetStringPtr(ctx.Get(prefix + "If-Match")), GetStringPtr(ctx.Get(prefix + "If-None-Match"))
}

// ParsePreconditionDateHeaders parses the "If-Modified-Since" and "If-Unmodified-Since"
// headers from fiber context to *time.Time
func ParsePreconditionDateHeaders(ctx *fiber.Ctx, opts ...preconditionOpt) (*time.Time, *time.Time) {
	cfg := new(precondtionCfg)
	for _, opt := range opts {
		opt(cfg)
	}
	prefix := ""
	if cfg.withCopySource {
		prefix = "X-Amz-Copy-Source-"
	}

	ifModSince := ctx.Get(prefix + "If-Modified-Since")
	ifUnmodSince := ctx.Get(prefix + "If-Unmodified-Since")

	ifModSinceParsed := ParsePreconditionDateHeader(ifModSince)
	ifUnmodSinceParsed := ParsePreconditionDateHeader(ifUnmodSince)

	return ifModSinceParsed, ifUnmodSinceParsed
}

// ParsePreconditionDateHeader tries to parse the given date string as
// - RFC1123
// - RFC3339
// both are valid
func ParsePreconditionDateHeader(date string) *time.Time {
	if date == "" {
		return nil
	}
	// try to parse as RFC1123
	parsed, err := time.Parse(time.RFC1123, date)
	if err == nil {
		// ignore future dates
		if parsed.After(time.Now()) {
			return nil
		}

		return &parsed
	}

	// try to parse as RFC3339
	parsed, err = time.Parse(time.RFC3339, date)
	if err == nil {
		// ignore future dates
		if parsed.After(time.Now()) {
			return nil
		}

		return &parsed
	}

	return nil
}

// ParseIfMatchSize parses the 'x-amz-if-match-size' to *int64
// if parsing fails, returns nil
func ParseIfMatchSize(ctx *fiber.Ctx) *int64 {
	ifMatchSizeHdr := ctx.Get("x-amz-if-match-size")
	if ifMatchSizeHdr == "" {
		return nil
	}
	ifMatchSize, err := strconv.ParseInt(ifMatchSizeHdr, 10, 64)
	if err != nil {
		debuglogger.Logf("failed to parse 'x-amz-if-match-size': %s", ifMatchSizeHdr)
		return nil
	}

	return &ifMatchSize
}
