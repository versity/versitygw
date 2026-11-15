// Copyright 2026 Versity Software
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

package controllers

import (
	"io"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"

	"github.com/versity/versitygw/cumiddleware"
	"github.com/versity/versitygw/hipv3backend"
	"github.com/versity/versitygw/rdma/rcdial"
	"github.com/versity/versitygw/s3err"
)

// These tests exercise the production ProcessController reply-header
// path end to end: an adapter records a successful-transfer reply on
// the request context, and ProcessController must stamp it as the
// x-amz-rc-rdma-reply header on the HTTP response, emitting nothing
// on the error path. The adapter itself is stubbed with the record
// call because the transport lives in a package that cannot be
// imported here without a cycle; the controller side under test is
// purely the header emission.

// recordReply records a successful-transfer reply on the request
// context through the adapter's own setter, keeping the emission
// path under test identical to what a real transfer records.
func recordReply(ctx fiber.Ctx, status int, count uint64) {
	hipv3backend.SetReply(ctx.RequestCtx(), status, count)
}

func TestProcessControllerStampsV3ReplyHeader(t *testing.T) {
	app := fiber.New()
	svc := &Services{}
	app.Get("/bucket/*", ProcessHandlers(
		func(ctx fiber.Ctx) (*Response, error) {
			recordReply(ctx, 200, 64)
			return &Response{Data: nil}, nil
		}, "GetObject", svc))

	req := httptest.NewRequest("GET", "/bucket/key", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	want := "200:0000000000000040"
	if got := resp.Header.Get(cumiddleware.HeaderRDMAv3Reply); got != want {
		t.Errorf("reply header = %q, want %q", got, want)
	}
	if len(body) != 0 {
		t.Errorf("body = %d bytes, want bodyless", len(body))
	}
}

func TestProcessControllerRangedV3ReplyHeader(t *testing.T) {
	app := fiber.New()
	svc := &Services{}
	app.Get("/bucket/*", ProcessHandlers(
		func(ctx fiber.Ctx) (*Response, error) {
			recordReply(ctx, 206, 96)
			return &Response{Data: nil}, nil
		}, "GetObject", svc))

	req := httptest.NewRequest("GET", "/bucket/key", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	want := "206:0000000000000060"
	if got := resp.Header.Get(cumiddleware.HeaderRDMAv3Reply); got != want {
		t.Errorf("reply header = %q, want %q", got, want)
	}
}

func TestProcessControllerOmitsV3ReplyHeaderOnError(t *testing.T) {
	app := fiber.New()
	svc := &Services{}
	app.Get("/bucket/*", ProcessHandlers(
		func(ctx fiber.Ctx) (*Response, error) {
			// A failed transfer records nothing; the header must
			// stay absent even though the controller returns an
			// error response body.
			return nil, errV3TestBoom
		}, "GetObject", svc))

	req := httptest.NewRequest("GET", "/bucket/key", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get(cumiddleware.HeaderRDMAv3Reply); got != "" {
		t.Errorf("reply header = %q on error, want empty", got)
	}
}

// errV3TestBoom is a backend-shaped error for the omission test.
var errV3TestBoom = s3err.APIError{
	Code:           "NoSuchKey",
	Description:    "test fixture",
	HTTPStatusCode: 404,
}

// The wire grammar of the emitted reply: three status digits, a
// colon, sixteen lowercase hex digits for the byte count.
func TestV3ReplyWireForm(t *testing.T) {
	for _, tc := range []struct {
		status int
		count  uint64
		want   string
	}{
		{200, 0x40, "200:0000000000000040"},
		{206, 0x60, "206:0000000000000060"},
		{200, 1, "200:0000000000000001"},
	} {
		got := rcdial.FormatReply(tc.status, tc.count)
		if got != tc.want {
			t.Errorf("FormatReply(%d, %d) = %q, want %q", tc.status, tc.count, got, tc.want)
		}
		if _, err := rcdial.ParseReply(got); err != nil {
			t.Errorf("ParseReply(%q): %v", got, err)
		}
	}
}
