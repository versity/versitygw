// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an "AS
// IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied.  See the License for the specific language
// governing permissions and limitations under the License.

package s3api

import (
	"encoding/xml"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"

	"github.com/versity/versitygw/rdma/rcroutes"
	"github.com/versity/versitygw/s3err"
)

// This file pins the wire behavior of RDMA control-route error
// responses at the production server boundary: the real error
// handler, the real request-ID middleware, and the terminal
// serializer the RDMA routes use. The RC route handlers live in
// rdma/rcroutes; these tests exercise the same response path a
// client observes.

type rcErrorResponse struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	RequestID string   `xml:"RequestId"`
	HostID    string   `xml:"HostId"`
}

func TestRCRouteErrorPreservesS3Error(t *testing.T) {
	server, err := newTestS3ApiServer(
		WithRoute(http.MethodPost, "/.hipobj-rc/op", func(ctx fiber.Ctx) error {
			return rcroutes.WriteRouteError(ctx,
				s3err.GetAPIError(s3err.ErrAccessDenied))
		}),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	resp, err := server.app.Test(httptest.NewRequest(http.MethodPost, "/.hipobj-rc/op", nil))
	if err != nil {
		t.Fatalf("app.Test() error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	var er rcErrorResponse
	if err := xml.NewDecoder(resp.Body).Decode(&er); err != nil {
		t.Fatalf("decode XML body: %v", err)
	}
	if er.Code != "AccessDenied" {
		t.Fatalf("code = %q, want AccessDenied", er.Code)
	}
	if er.RequestID == "" || er.HostID == "" {
		t.Fatal("response missing RequestId or HostId")
	}
	if ct := resp.Header.Get("Content-Type"); ct != fiber.MIMEApplicationXML {
		t.Fatalf("content-type = %q, want %q", ct, fiber.MIMEApplicationXML)
	}
}

func TestRCRouteErrorRawFiberIs500(t *testing.T) {
	// Control case: an ordinary fiber error collapses into the
	// generic 500 of the production error handler. This is the
	// behavior WriteRouteError exists to avoid.
	server, err := newTestS3ApiServer(
		WithRoute(http.MethodPost, "/.hipobj-rc/op", func(ctx fiber.Ctx) error {
			return fiber.NewError(fiber.StatusTeapot, "raw")
		}),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	resp, err := server.app.Test(httptest.NewRequest(http.MethodPost, "/.hipobj-rc/op", nil))
	if err != nil {
		t.Fatalf("app.Test() error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d (production handler collapses fiber errors)",
			resp.StatusCode, http.StatusInternalServerError)
	}
}

func TestRCRouteErrorUnexpectedIsGeneric500(t *testing.T) {
	server, err := newTestS3ApiServer(
		WithRoute(http.MethodPost, "/.hipobj-rc/op", func(ctx fiber.Ctx) error {
			return rcroutes.WriteRouteError(ctx, errors.New("boom"))
		}),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	resp, err := server.app.Test(httptest.NewRequest(http.MethodPost, "/.hipobj-rc/op", nil))
	if err != nil {
		t.Fatalf("app.Test() error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}
	var er rcErrorResponse
	if err := xml.NewDecoder(resp.Body).Decode(&er); err != nil {
		t.Fatalf("decode XML body: %v", err)
	}
	if er.Code != "InternalError" {
		t.Fatalf("code = %q, want InternalError", er.Code)
	}
}

func TestRCRouteErrorStubNotImplemented(t *testing.T) {
	server, err := newTestS3ApiServer(
		WithRoute(http.MethodPost, "/.hipobj-rc/op", func(ctx fiber.Ctx) error {
			return rcroutes.WriteRouteError(ctx, rcroutes.ErrRouteNotImplemented{})
		}),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	resp, err := server.app.Test(httptest.NewRequest(http.MethodPost, "/.hipobj-rc/op", nil))
	if err != nil {
		t.Fatalf("app.Test() error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotImplemented)
	}
	var er rcErrorResponse
	if err := xml.NewDecoder(resp.Body).Decode(&er); err != nil {
		t.Fatalf("decode XML body: %v", err)
	}
	if er.Code != "NotImplemented" {
		t.Fatalf("code = %q, want NotImplemented", er.Code)
	}
}
