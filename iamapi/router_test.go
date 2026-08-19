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

package iamapi

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/iamapi/internal/iammiddleware"
)

func TestIAMApiRouter_InitRegistersGetAndPostActionRoutesForAnyPath(t *testing.T) {
	app := fiber.New()
	router := &IAMApiRouter{app: app}
	router.Init()

	methodCounts := map[string]int{}
	for _, routes := range app.Stack() {
		for _, route := range routes {
			if route.Path != "/*" {
				continue
			}
			methodCounts[route.Method]++
		}
	}

	// GET and POST each have an action route plus the all-method fallback;
	// other methods have only the fallback.
	if methodCounts[http.MethodGet] != 2 || methodCounts[http.MethodPost] != 2 || methodCounts[http.MethodPut] != 1 {
		t.Fatalf("wildcard route method counts = %v", methodCounts)
	}
}

func TestIAMApiRouter_RouteActionDetectsQueryAction(t *testing.T) {
	app := fiber.New()
	router := &IAMApiRouter{
		actions: map[string]ActionHandler{
			"GetUser": func(ctx fiber.Ctx) (*Response, error) {
				return &Response{Status: http.StatusAccepted}, nil
			},
		},
	}
	app.Get("/", ProcessHandlers(router.routeAction))

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/?Action=GetUser&Version="+iamAPIVersion, nil))
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusAccepted)
	}
}

func TestIAMApiRouter_RouteActionDetectsFormAction(t *testing.T) {
	app := fiber.New()
	router := &IAMApiRouter{
		actions: map[string]ActionHandler{
			"CreateUser": func(ctx fiber.Ctx) (*Response, error) {
				return &Response{Status: http.StatusCreated}, nil
			},
		},
	}
	app.Post("/", ProcessHandlers(router.routeAction))

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString("Action=CreateUser&Version="+iamAPIVersion))
	req.Header.Set("Content-Type", fiber.MIMEApplicationForm)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}
}

func TestIAMApiRouter_RouteActionValidatesVersionBeforeAction(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		message string
	}{
		{
			name:    "missing version",
			target:  "/?Action=ListUsers",
			message: "Could not find operation ListUsers for version NO_VERSION_SPECIFIED",
		},
		{
			name:    "invalid version",
			target:  "/?Action=ListUsers&Version=this-is-custom-invalid-version",
			message: "Could not find operation ListUsers for version this-is-custom-invalid-version",
		},
		{
			name:    "unknown action",
			target:  "/?Action=ListUserssssss&Version=" + iamAPIVersion,
			message: "Could not find operation ListUserssssss for version 2010-05-08",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := fiber.New()
			router := &IAMApiRouter{actions: map[string]ActionHandler{}}
			app.Get("/", ProcessHandlers(router.routeAction))

			resp, err := app.Test(httptest.NewRequest(http.MethodGet, tt.target, nil))
			if err != nil {
				t.Fatalf("app.Test: %v", err)
			}
			requireIAMError(t, resp, http.StatusBadRequest, "Sender", "InvalidAction", tt.message)
		})
	}
}

func TestIAMApiRouter_ActionRoutesMatchAnyPath(t *testing.T) {
	app := fiber.New(fiber.Config{ErrorHandler: iammiddleware.GlobalErrorHandler})
	router := &IAMApiRouter{app: app, rootCreds: &testRoot}
	router.Init()

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/any/nested/path?Action=ListUsers&Version="+iamAPIVersion, nil))
	if err != nil {
		t.Fatalf("GET app.Test: %v", err)
	}
	requireIAMError(t, resp, http.StatusForbidden, "Sender", "MissingAuthenticationToken", "Request is missing Authentication Token")

	req := httptest.NewRequest(http.MethodPost, "/another/path", bytes.NewBufferString("Action=ListUsers&Version="+iamAPIVersion))
	req.Header.Set("Content-Type", fiber.MIMEApplicationForm)
	resp, err = app.Test(req)
	if err != nil {
		t.Fatalf("POST app.Test: %v", err)
	}
	requireIAMError(t, resp, http.StatusForbidden, "Sender", "MissingAuthenticationToken", "Request is missing Authentication Token")
}

func TestIAMApiRouter_RootWithoutActionRedirects(t *testing.T) {
	app := fiber.New()
	router := &IAMApiRouter{app: app}
	router.Init()

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/", nil))
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusFound)
	}
	if got := resp.Header.Get("Location"); got != productURL {
		t.Fatalf("Location = %q, want %q", got, productURL)
	}
	if got := resp.Header.Get(HeaderAmznRequestID); got == "" {
		t.Fatal("missing x-amzn-RequestId")
	}
	if got := resp.Header.Get("Content-Length"); got != "0" {
		t.Fatalf("Content-Length = %q, want 0", got)
	}
	if len(body) != 0 {
		t.Fatalf("body = %q, want empty", string(body))
	}
}

func TestIAMApiRouter_UnmatchedRouteReturnsUnknownOperation(t *testing.T) {
	app := fiber.New()
	router := &IAMApiRouter{app: app}
	router.Init()

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/not-an-action-route", nil))
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
	if string(body) != string(unknownOperationBody) {
		t.Fatalf("body = %q, want %q", string(body), string(unknownOperationBody))
	}
	if got := resp.Header.Get("Content-Length"); got != strconv.Itoa(len(unknownOperationBody)) {
		t.Fatalf("Content-Length = %q, want %d", got, len(unknownOperationBody))
	}
	if got := resp.Header.Get(HeaderAmznRequestID); got == "" {
		t.Fatal("missing x-amzn-RequestId")
	}
}
