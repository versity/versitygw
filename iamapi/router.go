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
	"net/http"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/iamapi/iamerr"
	"github.com/versity/versitygw/iamapi/internal/iammiddleware"
	"github.com/versity/versitygw/iamapi/internal/iamutil"
	"github.com/versity/versitygw/iamapi/storage"
)

const (
	iamAPIVersion      = "2010-05-08"
	noVersionSpecified = "NO_VERSION_SPECIFIED"
	productURL         = "https://www.versity.com/products/versitygw/"
)

var unknownOperationBody = []byte("<UnknownOperationException/>\n")

type IAMApiRouter struct {
	app       *fiber.App
	store     storage.Storer
	Ctrl      IAMApiController
	actions   map[string]ActionHandler
	rootCreds *RootCredentials
}

func (r *IAMApiRouter) Init() {
	ctrl := NewController(r.store)
	r.Ctrl = ctrl

	r.actions = map[string]ActionHandler{
		// User CRUD
		"CreateUser": ctrl.CreateUser,
		"DeleteUser": ctrl.DeleteUser,
		"GetUser":    ctrl.GetUser,
		"ListUsers":  ctrl.ListUsers,
		"UpdateUser": ctrl.UpdateUser,
		// User Access Key CRUD
		"CreateAccessKey":      ctrl.CreateAccessKey,
		"UpdateAccessKey":      ctrl.UpdateAccessKey,
		"DeleteAccessKey":      ctrl.DeleteAccessKey,
		"GetAccessKeyLastUsed": ctrl.GetAccessKeyLastUsed,
		"ListAccessKeys":       ctrl.ListAccessKeys,
	}

	actionRoute := ProcessHandlers(r.routeAction, iammiddleware.VerifyIAMAuth(r.rootCreds))
	r.app.Get("/*", iamutil.MatchQueryOrFormArgs("Action"), actionRoute)
	r.app.Post("/*", iamutil.MatchQueryOrFormArgs("Action"), actionRoute)

	r.app.All("/", r.redirectRoot)
	r.app.All("*", r.unknownOperation)
}

func (r *IAMApiRouter) routeAction(ctx fiber.Ctx) (*Response, error) {
	action, _ := iamutil.RequestParam(ctx, "Action")
	version, versionSpecified := iamutil.RequestParam(ctx, "Version")
	if !versionSpecified {
		version = noVersionSpecified
	}
	if version != iamAPIVersion {
		return &Response{}, iamerr.InvalidAction(action, version)
	}

	handler, ok := r.actions[action]
	if !ok {
		return &Response{}, iamerr.InvalidAction(action, version)
	}

	return handler(ctx)
}

func (r *IAMApiRouter) redirectRoot(ctx fiber.Ctx) error {
	iammiddleware.EnsureRequestID(ctx)
	ctx.Set(fiber.HeaderLocation, productURL)
	ctx.Status(http.StatusFound)
	return nil
}

func (r *IAMApiRouter) unknownOperation(ctx fiber.Ctx) error {
	iammiddleware.EnsureRequestID(ctx)
	return ctx.Status(http.StatusNotFound).Send(unknownOperationBody)
}
