// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package private implements the standalone IAM service's private endpoint
// set: derive a SigV4 signing key, evaluate IAM identity policies, and
// resolve an access key id to the principal that owns it. All three exist
// purely so the S3 gateway can authenticate and authorize its own callers
// without ever holding a plaintext secret or a policy document itself.
// This is a separate fiber app from the public control-plane
// iamapi.IAMApiServer, meant to be served on its own listener(s), never the
// public one.
//
// The endpoints authenticate strictly as the configured root credential
// — only the S3 gateway itself, signing as its own IAM-client identity, ever
// legitimately calls them. Transport security is enforced by ServeMultiPort,
// not by request handling
package private

import (
	"fmt"
	"os"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/logger"
	"github.com/versity/versitygw/iamapi/internal/iammiddleware"
	"github.com/versity/versitygw/iamapi/storage"
	"github.com/versity/versitygw/internal/sigv4auth"
)

const (
	// These are exported so auth.IAMServiceStandalone (the S3-side client)
	// shares one source of truth for the routes rather than duplicating the
	// literal path strings.
	DerivePath          = "/private/derive-signing-key"
	EvaluatePath        = "/private/evaluate-policy"
	ResolveIdentityPath = "/private/resolve-identity"

	// privateService is the SigV4 credential-scope service name the S3
	// gateway signs its own requests to these endpoints with. It's an
	// internal detail — these routes aren't part of any AWS-compatible
	// API — reusing "iam" is simplest and avoids inventing a new constant
	// consumers on both sides would have to agree on.
	privateService = sigv4auth.ServiceIAM
)

// PrivateAPI is the standalone IAM service's private endpoint set
type PrivateAPI struct {
	app        *fiber.App
	store      storage.Storer
	socketPerm os.FileMode
	quiet      bool
}

type PrivateAPIOption func(*PrivateAPI)

// WithPrivateSocketPerm sets the file-mode permission applied to any
// file-backed unix-socket listener address (no effect on TCP addresses or
// Linux abstract-namespace sockets).
func WithPrivateSocketPerm(perm os.FileMode) PrivateAPIOption {
	return func(p *PrivateAPI) { p.socketPerm = perm }
}

// WithPrivateQuiet suppresses per-request summary logging, mirroring
// iamapi.WithQuiet for the public API. Callers should gate both on the same
// flag so the two log streams turn on and off together.
func WithPrivateQuiet() PrivateAPIOption {
	return func(p *PrivateAPI) { p.quiet = true }
}

// New constructs the private endpoint set. root is the identity these
// endpoints authenticate every request against.
func New(store storage.Storer, root iammiddleware.RootCredentials, opts ...PrivateAPIOption) (*PrivateAPI, error) {
	if store == nil {
		return nil, fmt.Errorf("iamapi/private: storer is required")
	}

	p := &PrivateAPI{store: store}
	for _, opt := range opts {
		opt(p)
	}

	app := fiber.New(fiber.Config{
		AppName:      "versitygw-iam-private",
		ServerHeader: "VERSITYGW",
		ErrorHandler: p.errorHandler,
	})
	p.app = app

	if !p.quiet {
		app.Use("*", logger.New(logger.Config{
			Format: "${time} | vgw-iam-private | ${status} | ${latency} | ${ip} | ${method} | ${path} | ${error} | ${queryParams}\n",
		}))
	}

	rootAuth := iammiddleware.VerifyRootOnlySigV4(privateService, &root)
	app.Post(DerivePath, chainHandlers(rootAuth, p.handleDeriveSigningKey))
	app.Post(EvaluatePath, chainHandlers(rootAuth, p.handleEvaluatePolicy))
	app.Post(ResolveIdentityPath, chainHandlers(rootAuth, p.handleResolveIdentity))

	return p, nil
}

// chainHandlers composes handlers into one, calling each in turn and
// stopping at the first error.
func chainHandlers(handlers ...fiber.Handler) fiber.Handler {
	return func(ctx fiber.Ctx) error {
		for _, h := range handlers {
			if err := h(ctx); err != nil {
				return err
			}
		}
		return nil
	}
}
