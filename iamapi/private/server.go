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
	"strconv"

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
	DerivePath            = "/private/derive-signing-key"
	EvaluatePath          = "/private/evaluate-policy"
	ResolveIdentityPath   = "/private/resolve-identity"
	ResolvePrincipalsPath = "/private/resolve-principals"
	VersionPath           = "/private/version"

	// ProtocolHeader carries the private protocol version each peer speaks.
	// Both send it: the S3 gateway on every request, this service on every
	// response, including error responses.
	ProtocolHeader = "X-Vgw-Private-Protocol"

	// ProtocolVersion is the private protocol version this build speaks, and
	// MinClientProtocol the oldest S3 gateway it will serve. Together they
	// express compatibility in both directions, since a skew can be unsafe
	// from either side:
	//
	//   - Bump ProtocolVersion when the gateway starts relying on something
	//     an older service would silently ignore — a new request field, or a
	//     new endpoint. An unrecognized field is dropped by json.Unmarshal,
	//     so an older service evaluating without one (Condition being the
	//     worked example) is fail-open. The gateway catches this itself by
	//     refusing a service older than the version it speaks.
	//
	//   - Bump both when this service starts returning something an older
	//     gateway must understand to stay fail-closed — a new deny dimension,
	//     or a decision matrix that narrows an Allow, as HasSessionPolicy/
	//     SessionDecisions would have been had they landed later. An older
	//     gateway cannot detect this on its own: it does not know the field
	//     exists. This service refuses it instead.
	//
	//   - Bump neither for an addition an older gateway can safely ignore.
	//
	// Changing an existing field's meaning in place is not a bump; it is a
	// new route. The operational rule that falls out of all this: upgrade
	// the IAM service before the gateways.
	ProtocolVersion   = 1
	MinClientProtocol = 1

	// privateService is the SigV4 credential-scope service name the S3
	// gateway signs its own requests to these endpoints with. It's an
	// internal detail — these routes aren't part of any AWS-compatible
	// API — reusing "iam" is simplest and avoids inventing a new constant
	// consumers on both sides would have to agree on.
	privateService = sigv4auth.ServiceIAM
)

// PrivateAPI is the standalone IAM service's private endpoint set
type PrivateAPI struct {
	app           *fiber.App
	store         storage.Storer
	socketPerm    os.FileMode
	quiet         bool
	serverVersion string
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

// WithPrivateServerVersion sets the build version the version endpoint
// reports. It is what lets an operator map a protocol number back to an
// image, so it is worth passing even though nothing decides compatibility
// on it.
func WithPrivateServerVersion(version string) PrivateAPIOption {
	return func(p *PrivateAPI) { p.serverVersion = version }
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

	app.Use("*", p.checkProtocolVersion)

	rootAuth := iammiddleware.VerifyRootOnlySigV4(privateService, &root)
	app.Post(VersionPath, chainHandlers(rootAuth, p.handleVersion))
	app.Post(DerivePath, chainHandlers(rootAuth, p.handleDeriveSigningKey))
	app.Post(EvaluatePath, chainHandlers(rootAuth, p.handleEvaluatePolicy))
	app.Post(ResolveIdentityPath, chainHandlers(rootAuth, p.handleResolveIdentity))
	app.Post(ResolvePrincipalsPath, chainHandlers(rootAuth, p.handleResolvePrincipals))

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

// checkProtocolVersion answers every response with this build's protocol
// version and refuses a gateway too old for it to serve safely.
//
// It runs before root authentication so a version refusal is reported and
// logged as exactly that, rather than as a misleading 403 about the
// gateway's credential. The only thing that discloses to an unauthenticated
// peer is the protocol version, which the response header carries either
// way, on a listener that is already mTLS- or unix-socket-only.
func (p *PrivateAPI) checkProtocolVersion(ctx fiber.Ctx) error {
	ctx.Set(ProtocolHeader, strconv.Itoa(ProtocolVersion))

	// The version endpoint answers even a gateway this build refuses to
	// serve: it is how that gateway finds out what it is talking to. Keyed
	// on the path rather than on registration order, since a route
	// registered ahead of this middleware would not get the header set
	// above either.
	if ctx.Path() == VersionPath {
		return ctx.Next()
	}

	client, err := ParseProtocolVersion(ctx.Get(ProtocolHeader))
	if err != nil {
		return errProtocolMismatch(err.Error())
	}
	if client < MinClientProtocol {
		return errProtocolMismatch(fmt.Sprintf(
			"gateway speaks private protocol %d, this IAM service requires %d or newer: upgrade the gateway",
			client, MinClientProtocol))
	}

	return ctx.Next()
}

// ParseProtocolVersion reads a ProtocolHeader value. It is shared by both
// peers so they agree on what the header means, and is deliberately strict:
// a value it cannot read is a mismatch, never a default. Treating an absent
// or unreadable version as some assumed one is the fail-open direction for
// the check everything else is gated on.
func ParseProtocolVersion(value string) (int, error) {
	if value == "" {
		return 0, fmt.Errorf("no %s header", ProtocolHeader)
	}
	// Bounded before it is echoed into an error: this value is attacker-
	// controlled and ends up in a log line.
	if len(value) > maxProtocolDigits {
		return 0, fmt.Errorf("malformed %s header", ProtocolHeader)
	}
	// Digits only. Atoi by itself would also accept a leading sign, which is
	// not a version.
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return 0, fmt.Errorf("malformed %s header %q", ProtocolHeader, value)
		}
	}
	version, err := strconv.Atoi(value)
	if err != nil || version < 1 {
		return 0, fmt.Errorf("malformed %s header %q", ProtocolHeader, value)
	}
	return version, nil
}

// maxProtocolDigits bounds a protocol version's wire length, so an
// arbitrarily long header value never reaches a log line.
const maxProtocolDigits = 4
