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
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/logger"
	"github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/iamapi/internal/iammiddleware"
	"github.com/versity/versitygw/iamapi/internal/iamutil"
	"github.com/versity/versitygw/iamapi/storage"
	"github.com/versity/versitygw/internal/netutil"
)

const (
	shutDownDuration     = time.Second * 10
	requestHeaderMaxSize = 8 * 1024
)

// RootCredentials re-exports the type from iammiddleware so callers only need
// to import iamapi.
type RootCredentials = iammiddleware.RootCredentials

type CertStorage = netutil.CertStorage

func NewCertStorage() *CertStorage {
	return netutil.NewCertStorage()
}

type IAMApiServer struct {
	Router         *IAMApiRouter
	app            *fiber.App
	store          storage.Storer
	rootCreds      *RootCredentials
	CertStorage    *CertStorage
	quiet          bool
	keepAlive      bool
	health         string
	maxConnections int
	maxRequests    int
	socketPerm     os.FileMode
	onListen       func()
	// oidc holds the OIDC provider settings threaded into the router,
	// controller, and policy middleware; see OIDCConfig.
	oidc OIDCConfig
	// corsAllowOrigin is the single origin browsers may call this API from
	corsAllowOrigin string
}

// OIDCConfig groups the settings that govern how this API treats OIDC
// identity providers: whether CreateOpenIDConnectProvider may reach out for
// a thumbprint at all, and how strictly a provider's endpoint is validated
// and fetched from. The zero value is the default AWS-matching posture.
type OIDCConfig struct {
	// ThumbprintAutoFetchDisabled disables CreateOpenIDConnectProvider's
	// TLS auto-fetch fallback when ThumbprintList is omitted; see
	// WithOIDCThumbprintAutoFetchDisabled.
	ThumbprintAutoFetchDisabled bool
	// AllowPrivateEndpoints permits OIDC provider URLs that resolve to
	// loopback/private/link-local addresses, and that carry an explicit
	// port; see WithOIDCAllowPrivateEndpoints.
	AllowPrivateEndpoints bool
	// AllowInsecureTransport permits plaintext http OIDC provider URLs and
	// drops TLS verification for https ones; see
	// WithOIDCAllowInsecureTransport.
	AllowInsecureTransport bool
	// DiscoveryURLs holds "<provider url>=<discovery url>" pairs, each
	// redirecting one provider's discovery-document fetch; see
	// WithOIDCDiscoveryURLs.
	DiscoveryURLs []string
	// discovery is DiscoveryURLs parsed and keyed by stored provider Url,
	// built by New.
	discovery map[string]string
}

// endpointPolicy projects the endpoint relaxations into the form iamutil's
// URL-validation and fetch helpers take.
func (c OIDCConfig) endpointPolicy() iamutil.OIDCEndpointPolicy {
	return iamutil.OIDCEndpointPolicy{
		AllowPrivateEndpoints:  c.AllowPrivateEndpoints,
		AllowInsecureTransport: c.AllowInsecureTransport,
		DiscoveryURLs:          c.discovery,
	}
}

// parseDiscoveryURLs turns DiscoveryURLs' pairs into the map the endpoint
// policy takes, keyed by stored provider Url so a lookup by a provider's
// stored form hits directly. The provider Url is held to the same rules
// CreateOpenIDConnectProvider applies, so a pair naming a provider that could
// never be registered fails here; the discovery URL must be an absolute
// http or https URL, since it is fetched exactly as written.
func (c *OIDCConfig) parseDiscoveryURLs() error {
	if len(c.DiscoveryURLs) == 0 {
		return nil
	}
	c.discovery = make(map[string]string, len(c.DiscoveryURLs))
	for _, pair := range c.DiscoveryURLs {
		providerURL, discoveryURL, ok := cutDiscoveryURLPair(pair)
		providerURL, discoveryURL = strings.TrimSpace(providerURL), strings.TrimSpace(discoveryURL)
		if !ok || providerURL == "" {
			return fmt.Errorf("iamapi: oidc discovery url %q must be in <provider url>=<discovery url> form, with an http:// or https:// discovery url", pair)
		}
		stored, err := iamutil.ValidateOIDCProviderURL(providerURL, c.endpointPolicy())
		if err != nil {
			return fmt.Errorf("iamapi: oidc discovery url %q: invalid provider url %q: %w", pair, providerURL, err)
		}
		parsed, err := url.Parse(discoveryURL)
		if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
			return fmt.Errorf("iamapi: oidc discovery url %q: invalid discovery url %q", pair, discoveryURL)
		}
		if parsed.Scheme == "http" && !c.AllowInsecureTransport {
			return fmt.Errorf("iamapi: plaintext oidc discovery url %q requires insecure transport to be allowed", discoveryURL)
		}
		c.discovery[stored] = discoveryURL
	}
	return nil
}

// cutDiscoveryURLPair splits a "<provider url>=<discovery url>" pair at the
// "=" immediately preceding the discovery URL's scheme rather than at the
// first "=", since a provider Url's path may itself contain "=".
func cutDiscoveryURLPair(pair string) (providerURL, discoveryURL string, ok bool) {
	i := -1
	for _, sep := range []string{"=https://", "=http://"} {
		if j := strings.Index(pair, sep); j >= 0 && (i < 0 || j < i) {
			i = j
		}
	}
	if i < 0 {
		return "", "", false
	}
	return pair[:i], pair[i+1:], true
}

func New(store storage.Storer, root RootCredentials, opts ...Option) (*IAMApiServer, error) {
	if store == nil {
		return nil, fmt.Errorf("iamapi: storer is required")
	}

	server := &IAMApiServer{
		store:     store,
		rootCreds: &root,
		Router: &IAMApiRouter{
			store: store,
		},
	}

	for _, opt := range opts {
		opt(server)
	}

	if err := server.oidc.parseDiscoveryURLs(); err != nil {
		return nil, err
	}

	app := fiber.New(fiber.Config{
		AppName:           "versitygw-iam",
		ServerHeader:      "VERSITYGW",
		DisableKeepalive:  !server.keepAlive,
		ErrorHandler:      iammiddleware.GlobalErrorHandler,
		Concurrency:       server.maxConnections,
		ReadBufferSize:    requestHeaderMaxSize,
		StreamRequestBody: false,
	})

	server.app = app
	server.Router.app = app
	server.Router.rootCreds = server.rootCreds
	server.Router.oidc = server.oidc

	app.Use("*", recover.New(recover.Config{
		EnableStackTrace:  true,
		StackTraceHandler: iammiddleware.StackTraceHandler,
	}))

	if !server.quiet {
		app.Use("*", logger.New(logger.Config{
			Format: "${time} | vgw-iam | ${status} | ${latency} | ${ip} | ${method} | ${path} | ${error} | ${queryParams}\n",
			CustomTags: map[string]logger.LogFunc{
				logger.TagQueryStringParams: debuglogger.RedactedQueryParamsTag,
			},
		}))
	}

	if server.corsAllowOrigin != "" {
		app.Use("*", iammiddleware.CORS(server.corsAllowOrigin))
	}

	app.Use("*", iammiddleware.RequestIDs())

	if server.health != "" {
		app.Get(server.health, func(ctx fiber.Ctx) error {
			return ctx.SendStatus(http.StatusOK)
		})
	}

	if server.maxRequests > 0 {
		app.Use("*", iammiddleware.RateLimiter(server.maxRequests))
	}

	if debuglogger.IsDebugEnabled() {
		app.Use("*", iammiddleware.DebugLogger())
	}

	server.Router.Init()

	return server, nil
}

type Option func(*IAMApiServer)

func WithTLS(cs *CertStorage) Option {
	return func(s *IAMApiServer) { s.CertStorage = cs }
}

func WithQuiet() Option {
	return func(s *IAMApiServer) { s.quiet = true }
}

func WithHealth(health string) Option {
	return func(s *IAMApiServer) { s.health = health }
}

func WithKeepAlive() Option {
	return func(s *IAMApiServer) { s.keepAlive = true }
}

func WithConcurrencyLimiter(maxConnections, maxRequests int) Option {
	return func(s *IAMApiServer) {
		s.maxConnections = maxConnections
		s.maxRequests = maxRequests
	}
}

func WithSocketPerm(perm os.FileMode) Option {
	return func(s *IAMApiServer) { s.socketPerm = perm }
}

// WithCORSAllowOrigin sets the Access-Control-Allow-Origin value returned to
// browsers, and enables preflight handling. Required for the WebUI, which
// never shares a port with the IAM API. Empty (the default) skips the CORS
// middleware, leaving the API usable by CLI and SDK clients only.
func WithCORSAllowOrigin(origin string) Option {
	return func(s *IAMApiServer) { s.corsAllowOrigin = strings.TrimSpace(origin) }
}

func WithOnListen(fn func()) Option {
	return func(s *IAMApiServer) { s.onListen = fn }
}

// WithOIDCThumbprintAutoFetchDisabled disables CreateOpenIDConnectProvider's
// TLS auto-fetch fallback for when ThumbprintList is omitted. When set, an
// omitted ThumbprintList is rejected with a MissingValue error instead of
// the gateway making an outbound TLS connection to the caller-supplied URL
// — an operational safety valve for restricted/air-gapped deployments.
func WithOIDCThumbprintAutoFetchDisabled() Option {
	return func(s *IAMApiServer) { s.oidc.ThumbprintAutoFetchDisabled = true }
}

// WithOIDCAllowPrivateEndpoints permits an OIDC provider Url that resolves
// to a loopback/private/link-local address, and one carrying an explicit
// port. Both are refused by default, which makes an IdP that only exists on
// an internal network — a SPIFFE/SPIRE OIDC discovery provider on a cluster
// Service, say — impossible to register or verify tokens against. Transport
// is unaffected: still https, still fully verified.
func WithOIDCAllowPrivateEndpoints() Option {
	return func(s *IAMApiServer) { s.oidc.AllowPrivateEndpoints = true }
}

// WithOIDCAllowInsecureTransport permits plaintext http OIDC provider URLs
// and drops TLS certificate verification (ThumbprintList pinning included)
// for https ones, leaving the network path as the only thing authenticating
// the IdP. Intended for an IdP reachable only over a path that is itself
// trusted — a discovery provider bound to loopback as a sidecar in this
// process's own pod.
func WithOIDCAllowInsecureTransport() Option {
	return func(s *IAMApiServer) { s.oidc.AllowInsecureTransport = true }
}

// WithOIDCDiscoveryURLs redirects the discovery-document fetch of individual
// providers, taking "<provider url>=<discovery url>" pairs. The discovery URL
// is fetched exactly as given, so it must include the
// "/.well-known/openid-configuration" path when the IdP serves it there.
//
// Only the fetch moves: the provider Url is still what a token's iss claim
// and the fetched document's own issuer field must match, and the JWKS is
// still fetched from the jwks_uri that document publishes. That is what lets
// an IdP hand out tokens naming a public issuer while this gateway reads its
// keys over a cluster-internal path — the endpoints being private is the
// point, so a configured discovery URL and the jwks_uri it publishes are
// exempt from the private-address check without WithOIDCAllowPrivateEndpoints.
func WithOIDCDiscoveryURLs(pairs []string) Option {
	return func(s *IAMApiServer) { s.oidc.DiscoveryURLs = pairs }
}

func (s *IAMApiServer) ServeMultiPort(ports []string) error {
	if len(ports) == 0 {
		return fmt.Errorf("no ports specified")
	}

	var listeners []net.Listener
	for _, portSpec := range ports {
		var ln net.Listener
		var err error

		if s.CertStorage != nil {
			ln, err = netutil.NewMultiAddrTLSListener(fiber.NetworkTCP, portSpec, s.CertStorage.GetCertificate, netutil.ListenerOptions{SocketPerm: s.socketPerm})
		} else {
			ln, err = netutil.NewMultiAddrListener(fiber.NetworkTCP, portSpec, netutil.ListenerOptions{SocketPerm: s.socketPerm})
		}
		if err != nil {
			closeListeners(listeners)
			return fmt.Errorf("failed to bind iam listener %s: %w", portSpec, err)
		}

		listeners = append(listeners, ln)
	}

	if len(listeners) == 0 {
		return fmt.Errorf("failed to create any iam listeners")
	}

	finalListener := netutil.NewMultiListener(listeners...)

	if s.onListen != nil {
		fn := s.onListen
		s.app.Hooks().OnListen(func(fiber.ListenData) error {
			fn()
			return nil
		})
	}

	return s.app.Listener(finalListener, fiber.ListenConfig{
		DisableStartupMessage: true,
	})
}

// closeListeners closes already bound listeners so a failed bind part way
// through ServeMultiPort does not leave the earlier ports (and unix socket
// files) held open.
func closeListeners(listeners []net.Listener) {
	for _, ln := range listeners {
		if err := ln.Close(); err != nil {
			debuglogger.InternalError(fmt.Errorf("close iam listener %v: %w", ln.Addr(), err))
		}
	}
}

func (s *IAMApiServer) Shutdown() error {
	return s.app.ShutdownWithTimeout(shutDownDuration)
}
