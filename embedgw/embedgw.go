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

// Package embedgw provides a high-level entry point for running the VersityGW
// S3 gateway as a library, making it easy to embed the gateway into other
// applications.
//
// Note: only a single gateway instance per process is currently supported.
// Several subsystems (bucket-name validation, debug logging) rely on
// package-level globals that would race if RunVersityGW were called
// concurrently from multiple goroutines.
package embedgw

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/metrics"
	"github.com/versity/versitygw/s3api"
	"github.com/versity/versitygw/s3api/middlewares"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3event"
	"github.com/versity/versitygw/s3log"
	"github.com/versity/versitygw/website"
	"github.com/versity/versitygw/webui"
)

const awsDefaultRegion = "us-east-1"

// Config holds all configuration options for running the VersityGW gateway.
type Config struct {
	// RootUserAccess is the access key ID for the root account. The root
	// account is granted full authorization to all API requests after
	// authentication. Required.
	RootUserAccess string
	// RootUserSecret is the secret access key for the root account. Required.
	RootUserSecret string
	// Region is the AWS region name reported to S3 clients (e.g. "us-east-1").
	// Defaults to "us-east-1" when empty.
	Region string

	// Ports is the list of S3 API listening addresses. Each entry can be
	// "host:port" to bind a specific interface, or ":port" to bind all
	// interfaces. Hostnames are resolved to all matching IPs. UNIX domain
	// sockets are supported as absolute or relative paths, or Linux abstract
	// namespace sockets prefixed with "@" (e.g. "@versitygw-s3"). Multiple
	// entries are supported (e.g. [":7070", "localhost:9090"]). Required.
	Ports []string

	// AdminPorts is the list of admin API listening addresses. Accepts the
	// same formats as Ports. When empty, the admin API is served on the same
	// endpoints as the S3 API. Setting this allows finer-grained firewall
	// control over the admin endpoint with optionally separate TLS certs.
	AdminPorts []string

	// MaxConnections is the maximum number of concurrent TCP connections
	// accepted by the S3 API server.
	MaxConnections int
	// MaxRequests is the maximum number of concurrent in-flight S3 requests.
	// Should not exceed MaxConnections; if it does, a warning is logged.
	MaxRequests int

	// AdminMaxConnections is the maximum concurrent TCP connections for the
	// separate admin server. Only used when AdminPorts is non-empty.
	AdminMaxConnections int
	// AdminMaxRequests is the maximum concurrent in-flight requests for the
	// admin server. Should not exceed AdminMaxConnections.
	AdminMaxRequests int

	// MultipartMaxParts is the maximum number of parts allowed in a single
	// multipart upload. The S3 specification allows up to 10,000 parts;
	// the default value of 10000 matches the AWS S3 maximum. Clients that
	// attempt to upload more parts than this limit receive an error.
	MultipartMaxParts int

	// CertFile is the path to the TLS certificate file for the S3 API server.
	// Both CertFile and KeyFile must be provided together to enable TLS.
	CertFile string
	// KeyFile is the path to the TLS private key file for the S3 API server.
	KeyFile string

	// AdminCertFile is the path to the TLS certificate for the admin server.
	// Both AdminCertFile and AdminKeyFile must be provided together. When
	// empty and AdminPorts is set, the admin server runs without TLS.
	AdminCertFile string
	// AdminKeyFile is the path to the TLS private key for the admin server.
	AdminKeyFile string

	// CORSAllowOrigin sets the default Access-Control-Allow-Origin response
	// header value applied when no bucket-level CORS configuration exists and
	// for all admin API responses. When WebuiPorts is set and this is empty,
	// it defaults to "*". For production, set this to a specific origin
	// (e.g. "https://webui.example.com") to restrict cross-origin access.
	CORSAllowOrigin string

	// Debug enables verbose debug logging to stdout, including details for
	// signature verification steps. Not intended for production use.
	Debug bool
	// IAMDebug enables verbose IAM subsystem debug logging.
	IAMDebug bool
	// Quiet suppresses per-request summary logging to stdout.
	Quiet bool
	// Readonly restricts the gateway to read-only S3 operations; all write
	// requests are rejected.
	Readonly bool
	// KeepAlive enables HTTP keep-alive on S3 API connections.
	KeepAlive bool
	// DisableACLs disables ACL enforcement at the gateway level. All ACL
	// headers on requests are ignored and no access control is enforced via
	// bucket ACLs. PutBucketAcl returns AccessControlListNotSupported.
	// Prefer bucket policies over ACLs when this is enabled.
	DisableACLs bool
	// DisableStrictBucketNames allows legacy or non-DNS-compliant bucket
	// names by skipping strict validation. By default, bucket name validation
	// follows the rules described in the AWS S3 documentation.
	DisableStrictBucketNames bool

	// VirtualDomain enables virtual-hosted-style bucket addressing. Set to
	// the base domain name (e.g. "s3.example.com") so that bucket access uses
	// the form "https://<bucket>.s3.example.com/". Path-style addressing
	// remains enabled alongside it. Each bucket typically requires a DNS
	// entry pointing to the gateway.
	VirtualDomain string

	// HealthPath is the URL path for unauthenticated health-check requests
	// (e.g. "/healthz"). The endpoint returns HTTP 200 for GET requests and
	// is commonly used by load balancers. Any bucket whose name matches the
	// path segment is masked while this is set.
	HealthPath string

	// SocketPerm is the octal file-mode string for UNIX domain socket
	// permissions (e.g. "0660" for owner+group read/write). Has no effect on
	// TCP/IP addresses or Linux abstract "@" namespace sockets. When empty,
	// permissions are determined by the process umask.
	SocketPerm string

	// IAM Backends
	//
	// The gateway supports five external IAM backends. At most one may be
	// active at a time. When the fields for more than one backend are
	// populated, the first match in the following priority order wins:
	//
	//   1. IAMDir          -- local directory
	//   2. LDAPServerURL   -- LDAP
	//   3. S3IAMEndpoint   -- S3-backed
	//   4. VaultEndpointURL -- HashiCorp Vault
	//   5. IpaHost         -- FreeIPA
	//
	// Configuring an IAM backend is optional. When none of the trigger fields
	// above are set, the gateway runs in single-account mode: only the root
	// account (RootUserAccess/RootUserSecret) exists and the user management
	// API is unavailable.
	//
	// The IAMCache fields below apply to all backends except single-account
	// mode.

	// IAMDir enables the local file-based IAM backend. Set to the directory
	// path where account files are stored. Account data is plain text
	// protected only by filesystem permissions; suitable for development but
	// not recommended for production deployments.
	IAMDir string

	// LDAP IAM backend. Activated when LDAPServerURL is non-empty.

	// LDAPServerURL is the URL of the LDAP server (e.g. "ldap://ldap.example.com:389").
	LDAPServerURL string
	// LDAPBindDN is the distinguished name used to bind to the LDAP server.
	LDAPBindDN string
	// LDAPPassword is the password for LDAPBindDN.
	LDAPPassword string
	// LDAPQueryBase is the base DN for user search queries.
	LDAPQueryBase string
	// LDAPObjClasses is the LDAP object class filter for user entries.
	LDAPObjClasses string
	// LDAPAccessAttr is the LDAP attribute that holds the S3 access key ID.
	LDAPAccessAttr string
	// LDAPSecretAttr is the LDAP attribute that holds the S3 secret key.
	LDAPSecretAttr string
	// LDAPRoleAttr is the LDAP attribute that holds the user role.
	LDAPRoleAttr string
	// LDAPUserIDAttr is the LDAP attribute that holds the POSIX user ID.
	LDAPUserIDAttr string
	// LDAPGroupIDAttr is the LDAP attribute that holds the POSIX group ID.
	LDAPGroupIDAttr string
	// LDAPProjectIDAttr is the LDAP attribute that holds the project ID.
	LDAPProjectIDAttr string
	// LDAPTLSSkipVerify disables TLS certificate verification for the LDAP
	// connection. Use only in development or trusted internal environments.
	LDAPTLSSkipVerify bool

	// HashiCorp Vault IAM backend. Activated when VaultEndpointURL is non-empty.

	// VaultEndpointURL is the HashiCorp Vault server URL
	// (e.g. "https://vault.example.com:8200").
	VaultEndpointURL string
	// VaultNamespace is the Vault namespace to use (Vault Enterprise only).
	VaultNamespace string
	// VaultSecretStoragePath is the KV secrets engine path where account
	// data is stored.
	VaultSecretStoragePath string
	// VaultSecretStorageNamespace is the Vault namespace for the secrets
	// storage path (Vault Enterprise only).
	VaultSecretStorageNamespace string
	// VaultAuthMethod is the Vault authentication method to use
	// (e.g. "token", "approle").
	VaultAuthMethod string
	// VaultAuthNamespace is the Vault namespace used for authentication
	// (Vault Enterprise only).
	VaultAuthNamespace string
	// VaultMountPath is the mount path of the auth method in Vault.
	VaultMountPath string
	// VaultRootToken is the Vault token used when VaultAuthMethod is "token".
	VaultRootToken string
	// VaultRoleID is the AppRole role ID used when VaultAuthMethod is "approle".
	VaultRoleID string
	// VaultRoleSecret is the AppRole secret ID.
	VaultRoleSecret string
	// VaultServerCert is the path to the CA certificate used to verify the
	// Vault server's TLS certificate.
	VaultServerCert string
	// VaultClientCert is the path to the client TLS certificate for mutual
	// TLS authentication with Vault.
	VaultClientCert string
	// VaultClientCertKey is the path to the private key for VaultClientCert.
	VaultClientCertKey string

	// S3-backed IAM backend. Activated when S3IAMEndpoint is non-empty.

	// S3IAMAccess is the access key ID for the S3-backed IAM backend.
	S3IAMAccess string
	// S3IAMSecret is the secret key for the S3-backed IAM backend.
	S3IAMSecret string
	// S3IAMRegion is the AWS region of the S3-backed IAM bucket.
	S3IAMRegion string
	// S3IAMBucket is the bucket name that stores IAM account data.
	S3IAMBucket string
	// S3IAMEndpoint is the endpoint URL for the S3-backed IAM service.
	// Useful when using a non-AWS S3-compatible store.
	S3IAMEndpoint string
	// S3IAMDisableSSLVerify disables TLS certificate verification for the
	// S3-backed IAM connection. Use only in development or trusted internal
	// environments.
	S3IAMDisableSSLVerify bool

	// FreeIPA IAM backend. Activated when IpaHost is non-empty.

	// IpaHost is the hostname or URL of the FreeIPA server.
	IpaHost string
	// IpaVaultName is the name of the FreeIPA vault used to store credentials.
	IpaVaultName string
	// IpaUser is the FreeIPA username for authentication.
	IpaUser string
	// IpaPassword is the FreeIPA password for authentication.
	IpaPassword string
	// IpaInsecure disables TLS certificate verification for the FreeIPA
	// connection.
	IpaInsecure bool

	// IAM Cache
	//
	// The gateway maintains an in-memory cache of IAM account lookups to
	// reduce load on the external IAM backend. The cache applies to all
	// backends except single-account mode. All fields are optional.

	// IAMCacheDisable disables the in-memory IAM account cache. By default,
	// accounts are cached to reduce backend lookup frequency.
	IAMCacheDisable bool
	// IAMCacheTTL is the time-to-live in seconds for cached IAM entries.
	IAMCacheTTL int
	// IAMCachePrune is the interval in seconds between cache prune runs that
	// remove expired entries.
	IAMCachePrune int

	// Access Logging
	//
	// Records details of every S3 and admin API request. All three outputs
	// are independent and can be enabled simultaneously in any combination.
	// All are optional; omit or leave empty to disable that output.

	// AccessLog is the file path for S3 request access logs in the AWS S3
	// access log format. Use absolute paths; relative paths may break if the
	// server changes its working directory. Empty disables file logging.
	AccessLog string
	// LogWebhookURL is an HTTP(S) URL that receives S3 access log entries as
	// JSON-encoded POST requests. Can be set alongside AccessLog.
	LogWebhookURL string
	// AdminLogFile is the file path for admin API request logs.
	AdminLogFile string

	// Metrics
	//
	// The gateway can emit operational metrics to StatsD and DogStatsD.
	// Both backends may be active simultaneously; set either or both.
	// All fields are optional. When neither StatsdServers nor DogstatsServers
	// is set, metrics are disabled.

	// MetricsService is the service name label attached to all emitted metrics.
	// Defaults to the system hostname when empty.
	MetricsService string
	// StatsdServers is a comma-separated list of StatsD server addresses
	// (e.g. "localhost:8125").
	StatsdServers string
	// DogstatsServers is a comma-separated list of DogStatsD server addresses.
	DogstatsServers string

	// Bucket Event Notifications
	//
	// The gateway can forward S3 bucket events (object created, deleted, etc.)
	// to an external message broker or webhook. At most one event sink may be
	// active at a time. When more than one sink's fields are populated, the
	// first match in the following priority order wins:
	//
	//   1. EventWebhookURL -- HTTP/S webhook
	//   2. KafkaURL        -- Apache Kafka
	//   3. NatsURL         -- NATS
	//   4. RabbitmqURL     -- RabbitMQ
	//
	// Configuring event notifications is optional. When none of the trigger
	// fields above are set, event notifications are disabled.
	//
	// EventConfigFilePath applies to whichever sink is active and can be set
	// regardless of which sink is chosen.

	// KafkaURL is the broker URL for Kafka event notifications
	// (e.g. "kafka://broker:9092").
	KafkaURL string
	// KafkaTopic is the Kafka topic name for bucket event messages.
	KafkaTopic string
	// KafkaKey is the optional Kafka message key.
	KafkaKey string
	// NatsURL is the NATS server URL for event notifications
	// (e.g. "nats://localhost:4222").
	NatsURL string
	// NatsTopic is the NATS subject for bucket event messages.
	NatsTopic string
	// RabbitmqURL is the RabbitMQ connection URL
	// (e.g. "amqp://user:pass@rabbitmq:5672/").
	RabbitmqURL string
	// RabbitmqExchange is the RabbitMQ exchange to publish events to.
	// Leave empty to use the default exchange.
	RabbitmqExchange string
	// RabbitmqRoutingKey is the routing key for RabbitMQ event messages.
	// Leave empty to use no routing key.
	RabbitmqRoutingKey string
	// EventWebhookURL is an HTTP(S) URL that receives bucket event
	// notifications as POST requests.
	EventWebhookURL string
	// EventConfigFilePath is the path to a JSON event filter configuration
	// file that controls which events are forwarded to the active event sink.
	// When empty, all events are forwarded. Generate a default config with:
	// versitygw utils gen-event-filter-config --path <dir>
	EventConfigFilePath string

	// WebUI
	//
	// The browser-based management WebUI can be served in two independent
	// modes, which may be enabled simultaneously:
	//
	//   - Standalone server (WebuiPorts): the WebUI runs on its own dedicated
	//     listening address(es), separate from the S3 endpoint.
	//
	//   - Embedded on the S3 endpoint (WebuiS3Prefix): the WebUI is served
	//     directly from the S3 port under a URL path prefix. Useful when only
	//     one listening port is available.
	//
	// Both modes are optional. Leave WebuiPorts empty and WebuiS3Prefix empty
	// to disable the WebUI entirely.

	// WebuiPorts is the list of listening addresses for the standalone WebUI
	// server. Accepts the same formats as Ports. When empty, the WebUI server
	// is disabled.
	WebuiPorts []string
	// WebuiCertFile is the path to the TLS certificate for the WebUI server.
	// When empty and gateway TLS (CertFile/KeyFile) is configured, the WebUI
	// inherits those certs. Both WebuiCertFile and WebuiKeyFile must be
	// provided together.
	WebuiCertFile string
	// WebuiKeyFile is the path to the TLS private key for the WebUI server.
	WebuiKeyFile string
	// WebuiNoTLS forces the WebUI to use plain HTTP even when TLS certificates
	// are available. Useful when TLS is terminated by a reverse proxy in front
	// of the WebUI.
	WebuiNoTLS bool
	// WebuiGateways overrides the S3 gateway URLs provided to the WebUI. By
	// default the gateway auto-detects URLs from Ports. Set this when running
	// behind a reverse proxy or load balancer where the auto-detected URLs are
	// incorrect (e.g. ["https://s3.example.com", "http://192.168.1.1:7070"]).
	WebuiGateways []string
	// WebuiAdminGateways overrides the admin gateway URLs provided to the
	// WebUI. By default the gateway auto-detects URLs from AdminPorts, or
	// reuses WebuiGateways when AdminPorts is empty.
	WebuiAdminGateways []string
	// WebuiPathPrefix is the URL path prefix under which the WebUI and its
	// API endpoints are served (e.g. "/ui"). Must start with "/" and be a
	// single path segment with no trailing slash. Leave empty to serve from
	// the root path.
	WebuiPathPrefix string

	// WebuiS3Prefix mounts the WebUI directly on the S3 API endpoint at the
	// given path prefix (e.g. "/ui"). Requests matching the prefix are routed
	// to the WebUI instead of S3. Any bucket whose name equals the prefix
	// segment is masked. Leave empty to disable WebUI hosting on the S3
	// endpoint.
	WebuiS3Prefix string

	// Static website hosting endpoint
	//
	// WebsitePorts is the list of listening addresses for the static website
	// hosting endpoint. Accepts the same formats as Ports. When empty, the
	// website endpoint is disabled.
	WebsitePorts []string
	// WebsiteDomain is the base domain for website virtual-host routing. For
	// example, host "blog.example.com" serves bucket "blog" when this is
	// "example.com". When empty, the full request hostname is used as the
	// bucket name.
	WebsiteDomain string
	// WebsiteCertFile is the path to the TLS certificate for the website
	// endpoint. When empty and gateway TLS (CertFile/KeyFile) is configured,
	// the website endpoint inherits those certs. Both WebsiteCertFile and
	// WebsiteKeyFile must be provided together.
	WebsiteCertFile string
	// WebsiteKeyFile is the path to the TLS private key for the website
	// endpoint.
	WebsiteKeyFile string
	// WebsiteNoTLS forces the website endpoint to use plain HTTP even when TLS
	// certificates are available.
	WebsiteNoTLS bool

	// SigHup is an optional channel that signals the gateway to reload TLS
	// certificates and rotate log files (equivalent to SIGHUP). When nil,
	// this feature is disabled.
	SigHup <-chan struct{}

	// Version, Build, and BuildTime are displayed in the startup banner.
	// All three are optional; omit or leave empty to suppress the field.
	Version   string
	Build     string
	BuildTime string
}

// TODO: remove gatewayRunning once package-level globals (bucket-name
// validation, debug logging) are eliminated and concurrent calls are safe.
var gatewayRunning atomic.Bool

// RunVersityGW starts the VersityGW gateway with the supplied backend and
// configuration. It blocks until ctx is cancelled, or an error occurs. All
// subsystems are gracefully shut down before the function returns.
//
// Only one instance may run per process at a time. Calling RunVersityGW
// concurrently or a second time before the first call returns will return an
// error.
func RunVersityGW(ctx context.Context, be backend.Backend, cfg *Config) error {
	if !gatewayRunning.CompareAndSwap(false, true) {
		return fmt.Errorf("embedgw: RunVersityGW is already running; only one instance per process is supported")
	}
	defer gatewayRunning.Store(false)

	if cfg.RootUserAccess == "" || cfg.RootUserSecret == "" {
		return fmt.Errorf("root user access and secret key must be provided")
	}

	err := validateWebUIPathPrefix("WebuiPathPrefix", cfg.WebuiPathPrefix)
	if err != nil {
		return err
	}

	if cfg.MaxConnections < 1 {
		return fmt.Errorf("max-connections must be positive")
	}
	if cfg.MaxRequests < 1 {
		return fmt.Errorf("max-requests must be positive")
	}
	if cfg.MaxRequests > cfg.MaxConnections {
		log.Printf("WARNING: max-requests (%d) exceeds max-connections (%d) which could allow for gateway to panic before throttling requests",
			cfg.MaxRequests, cfg.MaxConnections)
	}
	if cfg.MultipartMaxParts < 1 {
		return fmt.Errorf("mp-max-parts must be positive")
	}

	if len(cfg.Ports) == 0 {
		return fmt.Errorf("no ports specified")
	}

	if cfg.Region == "" {
		cfg.Region = awsDefaultRegion
	}

	// WebUI runs in a browser and typically talks to the gateway/admin APIs cross-origin
	// (different port). If no bucket CORS configuration exists, those API responses need
	// a default Access-Control-Allow-Origin to be usable from the WebUI.
	corsAllowOrigin := cfg.CORSAllowOrigin
	if len(cfg.WebuiPorts) > 0 && strings.TrimSpace(corsAllowOrigin) == "" {
		corsAllowOrigin = "*"
		webuiScheme := "http"
		if !cfg.WebuiNoTLS && (strings.TrimSpace(cfg.WebuiCertFile) != "" || strings.TrimSpace(cfg.CertFile) != "") {
			webuiScheme = "https"
		}

		var suggestion string
		var allOrigins []string
		for _, addr := range cfg.WebuiPorts {
			ips, ipsErr := getMatchingIPs(addr)
			_, webPrt, prtErr := net.SplitHostPort(addr)
			if ipsErr == nil && prtErr == nil && len(ips) > 0 {
				for _, ip := range ips {
					allOrigins = append(allOrigins, fmt.Sprintf("%s://%s:%s", webuiScheme, ip, webPrt))
				}
			}
		}
		if len(allOrigins) > 0 {
			suggestion = fmt.Sprintf("consider setting it to one of: %s (or your public hostname)", strings.Join(allOrigins, ", "))
		} else {
			suggestion = fmt.Sprintf("consider setting it to %s://<host>:<port>", webuiScheme)
		}

		fmt.Fprintf(os.Stderr, "WARNING: WebuiPorts is set but CORSAllowOrigin is not; defaulting to '*'; %s\n", suggestion)
	}

	if err := validatePortConflicts(cfg.Ports, cfg.AdminPorts, cfg.WebuiPorts, cfg.WebsitePorts); err != nil {
		return err
	}

	if err := validateWebUIPathPrefix("WebuiS3Prefix", cfg.WebuiS3Prefix); err != nil {
		return err
	}

	// Pre-validate gateway URL lists once; both the WebuiS3Prefix block and the
	// WebuiPorts block need these, so validate here to avoid doing it twice.
	var validatedWebuiGateways []string
	if len(cfg.WebuiGateways) > 0 {
		validatedWebuiGateways, err = validateGatewayURLs(cfg.WebuiGateways, "WebuiGateways")
		if err != nil {
			return err
		}
	}
	var validatedWebuiAdminGateways []string
	if len(cfg.WebuiAdminGateways) > 0 {
		validatedWebuiAdminGateways, err = validateGatewayURLs(cfg.WebuiAdminGateways, "WebuiAdminGateways")
		if err != nil {
			return err
		}
	}

	utils.SetBucketNameValidationStrict(!cfg.DisableStrictBucketNames)

	var parsedSocketPerm os.FileMode
	if cfg.SocketPerm != "" {
		perm, err := strconv.ParseUint(cfg.SocketPerm, 8, 32)
		if err != nil {
			return fmt.Errorf("invalid SocketPerm value %q: must be an octal integer (e.g. '0660'): %w", cfg.SocketPerm, err)
		}
		parsedSocketPerm = os.FileMode(perm)
	}

	opts := []s3api.Option{
		s3api.WithConcurrencyLimiter(cfg.MaxConnections, cfg.MaxRequests),
		s3api.WithMpMaxParts(cfg.MultipartMaxParts),
	}
	if cfg.SocketPerm != "" {
		opts = append(opts, s3api.WithSocketPerm(parsedSocketPerm))
	}
	if corsAllowOrigin != "" {
		opts = append(opts, s3api.WithCORSAllowOrigin(corsAllowOrigin))
	}

	if cfg.CertFile != "" || cfg.KeyFile != "" {
		if cfg.CertFile == "" {
			return fmt.Errorf("TLS key specified without cert file")
		}
		if cfg.KeyFile == "" {
			return fmt.Errorf("TLS cert specified without key file")
		}
		cs := utils.NewCertStorage()
		if err := cs.SetCertificate(cfg.CertFile, cfg.KeyFile); err != nil {
			return fmt.Errorf("tls: load certs: %v", err)
		}
		opts = append(opts, s3api.WithTLS(cs))
	}
	if len(cfg.AdminPorts) == 0 {
		opts = append(opts, s3api.WithAdminServer())
	}
	if cfg.Quiet {
		opts = append(opts, s3api.WithQuiet())
	}
	if cfg.HealthPath != "" {
		opts = append(opts, s3api.WithHealth(cfg.HealthPath))
	}
	if cfg.Readonly {
		opts = append(opts, s3api.WithReadOnly())
	}
	if cfg.VirtualDomain != "" {
		opts = append(opts, s3api.WithHostStyle(cfg.VirtualDomain))
	}
	if cfg.KeepAlive {
		opts = append(opts, s3api.WithKeepAlive())
	}
	if cfg.DisableACLs {
		opts = append(opts, s3api.WithDisableACL())
	}
	if cfg.Debug {
		debuglogger.SetDebugEnabled()
	}
	if cfg.IAMDebug {
		debuglogger.SetIAMDebugEnabled()
	}

	iam, err := auth.New(&auth.Opts{
		RootAccount: auth.Account{
			Access: cfg.RootUserAccess,
			Secret: cfg.RootUserSecret,
			Role:   auth.RoleAdmin,
		},
		Dir:                         cfg.IAMDir,
		LDAPServerURL:               cfg.LDAPServerURL,
		LDAPBindDN:                  cfg.LDAPBindDN,
		LDAPPassword:                cfg.LDAPPassword,
		LDAPQueryBase:               cfg.LDAPQueryBase,
		LDAPObjClasses:              cfg.LDAPObjClasses,
		LDAPAccessAtr:               cfg.LDAPAccessAttr,
		LDAPSecretAtr:               cfg.LDAPSecretAttr,
		LDAPRoleAtr:                 cfg.LDAPRoleAttr,
		LDAPUserIdAtr:               cfg.LDAPUserIDAttr,
		LDAPGroupIdAtr:              cfg.LDAPGroupIDAttr,
		LDAPProjectIdAtr:            cfg.LDAPProjectIDAttr,
		LDAPTLSSkipVerify:           cfg.LDAPTLSSkipVerify,
		VaultEndpointURL:            cfg.VaultEndpointURL,
		VaultNamespace:              cfg.VaultNamespace,
		VaultSecretStoragePath:      cfg.VaultSecretStoragePath,
		VaultSecretStorageNamespace: cfg.VaultSecretStorageNamespace,
		VaultAuthMethod:             cfg.VaultAuthMethod,
		VaultAuthNamespace:          cfg.VaultAuthNamespace,
		VaultMountPath:              cfg.VaultMountPath,
		VaultRootToken:              cfg.VaultRootToken,
		VaultRoleId:                 cfg.VaultRoleID,
		VaultRoleSecret:             cfg.VaultRoleSecret,
		VaultServerCert:             cfg.VaultServerCert,
		VaultClientCert:             cfg.VaultClientCert,
		VaultClientCertKey:          cfg.VaultClientCertKey,
		S3Access:                    cfg.S3IAMAccess,
		S3Secret:                    cfg.S3IAMSecret,
		S3Region:                    cfg.S3IAMRegion,
		S3Bucket:                    cfg.S3IAMBucket,
		S3Endpoint:                  cfg.S3IAMEndpoint,
		S3DisableSSlVerfiy:          cfg.S3IAMDisableSSLVerify,
		CacheDisable:                cfg.IAMCacheDisable,
		CacheTTL:                    cfg.IAMCacheTTL,
		CachePrune:                  cfg.IAMCachePrune,
		IpaHost:                     cfg.IpaHost,
		IpaVaultName:                cfg.IpaVaultName,
		IpaUser:                     cfg.IpaUser,
		IpaPassword:                 cfg.IpaPassword,
		IpaInsecure:                 cfg.IpaInsecure,
	})
	if err != nil {
		return fmt.Errorf("setup iam: %w", err)
	}

	loggers, err := s3log.InitLogger(&s3log.LogConfig{
		LogFile:      cfg.AccessLog,
		WebhookURL:   cfg.LogWebhookURL,
		AdminLogFile: cfg.AdminLogFile,
	})
	if err != nil {
		return fmt.Errorf("setup logger: %w", err)
	}

	metricsManager, err := metrics.NewManager(ctx, metrics.Config{
		ServiceName:      cfg.MetricsService,
		StatsdServers:    cfg.StatsdServers,
		DogStatsdServers: cfg.DogstatsServers,
	})
	if err != nil {
		return fmt.Errorf("init metrics manager: %w", err)
	}

	evSender, err := s3event.InitEventSender(&s3event.EventConfig{
		KafkaURL:             cfg.KafkaURL,
		KafkaTopic:           cfg.KafkaTopic,
		KafkaTopicKey:        cfg.KafkaKey,
		NatsURL:              cfg.NatsURL,
		NatsTopic:            cfg.NatsTopic,
		RabbitmqURL:          cfg.RabbitmqURL,
		RabbitmqExchange:     cfg.RabbitmqExchange,
		RabbitmqRoutingKey:   cfg.RabbitmqRoutingKey,
		WebhookURL:           cfg.EventWebhookURL,
		FilterConfigFilePath: cfg.EventConfigFilePath,
	})
	if err != nil {
		return fmt.Errorf("init bucket event notifications: %w", err)
	}

	if cfg.WebuiS3Prefix != "" {
		s3SSLEnabled := cfg.CertFile != ""
		s3AdmSSLEnabled := s3SSLEnabled
		if len(cfg.AdminPorts) > 0 {
			s3AdmSSLEnabled = cfg.AdminCertFile != ""
		}

		var s3WebGateways []string
		if len(validatedWebuiGateways) > 0 {
			s3WebGateways = validatedWebuiGateways
		} else {
			for _, p := range cfg.Ports {
				urls, err := buildServiceURLs(p, s3SSLEnabled)
				if err != nil {
					return fmt.Errorf("webui-s3-prefix: build gateway URLs: %w", err)
				}
				s3WebGateways = append(s3WebGateways, urls...)
			}
			sortGatewayURLs(s3WebGateways)
		}

		s3WebAdminGateways := s3WebGateways
		if len(validatedWebuiAdminGateways) > 0 {
			s3WebAdminGateways = validatedWebuiAdminGateways
		} else if len(cfg.AdminPorts) > 0 {
			s3WebAdminGateways = nil
			for _, admPort := range cfg.AdminPorts {
				urls, err := buildServiceURLs(admPort, s3AdmSSLEnabled)
				if err != nil {
					return fmt.Errorf("webui-s3-prefix: build admin gateway URLs: %w", err)
				}
				s3WebAdminGateways = append(s3WebAdminGateways, urls...)
			}
			sortGatewayURLs(s3WebAdminGateways)
		}

		opts = append(opts, s3api.WithWebUI(cfg.WebuiS3Prefix, &webui.ServerConfig{
			Gateways:      s3WebGateways,
			AdminGateways: s3WebAdminGateways,
			Region:        cfg.Region,
		}))
	}

	srv, err := s3api.New(be, middlewares.RootUserConfig{
		Access: cfg.RootUserAccess,
		Secret: cfg.RootUserSecret,
	}, cfg.Region, iam, loggers.S3Logger, loggers.AdminLogger, evSender, metricsManager, opts...)
	if err != nil {
		return fmt.Errorf("init gateway: %v", err)
	}

	var admSrv *s3api.S3AdminServer

	if len(cfg.AdminPorts) > 0 {
		if cfg.AdminMaxConnections < 1 {
			return fmt.Errorf("admin-max-connections must be positive")
		}
		if cfg.AdminMaxRequests < 1 {
			return fmt.Errorf("admin-max-requests must be positive")
		}
		if cfg.AdminMaxRequests > cfg.AdminMaxConnections {
			log.Printf("WARNING: admin-max-requests (%d) exceeds admin-max-connections (%d) which could allow for gateway to panic before throttling requests",
				cfg.AdminMaxRequests, cfg.AdminMaxConnections)
		}

		admOpts := []s3api.AdminOpt{
			s3api.WithAdminConcurrencyLimiter(cfg.AdminMaxConnections, cfg.AdminMaxRequests),
		}

		if corsAllowOrigin != "" {
			admOpts = append(admOpts, s3api.WithAdminCORSAllowOrigin(corsAllowOrigin))
		}

		if cfg.AdminCertFile != "" || cfg.AdminKeyFile != "" {
			if cfg.AdminCertFile == "" {
				return fmt.Errorf("TLS key specified without cert file")
			}
			if cfg.AdminKeyFile == "" {
				return fmt.Errorf("TLS cert specified without key file")
			}
			cs := utils.NewCertStorage()
			if err = cs.SetCertificate(cfg.AdminCertFile, cfg.AdminKeyFile); err != nil {
				return fmt.Errorf("tls: load certs: %v", err)
			}
			admOpts = append(admOpts, s3api.WithAdminSrvTLS(cs))
		}
		if cfg.Quiet {
			admOpts = append(admOpts, s3api.WithAdminQuiet())
		}
		if cfg.Debug {
			admOpts = append(admOpts, s3api.WithAdminDebug())
		}
		if cfg.SocketPerm != "" {
			admOpts = append(admOpts, s3api.WithAdminSocketPerm(parsedSocketPerm))
		}

		admSrv = s3api.NewAdminServer(be, middlewares.RootUserConfig{Access: cfg.RootUserAccess, Secret: cfg.RootUserSecret}, cfg.Region, iam, loggers.AdminLogger, srv.Router.Ctrl, admOpts...)
	}

	var webSrv *webui.Server
	webTLSCert := ""
	webTLSKey := ""
	if len(cfg.WebuiPorts) > 0 {
		for _, addr := range cfg.WebuiPorts {
			if utils.IsUnixSocketPath(addr) {
				continue
			}
			_, webPrt, err := net.SplitHostPort(addr)
			if err != nil {
				return fmt.Errorf("webui listen address must be in the form ':port' or 'host:port': %w", err)
			}
			webPortNum, err := strconv.Atoi(webPrt)
			if err != nil {
				return fmt.Errorf("webui port must be a number: %w", err)
			}
			if webPortNum < 0 || webPortNum > 65535 {
				return fmt.Errorf("webui port must be between 0 and 65535")
			}
		}

		var webOpts []webui.Option
		if !cfg.WebuiNoTLS {
			webTLSCert = cfg.WebuiCertFile
			webTLSKey = cfg.WebuiKeyFile
			if webTLSCert == "" && webTLSKey == "" {
				webTLSCert = cfg.CertFile
				webTLSKey = cfg.KeyFile
			}
			if webTLSCert != "" || webTLSKey != "" {
				if webTLSCert == "" {
					return fmt.Errorf("webui TLS key specified without cert file")
				}
				if webTLSKey == "" {
					return fmt.Errorf("webui TLS cert specified without key file")
				}
				cs := utils.NewCertStorage()
				if err := cs.SetCertificate(webTLSCert, webTLSKey); err != nil {
					return fmt.Errorf("tls: load certs: %v", err)
				}
				webOpts = append(webOpts, webui.WithTLS(cs))
			}
		}

		sslEnabled := cfg.CertFile != ""
		admSSLEnabled := sslEnabled
		if len(cfg.AdminPorts) > 0 {
			admSSLEnabled = cfg.AdminCertFile != ""
		}

		var gateways []string
		if len(validatedWebuiGateways) > 0 {
			gateways = validatedWebuiGateways
		} else {
			for _, p := range cfg.Ports {
				urls, err := buildServiceURLs(p, sslEnabled)
				if err != nil {
					return fmt.Errorf("webui: build gateway URLs: %w", err)
				}
				gateways = append(gateways, urls...)
			}
			sortGatewayURLs(gateways)
		}

		adminGateways := gateways
		if len(validatedWebuiAdminGateways) > 0 {
			adminGateways = validatedWebuiAdminGateways
		} else if len(cfg.AdminPorts) > 0 {
			adminGateways = nil
			for _, admPort := range cfg.AdminPorts {
				urls, err := buildServiceURLs(admPort, admSSLEnabled)
				if err != nil {
					return fmt.Errorf("webui: build admin gateway URLs: %w", err)
				}
				adminGateways = append(adminGateways, urls...)
			}
			sortGatewayURLs(adminGateways)
		}

		if cfg.Quiet {
			webOpts = append(webOpts, webui.WithQuiet())
		}
		if cfg.WebuiPathPrefix != "" {
			webOpts = append(webOpts, webui.WithPathPrefix(cfg.WebuiPathPrefix))
		}
		if cfg.SocketPerm != "" {
			webOpts = append(webOpts, webui.WithSocketPerm(parsedSocketPerm))
		}

		webSrv, err = webui.NewServer(&webui.ServerConfig{
			Gateways:      gateways,
			AdminGateways: adminGateways,
			Region:        cfg.Region,
		}, webOpts...)
		if err != nil {
			return fmt.Errorf("init webui: %w", err)
		}
	}

	var wsSrv *website.Server
	wsTLSCert := ""
	wsTLSKey := ""
	if len(cfg.WebsitePorts) > 0 {
		for _, addr := range cfg.WebsitePorts {
			if utils.IsUnixSocketPath(addr) {
				continue
			}
			_, wsPrt, err := net.SplitHostPort(addr)
			if err != nil {
				return fmt.Errorf("website listen address must be in the form ':port' or 'host:port': %w", err)
			}
			wsPortNum, err := strconv.Atoi(wsPrt)
			if err != nil {
				return fmt.Errorf("website port must be a number: %w", err)
			}
			if wsPortNum < 0 || wsPortNum > 65535 {
				return fmt.Errorf("website port must be between 0 and 65535")
			}
		}

		var wsOpts []website.Option
		if !cfg.WebsiteNoTLS {
			wsTLSCert = cfg.WebsiteCertFile
			wsTLSKey = cfg.WebsiteKeyFile
			if wsTLSCert == "" && wsTLSKey == "" {
				wsTLSCert = cfg.CertFile
				wsTLSKey = cfg.KeyFile
			}
			if wsTLSCert != "" || wsTLSKey != "" {
				if wsTLSCert == "" {
					return fmt.Errorf("website TLS key specified without cert file")
				}
				if wsTLSKey == "" {
					return fmt.Errorf("website TLS cert specified without key file")
				}
				cs := utils.NewCertStorage()
				if err := cs.SetCertificate(wsTLSCert, wsTLSKey); err != nil {
					return fmt.Errorf("tls: load certs: %v", err)
				}
				wsOpts = append(wsOpts, website.WithTLS(cs))
			}
		}

		if cfg.Quiet {
			wsOpts = append(wsOpts, website.WithQuiet())
		}
		if cfg.SocketPerm != "" {
			wsOpts = append(wsOpts, website.WithSocketPerm(parsedSocketPerm))
		}

		wsSrv = website.NewServer(be, cfg.WebsiteDomain, wsOpts...)
	}

	if !cfg.Quiet {
		cfg.printBanner()
	}

	servers := 1
	if len(cfg.AdminPorts) > 0 {
		servers++
	}
	if len(cfg.WebuiPorts) > 0 {
		servers++
	}
	if len(cfg.WebsitePorts) > 0 {
		servers++
	}

	c := make(chan error, servers)
	go func() { c <- srv.ServeMultiPort(cfg.Ports) }()
	if len(cfg.AdminPorts) > 0 {
		go func() { c <- admSrv.ServeMultiPort(cfg.AdminPorts) }()
	}
	if len(cfg.WebuiPorts) > 0 {
		go func() { c <- webSrv.ServeMultiPort(cfg.WebuiPorts) }()
	}
	if len(cfg.WebsitePorts) > 0 {
		go func() { c <- wsSrv.ServeMultiPort(cfg.WebsitePorts) }()
	}

	// build a nil-safe sighup channel so the select below is always valid
	var sigHup <-chan struct{}
	if cfg.SigHup != nil {
		sigHup = cfg.SigHup
	} else {
		sigHup = make(chan struct{}) // never receives
	}

Loop:
	for {
		select {
		case <-ctx.Done():
			break Loop
		case err = <-c:
			break Loop
		case <-sigHup:
			if loggers.S3Logger != nil {
				err = loggers.S3Logger.HangUp()
				if err != nil {
					err = fmt.Errorf("HUP s3 logger: %w", err)
					break Loop
				}
			}
			if loggers.AdminLogger != nil {
				err = loggers.AdminLogger.HangUp()
				if err != nil {
					err = fmt.Errorf("HUP admin logger: %w", err)
					break Loop
				}
			}
			if cfg.CertFile != "" && cfg.KeyFile != "" {
				reloadErr := srv.CertStorage.SetCertificate(cfg.CertFile, cfg.KeyFile)
				if reloadErr != nil {
					debuglogger.InternalError(fmt.Errorf("srv cert reload failed: %w", reloadErr))
				} else {
					fmt.Printf("srv cert reloaded (cert: %s, key: %s)\n", cfg.CertFile, cfg.KeyFile)
				}
			}
			if len(cfg.AdminPorts) > 0 && cfg.AdminCertFile != "" && cfg.AdminKeyFile != "" {
				reloadErr := admSrv.CertStorage.SetCertificate(cfg.AdminCertFile, cfg.AdminKeyFile)
				if reloadErr != nil {
					debuglogger.InternalError(fmt.Errorf("admSrv cert reload failed: %w", reloadErr))
				} else {
					fmt.Printf("admSrv cert reloaded (cert: %s, key: %s)\n", cfg.AdminCertFile, cfg.AdminKeyFile)
				}
			}
			if len(cfg.WebuiPorts) > 0 && webTLSCert != "" && webTLSKey != "" {
				reloadErr := webSrv.CertStorage.SetCertificate(webTLSCert, webTLSKey)
				if reloadErr != nil {
					debuglogger.InternalError(fmt.Errorf("webSrv cert reload failed: %w", reloadErr))
				} else {
					fmt.Printf("webSrv cert reloaded (cert: %s, key: %s)\n", webTLSCert, webTLSKey)
				}
			}
			if len(cfg.WebsitePorts) > 0 && wsTLSCert != "" && wsTLSKey != "" {
				reloadErr := wsSrv.CertStorage.SetCertificate(wsTLSCert, wsTLSKey)
				if reloadErr != nil {
					debuglogger.InternalError(fmt.Errorf("wsSrv cert reload failed: %w", reloadErr))
				} else {
					fmt.Printf("wsSrv cert reloaded (cert: %s, key: %s)\n", wsTLSCert, wsTLSKey)
				}
			}
		}
	}
	saveErr := err

	err = srv.ShutDown()
	if err != nil {
		fmt.Fprintf(os.Stderr, "shutdown api server: %v\n", err)
	}

	if admSrv != nil {
		err := admSrv.Shutdown()
		if err != nil {
			fmt.Fprintf(os.Stderr, "shutdown admin server: %v\n", err)
		}
	}

	if webSrv != nil {
		err := webSrv.Shutdown()
		if err != nil {
			fmt.Fprintf(os.Stderr, "shutdown webui server: %v\n", err)
		}
	}

	if wsSrv != nil {
		err := wsSrv.Shutdown()
		if err != nil {
			fmt.Fprintf(os.Stderr, "shutdown website server: %v\n", err)
		}
	}

	be.Shutdown()

	err = iam.Shutdown()
	if err != nil {
		fmt.Fprintf(os.Stderr, "shutdown iam: %v\n", err)
	}

	if loggers.S3Logger != nil {
		err := loggers.S3Logger.Shutdown()
		if err != nil {
			fmt.Fprintf(os.Stderr, "shutdown s3 logger: %v\n", err)
		}
	}
	if loggers.AdminLogger != nil {
		err := loggers.AdminLogger.Shutdown()
		if err != nil {
			fmt.Fprintf(os.Stderr, "shutdown admin logger: %v\n", err)
		}
	}

	if evSender != nil {
		err := evSender.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "close event sender: %v\n", err)
		}
	}

	if metricsManager != nil {
		metricsManager.Close()
	}

	return saveErr
}

const (
	columnWidth = 70
	title       = "VersityGW"
)

func (cfg Config) printBanner() {
	ssl := cfg.CertFile != "" || cfg.KeyFile != ""
	admSSL := cfg.AdminCertFile != "" || cfg.AdminKeyFile != ""
	webuiSsl := !cfg.WebuiNoTLS && (cfg.WebuiCertFile != "" || cfg.WebuiKeyFile != "" || cfg.CertFile != "" || cfg.KeyFile != "")
	websiteSsl := !cfg.WebsiteNoTLS && (cfg.WebsiteCertFile != "" || cfg.WebsiteKeyFile != "" || cfg.CertFile != "" || cfg.KeyFile != "")

	if len(cfg.Ports) == 0 {
		fmt.Fprintf(os.Stderr, "No ports specified\n")
		return
	}

	var allInterfaces []string
	var allPorts []string
	interfaceMap := make(map[string]bool)

	for _, portSpec := range cfg.Ports {
		if utils.IsUnixSocketPath(portSpec) {
			allPorts = append(allPorts, portSpec)
			if !interfaceMap[portSpec] {
				interfaceMap[portSpec] = true
				allInterfaces = append(allInterfaces, portSpec)
			}
			continue
		}
		interfaces, err := getMatchingIPs(portSpec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to match local IP addresses for %s: %v\n", portSpec, err)
			continue
		}
		_, prt, err := net.SplitHostPort(portSpec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse port %s: %v\n", portSpec, err)
			continue
		}
		allPorts = append(allPorts, prt)
		for _, ip := range interfaces {
			key := net.JoinHostPort(ip, prt)
			if !interfaceMap[key] {
				interfaceMap[key] = true
				allInterfaces = append(allInterfaces, key)
			}
		}
	}

	if len(allInterfaces) == 0 {
		fmt.Fprintf(os.Stderr, "Failed to resolve any listening addresses\n")
		return
	}

	var allAdmInterfaces []string
	admInterfaceMap := make(map[string]bool)
	for _, admPort := range cfg.AdminPorts {
		if utils.IsUnixSocketPath(admPort) {
			if !admInterfaceMap[admPort] {
				admInterfaceMap[admPort] = true
				allAdmInterfaces = append(allAdmInterfaces, admPort)
			}
			continue
		}
		interfaces, err := getMatchingIPs(admPort)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to match admin port local IP addresses for %s: %v\n", admPort, err)
			continue
		}
		_, prt, err := net.SplitHostPort(admPort)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse admin port %s: %v\n", admPort, err)
			continue
		}
		for _, ip := range interfaces {
			key := net.JoinHostPort(ip, prt)
			if !admInterfaceMap[key] {
				admInterfaceMap[key] = true
				allAdmInterfaces = append(allAdmInterfaces, key)
			}
		}
	}

	versionStr := fmt.Sprintf("Version %v, Build %v", cfg.Version, cfg.Build)
	if cfg.BuildTime != "" {
		versionStr += fmt.Sprintf(", BuildTime %v", cfg.BuildTime)
	}
	var urls []string

	for _, addrPort := range allInterfaces {
		if utils.IsUnixSocketPath(addrPort) {
			urls = append(urls, "unix:"+addrPort)
			continue
		}
		ip, prt, err := net.SplitHostPort(addrPort)
		if err != nil {
			continue
		}
		hostPort := net.JoinHostPort(ip, prt)
		u := fmt.Sprintf("http://%s", hostPort)
		if ssl {
			u = fmt.Sprintf("https://%s", hostPort)
		}
		urls = append(urls, u)
	}

	var boundHost string
	if len(cfg.Ports) == 1 {
		if utils.IsUnixSocketPath(cfg.Ports[0]) {
			boundHost = fmt.Sprintf("(unix socket: %s)", cfg.Ports[0])
		} else {
			hst, prt, _ := net.SplitHostPort(cfg.Ports[0])
			if hst == "" {
				hst = "0.0.0.0"
			}
			boundHost = fmt.Sprintf("(bound on host %s and port %s)", hst, prt)
		}
	} else {
		portList := strings.Join(allPorts, ", ")
		boundHost = fmt.Sprintf("(bound on ports: %s)", portList)
	}

	lines := []string{
		centerText(title),
		centerText(versionStr),
		centerText(boundHost),
		centerText(""),
	}

	if len(allAdmInterfaces) > 0 {
		lines = append(lines, leftText("S3 service listening on:"))
	} else {
		lines = append(lines, leftText("Admin/S3 service listening on:"))
	}

	for _, u := range urls {
		lines = append(lines, leftText("  "+u))
	}

	if len(allAdmInterfaces) > 0 {
		lines = append(lines, centerText(""), leftText("Admin service listening on:"))
		for _, addrPort := range allAdmInterfaces {
			if utils.IsUnixSocketPath(addrPort) {
				lines = append(lines, leftText("  unix:"+addrPort))
				continue
			}
			ip, prt, err := net.SplitHostPort(addrPort)
			if err != nil {
				continue
			}
			hostPort := net.JoinHostPort(ip, prt)
			u := fmt.Sprintf("http://%s", hostPort)
			if admSSL {
				u = fmt.Sprintf("https://%s", hostPort)
			}
			lines = append(lines, leftText("  "+u))
		}
	}

	if len(cfg.WebuiPorts) > 0 {
		var allWebInterfaces []string
		webInterfaceMap := make(map[string]bool)

		for _, webuiAddr := range cfg.WebuiPorts {
			if strings.TrimSpace(webuiAddr) == "" {
				continue
			}
			if utils.IsUnixSocketPath(webuiAddr) {
				if !webInterfaceMap[webuiAddr] {
					webInterfaceMap[webuiAddr] = true
					allWebInterfaces = append(allWebInterfaces, webuiAddr)
				}
				continue
			}
			webInterfaces, err := getMatchingIPs(webuiAddr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to match webui port local IP addresses for %s: %v\n", webuiAddr, err)
				continue
			}
			_, webPrt, err := net.SplitHostPort(webuiAddr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to parse webui port %s: %v\n", webuiAddr, err)
				continue
			}
			for _, ip := range webInterfaces {
				key := net.JoinHostPort(ip, webPrt)
				if !webInterfaceMap[key] {
					webInterfaceMap[key] = true
					allWebInterfaces = append(allWebInterfaces, key)
				}
			}
		}

		if len(allWebInterfaces) > 0 {
			lines = append(lines, centerText(""), leftText("WebUI listening on:"))
			for _, addrPort := range allWebInterfaces {
				if utils.IsUnixSocketPath(addrPort) {
					lines = append(lines, leftText("  unix:"+addrPort))
					continue
				}
				ip, prt, err := net.SplitHostPort(addrPort)
				if err != nil {
					continue
				}
				hostPort := net.JoinHostPort(ip, prt)
				u := fmt.Sprintf("http://%s", hostPort)
				if webuiSsl {
					u = fmt.Sprintf("https://%s", hostPort)
				}
				lines = append(lines, leftText("  "+u+cfg.WebuiPathPrefix))
			}
		}
	}

	if cfg.WebuiS3Prefix != "" {
		lines = append(lines, centerText(""), leftText("WebUI embedded on S3 service at:"))
		for _, addrPort := range allInterfaces {
			ip, prt, err := net.SplitHostPort(addrPort)
			if err != nil {
				continue
			}
			hostPort := net.JoinHostPort(ip, prt)
			u := fmt.Sprintf("http://%s", hostPort)
			if ssl {
				u = fmt.Sprintf("https://%s", hostPort)
			}
			lines = append(lines, leftText("  "+u+cfg.WebuiS3Prefix))
		}
	}

	if len(cfg.WebsitePorts) > 0 {
		var allWebsiteInterfaces []string
		websiteInterfaceMap := make(map[string]bool)

		for _, websiteAddr := range cfg.WebsitePorts {
			if strings.TrimSpace(websiteAddr) == "" {
				continue
			}
			if utils.IsUnixSocketPath(websiteAddr) {
				if !websiteInterfaceMap[websiteAddr] {
					websiteInterfaceMap[websiteAddr] = true
					allWebsiteInterfaces = append(allWebsiteInterfaces, websiteAddr)
				}
				continue
			}
			websiteInterfaces, err := getMatchingIPs(websiteAddr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to match website port local IP addresses for %s: %v\n", websiteAddr, err)
				continue
			}
			_, websitePrt, err := net.SplitHostPort(websiteAddr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to parse website port %s: %v\n", websiteAddr, err)
				continue
			}
			for _, ip := range websiteInterfaces {
				key := net.JoinHostPort(ip, websitePrt)
				if !websiteInterfaceMap[key] {
					websiteInterfaceMap[key] = true
					allWebsiteInterfaces = append(allWebsiteInterfaces, key)
				}
			}
		}

		if len(allWebsiteInterfaces) > 0 {
			domainInfo := ""
			if cfg.WebsiteDomain != "" {
				domainInfo = fmt.Sprintf(" (domain: %s)", cfg.WebsiteDomain)
			}
			lines = append(lines,
				centerText(""),
				leftText("Website endpoint listening on:"+domainInfo),
			)
			for _, addrPort := range allWebsiteInterfaces {
				if utils.IsUnixSocketPath(addrPort) {
					lines = append(lines, leftText("  unix:"+addrPort))
					continue
				}
				ip, prt, err := net.SplitHostPort(addrPort)
				if err != nil {
					continue
				}
				hostPort := net.JoinHostPort(ip, prt)
				u := fmt.Sprintf("http://%s", hostPort)
				if websiteSsl {
					u = fmt.Sprintf("https://%s", hostPort)
				}
				lines = append(lines, leftText("  "+u))
			}
		}
	}

	fmt.Println("┌" + strings.Repeat("─", columnWidth-2) + "┐")
	for _, line := range lines {
		fmt.Printf("│%-*s│\n", columnWidth-2, line)
	}
	fmt.Println("└" + strings.Repeat("─", columnWidth-2) + "┘")
}

func centerText(text string) string {
	padding := max((columnWidth-2-len(text))/2, 0)
	return strings.Repeat(" ", padding) + text
}

func leftText(text string) string {
	if len(text) > columnWidth-2 {
		return text
	}
	return text + strings.Repeat(" ", columnWidth-2-len(text))
}

// getMatchingIPs returns all IP addresses that the server will listen on
// for the given address specification.
func getMatchingIPs(spec string) ([]string, error) {
	if utils.IsUnixSocketPath(spec) {
		return []string{spec}, nil
	}

	ips, err := utils.ResolveHostnameIPs(spec)
	if err != nil {
		return nil, fmt.Errorf("resolve hostname: %v", err)
	}

	if len(ips) == 1 && ips[0] == "" {
		return getAllLocalIPs()
	}

	var result []string
	for _, ip := range ips {
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			continue
		}
		if parsedIP.IsLinkLocalUnicast() || parsedIP.IsLinkLocalMulticast() || parsedIP.IsInterfaceLocalMulticast() {
			continue
		}
		result = append(result, ip)
	}

	return result, nil
}

// getAllLocalIPs returns all non-link-local IP addresses from local interfaces.
func getAllLocalIPs() ([]string, error) {
	var result []string

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipAddr, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}
			if ipAddr.IsLinkLocalUnicast() || ipAddr.IsInterfaceLocalMulticast() || ipAddr.IsLinkLocalMulticast() {
				continue
			}
			result = append(result, ipAddr.String())
		}
	}

	return result, nil
}

func buildServiceURLs(spec string, ssl bool) ([]string, error) {
	if utils.IsUnixSocketPath(spec) {
		return nil, nil
	}

	interfaces, err := getMatchingIPs(spec)
	if err != nil {
		return nil, err
	}
	_, prt, err := net.SplitHostPort(spec)
	if err != nil {
		return nil, fmt.Errorf("parse address/port: %w", err)
	}
	if len(interfaces) == 0 {
		interfaces = []string{"localhost"}
	}

	scheme := "http"
	if ssl {
		scheme = "https"
	}
	urls := make([]string, 0, len(interfaces))
	for _, ip := range interfaces {
		urls = append(urls, fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(ip, prt)))
	}
	return urls, nil
}

func isLocalhost(u string) bool {
	return strings.Contains(u, "localhost") ||
		strings.Contains(u, "127.0.0.1") ||
		strings.Contains(u, "[::1]")
}

func validateGatewayURLs(urls []string, urlType string) ([]string, error) {
	if len(urls) == 0 {
		return urls, nil
	}

	var validURLs []string
	for _, urlStr := range urls {
		if strings.TrimSpace(urlStr) == "" {
			continue
		}
		parsedURL, err := url.Parse(urlStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: invalid %s URL %q: %v\n", urlType, urlStr, err)
			continue
		}
		if parsedURL.Scheme == "" {
			fmt.Fprintf(os.Stderr, "WARNING: invalid %s URL %q: missing scheme (must be http:// or https://)\n", urlType, urlStr)
			continue
		}
		if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
			fmt.Fprintf(os.Stderr, "WARNING: invalid %s URL %q: unsupported scheme %q (must be http or https)\n", urlType, urlStr, parsedURL.Scheme)
			continue
		}
		if parsedURL.Host == "" {
			fmt.Fprintf(os.Stderr, "WARNING: invalid %s URL %q: missing host\n", urlType, urlStr)
			continue
		}
		validURLs = append(validURLs, urlStr)
	}

	if len(validURLs) == 0 {
		return nil, fmt.Errorf("%s URLs specified but none are valid", urlType)
	}

	return validURLs, nil
}

func validateWebUIPathPrefix(option, prefix string) error {
	if prefix == "" {
		return nil
	}
	if strings.TrimSpace(prefix) != prefix {
		return fmt.Errorf("invalid %v %q: must not contain leading or trailing whitespace", option, prefix)
	}
	if !strings.HasPrefix(prefix, "/") {
		return fmt.Errorf("invalid %v %q: must start with '/' (example: '/ui')", option, prefix)
	}
	if strings.HasSuffix(prefix, "/") {
		return fmt.Errorf("invalid %v %q: must not end with '/'", option, prefix)
	}
	if strings.Count(prefix, "/") > 1 {
		return fmt.Errorf("invalid %v %q: only a single path segment is allowed (example: '/ui')", option, prefix)
	}
	if strings.ContainsAny(prefix, "?#") {
		return fmt.Errorf("invalid %v %q: query strings and fragments are not allowed", option, prefix)
	}
	if strings.Contains(prefix, "\\") {
		return fmt.Errorf("invalid %v %q: backslashes are not allowed", option, prefix)
	}
	return nil
}

func sortGatewayURLs(urls []string) {
	if len(urls) <= 1 {
		return
	}
	var nonLocal []string
	var local []string
	for _, u := range urls {
		if isLocalhost(u) {
			local = append(local, u)
		} else {
			nonLocal = append(nonLocal, u)
		}
	}
	copy(urls, nonLocal)
	copy(urls[len(nonLocal):], local)
}

// validatePortConflicts checks for port conflicts across the S3 API, admin,
// WebUI, and website port lists before the servers are started.
//
// A bare port spec (e.g. ":7071") binds to all interfaces and conflicts with
// any other spec on the same port number. Two identical "ip:port" specs are
// allowed and will be caught by the OS later. UNIX socket paths are checked
// for duplicate path conflicts only and never conflict with TCP specs.
func validatePortConflicts(ports, admPorts, webuiPorts, websitePorts []string) error {
	type portSpec struct {
		spec     string
		port     string
		isBare   bool
		isUnix   bool
		portType string
	}

	var allSpecs []portSpec

	for _, p := range ports {
		if utils.IsUnixSocketPath(p) {
			allSpecs = append(allSpecs, portSpec{spec: p, port: p, isUnix: true, portType: "s3"})
			continue
		}
		_, port, err := net.SplitHostPort(p)
		if err != nil {
			continue
		}
		allSpecs = append(allSpecs, portSpec{
			spec:     p,
			port:     port,
			isBare:   strings.HasPrefix(p, ":"),
			portType: "s3",
		})
	}

	for _, p := range admPorts {
		if utils.IsUnixSocketPath(p) {
			allSpecs = append(allSpecs, portSpec{spec: p, port: p, isUnix: true, portType: "admin"})
			continue
		}
		_, port, err := net.SplitHostPort(p)
		if err != nil {
			continue
		}
		allSpecs = append(allSpecs, portSpec{
			spec:     p,
			port:     port,
			isBare:   strings.HasPrefix(p, ":"),
			portType: "admin",
		})
	}

	for _, p := range webuiPorts {
		if utils.IsUnixSocketPath(p) {
			allSpecs = append(allSpecs, portSpec{spec: p, port: p, isUnix: true, portType: "webui"})
			continue
		}
		_, port, err := net.SplitHostPort(p)
		if err != nil {
			continue
		}
		allSpecs = append(allSpecs, portSpec{
			spec:     p,
			port:     port,
			isBare:   strings.HasPrefix(p, ":"),
			portType: "webui",
		})
	}

	for _, p := range websitePorts {
		if utils.IsUnixSocketPath(p) {
			allSpecs = append(allSpecs, portSpec{spec: p, port: p, isUnix: true, portType: "website"})
			continue
		}
		_, port, err := net.SplitHostPort(p)
		if err != nil {
			continue
		}
		allSpecs = append(allSpecs, portSpec{
			spec:     p,
			port:     port,
			isBare:   strings.HasPrefix(p, ":"),
			portType: "website",
		})
	}

	for i, spec1 := range allSpecs {
		for j, spec2 := range allSpecs {
			if i >= j {
				continue
			}
			if spec1.isUnix || spec2.isUnix {
				if spec1.isUnix && spec2.isUnix && spec1.spec == spec2.spec {
					return fmt.Errorf("duplicate unix socket path: %s port %s conflicts with %s port %s",
						spec1.portType, spec1.spec, spec2.portType, spec2.spec)
				}
				continue
			}
			if spec1.port != spec2.port {
				continue
			}
			if !spec1.isBare && !spec2.isBare && spec1.spec == spec2.spec {
				continue
			}
			if spec1.isBare || spec2.isBare {
				return fmt.Errorf("port conflict: %s port %s conflicts with %s port %s (bare port specs bind to all interfaces)",
					spec1.portType, spec1.spec, spec2.portType, spec2.spec)
			}
		}
	}

	return nil
}
