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

package embedgw

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/iamapi"
	"github.com/versity/versitygw/iamapi/storage"
	"github.com/versity/versitygw/s3api/utils"
)

const iamTitle = "VersityGW IAM API"

// IAMConfig holds all configuration options for running the VersityGW IAM API.
type IAMConfig struct {
	// RootUserAccess is the access key ID used to authenticate IAM API
	// requests. Required.
	RootUserAccess string
	// RootUserSecret is the secret access key used to authenticate IAM API
	// requests. Required.
	RootUserSecret string

	// Ports is the list of IAM API listening addresses. Each entry accepts
	// the same formats as Config.Ports: "host:port", ":port", file-backed
	// UNIX socket paths, or Linux abstract namespace sockets prefixed with
	// "@". Required.
	Ports []string

	// MaxConnections is the maximum number of concurrent TCP connections
	// accepted by the IAM API server.
	MaxConnections int
	// MaxRequests is the maximum number of concurrent in-flight IAM API
	// requests. Should not exceed MaxConnections.
	MaxRequests int

	// CertFile is the path to the TLS certificate file for the IAM API server.
	// Both CertFile and KeyFile must be provided together to enable TLS.
	CertFile string
	// KeyFile is the path to the TLS private key file for the IAM API server.
	KeyFile string

	// Debug enables verbose request/response debug logging.
	Debug bool
	// Quiet suppresses per-request summary logging and startup output.
	Quiet bool
	// KeepAlive enables HTTP keep-alive on IAM API connections.
	KeepAlive bool

	// HealthPath is the URL path for unauthenticated health-check requests
	// (e.g. "/healthz"). The endpoint returns HTTP 200 for GET requests.
	HealthPath string

	// SocketPerm is the octal file-mode string for file-backed UNIX domain
	// socket permissions. It has no effect on TCP/IP addresses or Linux
	// abstract namespace sockets.
	SocketPerm string

	// IAMDir enables local file-backed IAM API storage. Set to the directory
	// path where the IAM API user database is stored.
	IAMDir string

	// VaultEndpointURL enables Vault-backed IAM API storage.
	VaultEndpointURL string
	// VaultNamespace is the fallback Vault namespace used when the specific
	// auth or secret-storage namespace is not set.
	VaultNamespace string
	// VaultSecretStoragePath is the KV v2 path prefix under which IAM users
	// are stored (defaults to "iam").
	VaultSecretStoragePath string
	// VaultSecretStorageNamespace overrides VaultNamespace for KV operations.
	VaultSecretStorageNamespace string
	// VaultAuthMethod is the AppRole mount path (defaults to "approle").
	VaultAuthMethod string
	// VaultAuthNamespace overrides VaultNamespace for AppRole login.
	VaultAuthNamespace string
	// VaultMountPath is the KV v2 engine mount path (defaults to "kv-v2").
	VaultMountPath string
	// VaultRootToken authenticates with a root token instead of AppRole.
	VaultRootToken string
	// VaultRoleID is the AppRole role ID.
	VaultRoleID string
	// VaultRoleSecret is the AppRole secret ID.
	VaultRoleSecret string
	// VaultServerCert is the PEM-encoded Vault server TLS certificate for
	// verification.
	VaultServerCert string
	// VaultClientCert is the PEM-encoded client TLS certificate presented to
	// Vault.
	VaultClientCert string
	// VaultClientCertKey is the PEM-encoded private key for VaultClientCert.
	VaultClientCertKey string

	// SigHup is an optional channel that signals the IAM API to reload TLS
	// certificates. When nil, this feature is disabled.
	SigHup <-chan struct{}

	// Version, Build, and BuildTime are displayed in the startup banner.
	// All three are optional.
	Version   string
	Build     string
	BuildTime string
}

var iamAPIRunning atomic.Bool

// RunIAMAPI starts the VersityGW IAM API with the supplied configuration. It
// blocks until ctx is cancelled, or an error occurs. The server is gracefully
// shut down before the function returns.
//
// Only one IAM API instance may run per process at a time. Calling RunIAMAPI
// concurrently or a second time before the first call returns will return an
// error.
func RunIAMAPI(ctx context.Context, cfg *IAMConfig) error {
	if cfg == nil {
		return fmt.Errorf("iam config is required")
	}
	if !iamAPIRunning.CompareAndSwap(false, true) {
		return fmt.Errorf("embedgw: RunIAMAPI is already running; only one instance per process is supported")
	}
	defer iamAPIRunning.Store(false)

	if cfg.MaxConnections < 1 {
		return fmt.Errorf("max-connections must be positive")
	}
	if cfg.MaxRequests < 1 {
		return fmt.Errorf("max-requests must be positive")
	}
	if cfg.MaxRequests > cfg.MaxConnections {
		log.Printf("WARNING: max-requests (%d) exceeds max-connections (%d) which could allow for IAM API to panic before throttling requests",
			cfg.MaxRequests, cfg.MaxConnections)
	}
	if len(cfg.Ports) == 0 {
		return fmt.Errorf("no ports specified")
	}
	if cfg.RootUserAccess == "" {
		return fmt.Errorf("root access key is required for IAM API authentication")
	}
	if cfg.RootUserSecret == "" {
		return fmt.Errorf("root secret key is required for IAM API authentication")
	}

	store, err := storage.New(storage.Config{
		Dir: cfg.IAMDir,
		Vault: storage.VaultConfig{
			EndpointURL:            cfg.VaultEndpointURL,
			Namespace:              cfg.VaultNamespace,
			SecretStoragePath:      cfg.VaultSecretStoragePath,
			SecretStorageNamespace: cfg.VaultSecretStorageNamespace,
			AuthMethod:             cfg.VaultAuthMethod,
			AuthNamespace:          cfg.VaultAuthNamespace,
			MountPath:              cfg.VaultMountPath,
			RootToken:              cfg.VaultRootToken,
			RoleID:                 cfg.VaultRoleID,
			RoleSecret:             cfg.VaultRoleSecret,
			ServerCert:             cfg.VaultServerCert,
			ClientCert:             cfg.VaultClientCert,
			ClientCertKey:          cfg.VaultClientCertKey,
		},
	})
	if err != nil {
		return err
	}

	opts := []iamapi.Option{
		iamapi.WithConcurrencyLimiter(cfg.MaxConnections, cfg.MaxRequests),
		iamapi.WithRootUserCreds(iamapi.RootCredentials{
			Access: cfg.RootUserAccess,
			Secret: cfg.RootUserSecret,
		}),
	}
	if cfg.HealthPath != "" {
		opts = append(opts, iamapi.WithHealth(cfg.HealthPath))
	}
	if cfg.KeepAlive {
		opts = append(opts, iamapi.WithKeepAlive())
	}
	if cfg.Quiet {
		opts = append(opts, iamapi.WithQuiet())
	}
	if cfg.Debug {
		debuglogger.SetDebugEnabled()
	}
	if cfg.SocketPerm != "" {
		perm, err := strconv.ParseUint(cfg.SocketPerm, 8, 32)
		if err != nil {
			return fmt.Errorf("invalid SocketPerm value %q: must be an octal integer (e.g. '0660'): %w", cfg.SocketPerm, err)
		}
		opts = append(opts, iamapi.WithSocketPerm(os.FileMode(perm)))
	}
	if cfg.CertFile != "" || cfg.KeyFile != "" {
		if cfg.CertFile == "" {
			return fmt.Errorf("TLS key specified without cert file")
		}
		if cfg.KeyFile == "" {
			return fmt.Errorf("TLS cert specified without key file")
		}
		cs := iamapi.NewCertStorage()
		if err := cs.SetCertificate(cfg.CertFile, cfg.KeyFile); err != nil {
			return fmt.Errorf("tls: load certs: %v", err)
		}
		opts = append(opts, iamapi.WithTLS(cs))
	}

	server, err := iamapi.New(store, opts...)
	if err != nil {
		return fmt.Errorf("init IAM API server: %w", err)
	}

	if !cfg.Quiet {
		cfg.printBanner()
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ServeMultiPort(cfg.Ports)
	}()

	var sigHup <-chan struct{}
	if cfg.SigHup != nil {
		sigHup = cfg.SigHup
	} else {
		sigHup = make(chan struct{})
	}

Loop:
	for {
		select {
		case <-ctx.Done():
			break Loop
		case err = <-errCh:
			break Loop
		case <-sigHup:
			if cfg.CertFile != "" && cfg.KeyFile != "" && server.CertStorage != nil {
				reloadErr := server.CertStorage.SetCertificate(cfg.CertFile, cfg.KeyFile)
				if reloadErr != nil {
					debuglogger.InternalError(fmt.Errorf("iam api cert reload failed: %w", reloadErr))
				} else {
					fmt.Printf("iam api cert reloaded (cert: %s, key: %s)\n", cfg.CertFile, cfg.KeyFile)
				}
			}
		}
	}
	saveErr := err

	if err := server.Shutdown(); err != nil {
		fmt.Fprintf(os.Stderr, "shutdown IAM API server: %v\n", err)
	}

	return saveErr
}

func (cfg IAMConfig) printBanner() {
	if len(cfg.Ports) == 0 {
		fmt.Fprintf(os.Stderr, "No ports specified\n")
		return
	}

	allInterfaces, allPorts := resolveIAMBannerInterfaces(cfg.Ports)
	if len(allInterfaces) == 0 {
		fmt.Fprintf(os.Stderr, "Failed to resolve any listening addresses\n")
		return
	}

	versionStr := fmt.Sprintf("Version %v, Build %v", cfg.Version, cfg.Build)
	if cfg.BuildTime != "" {
		versionStr += fmt.Sprintf(", BuildTime %v", cfg.BuildTime)
	}

	lines := []string{
		centerText(iamTitle),
		centerText(versionStr),
		centerText(formatIAMBannerBoundHost(cfg.Ports, allPorts)),
		centerText(""),
		leftText("IAM API service listening on:"),
	}

	for _, u := range buildIAMBannerURLs(allInterfaces, cfg.CertFile != "" || cfg.KeyFile != "") {
		lines = append(lines, leftText("  "+u))
	}

	fmt.Println("┌" + strings.Repeat("─", columnWidth-2) + "┐")
	for _, line := range lines {
		fmt.Printf("│%-*s│\n", columnWidth-2, line)
	}
	fmt.Println("└" + strings.Repeat("─", columnWidth-2) + "┘")
}

func resolveIAMBannerInterfaces(ports []string) ([]string, []string) {
	var allInterfaces []string
	var allPorts []string
	interfaceMap := make(map[string]bool)

	for _, portSpec := range ports {
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

	return allInterfaces, allPorts
}

func formatIAMBannerBoundHost(ports, allPorts []string) string {
	if len(ports) == 1 {
		if utils.IsUnixSocketPath(ports[0]) {
			return fmt.Sprintf("(unix socket: %s)", ports[0])
		}
		hst, prt, _ := net.SplitHostPort(ports[0])
		if hst == "" {
			hst = "0.0.0.0"
		}
		return fmt.Sprintf("(bound on host %s and port %s)", hst, prt)
	}

	return fmt.Sprintf("(bound on ports: %s)", strings.Join(allPorts, ", "))
}

func buildIAMBannerURLs(interfaces []string, tls bool) []string {
	var urls []string
	scheme := "http"
	if tls {
		scheme = "https"
	}

	for _, addrPort := range interfaces {
		if utils.IsUnixSocketPath(addrPort) {
			urls = append(urls, "unix:"+addrPort)
			continue
		}

		ip, prt, err := net.SplitHostPort(addrPort)
		if err != nil {
			continue
		}
		urls = append(urls, fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(ip, prt)))
	}

	return urls
}
