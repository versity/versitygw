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

package main

import (
	"log"
	"net/http"

	"github.com/urfave/cli/v2"
	"github.com/versity/versitygw/embedgw"
)

var (
	iamServerDir                            string
	iamServerVaultEndpointURL               string
	iamServerVaultNamespace                 string
	iamServerVaultSecretStoragePath         string
	iamServerVaultSecretStorageNS           string
	iamServerVaultAuthMethod                string
	iamServerVaultAuthNamespace             string
	iamServerVaultMountPath                 string
	iamServerVaultRootToken                 string
	iamServerVaultRoleID                    string
	iamServerVaultRoleSecret                string
	iamServerVaultServerCert                string
	iamServerVaultClientCert                string
	iamServerVaultClientCertKey             string
	iamServerDisableOIDCThumbprintAutoFetch bool
	iamServerPrivateCert                    string
	iamServerPrivateCertKey                 string
	iamServerPrivateClientCA                string
	iamServerPrivateSocketPerm              string
)

func iamCommand() *cli.Command {
	return &cli.Command{
		Name:        "iam",
		Usage:       "IAM API server",
		Description: "Run the standalone IAM API server.",
		Action:      runIAM,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "dir",
				Usage:       "directory path for file-backed IAM storage",
				EnvVars:     []string{"VGW_IAM_DIR"},
				Destination: &iamServerDir,
			},
			&cli.StringFlag{
				Name:        "vault-endpoint-url",
				Usage:       "vault server url for IAM storage",
				EnvVars:     []string{"VGW_IAM_VAULT_ENDPOINT_URL"},
				Destination: &iamServerVaultEndpointURL,
			},
			&cli.StringFlag{
				Name:        "vault-namespace",
				Usage:       "fallback vault namespace for IAM storage (overridden by vault-auth-namespace / vault-secret-storage-namespace)",
				EnvVars:     []string{"VGW_IAM_VAULT_NAMESPACE"},
				Destination: &iamServerVaultNamespace,
			},
			&cli.StringFlag{
				Name:        "vault-secret-storage-path",
				Usage:       "vault KV v2 path prefix for IAM user storage (default: iam)",
				EnvVars:     []string{"VGW_IAM_VAULT_SECRET_STORAGE_PATH"},
				Destination: &iamServerVaultSecretStoragePath,
			},
			&cli.StringFlag{
				Name:        "vault-secret-storage-namespace",
				Usage:       "vault namespace for KV v2 IAM storage (overrides vault-namespace)",
				EnvVars:     []string{"VGW_IAM_VAULT_SECRET_STORAGE_NAMESPACE"},
				Destination: &iamServerVaultSecretStorageNS,
			},
			&cli.StringFlag{
				Name:        "vault-auth-method",
				Usage:       "vault auth method mount path (default: approle)",
				EnvVars:     []string{"VGW_IAM_VAULT_AUTH_METHOD"},
				Destination: &iamServerVaultAuthMethod,
			},
			&cli.StringFlag{
				Name:        "vault-auth-namespace",
				Usage:       "vault namespace for AppRole login (overrides vault-namespace)",
				EnvVars:     []string{"VGW_IAM_VAULT_AUTH_NAMESPACE"},
				Destination: &iamServerVaultAuthNamespace,
			},
			&cli.StringFlag{
				Name:        "vault-mount-path",
				Usage:       "vault KV v2 engine mount path (default: kv-v2)",
				EnvVars:     []string{"VGW_IAM_VAULT_MOUNT_PATH"},
				Destination: &iamServerVaultMountPath,
			},
			&cli.StringFlag{
				Name:        "vault-root-token",
				Usage:       "vault root token for authentication (mutually exclusive with vault-role-id/vault-role-secret)",
				EnvVars:     []string{"VGW_IAM_VAULT_ROOT_TOKEN"},
				Destination: &iamServerVaultRootToken,
			},
			&cli.StringFlag{
				Name:        "vault-role-id",
				Usage:       "vault AppRole role ID for authentication",
				EnvVars:     []string{"VGW_IAM_VAULT_ROLE_ID"},
				Destination: &iamServerVaultRoleID,
			},
			&cli.StringFlag{
				Name:        "vault-role-secret",
				Usage:       "vault AppRole secret ID for authentication",
				EnvVars:     []string{"VGW_IAM_VAULT_ROLE_SECRET"},
				Destination: &iamServerVaultRoleSecret,
			},
			&cli.StringFlag{
				Name:        "vault-server-cert",
				Usage:       "PEM-encoded vault server TLS certificate for verification",
				EnvVars:     []string{"VGW_IAM_VAULT_SERVER_CERT"},
				Destination: &iamServerVaultServerCert,
			},
			&cli.StringFlag{
				Name:        "vault-client-cert",
				Usage:       "PEM-encoded client TLS certificate presented to vault",
				EnvVars:     []string{"VGW_IAM_VAULT_CLIENT_CERT"},
				Destination: &iamServerVaultClientCert,
			},
			&cli.StringFlag{
				Name:        "vault-client-cert-key",
				Usage:       "PEM-encoded private key for vault-client-cert",
				EnvVars:     []string{"VGW_IAM_VAULT_CLIENT_CERT_KEY"},
				Destination: &iamServerVaultClientCertKey,
			},
			&cli.BoolFlag{
				Name:        "quiet",
				Usage:       "silence stdout request logging output",
				EnvVars:     []string{"VGW_QUIET"},
				Destination: &quiet,
				Aliases:     []string{"q"},
			},
			&cli.BoolFlag{
				Name:        "disable-oidc-thumbprint-autofetch",
				Usage:       "reject CreateOpenIDConnectProvider requests that omit ThumbprintList instead of auto-fetching it over an outbound TLS connection",
				EnvVars:     []string{"VGW_IAM_DISABLE_OIDC_THUMBPRINT_AUTOFETCH"},
				Destination: &iamServerDisableOIDCThumbprintAutoFetch,
			},
			&cli.StringSliceFlag{
				Name:    "private-ports",
				Usage:   "private endpoint listen address: a unix socket path, or <ip>:<port>/:<port> when mTLS (--private-cert/--private-cert-key/--private-client-ca) is also configured — refuses to start otherwise (can be specified multiple times)",
				EnvVars: []string{"VGW_IAM_PRIVATE_PORTS"},
			},
			&cli.StringFlag{
				Name:        "private-cert",
				Usage:       "TLS server certificate for the private endpoint listener (required for a non-unix-socket --private-ports address)",
				EnvVars:     []string{"VGW_IAM_PRIVATE_CERT"},
				Destination: &iamServerPrivateCert,
			},
			&cli.StringFlag{
				Name:        "private-cert-key",
				Usage:       "TLS private key for --private-cert",
				EnvVars:     []string{"VGW_IAM_PRIVATE_CERT_KEY"},
				Destination: &iamServerPrivateCertKey,
			},
			&cli.StringFlag{
				Name:        "private-client-ca",
				Usage:       "PEM-encoded CA bundle used to verify the S3 gateway's client certificate on the private endpoint listener (required for a non-unix-socket --private-ports address, together with --private-cert/--private-cert-key)",
				EnvVars:     []string{"VGW_IAM_PRIVATE_CLIENT_CA"},
				Destination: &iamServerPrivateClientCA,
			},
			&cli.StringFlag{
				Name:        "private-socket-perm",
				Usage:       "octal file-mode permission for a file-backed unix-socket --private-ports address (e.g. '0660'); no effect on TCP or abstract-namespace sockets",
				EnvVars:     []string{"VGW_IAM_PRIVATE_SOCKET_PERM"},
				Destination: &iamServerPrivateSocketPerm,
			},
		},
	}
}

func runIAM(ctx *cli.Context) error {
	if pprof != "" {
		go func() {
			log.Printf("pprof: listening on %s", pprof)
			if err := http.ListenAndServe(pprof, nil); err != nil {
				log.Printf("pprof: server exited: %v", err)
			}
		}()
	}

	logLvl, err := parseLogLevel()
	if err != nil {
		return err
	}

	return embedgw.RunIAMAPI(ctx.Context, &embedgw.IAMConfig{
		RootUserAccess:                 rootUserAccess,
		RootUserSecret:                 rootUserSecret,
		Ports:                          ports,
		MaxConnections:                 maxConnections,
		MaxRequests:                    maxRequests,
		CertFile:                       certFile,
		KeyFile:                        keyFile,
		LogLevel:                       logLvl,
		Quiet:                          quiet,
		KeepAlive:                      keepAlive,
		HealthPath:                     healthPath,
		SocketPerm:                     socketPerm,
		PrivatePorts:                   ctx.StringSlice("private-ports"),
		PrivateCertFile:                iamServerPrivateCert,
		PrivateKeyFile:                 iamServerPrivateCertKey,
		PrivateClientCAFile:            iamServerPrivateClientCA,
		PrivateSocketPerm:              iamServerPrivateSocketPerm,
		IAMDir:                         iamServerDir,
		VaultEndpointURL:               iamServerVaultEndpointURL,
		VaultNamespace:                 iamServerVaultNamespace,
		VaultSecretStoragePath:         iamServerVaultSecretStoragePath,
		VaultSecretStorageNamespace:    iamServerVaultSecretStorageNS,
		VaultAuthMethod:                iamServerVaultAuthMethod,
		VaultAuthNamespace:             iamServerVaultAuthNamespace,
		VaultMountPath:                 iamServerVaultMountPath,
		VaultRootToken:                 iamServerVaultRootToken,
		VaultRoleID:                    iamServerVaultRoleID,
		VaultRoleSecret:                iamServerVaultRoleSecret,
		VaultServerCert:                iamServerVaultServerCert,
		VaultClientCert:                iamServerVaultClientCert,
		VaultClientCertKey:             iamServerVaultClientCertKey,
		DisableOIDCThumbprintAutoFetch: iamServerDisableOIDCThumbprintAutoFetch,
		Version:                        Version,
		Build:                          Build,
		BuildTime:                      BuildTime,
	})
}
