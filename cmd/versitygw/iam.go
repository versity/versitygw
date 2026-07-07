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
	iamServerDir                    string
	iamServerVaultEndpointURL       string
	iamServerVaultNamespace         string
	iamServerVaultSecretStoragePath string
	iamServerVaultSecretStorageNS   string
	iamServerVaultAuthMethod        string
	iamServerVaultAuthNamespace     string
	iamServerVaultMountPath         string
	iamServerVaultRootToken         string
	iamServerVaultRoleID            string
	iamServerVaultRoleSecret        string
	iamServerVaultServerCert        string
	iamServerVaultClientCert        string
	iamServerVaultClientCertKey     string
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

	return embedgw.RunIAMAPI(ctx.Context, &embedgw.IAMConfig{
		RootUserAccess:              rootUserAccess,
		RootUserSecret:              rootUserSecret,
		Ports:                       ports,
		MaxConnections:              maxConnections,
		MaxRequests:                 maxRequests,
		CertFile:                    certFile,
		KeyFile:                     keyFile,
		Debug:                       debug,
		Quiet:                       quiet,
		KeepAlive:                   keepAlive,
		HealthPath:                  healthPath,
		SocketPerm:                  socketPerm,
		IAMDir:                      iamServerDir,
		VaultEndpointURL:            iamServerVaultEndpointURL,
		VaultNamespace:              iamServerVaultNamespace,
		VaultSecretStoragePath:      iamServerVaultSecretStoragePath,
		VaultSecretStorageNamespace: iamServerVaultSecretStorageNS,
		VaultAuthMethod:             iamServerVaultAuthMethod,
		VaultAuthNamespace:          iamServerVaultAuthNamespace,
		VaultMountPath:              iamServerVaultMountPath,
		VaultRootToken:              iamServerVaultRootToken,
		VaultRoleID:                 iamServerVaultRoleID,
		VaultRoleSecret:             iamServerVaultRoleSecret,
		VaultServerCert:             iamServerVaultServerCert,
		VaultClientCert:             iamServerVaultClientCert,
		VaultClientCertKey:          iamServerVaultClientCertKey,
		Version:                     Version,
		Build:                       Build,
		BuildTime:                   BuildTime,
	})
}
