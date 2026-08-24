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
	"github.com/versity/versitygw/cmd/internal/gwcli"
	"github.com/versity/versitygw/embedgw"
)

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
		RootUserAccess:                 gwcli.RootUserAccess,
		RootUserSecret:                 gwcli.RootUserSecret,
		Ports:                          ports,
		MaxConnections:                 maxConnections,
		MaxRequests:                    maxRequests,
		CertFile:                       certFile,
		KeyFile:                        keyFile,
		LogLevel:                       logLvl,
		Quiet:                          quiet || ctx.Bool("quiet"),
		KeepAlive:                      keepAlive,
		HealthPath:                     healthPath,
		SocketPerm:                     socketPerm,
		PrivatePorts:                   ctx.StringSlice("private-ports"),
		PrivateCertFile:                ctx.String("private-cert"),
		PrivateKeyFile:                 ctx.String("private-cert-key"),
		PrivateClientCAFile:            ctx.String("private-client-ca"),
		PrivateSocketPerm:              ctx.String("private-socket-perm"),
		IAMDir:                         ctx.String("dir"),
		VaultEndpointURL:               ctx.String("vault-endpoint-url"),
		VaultNamespace:                 ctx.String("vault-namespace"),
		VaultSecretStoragePath:         ctx.String("vault-secret-storage-path"),
		VaultSecretStorageNamespace:    ctx.String("vault-secret-storage-namespace"),
		VaultAuthMethod:                ctx.String("vault-auth-method"),
		VaultAuthNamespace:             ctx.String("vault-auth-namespace"),
		VaultMountPath:                 ctx.String("vault-mount-path"),
		VaultRootToken:                 ctx.String("vault-root-token"),
		VaultRoleID:                    ctx.String("vault-role-id"),
		VaultRoleSecret:                ctx.String("vault-role-secret"),
		VaultServerCert:                ctx.String("vault-server-cert"),
		VaultClientCert:                ctx.String("vault-client-cert"),
		VaultClientCertKey:             ctx.String("vault-client-cert-key"),
		DisableOIDCThumbprintAutoFetch: ctx.Bool("disable-oidc-thumbprint-autofetch"),
		CORSAllowOrigin:                corsAllowOrigin,
		Region:                         region,
		WebuiPorts:                     webuiPorts,
		WebuiCertFile:                  webuiCertFile,
		WebuiKeyFile:                   webuiKeyFile,
		WebuiNoTLS:                     webuiNoTLS,
		WebuiPathPrefix:                webuiPathPrefix,
		WebuiIAMGateways:               webuiIAMGateways,
		WebuiGateways:                  webuiGateways,
		WebuiAdminGateways:             webuiAdminGateways,
		Version:                        Version,
		Build:                          Build,
		BuildTime:                      BuildTime,
	})
}
