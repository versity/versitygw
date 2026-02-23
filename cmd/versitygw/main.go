// Copyright 2023 Versity Software
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
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/urfave/cli/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/metrics"
	"github.com/versity/versitygw/s3api"
	"github.com/versity/versitygw/s3api/middlewares"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3event"
	"github.com/versity/versitygw/s3log"
	"github.com/versity/versitygw/webui"
)

var (
	ports                                  []string
	admPorts                               []string
	rootUserAccess                         string
	rootUserSecret                         string
	region                                 string
	maxConnections, maxRequests            int
	adminMaxConnections, adminMaxRequests  int
	corsAllowOrigin                        string
	admCertFile, admKeyFile                string
	certFile, keyFile                      string
	kafkaURL, kafkaTopic, kafkaKey         string
	natsURL, natsTopic                     string
	rabbitmqURL, rabbitmqExchange          string
	rabbitmqRoutingKey                     string
	eventWebhookURL                        string
	eventConfigFilePath                    string
	logWebhookURL, accessLog               string
	adminLogFile                           string
	healthPath                             string
	virtualDomain                          string
	debug                                  bool
	keepAlive                              bool
	pprof                                  string
	quiet                                  bool
	readonly                               bool
	disableStrictBucketNames               bool
	iamDir                                 string
	ldapURL, ldapBindDN, ldapPassword      string
	ldapQueryBase, ldapObjClasses          string
	ldapAccessAtr, ldapSecAtr, ldapRoleAtr string
	ldapUserIdAtr, ldapGroupIdAtr          string
	ldapProjectIdAtr                       string
	ldapTLSSkipVerify                      bool
	vaultEndpointURL, vaultNamespace       string
	vaultSecretStoragePath                 string
	vaultSecretStorageNamespace            string
	vaultAuthMethod, vaultAuthNamespace    string
	vaultMountPath                         string
	vaultRootToken, vaultRoleId            string
	vaultRoleSecret, vaultServerCert       string
	vaultClientCert, vaultClientCertKey    string
	s3IamAccess, s3IamSecret               string
	s3IamRegion, s3IamBucket               string
	s3IamEndpoint                          string
	s3IamSslNoVerify                       bool
	iamCacheDisable                        bool
	iamCacheTTL                            int
	iamCachePrune                          int
	metricsService                         string
	statsdServers                          string
	dogstatsServers                        string
	ipaHost, ipaVaultName                  string
	ipaUser, ipaPassword                   string
	ipaInsecure                            bool
	iamDebug                               bool
	webuiPorts                             []string
	webuiCertFile, webuiKeyFile            string
	webuiNoTLS                             bool
	webuiGateways                          []string
	webuiAdminGateways                     []string
)

var (
	// Version is the latest tag (set within Makefile)
	Version = "git"
	// Build is the commit hash (set within Makefile)
	Build = "norev"
	// BuildTime is the date/time of build (set within Makefile)
	BuildTime = "none"
)

func main() {
	setupSignalHandler()

	app := initApp()

	app.Commands = []*cli.Command{
		posixCommand(),
		scoutfsCommand(),
		s3Command(),
		azureCommand(),
		pluginCommand(),
		adminCommand(),
		testCommand(),
		utilsCommand(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-sigDone
		fmt.Fprintf(os.Stderr, "terminating signal caught, shutting down\n")
		cancel()
	}()

	if err := app.RunContext(ctx, os.Args); err != nil {
		log.Fatal(err)
	}
}

func initApp() *cli.App {
	return &cli.App{
		Usage: "Versity S3 Gateway",
		Description: `The Versity S3 Gateway is an S3 protocol translator that allows an S3 client
to access the supported backend storage as if it was a native S3 service.
VersityGW is an open-source project licensed under the Apache 2.0 License. The
source code is hosted on GitHub at https://github.com/versity/versitygw, and
documentation can be found in the GitHub wiki.`,
		Copyright: "Copyright (c) 2023-2024 Versity Software",
		Before: func(ctx *cli.Context) error {
			// Initialize global variables from context (including default values)
			ports = ctx.StringSlice("port")
			webuiPorts = ctx.StringSlice("webui")
			admPorts = ctx.StringSlice("admin-port")
			webuiGateways = ctx.StringSlice("webui-gateways")
			webuiAdminGateways = ctx.StringSlice("webui-admin-gateways")
			return nil
		},
		Action: func(ctx *cli.Context) error {
			return ctx.App.Command("help").Run(ctx)
		},
		Flags: initFlags(),
	}
}

func initFlags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:    "version",
			Usage:   "list versitygw version",
			Aliases: []string{"v"},
			Action: func(*cli.Context, bool) error {
				fmt.Println("Version  :", Version)
				fmt.Println("Build    :", Build)
				fmt.Println("BuildTime:", BuildTime)
				os.Exit(0)
				return nil
			},
		},
		&cli.StringSliceFlag{
			Name:    "port",
			Usage:   "gateway listen address <ip>:<port> or :<port> (can be specified multiple times for listening on multiple addresses)",
			EnvVars: []string{"VGW_PORT"},
			Value:   cli.NewStringSlice(":7070"),
			Aliases: []string{"p"},
		},
		&cli.StringSliceFlag{
			Name:    "webui",
			Usage:   "enable WebUI server on the specified listen address (e.g. ':7071', '127.0.0.1:7071', 'localhost:7071'; can be specified multiple times for listening on multiple addresses; disabled when omitted)",
			EnvVars: []string{"VGW_WEBUI_PORT"},
		},
		&cli.StringFlag{
			Name:        "webui-cert",
			Usage:       "TLS cert file for WebUI (defaults to --cert value when WebUI is enabled)",
			EnvVars:     []string{"VGW_WEBUI_CERT"},
			Destination: &webuiCertFile,
		},
		&cli.StringFlag{
			Name:        "webui-key",
			Usage:       "TLS key file for WebUI (defaults to --key value when WebUI is enabled)",
			EnvVars:     []string{"VGW_WEBUI_KEY"},
			Destination: &webuiKeyFile,
		},
		&cli.BoolFlag{
			Name:        "webui-no-tls",
			Usage:       "disable TLS for WebUI even if TLS is configured for the gateway",
			EnvVars:     []string{"VGW_WEBUI_NO_TLS"},
			Destination: &webuiNoTLS,
		},
		&cli.StringSliceFlag{
			Name:    "webui-gateways",
			Usage:   "override auto-detected S3 gateway URLs for WebUI (e.g. 'http://localhost:7070', 'https://s3.example.com'; can be specified multiple times)",
			EnvVars: []string{"VGW_WEBUI_GATEWAYS"},
		},
		&cli.StringSliceFlag{
			Name:    "webui-admin-gateways",
			Usage:   "override auto-detected admin gateway URLs for WebUI (e.g. 'http://localhost:7080', 'https://admin.example.com'; can be specified multiple times)",
			EnvVars: []string{"VGW_WEBUI_ADMIN_GATEWAYS"},
		},
		&cli.StringFlag{
			Name:        "access",
			Usage:       "root user access key",
			EnvVars:     []string{"ROOT_ACCESS_KEY_ID", "ROOT_ACCESS_KEY"},
			Aliases:     []string{"a"},
			Destination: &rootUserAccess,
		},
		&cli.StringFlag{
			Name:        "secret",
			Usage:       "root user secret access key",
			EnvVars:     []string{"ROOT_SECRET_ACCESS_KEY", "ROOT_SECRET_KEY"},
			Aliases:     []string{"s"},
			Destination: &rootUserSecret,
		},
		&cli.StringFlag{
			Name:        "region",
			Usage:       "s3 region string",
			EnvVars:     []string{"VGW_REGION"},
			Value:       "us-east-1",
			Destination: &region,
			Aliases:     []string{"r"},
		},
		&cli.IntFlag{
			Name:        "max-connections",
			Usage:       "maximum number of concurrent connections s3 api server may serve",
			EnvVars:     []string{"VGW_MAX_CONNECTIONS"},
			Value:       250000,
			Destination: &maxConnections,
			Aliases:     []string{"mc"},
		},
		&cli.IntFlag{
			Name:        "max-requests",
			Usage:       "maximum number of in-flight requests s3 api server may serve",
			EnvVars:     []string{"VGW_MAX_REQUESTS"},
			Value:       100000,
			Destination: &maxRequests,
			Aliases:     []string{"mr"},
		},
		&cli.StringFlag{
			Name:        "cors-allow-origin",
			Usage:       "default CORS Access-Control-Allow-Origin value (applied when no bucket CORS configuration exists, and for admin APIs)",
			EnvVars:     []string{"VGW_CORS_ALLOW_ORIGIN"},
			Destination: &corsAllowOrigin,
		},
		&cli.StringFlag{
			Name:        "cert",
			Usage:       "TLS cert file",
			EnvVars:     []string{"VGW_CERT"},
			Destination: &certFile,
		},
		&cli.StringFlag{
			Name:        "key",
			Usage:       "TLS key file",
			EnvVars:     []string{"VGW_KEY"},
			Destination: &keyFile,
		},
		&cli.StringSliceFlag{
			Name:    "admin-port",
			Usage:   "gateway admin server listen address <ip>:<port> or :<port> (can be specified multiple times for listening on multiple addresses)",
			EnvVars: []string{"VGW_ADMIN_PORT"},
			Aliases: []string{"ap"},
		},
		&cli.IntFlag{
			Name:        "admin-max-connections",
			Usage:       "maximum number of concurrent connections s3 admin server may handle",
			EnvVars:     []string{"VGW_ADMIN_MAX_CONNECTIONS"},
			Value:       250000,
			Destination: &adminMaxConnections,
			Aliases:     []string{"amc"},
		},
		&cli.IntFlag{
			Name:        "admin-max-requests",
			Usage:       "maximum number of in-flight requests s3 admin server may handle",
			EnvVars:     []string{"VGW_ADMIN_MAX_REQUESTS"},
			Value:       100000,
			Destination: &adminMaxRequests,
			Aliases:     []string{"amr"},
		},
		&cli.StringFlag{
			Name:        "admin-cert",
			Usage:       "TLS cert file for admin server",
			EnvVars:     []string{"VGW_ADMIN_CERT"},
			Destination: &admCertFile,
		},
		&cli.StringFlag{
			Name:        "admin-cert-key",
			Usage:       "TLS key file for admin server",
			EnvVars:     []string{"VGW_ADMIN_CERT_KEY"},
			Destination: &admKeyFile,
		},
		&cli.BoolFlag{
			Name:        "debug",
			Usage:       "enable debug output",
			Value:       false,
			EnvVars:     []string{"VGW_DEBUG"},
			Destination: &debug,
		},
		&cli.StringFlag{
			Name:        "pprof",
			Usage:       "enable pprof debug on specified port",
			EnvVars:     []string{"VGW_PPROF"},
			Destination: &pprof,
		},
		&cli.BoolFlag{
			Name:        "keep-alive",
			Usage:       "enable keep-alive connections (for finnicky clients)",
			EnvVars:     []string{"VGW_KEEP_ALIVE"},
			Destination: &keepAlive,
		},
		&cli.BoolFlag{
			Name:        "quiet",
			Usage:       "silence stdout request logging output",
			EnvVars:     []string{"VGW_QUIET"},
			Destination: &quiet,
			Aliases:     []string{"q"},
		},
		&cli.StringFlag{
			Name:        "virtual-domain",
			Usage:       "enables the virtual host style bucket addressing with the specified arg as the base domain",
			EnvVars:     []string{"VGW_VIRTUAL_DOMAIN"},
			Destination: &virtualDomain,
			Aliases:     []string{"vd"},
		},
		&cli.StringFlag{
			Name:        "access-log",
			Usage:       "enable server access logging to specified file",
			EnvVars:     []string{"LOGFILE", "VGW_ACCESS_LOG"},
			Destination: &accessLog,
		},
		&cli.StringFlag{
			Name:        "admin-access-log",
			Usage:       "enable admin server access logging to specified file",
			EnvVars:     []string{"LOGFILE", "VGW_ADMIN_ACCESS_LOG"},
			Destination: &adminLogFile,
		},
		&cli.StringFlag{
			Name:        "log-webhook-url",
			Usage:       "webhook url to send the audit logs",
			EnvVars:     []string{"WEBHOOK", "VGW_LOG_WEBHOOK_URL"},
			Destination: &logWebhookURL,
		},
		&cli.StringFlag{
			Name:        "event-kafka-url",
			Usage:       "kafka server url to send the bucket notifications.",
			EnvVars:     []string{"VGW_EVENT_KAFKA_URL"},
			Destination: &kafkaURL,
			Aliases:     []string{"eku"},
		},
		&cli.StringFlag{
			Name:        "event-kafka-topic",
			Usage:       "kafka server pub-sub topic to send the bucket notifications to",
			EnvVars:     []string{"VGW_EVENT_KAFKA_TOPIC"},
			Destination: &kafkaTopic,
			Aliases:     []string{"ekt"},
		},
		&cli.StringFlag{
			Name:        "event-kafka-key",
			Usage:       "kafka server put-sub topic key to send the bucket notifications to",
			EnvVars:     []string{"VGW_EVENT_KAFKA_KEY"},
			Destination: &kafkaKey,
			Aliases:     []string{"ekk"},
		},
		&cli.StringFlag{
			Name:        "event-nats-url",
			Usage:       "nats server url to send the bucket notifications",
			EnvVars:     []string{"VGW_EVENT_NATS_URL"},
			Destination: &natsURL,
			Aliases:     []string{"enu"},
		},
		&cli.StringFlag{
			Name:        "event-nats-topic",
			Usage:       "nats server pub-sub topic to send the bucket notifications to",
			EnvVars:     []string{"VGW_EVENT_NATS_TOPIC"},
			Destination: &natsTopic,
			Aliases:     []string{"ent"},
		},
		&cli.StringFlag{
			Name:        "event-rabbitmq-url",
			Usage:       "rabbitmq server url to send the bucket notifications (amqp or amqps scheme)",
			EnvVars:     []string{"VGW_EVENT_RABBITMQ_URL"},
			Destination: &rabbitmqURL,
			Aliases:     []string{"eru"},
		},
		&cli.StringFlag{
			Name:        "event-rabbitmq-exchange",
			Usage:       "rabbitmq exchange to publish bucket notifications to (blank for default)",
			EnvVars:     []string{"VGW_EVENT_RABBITMQ_EXCHANGE"},
			Destination: &rabbitmqExchange,
			Aliases:     []string{"ere"},
		},
		&cli.StringFlag{
			Name:        "event-rabbitmq-routing-key",
			Usage:       "rabbitmq routing key when publishing bucket notifications (defaults to bucket name when blank)",
			EnvVars:     []string{"VGW_EVENT_RABBITMQ_ROUTING_KEY"},
			Destination: &rabbitmqRoutingKey,
			Aliases:     []string{"errk"},
		},
		&cli.StringFlag{
			Name:        "event-webhook-url",
			Usage:       "webhook url to send bucket notifications",
			EnvVars:     []string{"VGW_EVENT_WEBHOOK_URL"},
			Destination: &eventWebhookURL,
			Aliases:     []string{"ewu"},
		},
		&cli.StringFlag{
			Name:        "event-filter",
			Usage:       "bucket event notifications filters configuration file path",
			EnvVars:     []string{"VGW_EVENT_FILTER"},
			Destination: &eventConfigFilePath,
			Aliases:     []string{"ef"},
		},
		&cli.StringFlag{
			Name:        "iam-dir",
			Usage:       "if defined, run internal iam service within this directory",
			EnvVars:     []string{"VGW_IAM_DIR"},
			Destination: &iamDir,
		},
		&cli.StringFlag{
			Name:        "iam-ldap-url",
			Usage:       "ldap server url to store iam data",
			EnvVars:     []string{"VGW_IAM_LDAP_URL"},
			Destination: &ldapURL,
		},
		&cli.StringFlag{
			Name:        "iam-ldap-bind-dn",
			Usage:       "ldap server binding dn, example: 'cn=admin,dc=example,dc=com'",
			EnvVars:     []string{"VGW_IAM_LDAP_BIND_DN"},
			Destination: &ldapBindDN,
		},
		&cli.StringFlag{
			Name:        "iam-ldap-bind-pass",
			Usage:       "ldap server user password",
			EnvVars:     []string{"VGW_IAM_LDAP_BIND_PASS"},
			Destination: &ldapPassword,
		},
		&cli.StringFlag{
			Name:        "iam-ldap-query-base",
			Usage:       "ldap server destination query, example: 'ou=iam,dc=example,dc=com'",
			EnvVars:     []string{"VGW_IAM_LDAP_QUERY_BASE"},
			Destination: &ldapQueryBase,
		},
		&cli.StringFlag{
			Name:        "iam-ldap-object-classes",
			Usage:       "ldap server object classes used to store the data. provide it as comma separated string, example: 'top,person'",
			EnvVars:     []string{"VGW_IAM_LDAP_OBJECT_CLASSES"},
			Destination: &ldapObjClasses,
		},
		&cli.StringFlag{
			Name:        "iam-ldap-access-atr",
			Usage:       "ldap server user access key id attribute name",
			EnvVars:     []string{"VGW_IAM_LDAP_ACCESS_ATR"},
			Destination: &ldapAccessAtr,
		},
		&cli.StringFlag{
			Name:        "iam-ldap-secret-atr",
			Usage:       "ldap server user secret access key attribute name",
			EnvVars:     []string{"VGW_IAM_LDAP_SECRET_ATR"},
			Destination: &ldapSecAtr,
		},
		&cli.StringFlag{
			Name:        "iam-ldap-role-atr",
			Usage:       "ldap server user role attribute name",
			EnvVars:     []string{"VGW_IAM_LDAP_ROLE_ATR"},
			Destination: &ldapRoleAtr,
		},
		&cli.StringFlag{
			Name:        "iam-ldap-user-id-atr",
			Usage:       "ldap server user id attribute name",
			EnvVars:     []string{"VGW_IAM_LDAP_USER_ID_ATR"},
			Destination: &ldapUserIdAtr,
		},
		&cli.StringFlag{
			Name:        "iam-ldap-group-id-atr",
			Usage:       "ldap server user group id attribute name",
			EnvVars:     []string{"VGW_IAM_LDAP_GROUP_ID_ATR"},
			Destination: &ldapGroupIdAtr,
		},
		&cli.StringFlag{
			Name:        "iam-ldap-project-id-atr",
			Usage:       "ldap server user project id attribute name",
			EnvVars:     []string{"VGW_IAM_LDAP_PROJECT_ID_ATR"},
			Destination: &ldapProjectIdAtr,
		},
		&cli.BoolFlag{
			Name:        "iam-ldap-tls-skip-verify",
			Usage:       "disable TLS certificate verification for LDAP connections (insecure, for self-signed certificates)",
			EnvVars:     []string{"VGW_IAM_LDAP_TLS_SKIP_VERIFY"},
			Destination: &ldapTLSSkipVerify,
		},
		&cli.StringFlag{
			Name:        "iam-vault-endpoint-url",
			Usage:       "vault server url",
			EnvVars:     []string{"VGW_IAM_VAULT_ENDPOINT_URL"},
			Destination: &vaultEndpointURL,
		},
		&cli.StringFlag{
			Name:        "iam-vault-namespace",
			Usage:       "vault server namespace",
			EnvVars:     []string{"VGW_IAM_VAULT_NAMESPACE"},
			Destination: &vaultNamespace,
		},
		&cli.StringFlag{
			Name:        "iam-vault-secret-storage-path",
			Usage:       "vault server secret storage path",
			EnvVars:     []string{"VGW_IAM_VAULT_SECRET_STORAGE_PATH"},
			Destination: &vaultSecretStoragePath,
		},
		&cli.StringFlag{
			Name:        "iam-vault-secret-storage-namespace",
			Usage:       "vault server secret storage namespace",
			EnvVars:     []string{"VGW_IAM_VAULT_SECRET_STORAGE_NAMESPACE"},
			Destination: &vaultSecretStorageNamespace,
		},
		&cli.StringFlag{
			Name:        "iam-vault-auth-method",
			Usage:       "vault server auth method",
			EnvVars:     []string{"VGW_IAM_VAULT_AUTH_METHOD"},
			Destination: &vaultAuthMethod,
		},
		&cli.StringFlag{
			Name:        "iam-vault-auth-namespace",
			Usage:       "vault server auth namespace",
			EnvVars:     []string{"VGW_IAM_VAULT_AUTH_NAMESPACE"},
			Destination: &vaultAuthNamespace,
		},
		&cli.StringFlag{
			Name:        "iam-vault-mount-path",
			Usage:       "vault server mount path",
			EnvVars:     []string{"VGW_IAM_VAULT_MOUNT_PATH"},
			Destination: &vaultMountPath,
		},
		&cli.StringFlag{
			Name:        "iam-vault-root-token",
			Usage:       "vault server root token",
			EnvVars:     []string{"VGW_IAM_VAULT_ROOT_TOKEN"},
			Destination: &vaultRootToken,
		},
		&cli.StringFlag{
			Name:        "iam-vault-role-id",
			Usage:       "vault server user role id",
			EnvVars:     []string{"VGW_IAM_VAULT_ROLE_ID"},
			Destination: &vaultRoleId,
		},
		&cli.StringFlag{
			Name:        "iam-vault-role-secret",
			Usage:       "vault server user role secret",
			EnvVars:     []string{"VGW_IAM_VAULT_ROLE_SECRET"},
			Destination: &vaultRoleSecret,
		},
		&cli.StringFlag{
			Name:        "iam-vault-server_cert",
			Usage:       "vault server TLS certificate",
			EnvVars:     []string{"VGW_IAM_VAULT_SERVER_CERT"},
			Destination: &vaultServerCert,
		},
		&cli.StringFlag{
			Name:        "iam-vault-client_cert",
			Usage:       "vault client TLS certificate",
			EnvVars:     []string{"VGW_IAM_VAULT_CLIENT_CERT"},
			Destination: &vaultClientCert,
		},
		&cli.StringFlag{
			Name:        "iam-vault-client_cert_key",
			Usage:       "vault client TLS certificate key",
			EnvVars:     []string{"VGW_IAM_VAULT_CLIENT_CERT_KEY"},
			Destination: &vaultClientCertKey,
		},
		&cli.StringFlag{
			Name:        "s3-iam-access",
			Usage:       "s3 IAM access key",
			EnvVars:     []string{"VGW_S3_IAM_ACCESS_KEY"},
			Destination: &s3IamAccess,
		},
		&cli.StringFlag{
			Name:        "s3-iam-secret",
			Usage:       "s3 IAM secret key",
			EnvVars:     []string{"VGW_S3_IAM_SECRET_KEY"},
			Destination: &s3IamSecret,
		},
		&cli.StringFlag{
			Name:        "s3-iam-region",
			Usage:       "s3 IAM region",
			EnvVars:     []string{"VGW_S3_IAM_REGION"},
			Destination: &s3IamRegion,
			Value:       "us-east-1",
		},
		&cli.StringFlag{
			Name:        "s3-iam-bucket",
			Usage:       "s3 IAM bucket",
			EnvVars:     []string{"VGW_S3_IAM_BUCKET"},
			Destination: &s3IamBucket,
		},
		&cli.StringFlag{
			Name:        "s3-iam-endpoint",
			Usage:       "s3 IAM endpoint",
			EnvVars:     []string{"VGW_S3_IAM_ENDPOINT"},
			Destination: &s3IamEndpoint,
		},
		&cli.BoolFlag{
			Name:        "s3-iam-noverify",
			Usage:       "s3 IAM disable ssl verification",
			EnvVars:     []string{"VGW_S3_IAM_NO_VERIFY"},
			Destination: &s3IamSslNoVerify,
		},
		&cli.BoolFlag{
			Name:        "iam-cache-disable",
			Usage:       "disable local iam cache",
			EnvVars:     []string{"VGW_IAM_CACHE_DISABLE"},
			Destination: &iamCacheDisable,
		},
		&cli.IntFlag{
			Name:        "iam-cache-ttl",
			Usage:       "local iam cache entry ttl (seconds)",
			EnvVars:     []string{"VGW_IAM_CACHE_TTL"},
			Value:       120,
			Destination: &iamCacheTTL,
		},
		&cli.IntFlag{
			Name:        "iam-cache-prune",
			Usage:       "local iam cache cleanup interval (seconds)",
			EnvVars:     []string{"VGW_IAM_CACHE_PRUNE"},
			Value:       3600,
			Destination: &iamCachePrune,
		},
		&cli.BoolFlag{
			Name:        "iam-debug",
			Usage:       "enable IAM debug output",
			Value:       false,
			EnvVars:     []string{"VGW_IAM_DEBUG"},
			Destination: &iamDebug,
		},
		&cli.StringFlag{
			Name: "health",
			Usage: `health check endpoint path. Health endpoint will be configured on GET http method: GET <health>
					NOTICE: the path has to be specified with '/'. e.g /health`,
			EnvVars:     []string{"VGW_HEALTH"},
			Destination: &healthPath,
		},
		&cli.BoolFlag{
			Name:        "readonly",
			Usage:       "allow only read operations across all the gateway",
			EnvVars:     []string{"VGW_READ_ONLY"},
			Destination: &readonly,
		},
		&cli.BoolFlag{
			Name:        "disable-strict-bucket-names",
			Usage:       "allow relaxed bucket naming (disables strict validation checks)",
			EnvVars:     []string{"VGW_DISABLE_STRICT_BUCKET_NAMES"},
			Destination: &disableStrictBucketNames,
		},
		&cli.StringFlag{
			Name:        "metrics-service-name",
			Usage:       "service name tag for metrics, hostname if blank",
			EnvVars:     []string{"VGW_METRICS_SERVICE_NAME"},
			Aliases:     []string{"msn"},
			Destination: &metricsService,
		},
		&cli.StringFlag{
			Name:        "metrics-statsd-servers",
			Usage:       "StatsD server urls comma separated. e.g. 'statsd1.example.com:8125,statsd2.example.com:8125'",
			EnvVars:     []string{"VGW_METRICS_STATSD_SERVERS"},
			Aliases:     []string{"mss"},
			Destination: &statsdServers,
		},
		&cli.StringFlag{
			Name:        "metrics-dogstatsd-servers",
			Usage:       "DogStatsD server urls comma separated. e.g. '127.0.0.1:8125,dogstats.example.com:8125'",
			EnvVars:     []string{"VGW_METRICS_DOGSTATS_SERVERS"},
			Aliases:     []string{"mds"},
			Destination: &dogstatsServers,
		},
		&cli.StringFlag{
			Name:        "ipa-host",
			Usage:       "FreeIPA server url e.g. https://ipa.example.test",
			EnvVars:     []string{"VGW_IPA_HOST"},
			Destination: &ipaHost,
		},
		&cli.StringFlag{
			Name:        "ipa-vault-name",
			Usage:       "A name of the user vault containing their secret",
			EnvVars:     []string{"VGW_IPA_VAULT_NAME"},
			Destination: &ipaVaultName,
		},
		&cli.StringFlag{
			Name:        "ipa-user",
			Usage:       "Username used to connect to FreeIPA (requires permissions to read user vault contents)",
			EnvVars:     []string{"VGW_IPA_USER"},
			Destination: &ipaUser,
		},
		&cli.StringFlag{
			Name:        "ipa-password",
			Usage:       "Password of the user used to connect to FreeIPA",
			EnvVars:     []string{"VGW_IPA_PASSWORD"},
			Destination: &ipaPassword,
		},
		&cli.BoolFlag{
			Name:        "ipa-insecure",
			Usage:       "Disable verify TLS certificate of FreeIPA server",
			EnvVars:     []string{"VGW_IPA_INSECURE"},
			Destination: &ipaInsecure,
		},
	}
}

func runGateway(ctx context.Context, be backend.Backend) error {
	if rootUserAccess == "" || rootUserSecret == "" {
		return fmt.Errorf("root user access and secret key must be provided")
	}

	if maxConnections < 1 {
		log.Fatal("max-connections must be positive")
	}
	if maxRequests < 1 {
		log.Fatal("max-requests must be positive")
	}
	if maxRequests > maxConnections {
		log.Printf("WARNING: max-requests (%d) exceeds max-connections (%d) which could allow for gateway to panic before throttling requests",
			maxRequests, maxConnections)
	}

	// Ensure we have at least one port specified
	if len(ports) == 0 {
		log.Fatal("no ports specified")
	}

	// WebUI runs in a browser and typically talks to the gateway/admin APIs cross-origin
	// (different port). If no bucket CORS configuration exists, those API responses need
	// a default Access-Control-Allow-Origin to be usable from the WebUI.
	if len(webuiPorts) > 0 && strings.TrimSpace(corsAllowOrigin) == "" {
		// A single Access-Control-Allow-Origin value cannot cover multiple specific
		// origins. Default to '*' for usability and print a warning so operators can
		// lock it down explicitly.
		corsAllowOrigin = "*"
		webuiScheme := "http"
		if !webuiNoTLS && (strings.TrimSpace(webuiCertFile) != "" || strings.TrimSpace(certFile) != "") {
			webuiScheme = "https"
		}

		// Suggest a more secure explicit origin based on the actual WebUI listening interfaces.
		// (Browsers require an exact origin match; this is typically one chosen hostname/IP.)
		var suggestion string
		var allOrigins []string
		for _, addr := range webuiPorts {
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

		fmt.Fprintf(os.Stderr, "WARNING: --webui is enabled but --cors-allow-origin is not set; defaulting to '*'; %s\n", suggestion)
	}

	// Validate port conflicts across s3 api, admin, and webui ports
	if err := validatePortConflicts(ports, admPorts, webuiPorts); err != nil {
		return err
	}

	utils.SetBucketNameValidationStrict(!disableStrictBucketNames)

	if pprof != "" {
		// listen on specified port for pprof debug
		// point browser to http://<ip:port>/debug/pprof/
		go func() {
			log.Fatal(http.ListenAndServe(pprof, nil))
		}()
	}

	opts := []s3api.Option{
		s3api.WithConcurrencyLimiter(maxConnections, maxRequests),
	}
	if corsAllowOrigin != "" {
		opts = append(opts, s3api.WithCORSAllowOrigin(corsAllowOrigin))
	}

	if certFile != "" || keyFile != "" {
		if certFile == "" {
			return fmt.Errorf("TLS key specified without cert file")
		}
		if keyFile == "" {
			return fmt.Errorf("TLS cert specified without key file")
		}

		cs := utils.NewCertStorage()
		err := cs.SetCertificate(certFile, keyFile)
		if err != nil {
			return fmt.Errorf("tls: load certs: %v", err)
		}
		opts = append(opts, s3api.WithTLS(cs))
	}
	if len(admPorts) == 0 {
		opts = append(opts, s3api.WithAdminServer())
	}
	if quiet {
		opts = append(opts, s3api.WithQuiet())
	}
	if healthPath != "" {
		opts = append(opts, s3api.WithHealth(healthPath))
	}
	if readonly {
		opts = append(opts, s3api.WithReadOnly())
	}
	if virtualDomain != "" {
		opts = append(opts, s3api.WithHostStyle(virtualDomain))
	}
	if keepAlive {
		opts = append(opts, s3api.WithKeepAlive())
	}
	if debug {
		debuglogger.SetDebugEnabled()
	}
	if iamDebug {
		debuglogger.SetIAMDebugEnabled()
	}

	iam, err := auth.New(&auth.Opts{
		RootAccount: auth.Account{
			Access: rootUserAccess,
			Secret: rootUserSecret,
			Role:   auth.RoleAdmin,
		},
		Dir:                         iamDir,
		LDAPServerURL:               ldapURL,
		LDAPBindDN:                  ldapBindDN,
		LDAPPassword:                ldapPassword,
		LDAPQueryBase:               ldapQueryBase,
		LDAPObjClasses:              ldapObjClasses,
		LDAPAccessAtr:               ldapAccessAtr,
		LDAPSecretAtr:               ldapSecAtr,
		LDAPRoleAtr:                 ldapRoleAtr,
		LDAPUserIdAtr:               ldapUserIdAtr,
		LDAPGroupIdAtr:              ldapGroupIdAtr,
		LDAPProjectIdAtr:            ldapProjectIdAtr,
		LDAPTLSSkipVerify:           ldapTLSSkipVerify,
		VaultEndpointURL:            vaultEndpointURL,
		VaultNamespace:              vaultNamespace,
		VaultSecretStoragePath:      vaultSecretStoragePath,
		VaultSecretStorageNamespace: vaultSecretStorageNamespace,
		VaultAuthMethod:             vaultAuthMethod,
		VaultAuthNamespace:          vaultAuthNamespace,
		VaultMountPath:              vaultMountPath,
		VaultRootToken:              vaultRootToken,
		VaultRoleId:                 vaultRoleId,
		VaultRoleSecret:             vaultRoleSecret,
		VaultServerCert:             vaultServerCert,
		VaultClientCert:             vaultClientCert,
		VaultClientCertKey:          vaultClientCertKey,
		S3Access:                    s3IamAccess,
		S3Secret:                    s3IamSecret,
		S3Region:                    s3IamRegion,
		S3Bucket:                    s3IamBucket,
		S3Endpoint:                  s3IamEndpoint,
		S3DisableSSlVerfiy:          s3IamSslNoVerify,
		CacheDisable:                iamCacheDisable,
		CacheTTL:                    iamCacheTTL,
		CachePrune:                  iamCachePrune,
		IpaHost:                     ipaHost,
		IpaVaultName:                ipaVaultName,
		IpaUser:                     ipaUser,
		IpaPassword:                 ipaPassword,
		IpaInsecure:                 ipaInsecure,
	})
	if err != nil {
		return fmt.Errorf("setup iam: %w", err)
	}

	loggers, err := s3log.InitLogger(&s3log.LogConfig{
		LogFile:      accessLog,
		WebhookURL:   logWebhookURL,
		AdminLogFile: adminLogFile,
	})
	if err != nil {
		return fmt.Errorf("setup logger: %w", err)
	}

	metricsManager, err := metrics.NewManager(ctx, metrics.Config{
		ServiceName:      metricsService,
		StatsdServers:    statsdServers,
		DogStatsdServers: dogstatsServers,
	})
	if err != nil {
		return fmt.Errorf("init metrics manager: %w", err)
	}

	evSender, err := s3event.InitEventSender(&s3event.EventConfig{
		KafkaURL:             kafkaURL,
		KafkaTopic:           kafkaTopic,
		KafkaTopicKey:        kafkaKey,
		NatsURL:              natsURL,
		NatsTopic:            natsTopic,
		RabbitmqURL:          rabbitmqURL,
		RabbitmqExchange:     rabbitmqExchange,
		RabbitmqRoutingKey:   rabbitmqRoutingKey,
		WebhookURL:           eventWebhookURL,
		FilterConfigFilePath: eventConfigFilePath,
	})
	if err != nil {
		return fmt.Errorf("init bucket event notifications: %w", err)
	}

	srv, err := s3api.New(be, middlewares.RootUserConfig{
		Access: rootUserAccess,
		Secret: rootUserSecret,
	}, region, iam, loggers.S3Logger, loggers.AdminLogger, evSender, metricsManager, opts...)
	if err != nil {
		return fmt.Errorf("init gateway: %v", err)
	}

	var admSrv *s3api.S3AdminServer

	if len(admPorts) > 0 {
		var opts []s3api.AdminOpt

		if adminMaxConnections < 1 {
			log.Fatal("admin-max-connections must be positive")
		}
		if adminMaxRequests < 1 {
			log.Fatal("admin-max-requests must be positive")
		}
		if adminMaxRequests > adminMaxConnections {
			log.Printf("WARNING: admin-max-requests (%d) exceeds admin-max-connections (%d) which could allow for gateway to panic before throttling requests",
				adminMaxRequests, adminMaxConnections)
		}

		opts = []s3api.AdminOpt{
			s3api.WithAdminConcurrencyLimiter(adminMaxConnections, adminMaxRequests),
		}

		if corsAllowOrigin != "" {
			opts = append(opts, s3api.WithAdminCORSAllowOrigin(corsAllowOrigin))
		}

		if admCertFile != "" || admKeyFile != "" {
			if admCertFile == "" {
				return fmt.Errorf("TLS key specified without cert file")
			}
			if admKeyFile == "" {
				return fmt.Errorf("TLS cert specified without key file")
			}

			cs := utils.NewCertStorage()
			err = cs.SetCertificate(admCertFile, admKeyFile)
			if err != nil {
				return fmt.Errorf("tls: load certs: %v", err)
			}
			opts = append(opts, s3api.WithAdminSrvTLS(cs))
		}
		if quiet {
			opts = append(opts, s3api.WithAdminQuiet())
		}
		if debug {
			opts = append(opts, s3api.WithAdminDebug())
		}

		admSrv = s3api.NewAdminServer(be, middlewares.RootUserConfig{Access: rootUserAccess, Secret: rootUserSecret}, region, iam, loggers.AdminLogger, srv.Router.Ctrl, opts...)
	}

	var webSrv *webui.Server
	webuiSSLEnabled := false
	webTLSCert := ""
	webTLSKey := ""
	if len(webuiPorts) > 0 {
		// Validate all webui addresses
		for _, addr := range webuiPorts {
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
		if !webuiNoTLS {
			// WebUI can either use explicitly provided TLS files or reuse the
			// gateway's TLS files by default.
			webTLSCert = webuiCertFile
			webTLSKey = webuiKeyFile
			if webTLSCert == "" && webTLSKey == "" {
				webTLSCert = certFile
				webTLSKey = keyFile
			}
			if webTLSCert != "" || webTLSKey != "" {
				if webTLSCert == "" {
					return fmt.Errorf("webui TLS key specified without cert file")
				}
				if webTLSKey == "" {
					return fmt.Errorf("webui TLS cert specified without key file")
				}
				webuiSSLEnabled = true

				cs := utils.NewCertStorage()
				err := cs.SetCertificate(webTLSCert, webTLSKey)
				if err != nil {
					return fmt.Errorf("tls: load certs: %v", err)
				}

				webOpts = append(webOpts, webui.WithTLS(cs))
			}
		}

		sslEnabled := certFile != ""
		admSSLEnabled := sslEnabled
		if len(admPorts) > 0 {
			admSSLEnabled = admCertFile != ""
		}

		var gateways []string
		if len(webuiGateways) > 0 {
			// Use explicitly provided gateway URLs if specified
			// Validate explicitly provided URLs
			validGateways, err := validateGatewayURLs(webuiGateways, "webui gateway")
			if err != nil {
				return err
			}
			gateways = validGateways
		} else {
			// Auto-detect from configured ports
			for _, p := range ports {
				urls, err := buildServiceURLs(p, sslEnabled)
				if err != nil {
					return fmt.Errorf("webui: build gateway URLs: %w", err)
				}
				gateways = append(gateways, urls...)
			}
			// Sort so localhost/127.0.0.1 URLs appear last
			sortGatewayURLs(gateways)
		}

		adminGateways := gateways
		if len(webuiAdminGateways) > 0 {
			// Validate explicitly provided admin gateway URLs
			validAdminGateways, err := validateGatewayURLs(webuiAdminGateways, "webui admin gateway")
			if err != nil {
				return err
			}
			adminGateways = validAdminGateways
		} else if len(admPorts) > 0 {
			// Auto-detect from configured admin ports
			adminGateways = nil
			for _, admPort := range admPorts {
				urls, err := buildServiceURLs(admPort, admSSLEnabled)
				if err != nil {
					return fmt.Errorf("webui: build admin gateway URLs: %w", err)
				}
				adminGateways = append(adminGateways, urls...)
			}
			// Sort so localhost/127.0.0.1 URLs appear last
			sortGatewayURLs(adminGateways)
		}

		if quiet {
			webOpts = append(webOpts, webui.WithQuiet())
		}

		webSrv = webui.NewServer(&webui.ServerConfig{
			Gateways:      gateways,
			AdminGateways: adminGateways,
			Region:        region,
		}, webOpts...)
	}

	if !quiet {
		printBanner(ports, admPorts, certFile != "" || keyFile != "", admCertFile != "" || admKeyFile != "", webuiPorts, webuiSSLEnabled)
	}

	servers := 1
	if len(admPorts) > 0 {
		servers++
	}
	if len(webuiPorts) > 0 {
		servers++
	}

	c := make(chan error, servers)
	go func() { c <- srv.ServeMultiPort(ports) }()
	if len(admPorts) > 0 {
		go func() { c <- admSrv.ServeMultiPort(admPorts) }()
	}
	if len(webuiPorts) > 0 {
		go func() { c <- webSrv.ServeMultiPort(webuiPorts) }()
	}

	// for/select blocks until shutdown
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
			if certFile != "" && keyFile != "" {
				err = srv.CertStorage.SetCertificate(certFile, keyFile)
				if err != nil {
					debuglogger.InternalError(fmt.Errorf("srv cert reload failed: %w", err))
				} else {
					fmt.Printf("srv cert reloaded (cert: %s, key: %s)\n", certFile, keyFile)
				}
			}
			if len(admPorts) > 0 && admCertFile != "" && admKeyFile != "" {
				err = admSrv.CertStorage.SetCertificate(admCertFile, admKeyFile)
				if err != nil {
					debuglogger.InternalError(fmt.Errorf("admSrv cert reload failed: %w", err))
				} else {
					fmt.Printf("admSrv cert reloaded (cert: %s, key: %s)\n", admCertFile, admKeyFile)
				}
			}
			if len(webuiPorts) > 0 && webTLSCert != "" && webTLSKey != "" {
				err := webSrv.CertStorage.SetCertificate(webTLSCert, webTLSKey)
				if err != nil {
					debuglogger.InternalError(fmt.Errorf("webSrv cert reload failed: %w", err))
				} else {
					fmt.Printf("webSrv cert reloaded (cert: %s, key: %s)\n", webTLSCert, webTLSKey)
				}
			}
		}
	}
	saveErr := err

	// first shut down the s3api and admin servers
	// as they have dependecy from other modules
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

func printBanner(ports []string, admPorts []string, ssl, admSsl bool, webuiAddrs []string, webuiSsl bool) {
	if len(ports) == 0 {
		fmt.Fprintf(os.Stderr, "No ports specified\n")
		return
	}

	// Collect all interfaces for all ports
	var allInterfaces []string
	var allPorts []string
	interfaceMap := make(map[string]bool) // deduplicate

	for _, portSpec := range ports {
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

	// Collect all admin interfaces for all admin ports
	var allAdmInterfaces []string
	admInterfaceMap := make(map[string]bool)
	for _, admPort := range admPorts {
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

	title := "VersityGW"
	version := fmt.Sprintf("Version %v, Build %v", Version, Build)
	urls := []string{}

	// Build URLs for all listening addresses
	for _, addrPort := range allInterfaces {
		ip, prt, err := net.SplitHostPort(addrPort)
		if err != nil {
			// Shouldn't happen as we constructed these properly, but handle it
			continue
		}
		// Rebuild the host:port using JoinHostPort to ensure IPv6 addresses have brackets
		hostPort := net.JoinHostPort(ip, prt)
		url := fmt.Sprintf("http://%s", hostPort)
		if ssl {
			url = fmt.Sprintf("https://%s", hostPort)
		}
		urls = append(urls, url)
	}

	// Determine bound host description
	var boundHost string
	if len(ports) == 1 {
		hst, prt, _ := net.SplitHostPort(ports[0])
		if hst == "" {
			hst = "0.0.0.0"
		}
		boundHost = fmt.Sprintf("(bound on host %s and port %s)", hst, prt)
	} else {
		// Multiple ports
		portList := strings.Join(allPorts, ", ")
		boundHost = fmt.Sprintf("(bound on ports: %s)", portList)
	}

	lines := []string{
		centerText(title),
		centerText(version),
		centerText(boundHost),
		centerText(""),
	}

	if len(allAdmInterfaces) > 0 {
		lines = append(lines,
			leftText("S3 service listening on:"),
		)
	} else {
		lines = append(lines,
			leftText("Admin/S3 service listening on:"),
		)
	}

	for _, url := range urls {
		lines = append(lines, leftText("  "+url))
	}

	if len(allAdmInterfaces) > 0 {
		lines = append(lines,
			centerText(""),
			leftText("Admin service listening on:"),
		)

		for _, addrPort := range allAdmInterfaces {
			ip, prt, err := net.SplitHostPort(addrPort)
			if err != nil {
				continue
			}
			hostPort := net.JoinHostPort(ip, prt)
			url := fmt.Sprintf("http://%s", hostPort)
			if admSsl {
				url = fmt.Sprintf("https://%s", hostPort)
			}
			lines = append(lines, leftText("  "+url))
		}
	}

	// Collect all webui interfaces for all webui addresses
	if len(webuiAddrs) > 0 {
		var allWebInterfaces []string
		webInterfaceMap := make(map[string]bool)

		for _, webuiAddr := range webuiAddrs {
			if strings.TrimSpace(webuiAddr) == "" {
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
			lines = append(lines,
				centerText(""),
				leftText("WebUI listening on:"),
			)
			for _, addrPort := range allWebInterfaces {
				ip, prt, err := net.SplitHostPort(addrPort)
				if err != nil {
					continue
				}
				hostPort := net.JoinHostPort(ip, prt)
				url := fmt.Sprintf("http://%s", hostPort)
				if webuiSsl {
					url = fmt.Sprintf("https://%s", hostPort)
				}
				lines = append(lines, leftText("  "+url))
			}
		}
	}

	// Print the top border
	fmt.Println("┌" + strings.Repeat("─", columnWidth-2) + "┐")

	// Print each line
	for _, line := range lines {
		fmt.Printf("│%-*s│\n", columnWidth-2, line)
	}

	// Print the bottom border
	fmt.Println("└" + strings.Repeat("─", columnWidth-2) + "┘")
}

// getMatchingIPs returns all IP addresses that the server will listen on
// for the given address specification. For hostnames, it resolves to all
// IP addresses (e.g., localhost -> 127.0.0.1 and ::1).
func getMatchingIPs(spec string) ([]string, error) {
	ips, err := utils.ResolveHostnameIPs(spec)
	if err != nil {
		return nil, fmt.Errorf("resolve hostname: %v", err)
	}

	// If empty host (e.g., ":8080"), enumerate all local interfaces
	if len(ips) == 1 && ips[0] == "" {
		return getAllLocalIPs()
	}

	// Filter out link-local addresses
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

// getAllLocalIPs returns all non-link-local IP addresses from local interfaces
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
		urls = append(urls, fmt.Sprintf("%s://%s:%s", scheme, ip, prt))
	}
	return urls, nil
}

// isLocalhost checks if a URL contains a localhost address
func isLocalhost(url string) bool {
	return strings.Contains(url, "localhost") ||
		strings.Contains(url, "127.0.0.1") ||
		strings.Contains(url, "[::1]")
}

// validateGatewayURLs validates a list of gateway URLs and returns only valid ones.
// It prints warnings for invalid URLs and returns an error if the input list is non-empty
// but contains no valid URLs after filtering.
func validateGatewayURLs(urls []string, urlType string) ([]string, error) {
	if len(urls) == 0 {
		return urls, nil
	}

	var validURLs []string
	for _, urlStr := range urls {
		// Skip empty strings
		if strings.TrimSpace(urlStr) == "" {
			continue
		}

		parsedURL, err := url.Parse(urlStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: invalid %s URL %q: %v\n", urlType, urlStr, err)
			continue
		}

		// Ensure the URL has a scheme (http or https)
		if parsedURL.Scheme == "" {
			fmt.Fprintf(os.Stderr, "WARNING: invalid %s URL %q: missing scheme (must be http:// or https://)\n", urlType, urlStr)
			continue
		}

		if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
			fmt.Fprintf(os.Stderr, "WARNING: invalid %s URL %q: unsupported scheme %q (must be http or https)\n", urlType, urlStr, parsedURL.Scheme)
			continue
		}

		// Ensure the URL has a host
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

// sortGatewayURLs sorts a list of URLs so that localhost and 127.0.0.1 URLs appear last
func sortGatewayURLs(urls []string) {
	if len(urls) <= 1 {
		return
	}

	// Partition URLs into two groups: non-localhost and localhost
	var nonLocal []string
	var local []string

	for _, url := range urls {
		if isLocalhost(url) {
			local = append(local, url)
		} else {
			nonLocal = append(nonLocal, url)
		}
	}

	// Rebuild the slice with non-localhost first, then localhost
	copy(urls, nonLocal)
	copy(urls[len(nonLocal):], local)
}

// validatePortConflicts checks for port conflicts across s3 api, admin, and webui ports.
// A bare port spec (e.g., ":7071") binds to all interfaces and will conflict with any other
// binding on the same port, whether it's ":7071" or "ip:7071".
// However, two identical "ip:port" specs are allowed (will be caught by later errors).
// This is needed because net.Listen() does not return the address already in use
// error for the bare port spec arguments.
func validatePortConflicts(ports, admPorts, webuiPorts []string) error {
	type portSpec struct {
		spec     string
		port     string
		isBare   bool
		portType string // "s3", "admin", or "webui"
	}

	var allSpecs []portSpec

	// Collect all port specs
	for _, p := range ports {
		_, port, err := net.SplitHostPort(p)
		if err != nil {
			continue // will be caught by later validation
		}
		allSpecs = append(allSpecs, portSpec{
			spec:     p,
			port:     port,
			isBare:   strings.HasPrefix(p, ":"),
			portType: "s3",
		})
	}

	for _, p := range admPorts {
		_, port, err := net.SplitHostPort(p)
		if err != nil {
			continue // will be caught by later validation
		}
		allSpecs = append(allSpecs, portSpec{
			spec:     p,
			port:     port,
			isBare:   strings.HasPrefix(p, ":"),
			portType: "admin",
		})
	}

	for _, p := range webuiPorts {
		_, port, err := net.SplitHostPort(p)
		if err != nil {
			continue // will be caught by later validation
		}
		allSpecs = append(allSpecs, portSpec{
			spec:     p,
			port:     port,
			isBare:   strings.HasPrefix(p, ":"),
			portType: "webui",
		})
	}

	// Check for conflicts
	for i, spec1 := range allSpecs {
		for j, spec2 := range allSpecs {
			if i >= j {
				continue // skip comparing with self and already compared pairs
			}

			// If ports don't match, no conflict
			if spec1.port != spec2.port {
				continue
			}

			// If both are identical IP:port specs, allow (will be caught later)
			if !spec1.isBare && !spec2.isBare && spec1.spec == spec2.spec {
				continue
			}

			// If either is a bare port spec, it's a conflict with any other spec on the same port
			if spec1.isBare || spec2.isBare {
				return fmt.Errorf("port conflict: --%s %s conflicts with --%s %s (bare port specs bind to all interfaces)",
					spec1.portType, spec1.spec, spec2.portType, spec2.spec)
			}
		}
	}

	return nil
}

const columnWidth = 70

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
