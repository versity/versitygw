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
	"net/http"
	_ "net/http/pprof"
	"os"

	"github.com/urfave/cli/v2"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/embedgw"
	"github.com/versity/versitygw/s3api/utils"
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
	webuiPathPrefix                        string
	webuiS3Prefix                          string
	websitePorts                           []string
	websiteDomain                          string
	websiteCertFile, websiteKeyFile        string
	websiteNoTLS                           bool
	disableACLs                            bool
	mpMaxParts                             int
	copyObjectThreshold                    int64
	socketPerm                             string
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

	app.Commands = initCommands()

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

func initCommands() []*cli.Command {
	return []*cli.Command{
		posixCommand(),
		scoutfsCommand(),
		s3Command(),
		azureCommand(),
		iamCommand(),
		pluginCommand(),
		adminCommand(),
		testCommand(),
		utilsCommand(),
	}
}

func initApp() *cli.App {
	return &cli.App{
		EnableBashCompletion: true,
		Usage:                "Versity S3 Gateway",
		Description: `The Versity S3 Gateway is an S3 protocol translator that allows an S3 client
to access the supported backend storage as if it was a native S3 service.
VersityGW is an open-source project licensed under the Apache 2.0 License. The
source code is hosted on GitHub at https://github.com/versity/versitygw, and
documentation can be found in the GitHub wiki.`,
		Copyright: "Copyright (c) 2023-2026 Versity Software",
		Before: func(ctx *cli.Context) error {
			// Initialize global variables from context (including default values)
			ports = ctx.StringSlice("port")
			webuiPorts = ctx.StringSlice("webui")
			admPorts = ctx.StringSlice("admin-port")
			webuiGateways = ctx.StringSlice("webui-gateways")
			webuiAdminGateways = ctx.StringSlice("webui-admin-gateways")
			webuiPathPrefix = ctx.String("webui-path-prefix")
			websitePorts = ctx.StringSlice("website")

			// Resolve relative UNIX socket paths to absolute before any backend
			// (e.g. posix) can change the working directory via os.Chdir.
			var err error
			if ports, err = utils.AbsSocketPaths(ports); err != nil {
				return err
			}
			if admPorts, err = utils.AbsSocketPaths(admPorts); err != nil {
				return err
			}
			if webuiPorts, err = utils.AbsSocketPaths(webuiPorts); err != nil {
				return err
			}
			if websitePorts, err = utils.AbsSocketPaths(websitePorts); err != nil {
				return err
			}
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
			Usage:   "gateway listen address: <ip>:<port>, :<port>, /path/to/socket for file-backed UNIX sockets, or @name for Linux abstract namespace sockets (can be specified multiple times for listening on multiple addresses)",
			EnvVars: []string{"VGW_PORT"},
			Value:   cli.NewStringSlice(":7070"),
			Aliases: []string{"p"},
		},
		&cli.StringSliceFlag{
			Name:    "webui",
			Usage:   "enable WebUI server on the specified listen address (e.g. ':7071', '127.0.0.1:7071', 'localhost:7071', '/run/vgw/webui.sock'; supports the same UNIX socket forms as --port; can be specified multiple times for listening on multiple addresses; disabled when omitted)",
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
			Name:        "webui-path-prefix",
			Usage:       "mount the WebUI under a path prefix (e.g. '/ui'); must be single segment path that starts with '/'",
			EnvVars:     []string{"VGW_WEBUI_PATH_PREFIX"},
			Destination: &webuiPathPrefix,
		},
		&cli.StringFlag{
			Name:        "webui-s3-prefix",
			Usage:       "mount the WebUI on the S3 port at the given path prefix (e.g. '/ui'); must start with '/', must not be '/', and must not end with '/'",
			EnvVars:     []string{"VGW_WEBUI_S3_PREFIX"},
			Destination: &webuiS3Prefix,
		},
		&cli.StringSliceFlag{
			Name:    "website",
			Usage:   "enable static website hosting endpoint on the specified listen address (e.g. ':8080'; same forms as --port; can be specified multiple times; requires --website-domain)",
			EnvVars: []string{"VGW_WEBSITE_PORT"},
		},
		&cli.StringFlag{
			Name:        "website-domain",
			Usage:       "base domain for website virtual-host routing (e.g. 'example.com'); host 'blog.example.com' serves bucket 'blog', host 'example.com' serves bucket 'example.com'; when omitted the full hostname is used as the bucket name (catch-all mode, buckets named as FQDNs)",
			EnvVars:     []string{"VGW_WEBSITE_DOMAIN"},
			Destination: &websiteDomain,
		},
		&cli.StringFlag{
			Name:        "website-cert",
			Usage:       "TLS cert file for website endpoint (defaults to --cert value when website is enabled)",
			EnvVars:     []string{"VGW_WEBSITE_CERT"},
			Destination: &websiteCertFile,
		},
		&cli.StringFlag{
			Name:        "website-key",
			Usage:       "TLS key file for website endpoint (defaults to --key value when website is enabled)",
			EnvVars:     []string{"VGW_WEBSITE_KEY"},
			Destination: &websiteKeyFile,
		},
		&cli.BoolFlag{
			Name:        "website-no-tls",
			Usage:       "disable TLS for website endpoint even if TLS is configured for the gateway",
			EnvVars:     []string{"VGW_WEBSITE_NO_TLS"},
			Destination: &websiteNoTLS,
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
			Usage:   "gateway admin server listen address: <ip>:<port>, :<port>, /path/to/socket for file-backed UNIX sockets, or @name for Linux abstract namespace sockets (can be specified multiple times for listening on multiple addresses)",
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
			Usage:       "enable keep-alive connections",
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
		&cli.BoolFlag{
			Name:        "disable-acl",
			Usage:       "disables gateway ACLs, by ignoring all ACL headers",
			EnvVars:     []string{"VGW_DISABLE_ACL"},
			Destination: &disableACLs,
			Aliases:     []string{"noacl"},
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
		&cli.IntFlag{
			Name:        "mp-max-parts",
			Usage:       "maximum number of parts allowed in a multipart upload",
			EnvVars:     []string{"VGW_MP_MAX_PARTS"},
			Value:       10000,
			Destination: &mpMaxParts,
		},
		&cli.Int64Flag{
			Name:        "copy-object-threshold",
			Usage:       "maximum allowed source object size in bytes for CopyObject; objects larger than this are rejected",
			EnvVars:     []string{"VGW_COPY_OBJECT_THRESHOLD"},
			Value:       5 * 1024 * 1024 * 1024,
			Destination: &copyObjectThreshold,
		},
		&cli.StringFlag{
			Name:        "socket-perm",
			Usage:       "file permissions for file-backed UNIX domain sockets (octal, e.g. '0660'); ignored for TCP/IP and abstract namespace sockets",
			EnvVars:     []string{"VGW_SOCKET_PERM"},
			Destination: &socketPerm,
		},
	}
}

func runGateway(ctx context.Context, be backend.Backend) error {
	if pprof != "" {
		// Listen on the specified address for pprof debug endpoints.
		// Point a browser to http://<host:port>/debug/pprof/
		go func() {
			log.Printf("pprof: listening on %s", pprof)
			if err := http.ListenAndServe(pprof, nil); err != nil {
				log.Printf("pprof: server exited: %v", err)
			}
		}()
	}

	if copyObjectThreshold < 1 {
		return fmt.Errorf("copy-object-threshold must be positive")
	}

	return embedgw.RunVersityGW(ctx, be, &embedgw.Config{
		RootUserAccess:              rootUserAccess,
		RootUserSecret:              rootUserSecret,
		Region:                      region,
		Ports:                       ports,
		AdminPorts:                  admPorts,
		MaxConnections:              maxConnections,
		MaxRequests:                 maxRequests,
		AdminMaxConnections:         adminMaxConnections,
		AdminMaxRequests:            adminMaxRequests,
		MultipartMaxParts:           mpMaxParts,
		CertFile:                    certFile,
		KeyFile:                     keyFile,
		AdminCertFile:               admCertFile,
		AdminKeyFile:                admKeyFile,
		CORSAllowOrigin:             corsAllowOrigin,
		Debug:                       debug,
		IAMDebug:                    iamDebug,
		Quiet:                       quiet,
		Readonly:                    readonly,
		KeepAlive:                   keepAlive,
		DisableACLs:                 disableACLs,
		DisableStrictBucketNames:    disableStrictBucketNames,
		VirtualDomain:               virtualDomain,
		HealthPath:                  healthPath,
		SocketPerm:                  socketPerm,
		IAMDir:                      iamDir,
		LDAPServerURL:               ldapURL,
		LDAPBindDN:                  ldapBindDN,
		LDAPPassword:                ldapPassword,
		LDAPQueryBase:               ldapQueryBase,
		LDAPObjClasses:              ldapObjClasses,
		LDAPAccessAttr:              ldapAccessAtr,
		LDAPSecretAttr:              ldapSecAtr,
		LDAPRoleAttr:                ldapRoleAtr,
		LDAPUserIDAttr:              ldapUserIdAtr,
		LDAPGroupIDAttr:             ldapGroupIdAtr,
		LDAPProjectIDAttr:           ldapProjectIdAtr,
		LDAPTLSSkipVerify:           ldapTLSSkipVerify,
		VaultEndpointURL:            vaultEndpointURL,
		VaultNamespace:              vaultNamespace,
		VaultSecretStoragePath:      vaultSecretStoragePath,
		VaultSecretStorageNamespace: vaultSecretStorageNamespace,
		VaultAuthMethod:             vaultAuthMethod,
		VaultAuthNamespace:          vaultAuthNamespace,
		VaultMountPath:              vaultMountPath,
		VaultRootToken:              vaultRootToken,
		VaultRoleID:                 vaultRoleId,
		VaultRoleSecret:             vaultRoleSecret,
		VaultServerCert:             vaultServerCert,
		VaultClientCert:             vaultClientCert,
		VaultClientCertKey:          vaultClientCertKey,
		S3IAMAccess:                 s3IamAccess,
		S3IAMSecret:                 s3IamSecret,
		S3IAMRegion:                 s3IamRegion,
		S3IAMBucket:                 s3IamBucket,
		S3IAMEndpoint:               s3IamEndpoint,
		S3IAMDisableSSLVerify:       s3IamSslNoVerify,
		IAMCacheDisable:             iamCacheDisable,
		IAMCacheTTL:                 iamCacheTTL,
		IAMCachePrune:               iamCachePrune,
		IpaHost:                     ipaHost,
		IpaVaultName:                ipaVaultName,
		IpaUser:                     ipaUser,
		IpaPassword:                 ipaPassword,
		IpaInsecure:                 ipaInsecure,
		AccessLog:                   accessLog,
		LogWebhookURL:               logWebhookURL,
		AdminLogFile:                adminLogFile,
		MetricsService:              metricsService,
		StatsdServers:               statsdServers,
		DogstatsServers:             dogstatsServers,
		KafkaURL:                    kafkaURL,
		KafkaTopic:                  kafkaTopic,
		KafkaKey:                    kafkaKey,
		NatsURL:                     natsURL,
		NatsTopic:                   natsTopic,
		RabbitmqURL:                 rabbitmqURL,
		RabbitmqExchange:            rabbitmqExchange,
		RabbitmqRoutingKey:          rabbitmqRoutingKey,
		EventWebhookURL:             eventWebhookURL,
		EventConfigFilePath:         eventConfigFilePath,
		WebuiPorts:                  webuiPorts,
		WebuiCertFile:               webuiCertFile,
		WebuiKeyFile:                webuiKeyFile,
		WebuiNoTLS:                  webuiNoTLS,
		WebuiGateways:               webuiGateways,
		WebuiAdminGateways:          webuiAdminGateways,
		WebuiPathPrefix:             webuiPathPrefix,
		WebuiS3Prefix:               webuiS3Prefix,
		WebsitePorts:                websitePorts,
		WebsiteDomain:               websiteDomain,
		WebsiteCertFile:             websiteCertFile,
		WebsiteKeyFile:              websiteKeyFile,
		WebsiteNoTLS:                websiteNoTLS,
		SigHup:                      sigHup,
		Version:                     Version,
		Build:                       Build,
		BuildTime:                   BuildTime,
	})
}
