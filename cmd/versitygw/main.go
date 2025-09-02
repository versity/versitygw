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
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/urfave/cli/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/debuglogger"
	"github.com/versity/versitygw/metrics"
	"github.com/versity/versitygw/s3api"
	"github.com/versity/versitygw/s3api/middlewares"
	"github.com/versity/versitygw/s3event"
	"github.com/versity/versitygw/s3log"
)

var (
	port, admPort                            string
	rootUserAccess                           string
	rootUserSecret                           string
	region                                   string
	admCertFile, admKeyFile                  string
	certFile, keyFile                        string
	kafkaURL, kafkaTopic, kafkaKey           string
	natsURL, natsTopic                       string
	rabbitmqURL, rabbitmqExchange            string
	rabbitmqRoutingKey                       string
	eventWebhookURL                          string
	eventConfigFilePath                      string
	logWebhookURL, accessLog                 string
	adminLogFile                             string
	healthPath                               string
	virtualDomain                            string
	debug                                    bool
	keepAlive                                bool
	pprof                                    string
	quiet                                    bool
	readonly                                 bool
	iamDir                                   string
	ldapURL, ldapBindDN, ldapPassword        string
	ldapQueryBase, ldapObjClasses            string
	ldapAccessAtr, ldapSecAtr, ldapRoleAtr   string
	ldapUserIdAtr, ldapGroupIdAtr            string
	ldapDebug                                bool
	vaultEndpointURL, vaultSecretStoragePath string
	vaultAuthMethod, vaultMountPath          string
	vaultRootToken, vaultRoleId              string
	vaultRoleSecret, vaultServerCert         string
	vaultClientCert, vaultClientCertKey      string
	s3IamAccess, s3IamSecret                 string
	s3IamRegion, s3IamBucket                 string
	s3IamEndpoint                            string
	s3IamSslNoVerify, s3IamDebug             bool
	iamCacheDisable                          bool
	iamCacheTTL                              int
	iamCachePrune                            int
	metricsService                           string
	statsdServers                            string
	dogstatsServers                          string
	ipaHost, ipaVaultName                    string
	ipaUser, ipaPassword                     string
	ipaInsecure, ipaDebug                    bool
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
		&cli.StringFlag{
			Name:        "port",
			Usage:       "gateway listen address <ip>:<port> or :<port>",
			EnvVars:     []string{"VGW_PORT"},
			Value:       ":7070",
			Destination: &port,
			Aliases:     []string{"p"},
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
		&cli.StringFlag{
			Name:        "admin-port",
			Usage:       "gateway admin server listen address <ip>:<port> or :<port>",
			EnvVars:     []string{"VGW_ADMIN_PORT"},
			Destination: &admPort,
			Aliases:     []string{"ap"},
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
		&cli.BoolFlag{
			Name:        "iam-ldap-debug",
			Usage:       "ldap server debug output",
			EnvVars:     []string{"VGW_IAM_LDAP_DEBUG"},
			Destination: &ldapDebug,
		},
		&cli.StringFlag{
			Name:        "iam-vault-endpoint-url",
			Usage:       "vault server url",
			EnvVars:     []string{"VGW_IAM_VAULT_ENDPOINT_URL"},
			Destination: &vaultEndpointURL,
		},
		&cli.StringFlag{
			Name:        "iam-vault-secret-storage-path",
			Usage:       "vault server secret storage path",
			EnvVars:     []string{"VGW_IAM_VAULT_SECRET_STORAGE_PATH"},
			Destination: &vaultSecretStoragePath,
		},
		&cli.StringFlag{
			Name:        "iam-vault-auth-method",
			Usage:       "vault server auth method",
			EnvVars:     []string{"VGW_IAM_VAULT_AUTH_METHOD"},
			Destination: &vaultAuthMethod,
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
			Name:        "s3-iam-debug",
			Usage:       "s3 IAM debug output",
			EnvVars:     []string{"VGW_S3_IAM_DEBUG"},
			Destination: &s3IamDebug,
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
		&cli.BoolFlag{
			Name:        "ipa-debug",
			Usage:       "FreeIPA IAM debug output",
			EnvVars:     []string{"VGW_IPA_DEBUG"},
			Destination: &ipaDebug,
		},
	}
}

func runGateway(ctx context.Context, be backend.Backend) error {
	if rootUserAccess == "" || rootUserSecret == "" {
		return fmt.Errorf("root user access and secret key must be provided")
	}

	if pprof != "" {
		// listen on specified port for pprof debug
		// point browser to http://<ip:port>/debug/pprof/
		go func() {
			log.Fatal(http.ListenAndServe(pprof, nil))
		}()
	}

	app := fiber.New(fiber.Config{
		AppName:               "versitygw",
		ServerHeader:          "VERSITYGW",
		StreamRequestBody:     true,
		DisableKeepalive:      !keepAlive,
		Network:               fiber.NetworkTCP,
		DisableStartupMessage: true,
	})

	var opts []s3api.Option

	if certFile != "" || keyFile != "" {
		if certFile == "" {
			return fmt.Errorf("TLS key specified without cert file")
		}
		if keyFile == "" {
			return fmt.Errorf("TLS cert specified without key file")
		}

		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return fmt.Errorf("tls: load certs: %v", err)
		}
		opts = append(opts, s3api.WithTLS(cert))
	}
	if admPort == "" {
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

	if debug {
		debuglogger.SetDebugEnabled()
	}

	iam, err := auth.New(&auth.Opts{
		RootAccount: auth.Account{
			Access: rootUserAccess,
			Secret: rootUserSecret,
			Role:   auth.RoleAdmin,
		},
		Dir:                    iamDir,
		LDAPServerURL:          ldapURL,
		LDAPBindDN:             ldapBindDN,
		LDAPPassword:           ldapPassword,
		LDAPQueryBase:          ldapQueryBase,
		LDAPObjClasses:         ldapObjClasses,
		LDAPAccessAtr:          ldapAccessAtr,
		LDAPSecretAtr:          ldapSecAtr,
		LDAPRoleAtr:            ldapRoleAtr,
		LDAPUserIdAtr:          ldapUserIdAtr,
		LDAPGroupIdAtr:         ldapGroupIdAtr,
		LDAPDebug:              ldapDebug,
		VaultEndpointURL:       vaultEndpointURL,
		VaultSecretStoragePath: vaultSecretStoragePath,
		VaultAuthMethod:        vaultAuthMethod,
		VaultMountPath:         vaultMountPath,
		VaultRootToken:         vaultRootToken,
		VaultRoleId:            vaultRoleId,
		VaultRoleSecret:        vaultRoleSecret,
		VaultServerCert:        vaultServerCert,
		VaultClientCert:        vaultClientCert,
		VaultClientCertKey:     vaultClientCertKey,
		S3Access:               s3IamAccess,
		S3Secret:               s3IamSecret,
		S3Region:               s3IamRegion,
		S3Bucket:               s3IamBucket,
		S3Endpoint:             s3IamEndpoint,
		S3DisableSSlVerfiy:     s3IamSslNoVerify,
		S3Debug:                s3IamDebug,
		CacheDisable:           iamCacheDisable,
		CacheTTL:               iamCacheTTL,
		CachePrune:             iamCachePrune,
		IpaHost:                ipaHost,
		IpaVaultName:           ipaVaultName,
		IpaUser:                ipaUser,
		IpaPassword:            ipaPassword,
		IpaInsecure:            ipaInsecure,
		IpaDebug:               ipaDebug,
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

	srv, err := s3api.New(app, be, middlewares.RootUserConfig{
		Access: rootUserAccess,
		Secret: rootUserSecret,
	}, port, region, iam, loggers.S3Logger, loggers.AdminLogger, evSender, metricsManager, opts...)
	if err != nil {
		return fmt.Errorf("init gateway: %v", err)
	}

	var admSrv *s3api.S3AdminServer

	if admPort != "" {
		admApp := fiber.New(fiber.Config{
			AppName:               "versitygw",
			ServerHeader:          "VERSITYGW",
			Network:               fiber.NetworkTCP,
			DisableStartupMessage: true,
		})

		var opts []s3api.AdminOpt

		if admCertFile != "" || admKeyFile != "" {
			if admCertFile == "" {
				return fmt.Errorf("TLS key specified without cert file")
			}
			if admKeyFile == "" {
				return fmt.Errorf("TLS cert specified without key file")
			}

			cert, err := tls.LoadX509KeyPair(admCertFile, admKeyFile)
			if err != nil {
				return fmt.Errorf("tls: load certs: %v", err)
			}
			opts = append(opts, s3api.WithAdminSrvTLS(cert))
		}
		if quiet {
			opts = append(opts, s3api.WithAdminQuiet())
		}
		if debug {
			opts = append(opts, s3api.WithAdminDebug())
		}

		admSrv = s3api.NewAdminServer(admApp, be, middlewares.RootUserConfig{Access: rootUserAccess, Secret: rootUserSecret}, admPort, region, iam, loggers.AdminLogger, opts...)
	}

	if !quiet {
		printBanner(port, admPort, certFile != "", admCertFile != "")
	}

	c := make(chan error, 2)
	go func() { c <- srv.Serve() }()
	if admPort != "" {
		go func() { c <- admSrv.Serve() }()
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
		}
	}
	saveErr := err

	be.Shutdown()

	err = iam.Shutdown()
	if err != nil {
		if saveErr == nil {
			saveErr = err
		}
		fmt.Fprintf(os.Stderr, "shutdown iam: %v\n", err)
	}

	if loggers.S3Logger != nil {
		err := loggers.S3Logger.Shutdown()
		if err != nil {
			if saveErr == nil {
				saveErr = err
			}
			fmt.Fprintf(os.Stderr, "shutdown s3 logger: %v\n", err)
		}
	}
	if loggers.AdminLogger != nil {
		err := loggers.AdminLogger.Shutdown()
		if err != nil {
			if saveErr == nil {
				saveErr = err
			}
			fmt.Fprintf(os.Stderr, "shutdown admin logger: %v\n", err)
		}
	}

	if evSender != nil {
		err := evSender.Close()
		if err != nil {
			if saveErr == nil {
				saveErr = err
			}
			fmt.Fprintf(os.Stderr, "close event sender: %v\n", err)
		}
	}

	if metricsManager != nil {
		metricsManager.Close()
	}

	return saveErr
}

func printBanner(port, admPort string, ssl, admSsl bool) {
	interfaces, err := getMatchingIPs(port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to match local IP addresses: %v\n", err)
		return
	}

	var admInterfaces []string
	if admPort != "" {
		admInterfaces, err = getMatchingIPs(admPort)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to match admin port local IP addresses: %v\n", err)
			return
		}
	}

	title := "VersityGW"
	version := fmt.Sprintf("Version %v, Build %v", Version, Build)
	urls := []string{}

	hst, prt, err := net.SplitHostPort(port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse port: %v\n", err)
		return
	}

	for _, ip := range interfaces {
		url := fmt.Sprintf("http://%s:%s", ip, prt)
		if ssl {
			url = fmt.Sprintf("https://%s:%s", ip, prt)
		}
		urls = append(urls, url)
	}

	if hst == "" {
		hst = "0.0.0.0"
	}

	boundHost := fmt.Sprintf("(bound on host %s and port %s)", hst, prt)

	lines := []string{
		centerText(title),
		centerText(version),
		centerText(boundHost),
		centerText(""),
	}

	if len(admInterfaces) > 0 {
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

	if len(admInterfaces) > 0 {
		lines = append(lines,
			centerText(""),
			leftText("Admin service listening on:"),
		)

		_, prt, err := net.SplitHostPort(admPort)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse port: %v\n", err)
			return
		}

		for _, ip := range admInterfaces {
			url := fmt.Sprintf("http://%s:%s", ip, prt)
			if admSsl {
				url = fmt.Sprintf("https://%s:%s", ip, prt)
			}
			lines = append(lines, leftText("  "+url))
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

// getMatchingIPs returns all IP addresses for local system interfaces that
// match the input address specification.
func getMatchingIPs(spec string) ([]string, error) {
	// Split the input spec into IP and port
	host, _, err := net.SplitHostPort(spec)
	if err != nil {
		return nil, fmt.Errorf("parse address/port: %v", err)
	}

	// Handle cases where IP is omitted (e.g., ":1234")
	if host == "" {
		host = "0.0.0.0"
	}

	ipaddr, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return nil, err
	}

	parsedInputIP := ipaddr.IP

	var result []string

	// Get all network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		// Get all addresses associated with the interface
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}

		for _, addr := range addrs {
			// Parse the address to get the IP part
			ipAddr, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				return nil, err
			}

			if ipAddr.IsLinkLocalUnicast() {
				continue
			}
			if ipAddr.IsInterfaceLocalMulticast() {
				continue
			}
			if ipAddr.IsLinkLocalMulticast() {
				continue
			}

			// Check if the IP matches the input specification
			if parsedInputIP.Equal(net.IPv4(0, 0, 0, 0)) || parsedInputIP.Equal(ipAddr) {
				result = append(result, ipAddr.String())
			}
		}
	}

	return result, nil
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
