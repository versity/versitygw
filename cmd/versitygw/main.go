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
	"net/http"
	_ "net/http/pprof"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/urfave/cli/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/metrics"
	"github.com/versity/versitygw/s3api"
	"github.com/versity/versitygw/s3api/middlewares"
	"github.com/versity/versitygw/s3event"
	"github.com/versity/versitygw/s3log"
)

var (
	port, admPort                          string
	rootUserAccess                         string
	rootUserSecret                         string
	region                                 string
	admCertFile, admKeyFile                string
	certFile, keyFile                      string
	kafkaURL, kafkaTopic, kafkaKey         string
	natsURL, natsTopic                     string
	eventWebhookURL                        string
	eventConfigFilePath                    string
	logWebhookURL                          string
	accessLog                              string
	healthPath                             string
	debug                                  bool
	pprof                                  string
	quiet                                  bool
	readonly                               bool
	iamDir                                 string
	ldapURL, ldapBindDN, ldapPassword      string
	ldapQueryBase, ldapObjClasses          string
	ldapAccessAtr, ldapSecAtr, ldapRoleAtr string
	s3IamAccess, s3IamSecret               string
	s3IamRegion, s3IamBucket               string
	s3IamEndpoint                          string
	s3IamSslNoVerify, s3IamDebug           bool
	iamCacheDisable                        bool
	iamCacheTTL                            int
	iamCachePrune                          int
	statsdServers                          string
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
		Name:  "versitygw",
		Usage: "Start S3 gateway service with specified backend storage.",
		Description: `The S3 gateway is an S3 protocol translator that allows an S3 client
to access the supported backend storage as if it was a native S3 service.`,
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
			Name:        "quiet",
			Usage:       "silence stdout request logging output",
			EnvVars:     []string{"VGW_QUIET"},
			Destination: &quiet,
			Aliases:     []string{"q"},
		},
		&cli.StringFlag{
			Name:        "access-log",
			Usage:       "enable server access logging to specified file",
			EnvVars:     []string{"LOGFILE", "VGW_ACCESS_LOG"},
			Destination: &accessLog,
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
			Name:        "metrics-statsd-servers",
			Usage:       "StatsD server urls comma separated. e.g. 'statsd.example1.com:8125, statsd.example2.com:8125'",
			EnvVars:     []string{"VGW_METRICS_STATSD_SERVERS"},
			Aliases:     []string{"mss"},
			Destination: &statsdServers,
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
		AppName:           "versitygw",
		ServerHeader:      "VERSITYGW",
		StreamRequestBody: true,
		DisableKeepalive:  true,
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
	if debug {
		opts = append(opts, s3api.WithDebug())
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

	admApp := fiber.New(fiber.Config{
		AppName:      "versitygw",
		ServerHeader: "VERSITYGW",
	})

	var admOpts []s3api.AdminOpt

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
		admOpts = append(admOpts, s3api.WithAdminSrvTLS(cert))
	}

	iam, err := auth.New(&auth.Opts{
		Dir:                iamDir,
		LDAPServerURL:      ldapURL,
		LDAPBindDN:         ldapBindDN,
		LDAPPassword:       ldapPassword,
		LDAPQueryBase:      ldapQueryBase,
		LDAPObjClasses:     ldapObjClasses,
		LDAPAccessAtr:      ldapAccessAtr,
		LDAPSecretAtr:      ldapSecAtr,
		LDAPRoleAtr:        ldapRoleAtr,
		S3Access:           s3IamAccess,
		S3Secret:           s3IamSecret,
		S3Region:           s3IamRegion,
		S3Bucket:           s3IamBucket,
		S3Endpoint:         s3IamEndpoint,
		S3DisableSSlVerfiy: s3IamSslNoVerify,
		S3Debug:            s3IamDebug,
		CacheDisable:       iamCacheDisable,
		CacheTTL:           iamCacheTTL,
		CachePrune:         iamCachePrune,
	})
	if err != nil {
		return fmt.Errorf("setup iam: %w", err)
	}

	logger, err := s3log.InitLogger(&s3log.LogConfig{
		LogFile:    accessLog,
		WebhookURL: logWebhookURL,
	})
	if err != nil {
		return fmt.Errorf("setup logger: %w", err)
	}

	metricsManager, err := metrics.NewManager(ctx, metrics.Config{
		StatsdServers: statsdServers,
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
		WebhookURL:           eventWebhookURL,
		FilterConfigFilePath: eventConfigFilePath,
	})
	if err != nil {
		return fmt.Errorf("init bucket event notifications: %w", err)
	}

	srv, err := s3api.New(app, be, middlewares.RootUserConfig{
		Access: rootUserAccess,
		Secret: rootUserSecret,
	}, port, region, iam, logger, evSender, metricsManager, opts...)
	if err != nil {
		return fmt.Errorf("init gateway: %v", err)
	}

	admSrv := s3api.NewAdminServer(admApp, be, middlewares.RootUserConfig{Access: rootUserAccess, Secret: rootUserSecret}, admPort, region, iam, admOpts...)

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
			if logger != nil {
				err = logger.HangUp()
				if err != nil {
					err = fmt.Errorf("HUP logger: %w", err)
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

	if logger != nil {
		err := logger.Shutdown()
		if err != nil {
			if saveErr == nil {
				saveErr = err
			}
			fmt.Fprintf(os.Stderr, "shutdown logger: %v\n", err)
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
