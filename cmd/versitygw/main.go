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
	"os"
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/urfave/cli/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3api"
	"github.com/versity/versitygw/s3api/middlewares"
	"github.com/versity/versitygw/s3event"
	"github.com/versity/versitygw/s3log"
)

var (
	port, admPort                  string
	rootUserAccess                 string
	rootUserSecret                 string
	region                         string
	admCertFile, admKeyFile        string
	certFile, keyFile              string
	kafkaURL, kafkaTopic, kafkaKey string
	natsURL, natsTopic             string
	logWebhookURL                  string
	accessLog                      string
	debug                          bool
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
		adminCommand(),
		testCommand(),
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
			Value:       "us-east-1",
			Destination: &region,
			Aliases:     []string{"r"},
		},
		&cli.StringFlag{
			Name:        "cert",
			Usage:       "TLS cert file",
			Destination: &certFile,
		},
		&cli.StringFlag{
			Name:        "key",
			Usage:       "TLS key file",
			Destination: &keyFile,
		},
		&cli.StringFlag{
			Name:        "admin-port",
			Usage:       "gateway admin server listen address <ip>:<port> or :<port>",
			Destination: &admPort,
			Aliases:     []string{"ap"},
		},
		&cli.StringFlag{
			Name:        "admin-cert",
			Usage:       "TLS cert file for admin server",
			Destination: &admCertFile,
		},
		&cli.StringFlag{
			Name:        "admin-cert-key",
			Usage:       "TLS key file for admin server",
			Destination: &admKeyFile,
		},
		&cli.BoolFlag{
			Name:        "debug",
			Usage:       "enable debug output",
			Destination: &debug,
		},
		&cli.StringFlag{
			Name:        "access-log",
			Usage:       "enable server access logging to specified file",
			EnvVars:     []string{"LOGFILE"},
			Destination: &accessLog,
		},
		&cli.StringFlag{
			Name:        "log-webhook-url",
			Usage:       "webhook url to send the audit logs",
			EnvVars:     []string{"WEBHOOK"},
			Destination: &logWebhookURL,
		},
		&cli.StringFlag{
			Name:        "event-kafka-url",
			Usage:       "kafka server url to send the bucket notifications.",
			Destination: &kafkaURL,
			Aliases:     []string{"eku"},
		},
		&cli.StringFlag{
			Name:        "event-kafka-topic",
			Usage:       "kafka server pub-sub topic to send the bucket notifications to",
			Destination: &kafkaTopic,
			Aliases:     []string{"ekt"},
		},
		&cli.StringFlag{
			Name:        "event-kafka-key",
			Usage:       "kafka server put-sub topic key to send the bucket notifications to",
			Destination: &kafkaKey,
			Aliases:     []string{"ekk"},
		},
		&cli.StringFlag{
			Name:        "event-nats-url",
			Usage:       "nats server url to send the bucket notifications",
			Destination: &natsURL,
			Aliases:     []string{"enu"},
		},
		&cli.StringFlag{
			Name:        "event-nats-topic",
			Usage:       "nats server pub-sub topic to send the bucket notifications to",
			Destination: &natsTopic,
			Aliases:     []string{"ent"},
		},
	}
}

func runGateway(ctx *cli.Context, be backend.Backend, s auth.Storer) error {
	// int32 max for 32 bit arch
	blimit := int64(2*1024*1024*1024 - 1)
	if strconv.IntSize > 32 {
		// 5GB max for 64 bit arch
		blimit = int64(5 * 1024 * 1024 * 1024)
	}

	app := fiber.New(fiber.Config{
		AppName:      "versitygw",
		ServerHeader: "VERSITYGW",
		BodyLimit:    int(blimit),
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

	admApp := fiber.New(fiber.Config{
		AppName:      "versitygw",
		ServerHeader: "VERSITYGW",
		BodyLimit:    5 * 1024 * 1024 * 1024,
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

	err := s.InitIAM()
	if err != nil {
		return fmt.Errorf("init iam: %w", err)
	}

	iam, err := auth.NewInternal(s)
	if err != nil {
		return fmt.Errorf("setup internal iam service: %w", err)
	}

	logger, err := s3log.InitLogger(&s3log.LogConfig{
		LogFile:    accessLog,
		WebhookURL: logWebhookURL,
	})
	if err != nil {
		return fmt.Errorf("setup logger: %w", err)
	}

	evSender, err := s3event.InitEventSender(&s3event.EventConfig{
		KafkaURL:      kafkaURL,
		KafkaTopic:    kafkaTopic,
		KafkaTopicKey: kafkaKey,
		NatsURL:       natsURL,
		NatsTopic:     natsTopic,
	})
	if err != nil {
		return fmt.Errorf("unable to connect to the message broker: %w", err)
	}

	srv, err := s3api.New(app, be, middlewares.RootUserConfig{
		Access: rootUserAccess,
		Secret: rootUserSecret,
	}, port, region, iam, logger, evSender, opts...)
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
			err = ctx.Err()
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

	be.Shutdown()
	if logger != nil {
		lerr := logger.Shutdown()
		if lerr != nil {
			fmt.Fprintf(os.Stderr, "shutdown logger: %v\n", lerr)
		}
	}
	return err
}
