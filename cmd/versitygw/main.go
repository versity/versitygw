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
	"crypto/tls"
	"fmt"
	"log"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/urfave/cli/v2"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/backend/auth"
	"github.com/versity/versitygw/s3api"
	"github.com/versity/versitygw/s3api/middlewares"
)

var (
	port              string
	adminAccess       string
	adminSecret       string
	region            string
	certFile, keyFile string
	debug             bool
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
	app := initApp()

	app.Commands = []*cli.Command{
		posixCommand(),
	}

	if err := app.Run(os.Args); err != nil {
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
			Usage:       "admin access account",
			Destination: &adminAccess,
			EnvVars:     []string{"ADMIN_ACCESS_KEY_ID", "ADMIN_ACCESS_KEY"},
		},
		&cli.StringFlag{
			Name:        "secret",
			Usage:       "admin secret access key",
			Destination: &adminSecret,
			EnvVars:     []string{"ADMIN_SECRET_ACCESS_KEY", "ADMIN_SECRET_KEY"},
		},
		&cli.StringFlag{
			Name:        "region",
			Usage:       "s3 region string",
			Value:       "us-east-1",
			Destination: &region,
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
		&cli.BoolFlag{
			Name:        "debug",
			Usage:       "enable debug output",
			Destination: &debug,
		},
	}
}

func runGateway(be backend.Backend) error {
	app := fiber.New(fiber.Config{
		AppName:      "versitygw",
		ServerHeader: "VERSITYGW",
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

	srv, err := s3api.New(app, be, port,
		middlewares.AdminConfig{
			AdminAccess: adminAccess,
			AdminSecret: adminSecret,
			Region:      region,
		}, auth.IAMServiceUnsupported{}, opts...)
	if err != nil {
		return fmt.Errorf("init gateway: %v", err)
	}

	return srv.Serve()
}
