package main

import (
	"fmt"

	"github.com/urfave/cli/v2"
	"github.com/versity/versitygw/integration"
)

var (
	awsID           string
	awsSecret       string
	endpoint        string
	prefix          string
	dstBucket       string
	partSize        int64
	objSize         int64
	concurrency     int
	files           int
	totalReqs       int
	upload          bool
	download        bool
	pathStyle       bool
	checksumDisable bool
)

func testCommand() *cli.Command {
	return &cli.Command{
		Name:  "test",
		Usage: "Client side testing command for the gateway",
		Description: `The testing CLI is used to test group of versitygw actions.
		It also includes some performance and stress testing`,
		Subcommands: initTestCommands(),
		Flags:       initTestFlags(),
	}
}

func initTestFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "access",
			Usage:       "aws user access key",
			EnvVars:     []string{"AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY"},
			Aliases:     []string{"a"},
			Destination: &awsID,
		},
		&cli.StringFlag{
			Name:        "secret",
			Usage:       "aws user secret access key",
			EnvVars:     []string{"AWS_SECRET_ACCESS_KEY", "AWS_SECRET_KEY"},
			Aliases:     []string{"s"},
			Destination: &awsSecret,
		},
		&cli.StringFlag{
			Name:        "endpoint",
			Usage:       "s3 server endpoint",
			Destination: &endpoint,
			Aliases:     []string{"e"},
		},
		&cli.BoolFlag{
			Name:        "debug",
			Usage:       "enable debug mode",
			Aliases:     []string{"d"},
			Destination: &debug,
		},
	}
}

func initTestCommands() []*cli.Command {
	return append([]*cli.Command{
		{
			Name:        "full-flow",
			Usage:       "Tests the full flow of gateway.",
			Description: `Runs all the available tests to test the full flow of the gateway.`,
			Action:      getAction(integration.TestFullFlow),
		},
		{
			Name:   "posix",
			Usage:  "Tests posix specific features",
			Action: getAction(integration.TestPosix),
		},
		{
			Name:  "bench",
			Usage: "Runs download/upload performance test on the gateway",
			Description: `Uploads/downloads some number(specified by flags) of files with some capacity(bytes).
			Logs the results to the console`,
			Flags: []cli.Flag{
				&cli.IntFlag{
					Name:        "files",
					Usage:       "Number of objects to read/write",
					Value:       1,
					Destination: &files,
				},
				&cli.Int64Flag{
					Name:        "objsize",
					Usage:       "Uploading object size",
					Value:       0,
					Destination: &objSize,
				},
				&cli.StringFlag{
					Name:        "prefix",
					Usage:       "Object name prefix",
					Destination: &prefix,
				},
				&cli.BoolFlag{
					Name:        "upload",
					Usage:       "Upload data to the gateway",
					Value:       false,
					Destination: &upload,
				},
				&cli.BoolFlag{
					Name:        "download",
					Usage:       "Download data to the gateway",
					Value:       false,
					Destination: &download,
				},
				&cli.StringFlag{
					Name:        "bucket",
					Usage:       "Destination bucket name to read/write data",
					Destination: &dstBucket,
				},
				&cli.Int64Flag{
					Name:        "partSize",
					Usage:       "Upload/download size per thread",
					Value:       64 * 1024 * 1024,
					Destination: &partSize,
				},
				&cli.IntFlag{
					Name:        "concurrency",
					Usage:       "Upload/download threads per object",
					Value:       1,
					Destination: &concurrency,
				},
				&cli.BoolFlag{
					Name:        "pathStyle",
					Usage:       "Use Pathstyle bucket addressing",
					Value:       false,
					Destination: &pathStyle,
				},
				&cli.BoolFlag{
					Name:        "checksumDis",
					Usage:       "Disable server checksum",
					Value:       false,
					Destination: &checksumDisable,
				},
			},
			Action: func(ctx *cli.Context) error {
				if upload && download {
					return fmt.Errorf("must only specify one of upload or download")
				}
				if !upload && !download {
					return fmt.Errorf("must specify one of upload or download")
				}

				if dstBucket == "" {
					return fmt.Errorf("must specify bucket")
				}

				opts := []integration.Option{
					integration.WithAccess(awsID),
					integration.WithSecret(awsSecret),
					integration.WithRegion(region),
					integration.WithEndpoint(endpoint),
					integration.WithConcurrency(concurrency),
					integration.WithPartSize(partSize),
				}
				if debug {
					opts = append(opts, integration.WithDebug())
				}
				if pathStyle {
					opts = append(opts, integration.WithPathStyle())
				}
				if checksumDisable {
					opts = append(opts, integration.WithDisableChecksum())
				}

				s3conf := integration.NewS3Conf(opts...)

				if upload {
					return integration.TestUpload(s3conf, files, objSize, dstBucket, prefix)
				} else {
					return integration.TestDownload(s3conf, files, objSize, dstBucket, prefix)
				}
			},
		},
		{
			Name:        "throughput",
			Usage:       "Runs throughput performance test on the gateway",
			Description: `Calls HeadBucket action the number of times and concurrency level specified with flags by measuring gateway throughput.`,
			Flags: []cli.Flag{
				&cli.IntFlag{
					Name:        "reqs",
					Usage:       "Total number of requests to send.",
					Value:       1000,
					Destination: &totalReqs,
				},
				&cli.StringFlag{
					Name:        "bucket",
					Usage:       "Destination bucket name to make the requests",
					Destination: &dstBucket,
				},
				&cli.IntFlag{
					Name:        "concurrency",
					Usage:       "threads per request",
					Value:       1,
					Destination: &concurrency,
				},
				&cli.BoolFlag{
					Name:        "checksumDis",
					Usage:       "Disable server checksum",
					Value:       false,
					Destination: &checksumDisable,
				},
			},
			Action: func(ctx *cli.Context) error {
				if dstBucket == "" {
					return fmt.Errorf("must specify the destination bucket")
				}

				opts := []integration.Option{
					integration.WithAccess(awsID),
					integration.WithSecret(awsSecret),
					integration.WithRegion(region),
					integration.WithEndpoint(endpoint),
					integration.WithConcurrency(concurrency),
				}
				if debug {
					opts = append(opts, integration.WithDebug())
				}
				if checksumDisable {
					opts = append(opts, integration.WithDisableChecksum())
				}

				s3conf := integration.NewS3Conf(opts...)

				return integration.TestReqPerSec(s3conf, totalReqs, dstBucket)
			},
		},
	}, extractIntTests()...)
}

type testFunc func(*integration.S3Conf)

func getAction(tf testFunc) func(*cli.Context) error {
	return func(ctx *cli.Context) error {
		opts := []integration.Option{
			integration.WithAccess(awsID),
			integration.WithSecret(awsSecret),
			integration.WithRegion(region),
			integration.WithEndpoint(endpoint),
		}
		if debug {
			opts = append(opts, integration.WithDebug())
		}

		s := integration.NewS3Conf(opts...)
		tf(s)

		fmt.Println()
		fmt.Println("RAN:", integration.RunCount, "PASS:", integration.PassCount, "FAIL:", integration.FailCount)
		if integration.FailCount > 0 {
			return fmt.Errorf("test failed with %v errors", integration.FailCount)
		}
		return nil
	}
}

func extractIntTests() (commands []*cli.Command) {
	tests := integration.GetIntTests()
	for key, val := range tests {
		commands = append(commands, &cli.Command{
			Name:  key,
			Usage: fmt.Sprintf("Runs %v integration test", key),
			Action: func(ctx *cli.Context) error {
				opts := []integration.Option{
					integration.WithAccess(awsID),
					integration.WithSecret(awsSecret),
					integration.WithRegion(region),
					integration.WithEndpoint(endpoint),
				}
				if debug {
					opts = append(opts, integration.WithDebug())
				}

				s := integration.NewS3Conf(opts...)
				err := val(s)
				return err
			},
		})
	}
	return
}
