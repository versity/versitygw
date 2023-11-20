package main

import (
	"fmt"
	"math"
	"os"
	"text/tabwriter"

	"github.com/urfave/cli/v2"
	"github.com/versity/versitygw/integration"
)

var (
	awsID           string
	awsSecret       string
	endpoint        string
	prefix          string
	dstBucket       string
	proxyURL        string
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
	return []*cli.Command{
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
					Required:    true,
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
				&cli.StringFlag{
					Name:        "proxy-url",
					Usage:       "S3 proxy server url to compare",
					Destination: &proxyURL,
				},
			},
			Action: func(ctx *cli.Context) error {
				if upload && download {
					return fmt.Errorf("must only specify one of upload or download")
				}
				if !upload && !download {
					return fmt.Errorf("must specify one of upload or download")
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
					if proxyURL == "" {
						integration.TestUpload(s3conf, files, objSize, dstBucket, prefix)
						return nil
					} else {
						size, elapsed, err := integration.TestUpload(s3conf, files, objSize, dstBucket, prefix)
						opts = append(opts, integration.WithEndpoint(proxyURL))
						proxyS3Conf := integration.NewS3Conf(opts...)
						proxySize, proxyElapsed, proxyErr := integration.TestUpload(proxyS3Conf, files, objSize, dstBucket, prefix)
						if err != nil || proxyErr != nil {
							return nil
						}

						printProxyResultsTable([][4]string{
							{"    #    ", "Total Size", "Time Taken", "Speed(MB/S)"},
							{"---------", "----------", "----------", "-----------"},
							{"S3 Server", fmt.Sprint(size), fmt.Sprintf("%v", elapsed), fmt.Sprint(int(math.Ceil(float64(size)/elapsed.Seconds()) / 1048576))},
							{"S3 Proxy", fmt.Sprint(proxySize), fmt.Sprintf("%v", proxyElapsed), fmt.Sprint(int(math.Ceil(float64(proxySize)/proxyElapsed.Seconds()) / 1048576))},
						})
						return nil
					}
				} else {
					if proxyURL == "" {
						integration.TestDownload(s3conf, files, objSize, dstBucket, prefix)
						return nil
					} else {
						size, elapsed, err := integration.TestDownload(s3conf, files, objSize, dstBucket, prefix)
						opts = append(opts, integration.WithEndpoint(proxyURL))
						proxyS3Conf := integration.NewS3Conf(opts...)
						proxySize, proxyElapsed, proxyErr := integration.TestDownload(proxyS3Conf, files, objSize, dstBucket, prefix)
						if err != nil || proxyErr != nil {
							return nil
						}

						printProxyResultsTable([][4]string{
							{"    #    ", "Total Size", "Time Taken", "Speed(MB/S)"},
							{"---------", "----------", "----------", "-----------"},
							{"S3 server", fmt.Sprint(size), fmt.Sprintf("%v", elapsed), fmt.Sprint(int(math.Ceil(float64(size)/elapsed.Seconds()) / 1048576))},
							{"S3 proxy", fmt.Sprint(proxySize), fmt.Sprintf("%v", proxyElapsed), fmt.Sprint(int(math.Ceil(float64(proxySize)/proxyElapsed.Seconds()) / 1048576))},
						})
						return nil
					}
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
				&cli.StringFlag{
					Name:        "proxy-url",
					Usage:       "S3 proxy server url to compare",
					Destination: &proxyURL,
				},
			},
			Action: func(ctx *cli.Context) error {
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

				if proxyURL == "" {
					_, _, err := integration.TestReqPerSec(s3conf, totalReqs, dstBucket)
					return err
				} else {
					elapsed, rps, err := integration.TestReqPerSec(s3conf, totalReqs, dstBucket)
					opts = append(opts, integration.WithEndpoint(proxyURL))
					s3proxy := integration.NewS3Conf(opts...)
					proxyElapsed, proxyRPS, proxyErr := integration.TestReqPerSec(s3proxy, totalReqs, dstBucket)
					if err != nil || proxyErr != nil {
						return nil
					}

					printProxyResultsTable([][4]string{
						{"    #    ", "Total Requests", "Time Taken", "Requests Per Second(Req/Sec)"},
						{"---------", "--------------", "----------", "----------------------------"},
						{"S3 Server", fmt.Sprint(totalReqs), fmt.Sprintf("%v", elapsed), fmt.Sprint(rps)},
						{"S3 Proxy", fmt.Sprint(totalReqs), fmt.Sprintf("%v", proxyElapsed), fmt.Sprint(proxyRPS)},
					})

					return nil
				}
			},
		},
	}
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

func printProxyResultsTable(stats [][4]string) {
	w := new(tabwriter.Writer)
	w.Init(os.Stdout, minwidth, tabwidth, padding, padchar, flags)
	for _, elem := range stats {
		fmt.Fprintf(w, "%v\t%v\t%v\t%v\n", elem[0], elem[1], elem[2], elem[3])
	}
	fmt.Fprintln(w)
	w.Flush()
}
