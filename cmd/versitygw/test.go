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
			Name:  "make-bucket",
			Usage: "Test bucket creation.",
			Description: `Calls s3 gateway create-bucket action to create a new bucket,
		then calls delete-bucket action to delete the bucket.`,
			Action: getAction(integration.TestMakeBucket),
		},
		{
			Name:  "put-get-object",
			Usage: "Test put & get object.",
			Description: `Creates a bucket with s3 gateway action, puts an object in it,
			gets the object from the bucket, deletes both the object and bucket.`,
			Action: getAction(integration.TestPutGetObject),
		},
		{
			Name:  "put-get-mp-object",
			Usage: "Test put & get multipart object.",
			Description: `Creates a bucket with s3 gateway action, puts an object in it with multipart upload,
			gets the object from the bucket, deletes both the object and bucket.`,
			Action: getAction(integration.TestPutGetMPObject),
		},
		{
			Name:  "put-dir-object",
			Usage: "Test put directory object.",
			Description: `Creates a bucket with s3 gateway action, puts a directory object in it,
			lists the bucket's objects, deletes both the objects and bucket.`,
			Action: getAction(integration.TestPutDirObject),
		},
		{
			Name:  "list-objects",
			Usage: "Test list-objects action.",
			Description: `Creates a bucket with s3 gateway action, puts 2 directory objects in it,
			lists the bucket's objects, deletes both the objects and bucket.`,
			Action: getAction(integration.TestListObject),
		},
		{
			Name:  "abort-mp",
			Usage: "Tests abort-multipart-upload action.",
			Description: `Creates a bucket with s3 gateway action, creates a multipart upload,
			lists the multipart upload, aborts the multipart upload, lists the multipart upload again,
			deletes both the objects and bucket.`,
			Action: getAction(integration.TestListAbortMultiPartObject),
		},
		{
			Name:  "list-parts",
			Usage: "Tests list-parts action.",
			Description: `Creates a bucket with s3 gateway action, creates a multipart upload,
			lists the upload parts, deletes both the objects and bucket.`,
			Action: getAction(integration.TestListMultiParts),
		},
		{
			Name:  "incorrect-mp",
			Usage: "Tests incorrect multipart case.",
			Description: `Creates a bucket with s3 gateway action, creates a multipart upload,
			uploads different parts, completes the multipart upload with incorrect part numbers,
			calls the head-object action, compares the content length, removes both the object and bucket`,
			Action: getAction(integration.TestIncorrectMultiParts),
		},
		{
			Name:  "incomplete-mp",
			Usage: "Tests incomplete multi parts.",
			Description: `Creates a bucket with s3 gateway action, creates a multipart upload,
			upload a part, lists the parts, checks if the uploaded part is in the list, 
			removes both the object and the bucket`,
			Action: getAction(integration.TestIncompleteMultiParts),
		},
		{
			Name:  "incomplete-put-object",
			Usage: "Tests incomplete put objects case.",
			Description: `Creates a bucket with s3 gateway action, puts an object in it,
			gets the object with head-object action, expects the object to be got, 
			removes both the object and bucket`,
			Action: getAction(integration.TestIncompletePutObject),
		},
		{
			Name:  "get-range",
			Usage: "Tests get object by range.",
			Description: `Creates a bucket with s3 gateway action, puts an object in it,
			gets the object by specifying the object range, compares the range with the original one,
			removes both the object and the bucket`,
			Action: getAction(integration.TestRangeGet),
		},
		{
			Name:  "invalid-mp",
			Usage: "Tests invalid multi part case.",
			Description: `Creates a bucket with s3 gateway action, creates a multi part upload,
			uploads an invalid part, gets the object with head-object action, expects to get error,
			removes both the object and bucket`,
			Action: getAction(integration.TestInvalidMultiParts),
		},
		{
			Name:  "object-tag-actions",
			Usage: "Tests get/put/delete object tag actions.",
			Description: `Creates a bucket with s3 gateway action, puts an object in it,
			puts some tags for the object, gets the tags, compares the results, removes the tags,
			gets the tags again, checks it to be empty, then removes both the object and bucket`,
			Action: getAction(integration.TestPutGetRemoveTags),
		},
		{
			Name:  "bucket-acl-actions",
			Usage: "Tests put/get bucket actions.",
			Description: `Creates a bucket with s3 gateway action, puts some bucket acls
			gets the acl, verifies it, then removes the bucket`,
			Action: getAction(integration.TestAclActions),
		},
		{
			Name:        "full-flow",
			Usage:       "Tests the full flow of gateway.",
			Description: `Runs all the available tests to test the full flow of the gateway.`,
			Action:      getAction(integration.TestFullFlow),
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

				return integration.TestPerformance(s3conf, upload, download, files, objSize, dstBucket, prefix)
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
