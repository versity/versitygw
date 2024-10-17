package main

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/backend/posix"
	"github.com/versity/versitygw/tests/integration"
)

const (
	tdir = "tempdir"
)

var (
	wg sync.WaitGroup
)

func initEnv(dir string) {
	// both
	debug = true
	region = "us-east-1"

	// server
	rootUserAccess = "user"
	rootUserSecret = "pass"
	iamDir = dir
	port = "127.0.0.1:7070"

	// client
	awsID = "user"
	awsSecret = "pass"
	endpoint = "http://127.0.0.1:7070"
}

func initPosix(ctx context.Context) {
	path, err := os.Getwd()
	if err != nil {
		log.Fatalf("get current directory: %v", err)
	}

	tempdir := filepath.Join(path, tdir)
	initEnv(tempdir)

	err = os.RemoveAll(tempdir)
	if err != nil {
		log.Fatalf("remove temp directory: %v", err)
	}

	err = os.Mkdir(tempdir, 0755)
	if err != nil {
		log.Fatalf("make temp directory: %v", err)
	}

	be, err := posix.New(tempdir, meta.XattrMeta{}, posix.PosixOpts{
		NewDirPerm: 0755,
	})
	if err != nil {
		log.Fatalf("init posix: %v", err)
	}

	wg.Add(1)
	go func() {
		err = runGateway(ctx, be)
		if err != nil && err != context.Canceled {
			log.Fatalf("run gateway: %v", err)
		}

		err := os.RemoveAll(tempdir)
		if err != nil {
			log.Fatalf("remove temp directory: %v", err)
		}
		wg.Done()
	}()

	// wait for server to start
	time.Sleep(1 * time.Second)
}

func TestIntegration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	initPosix(ctx)

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

	// replace below with desired test
	err := integration.HeadBucket_non_existing_bucket(s)
	if err != nil {
		t.Error(err)
	}

	cancel()
	wg.Wait()
}
