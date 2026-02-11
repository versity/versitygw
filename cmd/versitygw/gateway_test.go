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
	maxConnections = 250000
	maxRequests = 100000
	ports = []string{"127.0.0.1:7070"}

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
		NewDirPerm:  0755,
		Concurrency: 5000,
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

func TestValidatePortConflicts(t *testing.T) {
	tests := []struct {
		name        string
		ports       []string
		admPorts    []string
		webuiPorts  []string
		expectError bool
		description string
	}{
		{
			name:        "bare port conflict with bare port",
			ports:       []string{":7071"},
			admPorts:    []string{},
			webuiPorts:  []string{":7071"},
			expectError: true,
			description: "should fail: bare :7071 conflicts with bare :7071",
		},
		{
			name:        "bare port conflict with IP:port",
			ports:       []string{":7071"},
			admPorts:    []string{},
			webuiPorts:  []string{"127.0.0.1:7071"},
			expectError: true,
			description: "should fail: bare :7071 conflicts with 127.0.0.1:7071",
		},
		{
			name:        "IP:port conflict with bare port",
			ports:       []string{"127.0.0.1:7071"},
			admPorts:    []string{},
			webuiPorts:  []string{":7071"},
			expectError: true,
			description: "should fail: 127.0.0.1:7071 conflicts with bare :7071",
		},
		{
			name:        "same IP:port allowed",
			ports:       []string{"127.0.0.1:7071"},
			admPorts:    []string{},
			webuiPorts:  []string{"127.0.0.1:7071"},
			expectError: false,
			description: "should pass: identical IP:port specs are allowed",
		},
		{
			name:        "different IP:port no conflict",
			ports:       []string{"127.0.0.1:7071"},
			admPorts:    []string{},
			webuiPorts:  []string{"127.0.0.1:7072"},
			expectError: false,
			description: "should pass: different ports don't conflict",
		},
		{
			name:        "different IP same port no conflict when both have IP",
			ports:       []string{"127.0.0.1:7071"},
			admPorts:    []string{},
			webuiPorts:  []string{"192.168.1.1:7071"},
			expectError: false,
			description: "should pass: different IPs with same port are okay",
		},
		{
			name:        "admin port conflict with s3 port",
			ports:       []string{":7070"},
			admPorts:    []string{"127.0.0.1:7070"},
			webuiPorts:  []string{},
			expectError: true,
			description: "should fail: admin port conflicts with s3 port",
		},
		{
			name:        "all three conflict",
			ports:       []string{":8080"},
			admPorts:    []string{"127.0.0.1:8080"},
			webuiPorts:  []string{"192.168.1.1:8080"},
			expectError: true,
			description: "should fail: bare port conflicts with both admin and webui",
		},
		{
			name:        "no conflicts",
			ports:       []string{":7070"},
			admPorts:    []string{":8080"},
			webuiPorts:  []string{":9090"},
			expectError: false,
			description: "should pass: all different ports",
		},
		{
			name:        "IPv6 bare port conflict with IPv4 specified",
			ports:       []string{":7071"},
			admPorts:    []string{},
			webuiPorts:  []string{"[::1]:7071"},
			expectError: true,
			description: "should fail: bare :7071 conflicts with [::1]:7071",
		},
		{
			name:        "multiple ports with one conflict",
			ports:       []string{":7070", ":8080"},
			admPorts:    []string{":9090"},
			webuiPorts:  []string{"127.0.0.1:8080"},
			expectError: true,
			description: "should fail: :8080 conflicts with 127.0.0.1:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePortConflicts(tt.ports, tt.admPorts, tt.webuiPorts)
			if tt.expectError && err == nil {
				t.Errorf("%s: expected error but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("%s: expected no error but got: %v", tt.description, err)
			}
		})
	}
}
