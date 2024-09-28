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

package s3log

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

type AuditLogger interface {
	Log(ctx *fiber.Ctx, err error, body []byte, meta LogMeta)
	HangUp() error
	Shutdown() error
}

type LogMeta struct {
	BucketOwner string
	Action      string
	ObjectSize  int64
	HttpStatus  int
}

type LogConfig struct {
	LogFile      string
	WebhookURL   string
	AdminLogFile string
}

type LogFields struct {
	Time               time.Time
	HostID             string
	RequestID          string
	AclRequired        string
	Requester          string
	AccessPointARN     string
	Operation          string
	Key                string
	Referer            string
	TLSVersion         string
	ErrorCode          string
	HostHeader         string
	AuthenticationType string
	RemoteIP           string
	Bucket             string
	RequestURI         string
	UserAgent          string
	VersionID          string
	BucketOwner        string
	SignatureVersion   string
	CipherSuite        string
	ObjectSize         int64
	BytesSent          int
	HttpStatus         int
	TurnAroundTime     int64
	TotalTime          int64
}

type AdminLogFields struct {
	Time               time.Time
	UserAgent          string
	Referer            string
	RequestID          string
	Operation          string
	TLSVersion         string
	AuthenticationType string
	Requester          string
	ErrorCode          string
	RequestURI         string
	CipherSuite        string
	SignatureVersion   string
	RemoteIP           string
	BytesSent          int
	TurnAroundTime     int64
	HttpStatus         int
	TotalTime          int64
}

type Loggers struct {
	S3Logger    AuditLogger
	AdminLogger AuditLogger
}

func InitLogger(cfg *LogConfig) (*Loggers, error) {
	if cfg.WebhookURL != "" && cfg.LogFile != "" {
		return nil, fmt.Errorf("there should be specified one of the following: file, webhook")
	}
	loggers := new(Loggers)

	switch {
	case cfg.WebhookURL != "":
		fmt.Printf("initializing S3 access logs with '%v' webhook url\n", cfg.WebhookURL)
		l, err := InitWebhookLogger(cfg.WebhookURL)
		if err != nil {
			return nil, err
		}
		loggers.S3Logger = l
	case cfg.LogFile != "":
		fmt.Printf("initializing S3 access logs with '%v' file\n", cfg.LogFile)
		l, err := InitFileLogger(cfg.LogFile)
		if err != nil {
			return nil, err
		}

		loggers.S3Logger = l
	}

	if cfg.AdminLogFile != "" {
		fmt.Printf("initializing admin access logs with '%v' file\n", cfg.AdminLogFile)
		l, err := InitAdminFileLogger(cfg.AdminLogFile)
		if err != nil {
			return nil, err
		}

		loggers.AdminLogger = l
	}

	return loggers, nil
}

func genID() string {
	src := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, 8)

	if _, err := src.Read(b); err != nil {
		panic(err)
	}

	return strings.ToUpper(hex.EncodeToString(b))
}

func getTLSVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLSv1.0"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	default:
		return ""
	}
}
