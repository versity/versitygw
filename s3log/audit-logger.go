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
}

type LogMeta struct {
	BucketOwner string
	ObjectSize  int64
	Action      string
}

type LogConfig struct {
	IsFile     bool
	WebhookURL string
}

type LogFields struct {
	BucketOwner        string
	Bucket             string
	Time               time.Time
	RemoteIP           string
	Requester          string
	RequestID          string
	Operation          string
	Key                string
	RequestURI         string
	HttpStatus         int
	ErrorCode          string
	BytesSent          int
	ObjectSize         int64
	TotalTime          int64
	TurnAroundTime     int64
	Referer            string
	UserAgent          string
	VersionID          string
	HostID             string
	SignatureVersion   string
	CipherSuite        string
	AuthenticationType string
	HostHeader         string
	TLSVersion         string
	AccessPointARN     string
	AclRequired        string
}

func InitLogger(cfg *LogConfig) (AuditLogger, error) {
	if cfg.WebhookURL != "" && cfg.IsFile {
		return nil, fmt.Errorf("there should be specified one of the following: file, webhook")
	}
	if cfg.WebhookURL != "" {
		return InitWebhookLogger(cfg.WebhookURL)
	}
	if cfg.IsFile {
		return InitFileLogger()
	}

	return nil, nil
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
