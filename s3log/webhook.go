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
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
)

// WebhookLogger is a webhook URL audit log
type WebhookLogger struct {
	mu  sync.Mutex
	url string
}

var _ AuditLogger = &WebhookLogger{}

// InitWebhookLogger initializes audit logs to webhook URL
func InitWebhookLogger(url string) (AuditLogger, error) {
	client := &http.Client{
		Timeout: 3 * time.Second,
	}
	_, err := client.Post(url, "application/json", nil)
	if err != nil {
		if err, ok := err.(net.Error); ok && !err.Timeout() {
			return nil, fmt.Errorf("unreachable webhook url: %w", err)
		}
	}
	return &WebhookLogger{
		url: url,
	}, nil
}

// Log sends log message to webhook
func (wl *WebhookLogger) Log(ctx *fiber.Ctx, err error, body []byte, meta LogMeta) {
	wl.mu.Lock()
	defer wl.mu.Unlock()

	lf := LogFields{}

	access := "-"
	reqURI := ctx.OriginalURL()
	path := strings.Split(ctx.Path(), "/")
	var bucket, object string
	if len(path) > 1 {
		bucket, object = path[1], strings.Join(path[2:], "/")
	}
	errorCode := ""
	httpStatus := 200
	startTime, ok := utils.ContextKeyStartTime.Get(ctx).(time.Time)
	if !ok {
		startTime = time.Now()
	}
	tlsConnState := ctx.Context().TLSConnectionState()
	if tlsConnState != nil {
		lf.CipherSuite = tls.CipherSuiteName(tlsConnState.CipherSuite)
		lf.TLSVersion = getTLSVersionName(tlsConnState.Version)
	}

	if err != nil {
		serr, ok := err.(s3err.APIError)
		if ok {
			errorCode = serr.Code
			httpStatus = serr.HTTPStatusCode
		} else {
			errorCode = err.Error()
			httpStatus = 500
		}
	}

	acct, ok := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	if ok {
		access = acct.Access
	}

	lf.BucketOwner = meta.BucketOwner
	lf.Bucket = bucket
	lf.Time = time.Now()
	lf.RemoteIP = ctx.IP()
	lf.Requester = access
	lf.RequestID = genID()
	lf.Operation = meta.Action
	lf.Key = object
	lf.RequestURI = reqURI
	lf.HttpStatus = httpStatus
	lf.ErrorCode = errorCode
	lf.BytesSent = len(body)
	lf.ObjectSize = meta.ObjectSize
	lf.TotalTime = time.Since(startTime).Milliseconds()
	lf.TurnAroundTime = time.Since(startTime).Milliseconds()
	lf.Referer = ctx.Get("Referer")
	lf.UserAgent = ctx.Get("User-Agent")
	lf.VersionID = ctx.Query("versionId")
	lf.HostID = ctx.Get("X-Amz-Id-2")
	lf.SignatureVersion = "SigV4"
	lf.AuthenticationType = "AuthHeader"
	lf.HostHeader = fmt.Sprintf("s3.%v.amazonaws.com", utils.ContextKeyRegion.Get(ctx).(string))
	lf.AccessPointARN = fmt.Sprintf("arn:aws:s3:::%v", strings.Join(path, "/"))
	lf.AclRequired = "Yes"

	wl.sendLog(lf)
}

func (wl *WebhookLogger) sendLog(lf LogFields) {
	jsonLog, err := json.Marshal(lf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse the log data: %v\n", err.Error())
	}

	req, err := http.NewRequest(http.MethodPost, wl.url, bytes.NewReader(jsonLog))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	go makeRequest(req)
}

func makeRequest(req *http.Request) {
	client := &http.Client{
		Timeout: 1 * time.Second,
	}
	_, err := client.Do(req)
	if err != nil {
		if err, ok := err.(net.Error); ok && !err.Timeout() {
			fmt.Fprintf(os.Stderr, "error sending webhook log: %v\n", err)
		}
	}
}

// HangUp does nothing for webhooks
func (wl *WebhookLogger) HangUp() error {
	return nil
}

// Shutdown does nothing for webhooks
func (wl *WebhookLogger) Shutdown() error {
	return nil
}
