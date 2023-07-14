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
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/s3err"
)

type WebhookLogger struct {
	LogFields
	mu  sync.Mutex
	url string
}

var _ AuditLogger = &WebhookLogger{}

func InitWebhookLogger(url string) (AuditLogger, error) {
	client := &http.Client{
		Timeout: 3 * time.Second,
	}
	_, err := client.Post(url, "application/json", nil)
	if err != nil {
		if err, ok := err.(net.Error); ok && !err.Timeout() {
			return nil, fmt.Errorf("unreachable webhook url")
		}
	}
	return &WebhookLogger{
		url: url,
	}, nil
}

func (wl *WebhookLogger) Log(ctx *fiber.Ctx, err error, body []byte, meta LogMeta) {
	wl.mu.Lock()
	defer wl.mu.Unlock()

	access := "-"
	reqURI := ctx.Request().URI().String()
	path := strings.Split(ctx.Path(), "/")
	bucket, object := path[1], strings.Join(path[2:], "/")
	errorCode := ""
	httpStatus := 200
	startTime := ctx.Locals("startTime").(time.Time)
	tlsConnState := ctx.Context().TLSConnectionState()
	if tlsConnState != nil {
		wl.CipherSuite = tls.CipherSuiteName(tlsConnState.CipherSuite)
		wl.TLSVersion = getTLSVersionName(tlsConnState.Version)
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

	switch ctx.Locals("access").(type) {
	case string:
		access = ctx.Locals("access").(string)
	}

	wl.BucketOwner = meta.BucketOwner
	wl.Bucket = bucket
	wl.Time = time.Now()
	wl.RemoteIP = ctx.IP()
	wl.Requester = access
	wl.RequestID = genID()
	wl.Operation = meta.Action
	wl.Key = object
	wl.RequestURI = reqURI
	wl.HttpStatus = httpStatus
	wl.ErrorCode = errorCode
	wl.BytesSent = len(body)
	wl.ObjectSize = meta.ObjectSize
	wl.TotalTime = time.Since(startTime).Milliseconds()
	wl.TurnAroundTime = time.Since(startTime).Milliseconds()
	wl.Referer = ctx.Get("Referer")
	wl.UserAgent = ctx.Get("User-Agent")
	wl.VersionID = ctx.Query("versionId")
	wl.HostID = ctx.Get("X-Amz-Id-2")
	wl.SignatureVersion = "SigV4"
	wl.AuthenticationType = "AuthHeader"
	wl.HostHeader = fmt.Sprintf("s3.%v.amazonaws.com", ctx.Locals("region").(string))
	wl.AccessPointARN = fmt.Sprintf("arn:aws:s3:::%v", strings.Join(path, "/"))
	wl.AclRequired = "Yes"

	wl.sendLog()
}

func (wl *WebhookLogger) sendLog() {
	jsonLog, err := json.Marshal(wl)
	if err != nil {
		fmt.Printf("\n failed to parse the log data: %v", err.Error())
	}

	req, err := http.NewRequest(http.MethodPost, wl.url, bytes.NewReader(jsonLog))
	if err != nil {
		fmt.Println(err)
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
			fmt.Println("error sending the log to the specified url")
		}
	}
}
