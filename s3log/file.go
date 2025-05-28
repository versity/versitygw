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
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
)

const (
	logFileMode = 0600
	timeFormat  = "02/January/2006:15:04:05 -0700"
)

// FileLogger is a local file audit log
type FileLogger struct {
	logfile string
	f       *os.File
	gotErr  bool
	mu      sync.Mutex
}

var _ AuditLogger = &FileLogger{}

// InitFileLogger initializes audit logs to local file
func InitFileLogger(logname string) (AuditLogger, error) {
	f, err := os.OpenFile(logname, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("open log: %w", err)
	}

	f.WriteString(fmt.Sprintf("log starts %v\n", time.Now()))

	return &FileLogger{logfile: logname, f: f}, nil
}

// Log sends log message to file logger
func (f *FileLogger) Log(ctx *fiber.Ctx, err error, body []byte, meta LogMeta) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.gotErr {
		return
	}

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

	f.writeLog(lf)
}

func (f *FileLogger) writeLog(lf LogFields) {
	if lf.BucketOwner == "" {
		lf.BucketOwner = "-"
	}
	if lf.Bucket == "" {
		lf.Bucket = "-"
	}
	if lf.RemoteIP == "" {
		lf.RemoteIP = "-"
	}
	if lf.Requester == "" {
		lf.Requester = "-"
	}
	if lf.Operation == "" {
		lf.Operation = "-"
	}
	if lf.Key == "" {
		lf.Key = "-"
	}
	if lf.RequestURI == "" {
		lf.RequestURI = "-"
	}
	if lf.ErrorCode == "" {
		lf.ErrorCode = "-"
	}
	if lf.Referer == "" {
		lf.Referer = "-"
	}
	if lf.UserAgent == "" {
		lf.UserAgent = "-"
	}
	if lf.VersionID == "" {
		lf.VersionID = "-"
	}
	if lf.HostID == "" {
		lf.HostID = "-"
	}
	if lf.CipherSuite == "" {
		lf.CipherSuite = "-"
	}
	if lf.HostHeader == "" {
		lf.HostHeader = "-"
	}
	if lf.TLSVersion == "" {
		lf.TLSVersion = "-"
	}

	log := fmt.Sprintf("%v %v %v %v %v %v %v %v %v %v %v %v %v %v %v %v %v %v %v %v %v %v %v %v %v %v\n",
		lf.BucketOwner,
		lf.Bucket,
		fmt.Sprintf("[%v]", lf.Time.Format(timeFormat)),
		lf.RemoteIP,
		lf.Requester,
		lf.RequestID,
		lf.Operation,
		lf.Key,
		lf.RequestURI,
		lf.HttpStatus,
		lf.ErrorCode,
		lf.BytesSent,
		lf.ObjectSize,
		lf.TotalTime,
		lf.TurnAroundTime,
		lf.Referer,
		lf.UserAgent,
		lf.VersionID,
		lf.HostID,
		lf.SignatureVersion,
		lf.CipherSuite,
		lf.AuthenticationType,
		lf.HostHeader,
		lf.TLSVersion,
		lf.AccessPointARN,
		lf.AclRequired,
	)

	_, err := f.f.WriteString(log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error writing to log file: %v\n", err)
		// TODO: do we need to terminate on log error?
		// set err for now so that we don't spew errors
		f.gotErr = true
	}
}

// HangUp closes current logfile handle and opens a new one
// typically needed for log rotations
func (f *FileLogger) HangUp() error {
	err := f.f.Close()
	if err != nil {
		return fmt.Errorf("close log: %w", err)
	}

	f.f, err = os.OpenFile(f.logfile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open log: %w", err)
	}

	f.f.WriteString(fmt.Sprintf("log starts %v\n", time.Now()))

	return nil
}

// Shutdown closes logfile handle
func (f *FileLogger) Shutdown() error {
	return f.f.Close()
}
