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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/s3err"
)

const (
	logFile     = "access.log"
	logFileMode = 0600
	timeFormat  = "02/January/2006:15:04:05 -0700"
)

type FileLogger struct {
	LogFields
	mu sync.Mutex
}

var _ AuditLogger = &FileLogger{}

func InitFileLogger() (AuditLogger, error) {
	_, err := os.ReadFile(logFile)
	if err != nil && errors.Is(err, fs.ErrNotExist) {
		err := os.WriteFile(logFile, []byte{}, logFileMode)
		if err != nil {
			return nil, err
		} else {
			return nil, err
		}
	}

	return &FileLogger{}, nil
}

func (f *FileLogger) Log(ctx *fiber.Ctx, err error, body []byte, meta LogMeta) {
	f.mu.Lock()
	defer f.mu.Unlock()

	access := "-"
	reqURI := ctx.Request().URI().String()
	path := strings.Split(ctx.Path(), "/")
	bucket, object := path[1], strings.Join(path[2:], "/")
	errorCode := ""
	httpStatus := 200
	startTime := ctx.Locals("startTime").(time.Time)
	tlsConnState := ctx.Context().TLSConnectionState()
	if tlsConnState != nil {
		f.CipherSuite = tls.CipherSuiteName(tlsConnState.CipherSuite)
		f.TLSVersion = getTLSVersionName(tlsConnState.Version)
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

	f.BucketOwner = meta.BucketOwner
	f.Bucket = bucket
	f.Time = time.Now()
	f.RemoteIP = ctx.IP()
	f.Requester = access
	f.RequestID = genID()
	f.Operation = meta.Action
	f.Key = object
	f.RequestURI = reqURI
	f.HttpStatus = httpStatus
	f.ErrorCode = errorCode
	f.BytesSent = len(body)
	f.ObjectSize = meta.ObjectSize
	f.TotalTime = time.Since(startTime).Milliseconds()
	f.TurnAroundTime = time.Since(startTime).Milliseconds()
	f.Referer = ctx.Get("Referer")
	f.UserAgent = ctx.Get("User-Agent")
	f.VersionID = ctx.Query("versionId")
	f.HostID = ctx.Get("X-Amz-Id-2")
	f.SignatureVersion = "SigV4"
	f.AuthenticationType = "AuthHeader"
	f.HostHeader = fmt.Sprintf("s3.%v.amazonaws.com", ctx.Locals("region").(string))
	f.AccessPointARN = fmt.Sprintf("arn:aws:s3:::%v", strings.Join(path, "/"))
	f.AclRequired = "Yes"

	f.writeLog()
}

func (fl *FileLogger) writeLog() {
	if fl.BucketOwner == "" {
		fl.BucketOwner = "-"
	}
	if fl.Bucket == "" {
		fl.Bucket = "-"
	}
	if fl.RemoteIP == "" {
		fl.RemoteIP = "-"
	}
	if fl.Requester == "" {
		fl.Requester = "-"
	}
	if fl.Operation == "" {
		fl.Operation = "-"
	}
	if fl.Key == "" {
		fl.Key = "-"
	}
	if fl.RequestURI == "" {
		fl.RequestURI = "-"
	}
	if fl.ErrorCode == "" {
		fl.ErrorCode = "-"
	}
	if fl.Referer == "" {
		fl.Referer = "-"
	}
	if fl.UserAgent == "" {
		fl.UserAgent = "-"
	}
	if fl.VersionID == "" {
		fl.VersionID = "-"
	}
	if fl.HostID == "" {
		fl.HostID = "-"
	}
	if fl.CipherSuite == "" {
		fl.CipherSuite = "-"
	}
	if fl.HostHeader == "" {
		fl.HostHeader = "-"
	}
	if fl.TLSVersion == "" {
		fl.TLSVersion = "-"
	}

	log := fmt.Sprintf("\n%v %v %v %v %v %v %v %v %v %v %v %v %v %v %v %v %v %v %v %v %v %v %v %v %v %v",
		fl.BucketOwner,
		fl.Bucket,
		fmt.Sprintf("[%v]", fl.Time.Format(timeFormat)),
		fl.RemoteIP,
		fl.Requester,
		fl.RequestID,
		fl.Operation,
		fl.Key,
		fl.RequestURI,
		fl.HttpStatus,
		fl.ErrorCode,
		fl.BytesSent,
		fl.ObjectSize,
		fl.TotalTime,
		fl.TurnAroundTime,
		fl.Referer,
		fl.UserAgent,
		fl.VersionID,
		fl.HostID,
		fl.SignatureVersion,
		fl.CipherSuite,
		fl.AuthenticationType,
		fl.HostHeader,
		fl.TLSVersion,
		fl.AccessPointARN,
		fl.AclRequired,
	)

	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, logFileMode)
	if err != nil {
		fmt.Printf("error opening the log file: %v", err.Error())
	}
	defer file.Close()
	_, err = file.WriteString(log)
	if err != nil {
		fmt.Printf("error writing in log file: %v", err.Error())
	}
}
