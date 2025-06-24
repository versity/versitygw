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
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/s3api/utils"
)

// FileLogger is a local file audit log
type AdminFileLogger struct {
	FileLogger
}

var _ AuditLogger = &AdminFileLogger{}

// InitFileLogger initializes audit logs to local file
func InitAdminFileLogger(logname string) (AuditLogger, error) {
	f, err := os.OpenFile(logname, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("open log: %w", err)
	}

	f.WriteString(fmt.Sprintf("log starts %v\n", time.Now()))

	return &AdminFileLogger{FileLogger: FileLogger{logfile: logname, f: f}}, nil
}

// Log sends log message to file logger
func (f *AdminFileLogger) Log(ctx *fiber.Ctx, err error, body []byte, meta LogMeta) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.gotErr {
		return
	}

	lf := AdminLogFields{}

	access := "-"
	reqURI := ctx.OriginalURL()
	errorCode := ""
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
		errorCode = err.Error()
	}

	switch utils.ContextKeyAccount.Get(ctx).(type) {
	case auth.Account:
		access = utils.ContextKeyAccount.Get(ctx).(auth.Account).Access
	}

	lf.Time = time.Now()
	lf.RemoteIP = ctx.IP()
	lf.Requester = access
	lf.RequestID = genID()
	lf.Operation = meta.Action
	lf.RequestURI = reqURI
	lf.HttpStatus = meta.HttpStatus
	lf.ErrorCode = errorCode
	lf.BytesSent = len(body)
	lf.TotalTime = time.Since(startTime).Milliseconds()
	lf.TurnAroundTime = time.Since(startTime).Milliseconds()
	lf.Referer = ctx.Get("Referer")
	lf.UserAgent = ctx.Get("User-Agent")
	lf.SignatureVersion = "SigV4"
	lf.AuthenticationType = "AuthHeader"

	f.writeLog(lf)
}

func (f *AdminFileLogger) writeLog(lf AdminLogFields) {
	if lf.RemoteIP == "" {
		lf.RemoteIP = "-"
	}
	if lf.Requester == "" {
		lf.Requester = "-"
	}
	if lf.Operation == "" {
		lf.Operation = "-"
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
	if lf.CipherSuite == "" {
		lf.CipherSuite = "-"
	}
	if lf.TLSVersion == "" {
		lf.TLSVersion = "-"
	}

	log := fmt.Sprintf("%v %v %v %v %v %v %v %v %v %v %v %v %v %v %v %v %v\n",
		fmt.Sprintf("[%v]", lf.Time.Format(timeFormat)),
		lf.RemoteIP,
		lf.Requester,
		lf.RequestID,
		lf.Operation,
		lf.RequestURI,
		lf.HttpStatus,
		lf.ErrorCode,
		lf.BytesSent,
		lf.TotalTime,
		lf.TurnAroundTime,
		lf.Referer,
		lf.UserAgent,
		lf.SignatureVersion,
		lf.CipherSuite,
		lf.AuthenticationType,
		lf.TLSVersion,
	)

	_, err := f.f.WriteString(log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error writing to log file: %v\n", err)
		// TODO: do we need to terminate on log error?
		// set err for now so that we don't spew errors
		f.gotErr = true
	}
}
