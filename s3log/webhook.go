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
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/versity/versitygw/s3err"
)

type LogError struct {
	StatusCode int
	Message    string
}

type WebhookLogger struct {
	StorageSystem string
	Time          time.Time
	Action        string
	UserAccess    *string
	Bucket        *string
	Object        *string
	Response      any
	Error         *LogError
	url           string
	mu            sync.Mutex
}

type AuthSuccessLog struct {
	StorageSystem string
	Time          time.Time
	UserAccess    *string
	Message       string
}

type AuthErrorLog struct {
	StorageSystem string
	Time          time.Time
	UserAccess    *string
	ErrorMessage  string
	ErrorStatus   int
	ErrorType     string
}

var _ Logger = &WebhookLogger{}

func InitWebhookLogger(storageSystem, url string) Logger {
	return &WebhookLogger{
		url:           url,
		StorageSystem: storageSystem,
	}
}

func (l *WebhookLogger) SendSuccessLog(data any, action string, access, bucket, object *string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.Action = action
	l.UserAccess = access
	l.Bucket = bucket
	l.Object = object
	l.Response = data
	l.Time = time.Now()
	l.Error = nil

	l.sendLog(nil)
}

func (l *WebhookLogger) SendErrorLog(err error, action string, access, bucket, object *string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.Action = action
	l.UserAccess = access
	l.Bucket = bucket
	l.Object = object
	serr, ok := err.(s3err.APIError)
	if ok {
		l.Error = &LogError{
			StatusCode: serr.HTTPStatusCode,
			Message:    serr.Description,
		}
	} else {
		l.Error = &LogError{
			StatusCode: 500,
			Message:    err.Error(),
		}
	}
	l.Response = nil

	l.sendLog(nil)
}

func (l *WebhookLogger) SendAuthLog(access *string, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err != nil {
		serr, ok := err.(s3err.APIError)
		if ok {
			l.sendLog(AuthErrorLog{
				StorageSystem: l.StorageSystem,
				Time:          time.Now(),
				UserAccess:    access,
				ErrorMessage:  serr.Description,
				ErrorStatus:   serr.HTTPStatusCode,
				ErrorType:     "Authentication error",
			})
		} else {
			l.sendLog(AuthErrorLog{
				StorageSystem: l.StorageSystem,
				Time:          time.Now(),
				UserAccess:    access,
				ErrorMessage:  err.Error(),
				ErrorStatus:   500,
				ErrorType:     "Authentication error",
			})
		}
		return
	}
	l.sendLog(AuthSuccessLog{
		StorageSystem: l.StorageSystem,
		Time:          time.Now(),
		UserAccess:    access,
		Message:       "The user passed the authentication successfully",
	})
}

func (l *WebhookLogger) sendLog(data any) {
	if data == nil {
		data = l
	}
	jsonLog, err := json.Marshal(data)
	if err != nil {
		fmt.Printf("\n failed to parse the log data: %v", err.Error())
	}

	req, err := http.NewRequest(http.MethodPost, l.url, bytes.NewReader(jsonLog))
	if err != nil {
		fmt.Println(err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	client := &http.Client{}
	_, err = client.Do(req)
	if err != nil {
		fmt.Printf("\n failed to send the log %v", err.Error())
	}
}
