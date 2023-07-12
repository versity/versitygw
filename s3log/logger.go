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
	"fmt"
	"time"
)

type LoggerType string

const (
	WebhookLoggerType LoggerType = "webhook"
)

type Logger interface {
	SendErrorLog(err error, action string, access, bucket, object *string)
	SendSuccessLog(data any, action string, access, bucket, object *string)
	SendAuthLog(access *string, err error)
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

type LogConfig struct {
	WebhookURL    string
	KafkaURL      string
	KafkaTopic    string
	KafkaTopicKey string
	StorageSystem string
}

func InitLogger(cfg *LogConfig) (Logger, error) {
	if cfg.WebhookURL != "" && cfg.KafkaURL != "" {
		return nil, fmt.Errorf("specify one of 2 option for audit logging: kafka, webhook")
	}
	if cfg.WebhookURL != "" {
		return InitWebhookLogger(cfg.StorageSystem, cfg.WebhookURL)
	}
	if cfg.KafkaURL != "" {
		return InitKafkaLogger(cfg.StorageSystem, cfg.KafkaURL, cfg.KafkaTopic, cfg.KafkaTopicKey)
	}
	return nil, nil
}
