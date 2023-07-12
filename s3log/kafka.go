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
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/Shopify/sarama"
	"github.com/versity/versitygw/s3err"
)

type KafkaLogger struct {
	StorageSystem string
	Action        string
	UserAccess    *string
	Bucket        *string
	Object        *string
	Time          time.Time
	Response      any
	Error         *LogError
	topic         string
	key           string
	producer      sarama.SyncProducer
	mu            sync.Mutex
}

func InitKafkaLogger(storageSystem, url, topic, key string) (Logger, error) {
	if topic == "" {
		return nil, fmt.Errorf("kafka message topic should be specified")
	}

	config := sarama.NewConfig()
	config.Producer.Return.Successes = true

	producer, err := sarama.NewSyncProducer([]string{url}, config)
	if err != nil {
		return nil, err
	}

	return &KafkaLogger{
		StorageSystem: storageSystem,
		topic:         topic,
		key:           key,
		producer:      producer,
	}, nil
}

func (l *KafkaLogger) SendSuccessLog(data any, action string, access, bucket, object *string) {
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

func (l *KafkaLogger) SendErrorLog(err error, action string, access, bucket, object *string) {
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

func (l *KafkaLogger) SendAuthLog(access *string, err error) {
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

func (l *KafkaLogger) sendLog(data any) {
	if data == nil {
		data = l
	}
	msg, err := json.Marshal(data)
	if err != nil {
		fmt.Printf("\n failed to parse the log data: %v", err.Error())
	}

	var message *sarama.ProducerMessage

	if l.key == "" {
		message = &sarama.ProducerMessage{
			Topic: l.topic,
			Value: sarama.StringEncoder(msg),
		}
	} else {
		message = &sarama.ProducerMessage{
			Topic: l.topic,
			Key:   sarama.StringEncoder(l.key),
			Value: sarama.StringEncoder(msg),
		}
	}

	_, _, err = l.producer.SendMessage(message)
	if err != nil {
		fmt.Println(err)
	}
}
