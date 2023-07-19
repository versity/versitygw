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

package s3event

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
)

type S3EventSender interface {
	SendEvent(ctx *fiber.Ctx, meta EventMeta)
}

type EventMeta struct {
	BucketOwner string
	EventName   EventType
	ObjectSize  int64
	ObjectETag  *string
	VersionId   *string
}

type EventFields struct {
	Records []EventSchema
}

type EventType string

const (
	EventObjectPut               EventType = "s3:ObjectCreated:Put"
	EventObjectCopy              EventType = "s3:ObjectCreated:Copy"
	EventCompleteMultipartUpload EventType = "s3:ObjectCreated:CompleteMultipartUpload"
	EventObjectDelete            EventType = "s3:ObjectRemoved:Delete"
	EventObjectRestoreCompleted  EventType = "s3:ObjectRestore:Completed"
	EventObjectTaggingPut        EventType = "s3:ObjectTagging:Put"
	EventObjectTaggingDelete     EventType = "s3:ObjectTagging:Delete"
	EventObjectAclPut            EventType = "s3:ObjectAcl:Put"
	// Not supported
	// EventObjectRestorePost       EventType = "s3:ObjectRestore:Post"
	// EventObjectRestoreDelete     EventType = "s3:ObjectRestore:Delete"
)

type EventSchema struct {
	EventVersion      string                `json:"eventVersion"`
	EventSource       string                `json:"eventSource"`
	AwsRegion         string                `json:"awsRegion"`
	EventTime         string                `json:"eventTime"`
	EventName         EventType             `json:"eventName"`
	UserIdentity      EventUserIdentity     `json:"userIdentity"`
	RequestParameters EventRequestParams    `json:"requestParameters"`
	ResponseElements  EventResponseElements `json:"responseElements"`
	S3                EventS3Data           `json:"s3"`
	GlacierEventData  EventGlacierData      `json:"glacierEventData"`
}

type EventUserIdentity struct {
	PrincipalId string `json:"PrincipalId"`
}

type EventRequestParams struct {
	SourceIPAddress string `json:"sourceIPAddress"`
}

type EventResponseElements struct {
	RequestId string `json:"x-amz-request-id"`
	HostId    string `json:"x-amz-id-2"`
}

type EventS3Data struct {
	S3SchemaVersion string            `json:"s3SchemaVersion"`
	ConfigurationId string            `json:"configurationId"`
	Bucket          EventS3BucketData `json:"bucket"`
	Object          EventObjectData   `json:"object"`
}

type EventGlacierData struct {
	RestoreEventData EventRestoreData `json:"restoreEventData"`
}

type EventRestoreData struct {
	LifecycleRestorationExpiryTime string `json:"lifecycleRestorationExpiryTime"`
	LifecycleRestoreStorageClass   string `json:"lifecycleRestoreStorageClass"`
}

type EventS3BucketData struct {
	Name          string            `json:"name"`
	OwnerIdentity EventUserIdentity `json:"ownerIdentity"`
	Arn           string            `json:"arn"`
}

type EventObjectData struct {
	Key       string  `json:"key"`
	Size      int64   `json:"size"`
	ETag      *string `json:"eTag"`
	VersionId *string `json:"versionId"`
	Sequencer string  `json:"sequencer"`
}

type EventConfig struct {
	KafkaURL      string
	KafkaTopic    string
	KafkaTopicKey string
	NatsURL       string
	NatsTopic     string
}

func InitEventSender(cfg *EventConfig) (S3EventSender, error) {
	if cfg.KafkaURL != "" && cfg.NatsURL != "" {
		return nil, fmt.Errorf("there should be specified one of the following: kafka, nats")
	}
	if cfg.NatsURL != "" {
		return InitNatsNotifSender(cfg.NatsURL, cfg.NatsTopic)
	}
	if cfg.KafkaURL != "" {
		return InitKafkaEventService(cfg.KafkaURL, cfg.KafkaTopic, cfg.KafkaTopicKey)
	}
	return nil, nil
}
