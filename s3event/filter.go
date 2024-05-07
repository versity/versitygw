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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type EventType string

const (
	EventObjectCreated              EventType = "s3:ObjectCreated:*" // ObjectCreated
	EventObjectCreatedPut           EventType = "s3:ObjectCreated:Put"
	EventObjectCreatedPost          EventType = "s3:ObjectCreated:Post"
	EventObjectCreatedCopy          EventType = "s3:ObjectCreated:Copy"
	EventCompleteMultipartUpload    EventType = "s3:ObjectCreated:CompleteMultipartUpload"
	EventObjectRemoved              EventType = "s3:ObjectRemoved:*"
	EventObjectRemovedDelete        EventType = "s3:ObjectRemoved:Delete"
	EventObjectRemovedDeleteObjects EventType = "s3:ObjectRemoved:DeleteObjects" // non AWS custom type for DeleteObjects
	EventObjectTagging              EventType = "s3:ObjectTagging:*"             // ObjectTagging
	EventObjectTaggingPut           EventType = "s3:ObjectTagging:Put"
	EventObjectTaggingDelete        EventType = "s3:ObjectTagging:Delete"
	EventObjectAclPut               EventType = "s3:ObjectAcl:Put"
	EventObjectRestore              EventType = "s3:ObjectRestore:*" // ObjectRestore
	EventObjectRestorePost          EventType = "s3:ObjectRestore:Post"
	EventObjectRestoreCompleted     EventType = "s3:ObjectRestore:Completed"
	// EventObjectRestorePost       EventType = "s3:ObjectRestore:Post"
	// EventObjectRestoreDelete     EventType = "s3:ObjectRestore:Delete"
)

func (event EventType) IsValid() bool {
	_, ok := supportedEventFilters[event]
	return ok
}

var supportedEventFilters = map[EventType]struct{}{
	EventObjectCreated:              {},
	EventObjectCreatedPut:           {},
	EventObjectCreatedPost:          {},
	EventObjectCreatedCopy:          {},
	EventCompleteMultipartUpload:    {},
	EventObjectRemoved:              {},
	EventObjectRemovedDelete:        {},
	EventObjectRemovedDeleteObjects: {},
	EventObjectTagging:              {},
	EventObjectTaggingPut:           {},
	EventObjectTaggingDelete:        {},
	EventObjectAclPut:               {},
	EventObjectRestore:              {},
	EventObjectRestorePost:          {},
	EventObjectRestoreCompleted:     {},
}

type EventFilter map[EventType]bool

func parseEventFiltersFile(path string) (EventFilter, error) {
	// if no filter config file path is specified return nil map
	if path == "" {
		return nil, nil
	}

	configFilePath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	// Open the JSON file
	file, err := os.Open(configFilePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return parseEventFilters(file)
}

func parseEventFilters(r io.Reader) (EventFilter, error) {
	var filter EventFilter
	if err := json.NewDecoder(r).Decode(&filter); err != nil {
		return nil, err
	}

	if err := filter.Validate(); err != nil {
		return nil, err
	}

	return filter, nil
}

func (ef EventFilter) Validate() error {
	for event := range ef {
		if isValid := event.IsValid(); !isValid {
			return fmt.Errorf("invalid configuration property: %v", event)
		}
	}

	return nil
}

func (ef EventFilter) Filter(event EventType) bool {
	ev, found := ef[event]
	if found {
		return ev
	}

	// check wildcard match
	wildCardEv := EventType(string(event[:strings.LastIndex(string(event), ":")+1]) + "*")
	wildcard, found := ef[wildCardEv]
	if found {
		return wildcard
	}

	return false
}
