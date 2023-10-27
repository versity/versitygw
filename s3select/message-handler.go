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

package s3select

import (
	"bufio"
	"context"
)

type GetProgress func() (bytesScanned int64, bytesProcessed int64)

type MessageHandler struct{}

// Creates a new MessageHandler instance and starts the event streaming
func NewMessageHandler(ctx context.Context, w *bufio.Writer, getProgressFunc GetProgress) *MessageHandler {
	return &MessageHandler{}
}

// SendRecord sends a single Records message
func (mh *MessageHandler) SendRecord(payload []byte) error {
	return nil
}

// Finish terminates message stream with Stat and End message
func (mh *MessageHandler) Finish() error {
	return nil
}

// FinishWithError terminates event stream with error
func (mh *MessageHandler) FinishWithError(errorCode, errorMessage string) error {
	return nil
}
