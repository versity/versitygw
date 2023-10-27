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
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"strconv"
	"sync/atomic"
	"time"
)

const (
	maxRecordMessageLength = (128 << 10) - 256
)

var bufLength = payloadLenForMsgLen(maxRecordMessageLength)

// Records Message header
var recordsHeader = []byte{
	13, ':', 'm', 'e', 's', 's', 'a', 'g', 'e', '-', 't', 'y', 'p', 'e', 7, 0, 5, 'e', 'v', 'e', 'n', 't',
	13, ':', 'c', 'o', 'n', 't', 'e', 'n', 't', '-', 't', 'y', 'p', 'e', 7, 0, 24, 'a', 'p', 'p', 'l', 'i', 'c', 'a', 't', 'i', 'o', 'n', '/', 'o', 'c', 't', 'e', 't', '-', 's', 't', 'r', 'e', 'a', 'm',
	11, ':', 'e', 'v', 'e', 'n', 't', '-', 't', 'y', 'p', 'e', 7, 0, 7, 'R', 'e', 'c', 'o', 'r', 'd', 's',
}

// Continuation Message header
var continuationMessage = []byte{
	0, 0, 0, 57, // total byte-length.
	0, 0, 0, 41, // headers byte-length.
	139, 161, 157, 242, // prelude crc.
	13, ':', 'm', 'e', 's', 's', 'a', 'g', 'e', '-', 't', 'y', 'p', 'e', 7, 0, 5, 'e', 'v', 'e', 'n', 't', // headers.
	11, ':', 'e', 'v', 'e', 'n', 't', '-', 't', 'y', 'p', 'e', 7, 0, 4, 'C', 'o', 'n', 't', // headers.
	156, 134, 74, 13, // message crc.
}

// Progress Message header
var progressHeader = []byte{
	13, ':', 'm', 'e', 's', 's', 'a', 'g', 'e', '-', 't', 'y', 'p', 'e', 7, 0, 5, 'e', 'v', 'e', 'n', 't',
	13, ':', 'c', 'o', 'n', 't', 'e', 'n', 't', '-', 't', 'y', 'p', 'e', 7, 0, 8, 't', 'e', 'x', 't', '/', 'x', 'm', 'l',
	11, ':', 'e', 'v', 'e', 'n', 't', '-', 't', 'y', 'p', 'e', 7, 0, 8, 'P', 'r', 'o', 'g', 'r', 'e', 's', 's',
}

// Stats Message header
var statsHeader = []byte{
	13, ':', 'm', 'e', 's', 's', 'a', 'g', 'e', '-', 't', 'y', 'p', 'e', 7, 0, 5, 'e', 'v', 'e', 'n', 't',
	13, ':', 'c', 'o', 'n', 't', 'e', 'n', 't', '-', 't', 'y', 'p', 'e', 7, 0, 8, 't', 'e', 'x', 't', '/', 'x', 'm', 'l',
	11, ':', 'e', 'v', 'e', 'n', 't', '-', 't', 'y', 'p', 'e', 7, 0, 5, 'S', 't', 'a', 't', 's',
}

func genMessage(header, payload []byte) []byte {
	headerLength := len(header)
	payloadLength := len(payload)
	totalLength := headerLength + payloadLength + 16

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint32(totalLength))
	binary.Write(buf, binary.BigEndian, uint32(headerLength))
	prelude := buf.Bytes()
	binary.Write(buf, binary.BigEndian, crc32.ChecksumIEEE(prelude))
	buf.Write(header)
	if payload != nil {
		buf.Write(payload)
	}
	message := buf.Bytes()
	binary.Write(buf, binary.BigEndian, crc32.ChecksumIEEE(message))

	return buf.Bytes()
}

// Creates a new Record Message
func newRecordsMessage(payload []byte) []byte {
	return genMessage(recordsHeader, payload)
}

func payloadLenForMsgLen(messageLength int) int {
	return messageLength - len(recordsHeader) - 16
}

// Creates a new Progress Message
func newProgressMessage(bytesScanned, bytesProcessed, bytesReturned int64) []byte {
	payload := []byte(`<?xml version="1.0" encoding="UTF-8"?><Progress><BytesScanned>` +
		strconv.FormatInt(bytesScanned, 10) + `</BytesScanned><BytesProcessed>` +
		strconv.FormatInt(bytesProcessed, 10) + `</BytesProcessed><BytesReturned>` +
		strconv.FormatInt(bytesReturned, 10) + `</BytesReturned></Stats>`)
	return genMessage(progressHeader, payload)
}

// Creates new Stats Message. S3 sends this message at the end of the request before End message.
// It contains statistics about the query.
func newStatsMessage(bytesScanned, bytesProcessed, bytesReturned int64) []byte {
	payload := []byte(`<?xml version="1.0" encoding="UTF-8"?><Stats><BytesScanned>` +
		strconv.FormatInt(bytesScanned, 10) + `</BytesScanned><BytesProcessed>` +
		strconv.FormatInt(bytesProcessed, 10) + `</BytesProcessed><BytesReturned>` +
		strconv.FormatInt(bytesReturned, 10) + `</BytesReturned></Stats>`)
	return genMessage(statsHeader, payload)
}

// Indicates the end of the request, and no more messages will be sent.
// Request is not complete until client receives End message.
var endMessage = []byte{
	0, 0, 0, 56, // total byte-length.
	0, 0, 0, 40, // headers byte-length.
	193, 198, 132, 212, // prelude crc.
	13, ':', 'm', 'e', 's', 's', 'a', 'g', 'e', '-', 't', 'y', 'p', 'e', 7, 0, 5, 'e', 'v', 'e', 'n', 't', // headers.
	11, ':', 'e', 'v', 'e', 'n', 't', '-', 't', 'y', 'p', 'e', 7, 0, 3, 'E', 'n', 'd', // headers.
	207, 151, 211, 146, // message crc.
}

// Creates a new request level Error message.
func newErrorMessage(errorCode, errorMessage string) []byte {
	buf := new(bytes.Buffer)

	buf.Write([]byte{13, ':', 'm', 'e', 's', 's', 'a', 'g', 'e', '-', 't', 'y', 'p', 'e', 7, 0, 5, 'e', 'r', 'r', 'o', 'r'})

	buf.Write([]byte{14, ':', 'e', 'r', 'r', 'o', 'r', '-', 'm', 'e', 's', 's', 'a', 'g', 'e', 7})
	binary.Write(buf, binary.BigEndian, uint16(len(errorMessage)))
	buf.Write([]byte(errorMessage))

	buf.Write([]byte{11, ':', 'e', 'r', 'r', 'o', 'r', '-', 'c', 'o', 'd', 'e', 7})
	binary.Write(buf, binary.BigEndian, uint16(len(errorCode)))
	buf.Write([]byte(errorCode))

	return genMessage(buf.Bytes(), nil)
}

type GetProgress func() (int64, int64)

type MessageHandler struct {
	writer *bufio.Writer

	payloadBuffer      []byte
	payloadBufferIndex int
	payloadCh          chan *bytes.Buffer
	getProgress        GetProgress

	bytesReturned                          int64
	totalBytesScanned, totalBytesProcessed int64

	errCh  chan []byte
	doneCh chan struct{}
}

// Creates a new MessageHandler instance and starts the event streaming
func NewMessageHandler(w *bufio.Writer, getProgressFunc GetProgress) *MessageHandler {
	writer := &MessageHandler{
		writer: w,

		payloadBuffer: make([]byte, bufLength),
		payloadCh:     make(chan *bytes.Buffer, 1),
		getProgress:   getProgressFunc,

		errCh:  make(chan []byte),
		doneCh: make(chan struct{}),
	}
	go writer.start()
	return writer
}

// Writes a stream data in http response body and flushes
func (mh *MessageHandler) write(data []byte) bool {
	if _, err := mh.writer.Write(data); err != nil {
		return false
	}

	if err := mh.writer.Flush(); err != nil {
		return false
	}
	return true
}

// Starts a new go-routine which handles the event streaming
func (mh *MessageHandler) start() {
	continuationTicker := time.NewTicker(1 * time.Second)
	recordStagingTicker := time.NewTicker(500 * time.Millisecond)

	var progressTicker *time.Ticker
	var progressTickerC <-chan time.Time
	if mh.getProgress != nil {
		progressTicker = time.NewTicker(1 * time.Minute)
		progressTickerC = progressTicker.C
	}

	stopFlag := false
	for !stopFlag {
		select {
		case data := <-mh.errCh:
			stopFlag = true
			if !mh.flushRecords() {
				break
			}
			mh.write(data)

		case payload, ok := <-mh.payloadCh:
			if !ok {
				stopFlag = true

				if !mh.flushRecords() {
					break
				}

				bytesReturned := atomic.LoadInt64(&mh.bytesReturned)
				if !mh.write(newStatsMessage(mh.totalBytesScanned, mh.totalBytesProcessed, bytesReturned)) {
					break
				}
				mh.write(endMessage)
			} else {
				for payload.Len() > 0 {
					copiedLen := copy(mh.payloadBuffer[mh.payloadBufferIndex:], payload.Bytes())
					mh.payloadBufferIndex += copiedLen
					payload.Next(copiedLen)

					freeSpace := bufLength - mh.payloadBufferIndex
					if freeSpace == 0 {
						if !mh.flushRecords() {
							stopFlag = true
							break
						}
					}
				}
			}

		case <-recordStagingTicker.C:
			if !mh.flushRecords() {
				stopFlag = true
			}

		case <-continuationTicker.C:
			if !mh.write(continuationMessage) {
				stopFlag = true
			}
		case <-progressTickerC:
			bytesScanned, bytesProcessed := mh.getProgress()
			bytesReturned := atomic.LoadInt64(&mh.bytesReturned)
			if !mh.write(newProgressMessage(bytesScanned, bytesProcessed, bytesReturned)) {
				stopFlag = true
			}

		}

	}
	close(mh.doneCh)

	if progressTicker != nil {
		progressTicker.Stop()
	}
	recordStagingTicker.Stop()
	continuationTicker.Stop()
}

// Sends a single record
func (mh *MessageHandler) SendRecord(payload *bytes.Buffer) error {
	select {
	case mh.payloadCh <- payload:
		return nil
	case <-mh.doneCh:
		return fmt.Errorf("event-streaming is done")
	}
}

// Flushes the records in payloadBuffer
func (mh *MessageHandler) flushRecords() bool {
	if mh.payloadBufferIndex == 0 {
		return true
	}
	result := mh.write(newRecordsMessage(mh.payloadBuffer[0:mh.payloadBufferIndex]))
	if result {
		atomic.AddInt64(&mh.bytesReturned, int64(mh.payloadBufferIndex))
		mh.payloadBufferIndex = 0
	}
	return result
}

// Stops the event streaming, which causes a Stat then End events to be sent
func (mh *MessageHandler) Finish(bytesScanned, bytesProcessed int64) error {
	select {
	case <-mh.doneCh:
		return fmt.Errorf("event-streaming is done")
	default:
		mh.totalBytesScanned = bytesScanned
		mh.totalBytesProcessed = bytesProcessed
		close(mh.payloadCh)
		<-mh.doneCh
		return nil
	}
}

// Finishes the event streaming with error
func (mh *MessageHandler) FinishWithError(errorCode, errorMessage string) error {
	select {
	case <-mh.doneCh:
		return fmt.Errorf("event-streaming is done")
	case mh.errCh <- newErrorMessage(errorCode, errorMessage):
		<-mh.doneCh
		return nil
	}
}
