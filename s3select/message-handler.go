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
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"hash/crc32"
	"sync"
	"sync/atomic"
	"time"
)

// Protocol definition for messages can be found here:
// https://docs.aws.amazon.com/AmazonS3/latest/API/RESTSelectObjectAppendix.html

var (
	// From ptotocol def:
	// Enum indicating the header value type.
	// For Amazon S3 Select, this is always 7.
	headerValueType = byte(7)
)

func intToTwoBytes(i int) []byte {
	return []byte{byte(i >> 8), byte(i)}
}

func generateHeader(messages ...string) []byte {
	var header []byte

	for i, message := range messages {
		if i%2 == 1 {
			header = append(header, headerValueType)
			header = append(header, intToTwoBytes(len(message))...)
		} else {
			header = append(header, byte(len(message)))
		}
		header = append(header, message...)
	}

	return header
}

func generateOctetHeader(message string) []byte {
	return generateHeader(
		":message-type",
		"event",
		":content-type",
		"application/octet-stream",
		":event-type",
		message)
}

func generateTextHeader(message string) []byte {
	return generateHeader(
		":message-type",
		"event",
		":content-type",
		"text/xml",
		":event-type",
		message)
}

func generateNoContentHeader(message string) []byte {
	return generateHeader(
		":message-type",
		"event",
		":event-type",
		message)
}

const (
	// 4 bytes total byte len +
	// 4 bytes headers bytes len +
	// 4 bytes prelude CRC
	preludeLen = 12
	// CRC is uint32
	msgCrcLen = 4
)

var (
	recordsHeader       = generateOctetHeader("Records")
	continuationHeader  = generateNoContentHeader("Cont")
	continuationMessage = genMessage(continuationHeader, []byte{})
	progressHeader      = generateTextHeader("Progress")
	statsHeader         = generateTextHeader("Stats")
	endHeader           = generateNoContentHeader("End")
	endMessage          = genMessage(endHeader, []byte{})
)

func uintToBytes(n uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	return b
}

func generatePrelude(msgLen int, headerLen int) []byte {
	prelude := make([]byte, 0, preludeLen)

	// 4 bytes total byte len
	prelude = append(prelude, uintToBytes(uint32(msgLen+headerLen+preludeLen+msgCrcLen))...)
	// 4 bytes headers bytes len
	prelude = append(prelude, uintToBytes(uint32(headerLen))...)
	// 4 bytes prelude CRC
	prelude = append(prelude, uintToBytes(crc32.ChecksumIEEE(prelude))...)

	return prelude
}

const (
	maxHeaderSize = 1024 * 1024
)

func genMessage(header, payload []byte) []byte {
	var msg []byte
	// below is always true since the size is validated
	// in the send record
	if len(header) <= maxHeaderSize && len(payload) <= maxMessageSize {
		msglen := preludeLen + len(header) + len(payload) + msgCrcLen
		msg = make([]byte, 0, msglen)
	}

	msg = append(msg, generatePrelude(len(payload), len(header))...)
	msg = append(msg, header...)
	msg = append(msg, payload...)
	msg = append(msg, uintToBytes(crc32.ChecksumIEEE(msg))...)

	return msg
}

func genRecordsMessage(payload []byte) []byte {
	return genMessage(recordsHeader, payload)
}

type progress struct {
	XMLName        xml.Name `xml:"Progress"`
	BytesScanned   int64    `xml:"BytesScanned"`
	BytesProcessed int64    `xml:"BytesProcessed"`
	BytesReturned  int64    `xml:"BytesReturned"`
}

func genProgressMessage(bytesScanned, bytesProcessed, bytesReturned int64) []byte {
	progress := progress{
		BytesScanned:   bytesScanned,
		BytesProcessed: bytesProcessed,
		BytesReturned:  bytesReturned,
	}

	xmlData, _ := xml.MarshalIndent(progress, "", "    ")
	payload := []byte(xml.Header + string(xmlData))
	return genMessage(progressHeader, payload)
}

type stats struct {
	XMLName        xml.Name `xml:"Stats"`
	BytesScanned   int64    `xml:"BytesScanned"`
	BytesProcessed int64    `xml:"BytesProcessed"`
	BytesReturned  int64    `xml:"BytesReturned"`
}

func genStatsMessage(bytesScanned, bytesProcessed, bytesReturned int64) []byte {
	stats := stats{
		BytesScanned:   bytesScanned,
		BytesProcessed: bytesProcessed,
		BytesReturned:  bytesReturned,
	}

	xmlData, _ := xml.MarshalIndent(stats, "", "    ")
	payload := []byte(xml.Header + string(xmlData))
	return genMessage(statsHeader, payload)
}

func genErrorMessage(errorCode, errorMessage string) []byte {
	return genMessage(generateHeader(
		":error-code",
		errorCode,
		":error-message",
		errorMessage,
		":message-type",
		"error",
	), []byte{})
}

// GetProgress is a callback function that periodically retrieves the current
// values for the following if not nil.  This is used to send Progress
// messages back to client.
// BytesScanned => Number of bytes that have been processed before being uncompressed (if the file is compressed).
// BytesProcessed => Number of bytes that have been processed after being uncompressed (if the file is compressed).
type GetProgress func() (bytesScanned int64, bytesProcessed int64)

type MessageHandler struct {
	sync.Mutex
	ctx           context.Context
	cancel        context.CancelFunc
	writer        *bufio.Writer
	data          chan []byte
	getProgress   GetProgress
	stopCh        chan bool
	resetCh       chan bool
	bytesReturned int64
}

// NewMessageHandler creates a new MessageHandler instance and starts the event streaming
func NewMessageHandler(ctx context.Context, w *bufio.Writer, getProgressFunc GetProgress) *MessageHandler {
	ctx, cancel := context.WithCancel(ctx)

	mh := &MessageHandler{
		ctx:         ctx,
		cancel:      cancel,
		writer:      w,
		data:        make(chan []byte),
		getProgress: getProgressFunc,
		resetCh:     make(chan bool),
		stopCh:      make(chan bool),
	}

	go mh.sendBackgroundMessages(mh.resetCh, mh.stopCh)
	return mh
}

func (mh *MessageHandler) write(data []byte) error {
	mh.Lock()
	defer mh.Unlock()

	mh.stopCh <- true
	defer func() { mh.resetCh <- true }()

	_, err := mh.writer.Write(data)
	if err != nil {
		return err
	}

	return mh.writer.Flush()
}

const (
	continuationInterval = time.Second
	progressInterval     = time.Minute
)

func (mh *MessageHandler) sendBackgroundMessages(resetCh, stopCh <-chan bool) {
	continuationTicker := time.NewTicker(continuationInterval)
	defer continuationTicker.Stop()

	var progressTicker *time.Ticker
	var progressTickerChan <-chan time.Time
	if mh.getProgress != nil {
		progressTicker = time.NewTicker(progressInterval)
		progressTickerChan = progressTicker.C
		defer progressTicker.Stop()
	}

Loop:
	for {
		select {
		case <-mh.ctx.Done():
			break Loop

		case <-continuationTicker.C:
			err := mh.write(continuationMessage)
			if err != nil {
				mh.cancel()
				break Loop
			}

		case <-resetCh:
			continuationTicker.Reset(continuationInterval)

		case <-stopCh:
			continuationTicker.Stop()

		case <-progressTickerChan:
			var bytesScanned, bytesProcessed int64
			if mh.getProgress != nil {
				bytesScanned, bytesProcessed = mh.getProgress()
			}
			bytesReturned := atomic.LoadInt64(&mh.bytesReturned)
			err := mh.write(genProgressMessage(bytesScanned, bytesProcessed, bytesReturned))
			if err != nil {
				mh.cancel()
				break Loop
			}
		}
	}
}

// SendRecord sends a single Records message
func (mh *MessageHandler) SendRecord(payload []byte) error {
	if mh.ctx.Err() != nil {
		return mh.ctx.Err()
	}

	if len(payload) > maxMessageSize {
		return fmt.Errorf("record max size exceeded")
	}

	err := mh.write(genRecordsMessage(payload))
	if err != nil {
		return err
	}

	atomic.AddInt64(&mh.bytesReturned, int64(len(payload)))
	return nil
}

// Finish terminates message stream with Stats and End message
// generates stats and end message using function args based on:
// BytesScanned => Number of bytes that have been processed before being uncompressed (if the file is compressed).
// BytesProcessed => Number of bytes that have been processed after being uncompressed (if the file is compressed).
func (mh *MessageHandler) Finish(bytesScanned, bytesProcessed int64) error {
	if mh.ctx.Err() != nil {
		return mh.ctx.Err()
	}

	bytesReturned := atomic.LoadInt64(&mh.bytesReturned)
	err := mh.write(genStatsMessage(bytesScanned, bytesProcessed, bytesReturned))
	if err != nil {
		return err
	}

	err = mh.write(endMessage)
	if err != nil {
		return err
	}

	mh.cancel()
	return nil
}

// FinishWithError terminates event stream with error
func (mh *MessageHandler) FinishWithError(errorCode, errorMessage string) error {
	if mh.ctx.Err() != nil {
		return mh.ctx.Err()
	}
	err := mh.write(genErrorMessage(errorCode, errorMessage))
	if err != nil {
		return err
	}

	mh.cancel()
	return nil
}
