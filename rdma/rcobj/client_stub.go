// Copyright 2026 Versity Software
// Copyright 2026 Gluesys Inc. and Jihyeon Gim
// This file is licensed under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an "AS
// IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied.  See the License for the specific language
// governing permissions and limitations under the License.

//go:build linux && amd64 && (!cgo || !hipobj || cuobjclient_host)

package rcobj

import (
	"errors"
	"fmt"
	"unsafe"
)

// errNoCgo is returned by every entry point on builds without the
// hipobj tag or without cgo.
// Build with CGO_ENABLED=1 and -tags hipobj to link libhipobj.
var errNoCgo = errors.New("rcobj: libhipobj binding requires cgo and the hipobj build tag")

type Config struct {
	ControlEndpoint     string
	DeviceIndex         int
	NicHint             string
	ConnectDeadlineMs   uint32
	TransferDeadlineMs  uint32
	CancelCleanupBudget uint32

	Credentials Credentials
	Region      string

	// ProbeBucket/ProbeKey name the readable object the
	// admission probe reads. They must be set here, before the
	// client is constructed: an empty probe object leaves
	// admission fail-closed and every PREPARE fails.
	ProbeBucket string
	ProbeKey    string
}

type Credentials struct {
	AccessKey    string
	SecretKey    string
	SessionToken string
	Region       string
}

type Client struct{}

func Init(cfg Config) (*Client, error)                            { return nil, errNoCgo }
func (c *Client) Shutdown() error                                 { return errNoCgo }
func (c *Client) RegisterBuffer(p unsafe.Pointer, s uint64) error { return errNoCgo }
func (c *Client) DeregisterBuffer(p unsafe.Pointer) error         { return errNoCgo }
func (c *Client) Get(bucket, key string, devPtr unsafe.Pointer,
	size, offset uint64, query string) error {
	return errNoCgo
}
func (c *Client) Put(bucket, key string, devPtr unsafe.Pointer,
	size, offset uint64, query string) error {
	return errNoCgo
}

func NotSupported(err error) bool { return false }

// Valloc/Free are host-memory helpers; the stub cannot allocate
// C memory without cgo, so callers fail at Init instead.
func Valloc(size int) unsafe.Pointer { return nil }
func Free(p unsafe.Pointer)          {}

// Device-memory helpers: the stub has no HIP runtime linkage, so
// allocation fails and the copy helpers report the same condition.
func VallocDev(size int) (unsafe.Pointer, error) {
	return nil, errNoCgo
}
func FreeDev(p unsafe.Pointer) error { return errNoCgo }
func CopyDevHostToDev(dst unsafe.Pointer, src []byte) error {
	return errNoCgo
}
func CopyDevDevToHost(dst []byte, src unsafe.Pointer) error {
	return errNoCgo
}

type OpError struct {
	Op       string
	Code     int
	HipError int
}

func (e *OpError) Error() string {
	return fmt.Sprintf("%s: op error %d (hip %d)", e.Op, e.Code, e.HipError)
}
