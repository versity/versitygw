// Copyright 2026 Versity Software
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

//go:build !(linux && amd64 && cgo)

// Package hostclient is stubbed on platforms without RDMA verbs support.
package hostclient

import "errors"

// DefaultDCKey is the cuObjServer default Dynamic Connection key.
const DefaultDCKey uint64 = 0xffeeddcc

var errNotSupported = errors.New("hostclient: RDMA host client is only supported on linux/amd64 with cgo")

// Client is a non-functional stub on unsupported platforms.
type Client struct{}

// NewClient always returns an unsupported-platform error on this build.
func NewClient(dev string, port uint8, gidIndex int, dcKey uint64) (*Client, error) {
	return nil, errNotSupported
}

// Register always returns an unsupported-platform error on this build.
func (c *Client) Register(size int) ([]byte, error) { return nil, errNotSupported }

// Token always returns an unsupported-platform error on this build.
func (c *Client) Token() (string, error) { return "", errNotSupported }

// Buffer returns nil on this build.
func (c *Client) Buffer() []byte { return nil }

// BufferAddr returns 0 on this build.
func (c *Client) BufferAddr() uint64 { return 0 }

// Close is a no-op on this build.
func (c *Client) Close() {}
