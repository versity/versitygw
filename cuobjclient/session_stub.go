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

package cuobjclient

import (
	"fmt"

	s3lib "github.com/aws/aws-sdk-go-v2/service/s3"
)

// Session is a non-Linux stub so packages compile on unsupported platforms.
type Session struct{}

// NewSession always returns an unsupported-platform error on this build.
//
// On supported platforms, sessions are intended to be reused for multiple
// sequential transfers and are not safe for concurrent use by multiple
// goroutines.
func NewSession(size int) (*Session, error) {
	if size <= 0 {
		return nil, fmt.Errorf("invalid size %d", size)
	}
	if size > MaxTransferSize {
		return nil, fmt.Errorf("invalid size %d: exceeds MaxTransferSize (%d)", size, MaxTransferSize)
	}
	return nil, fmt.Errorf("cuobjclient: NewSession is only supported on linux/amd64 with cgo")
}

// Close is a no-op in the unsupported-platform stub.
func (s *Session) Close() {
	_ = s
}

// Upload always returns an unsupported-platform error on this build.
func (s *Session) Upload(base *s3lib.Client, bucket, key string, src []byte) error {
	_ = s
	_ = base
	_ = bucket
	_ = key
	_ = src
	return fmt.Errorf("cuobjclient: Upload is only supported on linux/amd64 with cgo")
}

// Download always returns an unsupported-platform error on this build.
func (s *Session) Download(base *s3lib.Client, bucket, key string, dst []byte) error {
	_ = s
	_ = base
	_ = bucket
	_ = key
	_ = dst
	return fmt.Errorf("cuobjclient: Download is only supported on linux/amd64 with cgo")
}
