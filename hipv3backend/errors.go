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

// Package hipv3backend serves hipobj-rc-v3 transfers on the ordinary
// S3 object operations. The adapter embeds the decorated backend and
// intercepts PutObject, UploadPart, and GetObject when the request
// context carries a parsed v3 token: the data moves over RDMA to or
// from the client's registered memory region, the HTTP body stays
// empty, and the reply header reports the transferred byte count on
// success only.
package hipv3backend

import (
	"fmt"

	"github.com/versity/versitygw/s3err"
)

// rdmaTransferFailed is the s3err the adapter returns when the RDMA
// leg (dial, read, write, or deadline) fails after the request was
// otherwise fine. The HTTP mapping is 502, keeping transport errors
// distinguishable from backend errors in the access log.
func rdmaTransferFailed(stage string, err error) s3err.APIError {
	return s3err.APIError{
		Code:           "RdmaTransferFailed",
		Description:    fmt.Sprintf("The %s stage of the hipobj-rc-v3 transfer failed: %v", stage, err),
		HTTPStatusCode: 502,
	}
}
