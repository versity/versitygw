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

package s3err

import "time"

// NotModifiedError is returned when a read precondition answers 304 Not Modified.
// ETag and LastModified are the object's, which the 304 response repeats
// (RFC 9110, section 15.4.5).
type NotModifiedError struct {
	APIError
	ETag         string
	LastModified time.Time
}

func (e NotModifiedError) Is(target error) bool {
	t, ok := target.(APIError)
	return ok && e.APIError == t
}

func GetNotModifiedErr(etag string, lastModified time.Time) NotModifiedError {
	return NotModifiedError{
		APIError:     GetAPIError(ErrNotModified),
		ETag:         etag,
		LastModified: lastModified,
	}
}
