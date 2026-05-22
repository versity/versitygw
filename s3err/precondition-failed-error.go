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

import "encoding/xml"

type Condition string

const (
	ConditionIfMatch              Condition = "If-Match"
	ConditionIfNoneMatch          Condition = "If-None-Match"
	ConditionIfUnmodifiedSince    Condition = "If-Unmodified-Since"
	ConditionIfMatchSize          Condition = "If-Match-Size"
	ConditionIfMatchInitiatedTime Condition = "If-Match-Initiated-Time"
	ConditionIfMatchLastModTime   Condition = "If-Match-Last-Mod-Time"
	ConditionPostBucket           Condition = "Bucket POST must be of the enclosure-type multipart/form-data"
)

// PreconditionFailedError is returned when a conditional request precondition is not met.
// Produces a <Condition> field in the XML response.
type PreconditionFailedError struct {
	APIError
	Condition Condition
}

func (e PreconditionFailedError) XMLBody(requestID, hostID string) []byte {
	return encodeResponse(struct {
		XMLName   xml.Name `xml:"Error"`
		Code      string
		Message   string
		Condition Condition `xml:",omitempty"`
		RequestID string    `xml:"RequestId,omitempty"`
		HostID    string    `xml:"HostId,omitempty"`
	}{
		Code:      e.Code,
		Message:   e.Description,
		Condition: e.Condition,
		RequestID: requestID,
		HostID:    hostID,
	})
}

func (e PreconditionFailedError) Is(target error) bool {
	t, ok := target.(APIError)
	return ok && e.APIError == t
}

func GetPreconditionFailedErr(condition Condition) PreconditionFailedError {
	return PreconditionFailedError{
		APIError:  GetAPIError(ErrPreconditionFailed),
		Condition: condition,
	}
}
