// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
// either express or implied.
// See the License for the specific language governing permissions
// and limitations under the License.

package rcroutes

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
)

// S3 part numbers are 1..10000. The DAOS backend rejects the same range.
const (
	rcMinPartNumber = 1
	rcMaxPartNumber = 10000
)

// errUnsupportedRCQuery is a target query the RC routes do not accept.
// The caller maps every case to the same bad-request response.
var errUnsupportedRCQuery = errors.New("unsupported rc query")

// rcTargetQuery is the part upload carried by an RC target, if any.
// A target with no query is an object GET or PUT.
type rcTargetQuery struct {
	uploadID string
	number   int32
	partPut  bool
}

// classifyRCTarget parses the query of an RC target.
//
// A PUT whose query is exactly uploadId and partNumber, with a
// non-empty id and a part number in 1..10000, is a part upload.
// Any other query is rejected. A target with no query is an object
// transfer. The first '?' is the query start, matching splitTarget.
func classifyRCTarget(isPut bool, target string) (rcTargetQuery, error) {
	i := strings.IndexByte(target, '?')
	if i < 0 {
		return rcTargetQuery{}, nil
	}
	q, err := url.ParseQuery(target[i+1:])
	if err != nil || !isPut || !exactPartQuery(q) {
		return rcTargetQuery{}, errUnsupportedRCQuery
	}
	id := q.Get("uploadId")
	n, nerr := strconv.ParseInt(q.Get("partNumber"), 10, 32)
	if id == "" || nerr != nil || n < rcMinPartNumber || n > rcMaxPartNumber {
		return rcTargetQuery{}, errUnsupportedRCQuery
	}
	return rcTargetQuery{uploadID: id, number: int32(n), partPut: true}, nil
}

func exactPartQuery(q url.Values) bool {
	if len(q) != 2 {
		return false
	}
	id, okID := q["uploadId"]
	pn, okPN := q["partNumber"]
	return okID && okPN && len(id) == 1 && len(pn) == 1
}
