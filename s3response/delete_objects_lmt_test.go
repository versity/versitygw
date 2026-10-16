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

package s3response

import (
	"encoding/xml"
	"testing"
	"time"
)

func TestDeleteObjectsUnmarshalLastModifiedTime(t *testing.T) {
	want := time.Date(2026, time.October, 7, 5, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		lmt  string
	}{
		// AWS SDKs and the AWS CLI serialize LastModifiedTime as an HTTP date.
		{name: "http-date", lmt: "Wed, 07 Oct 2026 05:00:00 GMT"},
		{name: "rfc3339", lmt: "2026-10-07T05:00:00Z"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := `<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">` +
				`<Object><Key>k</Key><ETag>"abc"</ETag>` +
				`<LastModifiedTime>` + tt.lmt + `</LastModifiedTime>` +
				`<Size>5</Size></Object>` +
				`<Quiet>true</Quiet></Delete>`

			var d DeleteObjects
			if err := xml.Unmarshal([]byte(body), &d); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if len(d.Objects) != 1 {
				t.Fatalf("expected 1 object, got %d", len(d.Objects))
			}
			obj := d.Objects[0]
			if obj.Key == nil || *obj.Key != "k" {
				t.Errorf("unexpected key: %v", obj.Key)
			}
			if obj.ETag == nil || *obj.ETag != `"abc"` {
				t.Errorf("unexpected etag: %v", obj.ETag)
			}
			if obj.Size == nil || *obj.Size != 5 {
				t.Errorf("unexpected size: %v", obj.Size)
			}
			if obj.LastModifiedTime == nil || !obj.LastModifiedTime.Equal(want) {
				t.Errorf("unexpected last modified time: %v", obj.LastModifiedTime)
			}
			if !d.Quiet {
				t.Errorf("expected quiet to be true")
			}
		})
	}

	t.Run("invalid", func(t *testing.T) {
		body := `<Delete><Object><Key>k</Key>` +
			`<LastModifiedTime>not a date</LastModifiedTime></Object></Delete>`

		var d DeleteObjects
		if err := xml.Unmarshal([]byte(body), &d); err == nil {
			t.Fatalf("expected an error for an invalid last modified time")
		}
	})
}
