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
	"errors"
	"testing"
	"time"

	"github.com/versity/versitygw/s3err"
)

func TestDeleteObjectsUnmarshalLastModifiedTime(t *testing.T) {
	want := time.Date(2026, time.October, 7, 5, 0, 0, 0, time.UTC)

	valid := []struct {
		name string
		lmt  string
	}{
		// AWS SDKs and the AWS CLI send this form.
		{name: "http date", lmt: "Wed, 07 Oct 2026 05:00:00 GMT"},
		{name: "rfc 850", lmt: "Wednesday, 07-Oct-26 05:00:00 GMT"},
		{name: "ansic", lmt: "Wed Oct  7 05:00:00 2026"},
		{name: "single digit day", lmt: "Wed, 7 Oct 2026 05:00:00 GMT"},
		{name: "zero offset", lmt: "Wed, 07 Oct 2026 05:00:00 +0000"},
		{name: "numeric offset", lmt: "Wed, 07 Oct 2026 07:00:00 +0200"},
		{name: "padded", lmt: "  Wed, 07 Oct 2026 05:00:00 GMT  "},
	}

	for _, tt := range valid {
		t.Run(tt.name, func(t *testing.T) {
			body := `<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">` +
				`<Object><Key>k</Key><ETag>"abc"</ETag>` +
				`<LastModifiedTime>` + tt.lmt + `</LastModifiedTime>` +
				`<Size>5</Size><VersionId>v1</VersionId></Object>` +
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
			if obj.VersionId == nil || *obj.VersionId != "v1" {
				t.Errorf("unexpected version id: %v", obj.VersionId)
			}
			if obj.LastModifiedTime == nil || !obj.LastModifiedTime.Equal(want) {
				t.Errorf("unexpected last modified time: %v", obj.LastModifiedTime)
			}
			if !d.Quiet {
				t.Errorf("expected quiet to be true")
			}
		})
	}

	malformed := s3err.GetAPIError(s3err.ErrMalformedXML)
	invalid := []struct {
		name    string
		objects string
		want    s3err.APIError
	}{
		// S3 rejects RFC 3339 here.
		{
			name:    "rfc3339",
			objects: `<Object><Key>k</Key><LastModifiedTime>2026-10-07T05:00:00Z</LastModifiedTime></Object>`,
			want:    s3err.GetInvalidDateAttributeErr("2026-10-07T05:00:00Z"),
		},
		{
			name:    "not a date",
			objects: `<Object><Key>k</Key><LastModifiedTime>not a date</LastModifiedTime></Object>`,
			want:    s3err.GetInvalidDateAttributeErr("not a date"),
		},
		{
			name:    "padded value echoed as sent",
			objects: `<Object><Key>k</Key><LastModifiedTime>  not a date  </LastModifiedTime></Object>`,
			want:    s3err.GetInvalidDateAttributeErr("  not a date  "),
		},
		{
			name: "first invalid date reported",
			objects: `<Object><Key>a</Key><LastModifiedTime>first</LastModifiedTime></Object>` +
				`<Object><Key>b</Key><LastModifiedTime>second</LastModifiedTime></Object>`,
			want: s3err.GetInvalidDateAttributeErr("first"),
		},
		{
			name:    "empty",
			objects: `<Object><Key>k</Key><LastModifiedTime></LastModifiedTime></Object>`,
			want:    malformed,
		},
		{
			name:    "whitespace only",
			objects: `<Object><Key>k</Key><LastModifiedTime>   </LastModifiedTime></Object>`,
			want:    malformed,
		},
		{
			name:    "self-closing",
			objects: `<Object><Key>k</Key><LastModifiedTime/></Object>`,
			want:    malformed,
		},
		{
			name: "empty wins over an earlier invalid date",
			objects: `<Object><Key>a</Key><LastModifiedTime>not a date</LastModifiedTime></Object>` +
				`<Object><Key>b</Key><LastModifiedTime></LastModifiedTime></Object>`,
			want: malformed,
		},
	}

	for _, tt := range invalid {
		t.Run(tt.name, func(t *testing.T) {
			var d DeleteObjects
			err := xml.Unmarshal([]byte(`<Delete>`+tt.objects+`</Delete>`), &d)
			var apiErr s3err.APIError
			if !errors.As(err, &apiErr) || apiErr != tt.want {
				t.Fatalf("expected %v, got %v", tt.want, err)
			}
		})
	}
}
