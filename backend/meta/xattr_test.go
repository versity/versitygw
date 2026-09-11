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

package meta

import (
	"path/filepath"
	"testing"
)

func TestXattrMetaPath(t *testing.T) {
	root := t.TempDir()
	abs := filepath.Join(t.TempDir(), "versions", "bucket")

	tests := []struct {
		name    string
		x       XattrMeta
		bucket  string
		object  string
		want    string
		wantErr bool
	}{
		{name: "bucket under root", x: XattrMeta{}.WithRootDir(root).(XattrMeta), bucket: "b", object: "", want: filepath.Join(root, "b")},
		{name: "object under root", x: XattrMeta{}.WithRootDir(root).(XattrMeta), bucket: "b", object: "d/o", want: filepath.Join(root, "b", "d", "o")},
		{name: "absolute bucket ignores root", x: XattrMeta{}.WithRootDir(root).(XattrMeta), bucket: abs, object: "o", want: filepath.Join(abs, "o")},
		{name: "absolute bucket without root", x: XattrMeta{}, bucket: abs, object: "o", want: filepath.Join(abs, "o")},
		{name: "relative bucket without root is cwd-relative", x: XattrMeta{}, bucket: "b", object: "o", want: filepath.Join("b", "o")},
		{name: "empty bucket", x: XattrMeta{}.WithRootDir(root).(XattrMeta), bucket: "", object: "o", wantErr: true},
		{name: "dot bucket", x: XattrMeta{}.WithRootDir(root).(XattrMeta), bucket: ".", object: "", wantErr: true},
		{name: "dotdot bucket", x: XattrMeta{}.WithRootDir(root).(XattrMeta), bucket: "..", object: "", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.x.path(tc.bucket, tc.object)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("path(%q, %q) = %q, want error", tc.bucket, tc.object, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("path(%q, %q): %v", tc.bucket, tc.object, err)
			}
			if got != tc.want {
				t.Fatalf("path(%q, %q) = %q, want %q", tc.bucket, tc.object, got, tc.want)
			}
		})
	}
}
