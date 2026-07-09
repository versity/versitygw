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

package policy

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestStringOrSliceUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		json string
		want StringOrSlice
	}{
		{"single string", `"s3:GetObject"`, StringOrSlice{"s3:GetObject"}},
		{"array of strings", `["s3:GetObject","s3:PutObject"]`, StringOrSlice{"s3:GetObject", "s3:PutObject"}},
		{"empty array", `[]`, StringOrSlice{}},
		{"empty string", `""`, StringOrSlice{""}},
		{"null", `null`, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got StringOrSlice
			if err := json.Unmarshal([]byte(tt.json), &got); err != nil {
				t.Fatalf("Unmarshal() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Unmarshal() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestDocumentUnmarshalJSON(t *testing.T) {
	t.Run("statement as array", func(t *testing.T) {
		var doc Document
		err := json.Unmarshal([]byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`), &doc)
		if err != nil {
			t.Fatalf("Unmarshal() error = %v", err)
		}
		if len(doc.Statement) != 1 {
			t.Fatalf("got %d statements, want 1", len(doc.Statement))
		}
	})

	t.Run("statement as single object", func(t *testing.T) {
		var doc Document
		err := json.Unmarshal([]byte(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`), &doc)
		if err != nil {
			t.Fatalf("Unmarshal() error = %v", err)
		}
		if len(doc.Statement) != 1 {
			t.Fatalf("got %d statements, want 1", len(doc.Statement))
		}
	})

	t.Run("statement absent leaves nil, not an unmarshal error", func(t *testing.T) {
		var doc Document
		err := json.Unmarshal([]byte(`{"Version":"2012-10-17"}`), &doc)
		if err != nil {
			t.Fatalf("Unmarshal() error = %v", err)
		}
		if doc.Statement != nil {
			t.Fatalf("Statement = %#v, want nil", doc.Statement)
		}
	})

	t.Run("statement null leaves nil, not an unmarshal error", func(t *testing.T) {
		var doc Document
		err := json.Unmarshal([]byte(`{"Version":"2012-10-17","Statement":null}`), &doc)
		if err != nil {
			t.Fatalf("Unmarshal() error = %v", err)
		}
		if doc.Statement != nil {
			t.Fatalf("Statement = %#v, want nil", doc.Statement)
		}
	})

	t.Run("version absent leaves empty string, not defaulted", func(t *testing.T) {
		// Unlike auth's S3 bucket-policy engine (which defaults a missing
		// Version to 2008-10-17), real IAM leaves an omitted Version on an
		// identity policy exactly as submitted - no default is injected.
		var doc Document
		err := json.Unmarshal([]byte(`{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`), &doc)
		if err != nil {
			t.Fatalf("Unmarshal() error = %v", err)
		}
		if doc.Version != "" {
			t.Fatalf("Version = %q, want empty", doc.Version)
		}
	})

	t.Run("top-level non-object is an unmarshal error", func(t *testing.T) {
		var doc Document
		if err := json.Unmarshal([]byte(`"hello"`), &doc); err == nil {
			t.Fatal("Unmarshal() error = nil, want non-nil")
		}
	})
}
