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
	"errors"
	"slices"
	"testing"
)

func TestSideCarReplaceObject(t *testing.T) {
	s, err := NewSideCar(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	// no metadata stored for the object
	if err := s.ReplaceObject("bucket", "obj", []string{"etag"}); err != nil {
		t.Fatalf("replace object without metadata: %v", err)
	}

	for _, attr := range []string{"etag", "checksums", "X-Amz-Tagging", "legal-hold"} {
		if err := s.StoreAttribute(nil, "bucket", "obj", attr, []byte(attr)); err != nil {
			t.Fatal(err)
		}
	}
	// the metadata of "obj/meta/child" is stored under the metadata
	// directory of "obj"
	if err := s.StoreAttribute(nil, "bucket", "obj/meta/child", "etag", []byte("child")); err != nil {
		t.Fatal(err)
	}

	if err := s.ReplaceObject("bucket", "obj", []string{"etag", "checksums"}); err != nil {
		t.Fatalf("replace object: %v", err)
	}

	for _, attr := range []string{"etag", "checksums"} {
		val, err := s.RetrieveAttribute(nil, "bucket", "obj", attr)
		if err != nil {
			t.Fatalf("kept attribute %v: %v", attr, err)
		}
		if string(val) != attr {
			t.Errorf("kept attribute %v: expected %q, got %q", attr, attr, val)
		}
	}
	for _, attr := range []string{"X-Amz-Tagging", "legal-hold"} {
		_, err := s.RetrieveAttribute(nil, "bucket", "obj", attr)
		if !errors.Is(err, ErrNoSuchKey) {
			t.Errorf("removed attribute %v: expected ErrNoSuchKey, got %v", attr, err)
		}
	}

	val, err := s.RetrieveAttribute(nil, "bucket", "obj/meta/child", "etag")
	if err != nil {
		t.Fatalf("nested object attribute: %v", err)
	}
	if string(val) != "child" {
		t.Errorf("nested object attribute: expected %q, got %q", "child", val)
	}

	attrs, err := s.ListAttributes("bucket", "obj")
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(attrs)
	if want := []string{"checksums", "child", "etag"}; !slices.Equal(attrs, want) {
		t.Errorf("expected the metadata directory entries to be %v, got %v", want, attrs)
	}
}
