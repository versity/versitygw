// Copyright 2023 Versity Software
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

package posix

import (
	"context"
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/versity/versitygw/backend/meta"
)

func TestListBucketsAndOwnersBucketLinks(t *testing.T) {
	a := assert.New(t)
	type link struct {
		from string
		to   string
	}
	testCases := []struct {
		name     string
		dirs     []string
		files    []string
		links    []link
		expected []string
	}{
		{"empty", []string{}, []string{}, nil, []string{}},
		{"single", []string{"abucket"}, []string{}, nil, []string{"abucket"}},
		{"basic three", []string{"ccc", "bbb", "aaa"}, []string{}, nil, []string{"aaa", "bbb", "ccc"}},
		{"case sensitive", []string{"Ccc", "bBb", "aaA"}, []string{}, nil, []string{"Ccc", "aaA", "bBb"}},
		{"link to single dir", []string{"frombucket"}, []string{}, []link{{"frombucket", "tobucket"}}, []string{"frombucket", "tobucket"}},
		{"link to single file", []string{}, []string{"fromfile"}, []link{{"fromfile", "tofile"}}, []string{}},
		{"link to non-existent", []string{}, []string{}, []link{{"doesnotexist", "tofile"}}, []string{}},
	}

	ctx := context.Background()
	var err error

	for _, tc := range testCases {
		gwDir := t.TempDir()

		t.Logf("%s: working in gw dir [%s]", tc.name, gwDir)
		os.Chdir(gwDir)
		for _, dir := range tc.dirs {
			err = os.Mkdir(dir, 0755)
			if err != nil {
				t.Fatalf("Failed to setup test: Mkdir err %s", err)
			}
		}
		for _, file := range tc.files {
			f, err := os.Create(file)
			if err != nil {
				t.Fatalf("Failed to setup test: Mkdir err %s", err)
			}
			f.Close()
		}
		for _, link := range tc.links {
			err = os.Symlink(link.from, link.to)
			if err != nil {
				t.Fatalf("Failed to setup test: Link err %s", err)
			}
		}

		meta := meta.XattrMeta{}
		var opts PosixOpts

		opts.BucketLinks = true

		p, err := New(gwDir, meta, opts)
		if err != nil {
			t.Errorf("Can't create posix backend")
		}
		resp, err := p.ListBucketsAndOwners(ctx)
		if err != nil {
			t.Fatalf("ListBucketsAndOwners failed: %s", err)
		}
		got := make([]string, 0)
		for _, bucket := range resp {
			got = append(got, bucket.Name)
		}
		sort.Strings(got)
		a.Equal(tc.expected, got)
	}
}
