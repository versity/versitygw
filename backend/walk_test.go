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

package backend_test

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io/fs"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3response"
)

type walkTest struct {
	fsys     fs.FS
	expected backend.WalkResults
	getobj   backend.GetObjFunc
}

func getObj(path string, d fs.DirEntry) (s3response.Object, error) {
	if d.IsDir() {
		etag := getMD5(path)

		fi, err := d.Info()
		if err != nil {
			return s3response.Object{}, fmt.Errorf("get fileinfo: %w", err)
		}
		mtime := fi.ModTime()

		return s3response.Object{
			ETag:         &etag,
			Key:          &path,
			LastModified: &mtime,
		}, nil
	}

	etag := getMD5(path)

	fi, err := d.Info()
	if err != nil {
		return s3response.Object{}, fmt.Errorf("get fileinfo: %w", err)
	}

	size := fi.Size()
	mtime := fi.ModTime()

	return s3response.Object{
		ETag:         &etag,
		Key:          &path,
		LastModified: &mtime,
		Size:         &size,
	}, nil
}

func getMD5(text string) string {
	hash := md5.Sum([]byte(text))
	return hex.EncodeToString(hash[:])
}

func TestWalk(t *testing.T) {
	tests := []walkTest{
		{
			// test case from
			// https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-prefixes.html
			fsys: fstest.MapFS{
				"sample.jpg":                       {},
				"photos/2006/January/sample.jpg":   {},
				"photos/2006/February/sample2.jpg": {},
				"photos/2006/February/sample3.jpg": {},
				"photos/2006/February/sample4.jpg": {},
			},
			expected: backend.WalkResults{
				CommonPrefixes: []types.CommonPrefix{{
					Prefix: backend.GetStringPtr("photos/"),
				}},
				Objects: []s3response.Object{{
					Key: backend.GetStringPtr("sample.jpg"),
				}},
			},
			getobj: getObj,
		},
		{
			// test case single dir/single file
			fsys: fstest.MapFS{
				"test/file": {},
			},
			expected: backend.WalkResults{
				CommonPrefixes: []types.CommonPrefix{{
					Prefix: backend.GetStringPtr("test/"),
				}},
				Objects: []s3response.Object{},
			},
			getobj: getObj,
		},
	}

	for _, tt := range tests {
		res, err := backend.Walk(context.Background(), tt.fsys, "", "/", "", 1000, tt.getobj, []string{})
		if err != nil {
			t.Fatalf("walk: %v", err)
		}

		compareResults(res, tt.expected, t)
	}
}

func compareResults(got, wanted backend.WalkResults, t *testing.T) {
	if !compareCommonPrefix(got.CommonPrefixes, wanted.CommonPrefixes) {
		t.Errorf("unexpected common prefix, got %v wanted %v",
			printCommonPrefixes(got.CommonPrefixes),
			printCommonPrefixes(wanted.CommonPrefixes))
	}

	if !compareObjects(got.Objects, wanted.Objects) {
		t.Errorf("unexpected object, got %v wanted %v",
			printObjects(got.Objects),
			printObjects(wanted.Objects))
	}
}

func compareCommonPrefix(a, b []types.CommonPrefix) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	if len(a) != len(b) {
		return false
	}

	for _, cp := range a {
		if containsCommonPrefix(cp, b) {
			return true
		}
	}
	return false
}

func containsCommonPrefix(c types.CommonPrefix, list []types.CommonPrefix) bool {
	for _, cp := range list {
		if *c.Prefix == *cp.Prefix {
			return true
		}
	}
	return false
}

func printCommonPrefixes(list []types.CommonPrefix) string {
	res := "["
	for _, cp := range list {
		if res == "[" {
			res = res + *cp.Prefix
		} else {
			res = res + ", " + *cp.Prefix
		}
	}
	return res + "]"
}

func compareObjects(a, b []s3response.Object) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	if len(a) != len(b) {
		return false
	}

	for _, cp := range a {
		if containsObject(cp, b) {
			return true
		}
	}
	return false
}

func containsObject(c s3response.Object, list []s3response.Object) bool {
	for _, cp := range list {
		if *c.Key == *cp.Key {
			return true
		}
	}
	return false
}

func printObjects(list []s3response.Object) string {
	res := "["
	for _, cp := range list {
		if res == "[" {
			res = res + *cp.Key
		} else {
			res = res + ", " + *cp.Key
		}
	}
	return res + "]"
}

type slowFS struct {
	fstest.MapFS
}

const (
	readDirPause = 100 * time.Millisecond

	// walkTimeOut should be less than the tree traversal time
	// which is the readdirPause time * the number of directories
	walkTimeOut = 500 * time.Millisecond
)

func (s *slowFS) ReadDir(name string) ([]fs.DirEntry, error) {
	time.Sleep(readDirPause)
	return s.MapFS.ReadDir(name)
}

func TestWalkStop(t *testing.T) {
	s := &slowFS{MapFS: fstest.MapFS{
		"/a/b/c/d/e/f/g/h/i/g/k/l/m/n": &fstest.MapFile{},
	}}

	ctx, cancel := context.WithTimeout(context.Background(), walkTimeOut)
	defer cancel()

	var err error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err = backend.Walk(ctx, s, "", "/", "", 1000,
			func(path string, d fs.DirEntry) (s3response.Object, error) {
				return s3response.Object{}, nil
			}, []string{})
	}()

	select {
	case <-time.After(1 * time.Second):
		t.Fatalf("walk is not terminated in time")
	case <-ctx.Done():
	}
	wg.Wait()
	if err != ctx.Err() {
		t.Fatalf("unexpected error: %v", err)
	}
}
