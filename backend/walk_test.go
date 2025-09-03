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
	fsys   fs.FS
	getobj backend.GetObjFunc
	cases  []testcase
}

type testcase struct {
	name      string
	prefix    string
	delimiter string
	marker    string
	maxObjs   int32
	expected  backend.WalkResults
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
			getobj: getObj,
			cases: []testcase{
				{
					name:      "aws example",
					delimiter: "/",
					maxObjs:   1000,
					expected: backend.WalkResults{
						CommonPrefixes: []types.CommonPrefix{{
							Prefix: backend.GetPtrFromString("photos/"),
						}},
						Objects: []s3response.Object{{
							Key: backend.GetPtrFromString("sample.jpg"),
						}},
					},
				},
				{
					name:      "max objs",
					delimiter: "/",
					prefix:    "photos/2006/February/",
					maxObjs:   2,
					expected: backend.WalkResults{
						Objects: []s3response.Object{
							{
								Key: backend.GetPtrFromString("photos/2006/February/sample2.jpg"),
							},
							{
								Key: backend.GetPtrFromString("photos/2006/February/sample3.jpg"),
							},
						},
					},
				},
			},
		},
		{
			// test case single dir/single file
			fsys: fstest.MapFS{
				"test/file": {},
			},
			getobj: getObj,
			cases: []testcase{
				{
					name:      "single dir single file",
					delimiter: "/",
					maxObjs:   1000,
					expected: backend.WalkResults{
						CommonPrefixes: []types.CommonPrefix{{
							Prefix: backend.GetPtrFromString("test/"),
						}},
						Objects: []s3response.Object{},
					},
				},
			},
		},
		{
			// non-standard delimiter
			fsys: fstest.MapFS{
				"photo|s/200|6/Januar|y/sampl|e1.jpg": {},
				"photo|s/200|6/Januar|y/sampl|e2.jpg": {},
				"photo|s/200|6/Januar|y/sampl|e3.jpg": {},
			},
			getobj: getObj,
			cases: []testcase{
				{
					name:      "different delimiter 1",
					delimiter: "|",
					maxObjs:   1000,
					expected: backend.WalkResults{
						CommonPrefixes: []types.CommonPrefix{{
							Prefix: backend.GetPtrFromString("photo|"),
						}},
					},
				},
				{
					name:      "different delimiter 2",
					delimiter: "|",
					maxObjs:   1000,
					prefix:    "photo|",
					expected: backend.WalkResults{
						CommonPrefixes: []types.CommonPrefix{{
							Prefix: backend.GetPtrFromString("photo|s/200|"),
						}},
					},
				},
				{
					name:      "different delimiter 3",
					delimiter: "|",
					maxObjs:   1000,
					prefix:    "photo|s/200|",
					expected: backend.WalkResults{
						CommonPrefixes: []types.CommonPrefix{{
							Prefix: backend.GetPtrFromString("photo|s/200|6/Januar|"),
						}},
					},
				},
				{
					name:      "different delimiter 4",
					delimiter: "|",
					maxObjs:   1000,
					prefix:    "photo|s/200|",
					expected: backend.WalkResults{
						CommonPrefixes: []types.CommonPrefix{{
							Prefix: backend.GetPtrFromString("photo|s/200|6/Januar|"),
						}},
					},
				},
				{
					name:      "different delimiter 5",
					delimiter: "|",
					maxObjs:   1000,
					prefix:    "photo|s/200|6/Januar|",
					expected: backend.WalkResults{
						CommonPrefixes: []types.CommonPrefix{{
							Prefix: backend.GetPtrFromString("photo|s/200|6/Januar|y/sampl|"),
						}},
					},
				},
				{
					name:      "different delimiter 6",
					delimiter: "|",
					maxObjs:   1000,
					prefix:    "photo|s/200|6/Januar|y/sampl|",
					expected: backend.WalkResults{
						Objects: []s3response.Object{
							{
								Key: backend.GetPtrFromString("photo|s/200|6/Januar|y/sampl|e1.jpg"),
							},
							{
								Key: backend.GetPtrFromString("photo|s/200|6/Januar|y/sampl|e2.jpg"),
							},
							{
								Key: backend.GetPtrFromString("photo|s/200|6/Januar|y/sampl|e3.jpg"),
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		for _, tc := range tt.cases {
			res, err := backend.Walk(context.Background(),
				tt.fsys, tc.prefix, tc.delimiter, tc.marker, tc.maxObjs,
				tt.getobj, []string{})
			if err != nil {
				t.Errorf("%v: walk: %v", tc.name, err)
			}

			compareResults(tc.name, res, tc.expected, t)
		}
	}
}

func compareResults(name string, got, wanted backend.WalkResults, t *testing.T) {
	if !compareCommonPrefix(got.CommonPrefixes, wanted.CommonPrefixes) {
		t.Errorf("%v: unexpected common prefix, got %v wanted %v",
			name,
			printCommonPrefixes(got.CommonPrefixes),
			printCommonPrefixes(wanted.CommonPrefixes))
	}

	if !compareObjects(got.Objects, wanted.Objects) {
		t.Errorf("%v: unexpected object, got %v wanted %v",
			name,
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
		var key string
		if cp.Key == nil {
			key = "<nil>"
		} else {
			key = *cp.Key
		}
		if res == "[" {
			res = res + key
		} else {
			res = res + ", " + key
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

// TestOrderWalk tests the lexicographic ordering of the object names
// for the case where readdir sort order of a directory is different
// than the lexicographic ordering of the full paths. The below has
// a readdir sort order for dir1/:
// a, a.b
// but if you consider the character that comes after a is "/", then
// the "." should come before "/" in the lexicographic ordering:
// a.b/, a/
func TestOrderWalk(t *testing.T) {
	tests := []walkTest{
		{
			fsys: fstest.MapFS{
				"dir1/a/file1":   {},
				"dir1/a/file2":   {},
				"dir1/a/file3":   {},
				"dir1/a.b/file1": {},
				"dir1/a.b/file2": {},
			},
			getobj: getObj,
			cases: []testcase{
				{
					name:    "order test",
					maxObjs: 1000,
					prefix:  "dir1/",
					expected: backend.WalkResults{
						Objects: []s3response.Object{
							{
								Key: backend.GetPtrFromString("dir1/"),
							},
							{
								Key: backend.GetPtrFromString("dir1/a.b/"),
							},
							{
								Key: backend.GetPtrFromString("dir1/a.b/file1"),
							},
							{
								Key: backend.GetPtrFromString("dir1/a.b/file2"),
							},
							{
								Key: backend.GetPtrFromString("dir1/a/"),
							},
							{
								Key: backend.GetPtrFromString("dir1/a/file1"),
							},
							{
								Key: backend.GetPtrFromString("dir1/a/file2"),
							},
							{
								Key: backend.GetPtrFromString("dir1/a/file3"),
							},
						},
					},
				},
			},
		},
		{
			fsys: fstest.MapFS{
				"dir|1/a/file1":   {},
				"dir|1/a/file2":   {},
				"dir|1/a/file3":   {},
				"dir|1/a.b/file1": {},
				"dir|1/a.b/file2": {},
			},
			getobj: getObj,
			cases: []testcase{
				{
					name:      "order test delim",
					maxObjs:   1000,
					delimiter: "|",
					prefix:    "dir|",
					expected: backend.WalkResults{
						Objects: []s3response.Object{
							{
								Key: backend.GetPtrFromString("dir|1/a.b/file1"),
							},
							{
								Key: backend.GetPtrFromString("dir|1/a.b/file2"),
							},
							{
								Key: backend.GetPtrFromString("dir|1/a/file1"),
							},
							{
								Key: backend.GetPtrFromString("dir|1/a/file2"),
							},
							{
								Key: backend.GetPtrFromString("dir|1/a/file3"),
							},
						},
					},
				},
			},
		},
		{
			fsys: fstest.MapFS{
				"a": &fstest.MapFile{Mode: fs.ModeDir},
			},
			getobj: getObj,
			cases: []testcase{
				{
					name:      "single dir obj",
					maxObjs:   1000,
					delimiter: "/",
					prefix:    "a",
					expected: backend.WalkResults{
						CommonPrefixes: []types.CommonPrefix{
							{
								Prefix: backend.GetPtrFromString("a/"),
							},
						},
					},
				},
				{
					name:      "single dir obj",
					maxObjs:   1000,
					delimiter: "/",
					prefix:    "a/",
					expected: backend.WalkResults{
						Objects: []s3response.Object{
							{
								Key: backend.GetPtrFromString("a/"),
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		for _, tc := range tt.cases {
			res, err := backend.Walk(context.Background(),
				tt.fsys, tc.prefix, tc.delimiter, tc.marker, tc.maxObjs,
				tt.getobj, []string{})
			if err != nil {
				t.Errorf("%v: walk: %v", tc.name, err)
			}

			compareResultsOrdered(tc.name, res, tc.expected, t)
		}
	}
}

type markerTest struct {
	fsys   fs.FS
	getobj backend.GetObjFunc
	cases  []markertestcase
}

type markertestcase struct {
	name      string
	prefix    string
	delimiter string
	marker    string
	maxObjs   int32
	expected  []backend.WalkResults
}

func TestMarker(t *testing.T) {
	tests := []markerTest{
		{
			fsys: fstest.MapFS{
				"dir/sample2.jpg": {},
				"dir/sample3.jpg": {},
				"dir/sample4.jpg": {},
				"dir/sample5.jpg": {},
			},
			getobj: getObj,
			cases: []markertestcase{
				{
					name:      "multi page marker",
					delimiter: "/",
					prefix:    "dir/",
					maxObjs:   2,
					expected: []backend.WalkResults{
						{
							Objects: []s3response.Object{
								{
									Key: backend.GetPtrFromString("dir/sample2.jpg"),
								},
								{
									Key: backend.GetPtrFromString("dir/sample3.jpg"),
								},
							},
							Truncated: true,
						},
						{
							Objects: []s3response.Object{
								{
									Key: backend.GetPtrFromString("dir/sample4.jpg"),
								},
								{
									Key: backend.GetPtrFromString("dir/sample5.jpg"),
								},
							},
						},
					},
				},
			},
		},
		{
			fsys: fstest.MapFS{
				"dir1/subdir/file.txt": {},
				"dir1/subdir.ext":      {},
				"dir1/subdir1.ext":     {},
				"dir1/subdir2.ext":     {},
			},
			getobj: getObj,
			cases: []markertestcase{
				{
					name:      "integration test case 1",
					maxObjs:   2,
					delimiter: "/",
					prefix:    "dir1/",
					expected: []backend.WalkResults{
						{
							Objects: []s3response.Object{
								{
									Key: backend.GetPtrFromString("dir1/subdir.ext"),
								},
							},
							CommonPrefixes: []types.CommonPrefix{
								{
									Prefix: backend.GetPtrFromString("dir1/subdir/"),
								},
							},
							Truncated: true,
						},
						{
							Objects: []s3response.Object{
								{
									Key: backend.GetPtrFromString("dir1/subdir1.ext"),
								},
								{
									Key: backend.GetPtrFromString("dir1/subdir2.ext"),
								},
							},
						},
					},
				},
			},
		},
		{
			fsys: fstest.MapFS{
				"asdf":          {},
				"boo/bar":       {},
				"boo/baz/xyzzy": {},
				"cquux/thud":    {},
				"cquux/bla":     {},
			},
			getobj: getObj,
			cases: []markertestcase{
				{
					name:      "integration test case2",
					maxObjs:   1,
					delimiter: "/",
					marker:    "boo/",
					expected: []backend.WalkResults{
						{
							Objects: []s3response.Object{},
							CommonPrefixes: []types.CommonPrefix{
								{
									Prefix: backend.GetPtrFromString("cquux/"),
								},
							},
						},
					},
				},
			},
		},
		{
			fsys: fstest.MapFS{
				"bar": {},
				"baz": {},
				"foo": {},
			},
			getobj: getObj,
			cases: []markertestcase{
				{
					name:    "exact limit count",
					maxObjs: 3,
					expected: []backend.WalkResults{
						{
							Objects: []s3response.Object{
								{
									Key: backend.GetPtrFromString("bar"),
								},
								{
									Key: backend.GetPtrFromString("baz"),
								},
								{
									Key: backend.GetPtrFromString("foo"),
								},
							},
						},
					},
				},
			},
		},
		{
			fsys: fstest.MapFS{
				"d1/f1": {},
				"d2/f2": {},
				"d3/f3": {},
				"d4/f4": {},
			},
			getobj: getObj,
			cases: []markertestcase{
				{
					name:      "limited common prefix",
					maxObjs:   3,
					delimiter: "/",
					expected: []backend.WalkResults{
						{
							CommonPrefixes: []types.CommonPrefix{
								{
									Prefix: backend.GetPtrFromString("d1/"),
								},
								{
									Prefix: backend.GetPtrFromString("d2/"),
								},
								{
									Prefix: backend.GetPtrFromString("d3/"),
								},
							},
							Truncated: true,
						},
						{
							CommonPrefixes: []types.CommonPrefix{
								{
									Prefix: backend.GetPtrFromString("d4/"),
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		for _, tc := range tt.cases {
			marker := tc.marker
			for i, page := range tc.expected {
				res, err := backend.Walk(context.Background(),
					tt.fsys, tc.prefix, tc.delimiter, marker, tc.maxObjs,
					tt.getobj, []string{})
				if err != nil {
					t.Errorf("%v: walk: %v", tc.name, err)
				}
				marker = res.NextMarker

				compareResultsOrdered(tc.name, res, page, t)

				if res.Truncated != page.Truncated {
					t.Errorf("%v page %v expected truncated %v, got %v",
						tc.name, i, page.Truncated, res.Truncated)
				}
			}
		}
	}
}

func compareResultsOrdered(name string, got, wanted backend.WalkResults, t *testing.T) {
	if !compareObjectsOrdered(got.Objects, wanted.Objects) {
		t.Errorf("%v: unexpected object, got %v wanted %v",
			name,
			printObjects(got.Objects),
			printObjects(wanted.Objects))
	}
	if !comparePrefixesOrdered(got.CommonPrefixes, wanted.CommonPrefixes) {
		t.Errorf("%v: unexpected prefix, got %v wanted %v",
			name,
			printCommonPrefixes(got.CommonPrefixes),
			printCommonPrefixes(wanted.CommonPrefixes))
	}
}

func compareObjectsOrdered(a, b []s3response.Object) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	if len(a) != len(b) {
		return false
	}

	for i, obj := range a {
		if *obj.Key != *b[i].Key {
			return false
		}
	}
	return true
}

func comparePrefixesOrdered(a, b []types.CommonPrefix) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	if len(a) != len(b) {
		return false
	}

	for i, cp := range a {
		if *cp.Prefix != *b[i].Prefix {
			return false
		}
	}
	return true
}
