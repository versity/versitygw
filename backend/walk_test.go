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
	"strings"
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
				"dir1/b":         {},
				"dir1/b./a":      {},
				"dir1/b..":       {},
			},
			getobj: getObj,
			cases: []testcase{
				{
					name:    "order test",
					maxObjs: 1000,
					prefix:  "dir1/",
					expected: backend.WalkResults{
						Objects: []s3response.Object{
							{Key: backend.GetPtrFromString("dir1/")},
							{Key: backend.GetPtrFromString("dir1/a.b/")},
							{Key: backend.GetPtrFromString("dir1/a.b/file1")},
							{Key: backend.GetPtrFromString("dir1/a.b/file2")},
							{Key: backend.GetPtrFromString("dir1/a/")},
							{Key: backend.GetPtrFromString("dir1/a/file1")},
							{Key: backend.GetPtrFromString("dir1/a/file2")},
							{Key: backend.GetPtrFromString("dir1/a/file3")},
							{Key: backend.GetPtrFromString("dir1/b")},
							{Key: backend.GetPtrFromString("dir1/b..")},
							{Key: backend.GetPtrFromString("dir1/b./")},
							{Key: backend.GetPtrFromString("dir1/b./a")},
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

// ---- Versioning Tests ----

// getVersionsTestFunc is a simple GetVersionsFunc implementation for tests that
// returns a single latest version for each file or directory encountered.
// Directories are reported with a trailing delimiter in the key to match the
// behavior of the non-versioned Walk tests where directory objects are listed.
func getVersionsTestFunc(path, versionIdMarker string, pastVersionIdMarker *bool, availableObjCount int, d fs.DirEntry) (*backend.ObjVersionFuncResult, error) {
	// If we have no available slots left, signal truncation (should be rare in these tests)
	if availableObjCount <= 0 {
		return &backend.ObjVersionFuncResult{Truncated: true, NextVersionIdMarker: ""}, nil
	}

	key := path
	if d.IsDir() {
		key = key + "/"
	}
	ver := "v1"
	latest := true
	ov := s3response.ObjectVersion{Key: &key, VersionId: &ver, IsLatest: &latest}
	return &backend.ObjVersionFuncResult{ObjectVersions: []s3response.ObjectVersion{ov}}, nil
}

// TestWalkVersions mirrors TestWalk but exercises WalkVersions and validates
// common prefixes and object versions for typical delimiter/prefix scenarios.
func TestWalkVersions(t *testing.T) {
	fsys := fstest.MapFS{
		"dir1/a/file1": {},
		"dir1/a/file2": {},
		"dir1/b/file3": {},
		"rootfile":     {},
	}

	// Without a delimiter, every directory and file becomes an object version
	// via the test GetVersionsFunc (directories have trailing '/').
	expected := backend.WalkVersioningResults{
		ObjectVersions: []s3response.ObjectVersion{
			{Key: backend.GetPtrFromString("dir1/")},
			{Key: backend.GetPtrFromString("dir1/a/")},
			{Key: backend.GetPtrFromString("dir1/a/file1")},
			{Key: backend.GetPtrFromString("dir1/a/file2")},
			{Key: backend.GetPtrFromString("dir1/b/")},
			{Key: backend.GetPtrFromString("dir1/b/file3")},
			{Key: backend.GetPtrFromString("rootfile")},
		},
	}

	res, err := backend.WalkVersions(context.Background(), fsys, "", "", "", "", 1000, getVersionsTestFunc, []string{})
	if err != nil {
		t.Fatalf("walk versions: %v", err)
	}
	compareVersionResultsOrdered("simple versions no delimiter", res, expected, t)
}

// TestOrderWalkVersions mirrors TestOrderWalk, exercising ordering semantics for
// version listings (lexicographic ordering of directory and file version keys).
func TestOrderWalkVersions(t *testing.T) {
	fsys := fstest.MapFS{
		"dir1/a/file1":   {},
		"dir1/a/file2":   {},
		"dir1/a/file3":   {},
		"dir1/a.b/file1": {},
		"dir1/a.b/file2": {},
	}

	// Expect lexicographic ordering similar to non-version walk when no delimiter.
	expected := backend.WalkVersioningResults{
		ObjectVersions: []s3response.ObjectVersion{
			{Key: backend.GetPtrFromString("dir1/")},
			{Key: backend.GetPtrFromString("dir1/a.b/")},
			{Key: backend.GetPtrFromString("dir1/a.b/file1")},
			{Key: backend.GetPtrFromString("dir1/a.b/file2")},
			{Key: backend.GetPtrFromString("dir1/a/")},
			{Key: backend.GetPtrFromString("dir1/a/file1")},
			{Key: backend.GetPtrFromString("dir1/a/file2")},
			{Key: backend.GetPtrFromString("dir1/a/file3")},
		},
	}

	res, err := backend.WalkVersions(context.Background(), fsys, "dir1/", "", "", "", 1000, getVersionsTestFunc, []string{})
	if err != nil {
		t.Fatalf("order walk versions: %v", err)
	}
	compareVersionResultsOrdered("order versions no delimiter", res, expected, t)
}

// compareVersionResults compares unordered sets of common prefixes and object versions
// compareVersionResultsOrdered compares ordered slices
func compareVersionResultsOrdered(name string, got, wanted backend.WalkVersioningResults, t *testing.T) {
	if !compareObjectVersionsOrdered(got.ObjectVersions, wanted.ObjectVersions) {
		t.Errorf("%v: unexpected object versions, got %v wanted %v", name, printVersionObjects(got.ObjectVersions), printVersionObjects(wanted.ObjectVersions))
	}
	if !comparePrefixesOrdered(got.CommonPrefixes, wanted.CommonPrefixes) {
		t.Errorf("%v: unexpected prefix, got %v wanted %v", name, printCommonPrefixes(got.CommonPrefixes), printCommonPrefixes(wanted.CommonPrefixes))
	}
}

func compareObjectVersionsOrdered(a, b []s3response.ObjectVersion) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	if len(a) != len(b) {
		return false
	}
	for i, ov := range a {
		if ov.Key == nil || b[i].Key == nil {
			return false
		}
		if *ov.Key != *b[i].Key {
			return false
		}
	}
	return true
}

func printVersionObjects(list []s3response.ObjectVersion) string {
	res := "["
	for _, ov := range list {
		var key string
		if ov.Key == nil {
			key = "<nil>"
		} else {
			key = *ov.Key
		}
		if res == "[" {
			res = res + key
		} else {
			res = res + ", " + key
		}
	}
	return res + "]"
}

// multiVersionGetVersionsFunc is a more sophisticated test function that simulates
// multiple versions per object, similar to the integration test behavior.
// It creates multiple versions for each file with deterministic version IDs.
func createMultiVersionFunc(files map[string]int) backend.GetVersionsFunc {
	// Pre-generate all versions for deterministic testing
	versionedFiles := make(map[string][]s3response.ObjectVersion)

	for path, versionCount := range files {
		versions := make([]s3response.ObjectVersion, versionCount)
		for i := range versionCount {
			versionId := fmt.Sprintf("v%d", i+1)
			isLatest := i == versionCount-1 // Last version is latest
			key := path

			versions[i] = s3response.ObjectVersion{
				Key:       &key,
				VersionId: &versionId,
				IsLatest:  &isLatest,
			}
		}
		// Reverse slice so latest comes first (reverse chronological order)
		for i, j := 0, len(versions)-1; i < j; i, j = i+1, j-1 {
			versions[i], versions[j] = versions[j], versions[i]
		}
		versionedFiles[path] = versions
	}

	return func(path, versionIdMarker string, pastVersionIdMarker *bool, availableObjCount int, d fs.DirEntry) (*backend.ObjVersionFuncResult, error) {
		if availableObjCount <= 0 {
			return &backend.ObjVersionFuncResult{Truncated: true}, nil
		}

		// Handle directories - just return a single directory version
		if d.IsDir() {
			key := path + "/"
			ver := "v1"
			latest := true
			ov := s3response.ObjectVersion{Key: &key, VersionId: &ver, IsLatest: &latest}
			return &backend.ObjVersionFuncResult{ObjectVersions: []s3response.ObjectVersion{ov}}, nil
		}

		// Get versions for this file
		versions, exists := versionedFiles[path]
		if !exists {
			// No versions for this file, skip it
			return &backend.ObjVersionFuncResult{}, backend.ErrSkipObj
		}

		// Handle version ID marker pagination
		startIdx := 0
		if versionIdMarker != "" && !*pastVersionIdMarker {
			// Find the starting position after the marker
			for i, version := range versions {
				if *version.VersionId == versionIdMarker {
					startIdx = i + 1
					*pastVersionIdMarker = true
					break
				}
			}
		}

		// Return available versions up to the limit
		endIdx := min(startIdx+availableObjCount, len(versions))

		result := &backend.ObjVersionFuncResult{
			ObjectVersions: versions[startIdx:endIdx],
		}

		// Check if we need to truncate
		if endIdx < len(versions) {
			result.Truncated = true
			result.NextVersionIdMarker = *versions[endIdx-1].VersionId
		}

		return result, nil
	}
}

// TestWalkVersionsTruncated tests the pagination behavior of WalkVersions
// when there are multiple versions per object and the result is truncated.
// This mirrors the integration test ListObjectVersions_multiple_object_versions_truncated.
func TestWalkVersionsTruncated(t *testing.T) {
	// Create filesystem with the same files as integration test
	fsys := fstest.MapFS{
		"foo": {},
		"bar": {},
		"baz": {},
	}

	// Define version counts per file (matching integration test)
	versionCounts := map[string]int{
		"foo": 4, // 4 versions
		"bar": 3, // 3 versions
		"baz": 5, // 5 versions
	}

	getVersionsFunc := createMultiVersionFunc(versionCounts)

	// Test first page with limit of 5 (should be truncated)
	maxKeys := 5
	res1, err := backend.WalkVersions(context.Background(), fsys, "", "", "", "", maxKeys, getVersionsFunc, []string{})
	if err != nil {
		t.Fatalf("walk versions first page: %v", err)
	}

	// Verify first page results
	if !res1.Truncated {
		t.Error("expected first page to be truncated")
	}

	if len(res1.ObjectVersions) != maxKeys {
		t.Errorf("expected %d versions in first page, got %d", maxKeys, len(res1.ObjectVersions))
	}

	// Expected order: bar (3 versions), baz (2 versions) - lexicographic order
	expectedFirstPage := []string{"bar", "bar", "bar", "baz", "baz"}
	if len(res1.ObjectVersions) != len(expectedFirstPage) {
		t.Fatalf("first page length mismatch: expected %d, got %d", len(expectedFirstPage), len(res1.ObjectVersions))
	}

	for i, expected := range expectedFirstPage {
		if res1.ObjectVersions[i].Key == nil || *res1.ObjectVersions[i].Key != expected {
			t.Errorf("first page[%d]: expected key %s, got %v", i, expected, res1.ObjectVersions[i].Key)
		}
	}

	// Verify next markers are set
	if res1.NextMarker == "" {
		t.Error("expected NextMarker to be set on truncated result")
	}
	if res1.NextVersionIdMarker == "" {
		t.Error("expected NextVersionIdMarker to be set on truncated result")
	}

	// Test second page using markers
	res2, err := backend.WalkVersions(context.Background(), fsys, "", "", res1.NextMarker, res1.NextVersionIdMarker, maxKeys, getVersionsFunc, []string{})
	if err != nil {
		t.Fatalf("walk versions second page: %v", err)
	}

	t.Logf("Second page: ObjectVersions=%d, Truncated=%v, NextMarker=%s, NextVersionIdMarker=%s",
		len(res2.ObjectVersions), res2.Truncated, res2.NextMarker, res2.NextVersionIdMarker)

	for i, ov := range res2.ObjectVersions {
		t.Logf("  [%d] Key=%s, VersionId=%s", i, *ov.Key, *ov.VersionId)
	}

	// Verify second page results
	// With maxKeys=5, we should have 3 pages total: 5 + 5 + 2 = 12

	// Test third page if needed
	var res3 backend.WalkVersioningResults
	if res2.Truncated {
		res3, err = backend.WalkVersions(context.Background(), fsys, "", "", res2.NextMarker, res2.NextVersionIdMarker, maxKeys, getVersionsFunc, []string{})
		if err != nil {
			t.Fatalf("walk versions third page: %v", err)
		}

		t.Logf("Third page: ObjectVersions=%d, Truncated=%v, NextMarker=%s, NextVersionIdMarker=%s",
			len(res3.ObjectVersions), res3.Truncated, res3.NextMarker, res3.NextVersionIdMarker)

		for i, ov := range res3.ObjectVersions {
			t.Logf("  [%d] Key=%s, VersionId=%s", i, *ov.Key, *ov.VersionId)
		}
	}

	// Verify total count across all pages
	totalVersions := len(res1.ObjectVersions) + len(res2.ObjectVersions) + len(res3.ObjectVersions)
	expectedTotal := versionCounts["foo"] + versionCounts["bar"] + versionCounts["baz"]
	if totalVersions != expectedTotal {
		t.Errorf("total versions mismatch: expected %d, got %d", expectedTotal, totalVersions)
	}
}

// TestWalkVersionsPrefixSkipsParents reproduces the bug (#1864) where
// ListObjectVersions with a deep prefix and delimiter="/" was incorrectly
// returning version entries for ancestor directories (e.g. "vendor/",
// "vendor/Backup/") in addition to the the prefix directory itself.
// Only "vendor/Backup/vendor/Clients/" should appear in ObjectVersions; all
// deeper entries should become CommonPrefixes.
func TestWalkVersionsPrefixSkipsParents(t *testing.T) {
	fsys := fstest.MapFS{
		"vendor":                                      {Mode: fs.ModeDir},
		"vendor/Backup":                               {Mode: fs.ModeDir},
		"vendor/Backup/vendor":                        {Mode: fs.ModeDir},
		"vendor/Backup/vendor/Clients":                {Mode: fs.ModeDir},
		"vendor/Backup/vendor/Clients/abc":            {Mode: fs.ModeDir},
		"vendor/Backup/vendor/Clients/abc/backup.vbm": {},
	}

	prefix := "vendor/Backup/vendor/Clients/"
	delimiter := "/"

	res, err := backend.WalkVersions(context.Background(), fsys, prefix, delimiter, "", "", 1000, getVersionsTestFunc, []string{})
	if err != nil {
		t.Fatalf("WalkVersions: %v", err)
	}

	// Only the exact prefix directory should appear as an ObjectVersion.
	expectedVersionKeys := []string{"vendor/Backup/vendor/Clients/"}
	if !compareObjectVersionsOrdered(res.ObjectVersions, makeObjectVersions(expectedVersionKeys)) {
		t.Errorf("unexpected ObjectVersions: got %v, want %v",
			printVersionObjects(res.ObjectVersions), expectedVersionKeys)
	}

	// The child directory should be a CommonPrefix.
	expectedPrefixes := []string{"vendor/Backup/vendor/Clients/abc/"}
	if !comparePrefixesUnordered(res.CommonPrefixes, expectedPrefixes) {
		t.Errorf("unexpected CommonPrefixes: got %v, want %v",
			printCommonPrefixes(res.CommonPrefixes), expectedPrefixes)
	}
}

// TestWalkVersionsPrefixNoDelimiterSkipsParents verifies that even without a
// delimiter, ancestor directories of the prefix are not returned as versions.
func TestWalkVersionsPrefixNoDelimiterSkipsParents(t *testing.T) {
	fsys := fstest.MapFS{
		"vendor":                                {Mode: fs.ModeDir},
		"vendor/Backup":                         {Mode: fs.ModeDir},
		"vendor/Backup/vendor":                  {Mode: fs.ModeDir},
		"vendor/Backup/vendor/Clients":          {Mode: fs.ModeDir},
		"vendor/Backup/vendor/Clients/file.vbm": {},
	}

	prefix := "vendor/Backup/vendor/Clients/"

	res, err := backend.WalkVersions(context.Background(), fsys, prefix, "", "", "", 1000, getVersionsTestFunc, []string{})
	if err != nil {
		t.Fatalf("WalkVersions: %v", err)
	}

	// Ancestor keys must not appear. every returned key must start with prefix.
	for _, ov := range res.ObjectVersions {
		if ov.Key == nil {
			t.Error("nil key in ObjectVersions")
			continue
		}
		if !strings.HasPrefix(*ov.Key, prefix) {
			t.Errorf("ancestor key leaked into results: %q", *ov.Key)
		}
	}

	// The prefix dir itself and its file should be the only versions.
	expectedVersionKeys := []string{
		"vendor/Backup/vendor/Clients/",
		"vendor/Backup/vendor/Clients/file.vbm",
	}
	if !compareObjectVersionsOrdered(res.ObjectVersions, makeObjectVersions(expectedVersionKeys)) {
		t.Errorf("unexpected ObjectVersions: got %v, want %v",
			printVersionObjects(res.ObjectVersions), expectedVersionKeys)
	}
}

// makeObjectVersions builds a []s3response.ObjectVersion slice with just keys
// set, for use in test comparisons.
func makeObjectVersions(keys []string) []s3response.ObjectVersion {
	ovs := make([]s3response.ObjectVersion, len(keys))
	for i, k := range keys {
		key := k
		ovs[i] = s3response.ObjectVersion{Key: &key}
	}
	return ovs
}

// comparePrefixesUnordered checks that got contains exactly the expected
// prefix strings regardless of order.
func comparePrefixesUnordered(got []types.CommonPrefix, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	wantSet := make(map[string]bool, len(want))
	for _, w := range want {
		wantSet[w] = true
	}
	for _, cp := range got {
		if cp.Prefix == nil || !wantSet[*cp.Prefix] {
			return false
		}
	}
	return true
}
