package backend_test

import (
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/scoutgw/backend"
)

type walkTest struct {
	fsys     fs.FS
	expected backend.WalkResults
}

func TestWalk(t *testing.T) {
	tests := []walkTest{{
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
			Objects: []types.Object{{
				Key: backend.GetStringPtr("sample.jpg"),
			}},
		},
	}}

	for _, tt := range tests {
		res, err := backend.Walk(tt.fsys, "", "/", "", 1000)
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
		t.Errorf("unexpected common prefix, got %v wanted %v",
			printObjects(got.Objects),
			printObjects(wanted.Objects))
	}
}

func compareCommonPrefix(a, b []types.CommonPrefix) bool {
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

func compareObjects(a, b []types.Object) bool {
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

func containsObject(c types.Object, list []types.Object) bool {
	for _, cp := range list {
		if *c.Key == *cp.Key {
			return true
		}
	}
	return false
}

func printObjects(list []types.Object) string {
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
