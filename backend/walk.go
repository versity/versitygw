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

package backend

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type WalkResults struct {
	CommonPrefixes []types.CommonPrefix
	Objects        []types.Object
	Truncated      bool
	NextMarker     string
}

type GetObjFunc func(path string, d fs.DirEntry) (types.Object, error)

var ErrSkipObj = errors.New("skip this object")

// Walk walks the supplied fs.FS and returns results compatible with list
// objects responses
func Walk(fileSystem fs.FS, prefix, delimiter, marker string, max int, getObj GetObjFunc, skipdirs []string) (WalkResults, error) {
	cpmap := make(map[string]struct{})
	var objects []types.Object

	var pastMarker bool
	if marker == "" {
		pastMarker = true
	}

	var pastMax bool
	var newMarker string
	var truncated bool

	err := fs.WalkDir(fileSystem, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if pastMax {
			newMarker = path
			truncated = true
			return fs.SkipAll
		}

		if d.IsDir() {
			// Ignore the root directory
			if path == "." {
				return nil
			}

			if contains(d.Name(), skipdirs) {
				return fs.SkipDir
			}

			// If prefix is defined and the directory does not match prefix,
			// do not descend into the directory because nothing will
			// match this prefix. Make sure to append the / at the end of
			// directories since this is implied as a directory path name.
			// If path is a prefix of prefix, then path could still be
			// building to match. So only skip if path isnt a prefix of prefix
			// and prefix isnt a prefix of path.
			if prefix != "" &&
				!strings.HasPrefix(path+string(os.PathSeparator), prefix) &&
				!strings.HasPrefix(prefix, path+string(os.PathSeparator)) {
				return fs.SkipDir
			}

			// TODO: can we do better here rather than a second readdir
			// per directory?
			ents, err := fs.ReadDir(fileSystem, path)
			if err != nil {
				return fmt.Errorf("readdir %q: %w", path, err)
			}
			if len(ents) == 0 {
				dirobj, err := getObj(path, d)
				if err == ErrSkipObj {
					return nil
				}
				if err != nil {
					return fmt.Errorf("directory to object %q: %w", path, err)
				}
				objects = append(objects, dirobj)
			}

			return nil
		}

		if !pastMarker {
			if path != marker {
				return nil
			}
			pastMarker = true
		}

		// If object doesn't have prefix, don't include in results.
		if prefix != "" && !strings.HasPrefix(path, prefix) {
			return nil
		}

		if delimiter == "" {
			// If no delimiter specified, then all files with matching
			// prefix are included in results
			obj, err := getObj(path, d)
			if err == ErrSkipObj {
				return nil
			}
			if err != nil {
				return fmt.Errorf("file to object %q: %w", path, err)
			}
			objects = append(objects, obj)

			if max > 0 && (len(objects)+len(cpmap)) == max {
				pastMax = true
			}

			return nil
		}

		// Since delimiter is specified, we only want results that
		// do not contain the delimiter beyond the prefix.  If the
		// delimiter exists past the prefix, then the substring
		// between the prefix and delimiter is part of common prefixes.
		//
		// For example:
		// prefix = A/
		// delimiter = /
		// and objects:
		// A/file
		// A/B/file
		// B/C
		// would return:
		// objects: A/file
		// common prefix: A/B/
		//
		// Note: No objects are included past the common prefix since
		// these are all rolled up into the common prefix.
		// Note: The delimiter can be anything, so we have to operate on
		// the full path without any assumptions on posix directory hierarchy
		// here.  Usually the delimiter will be "/", but thats not required.
		suffix := strings.TrimPrefix(path, prefix)
		before, _, found := strings.Cut(suffix, delimiter)
		if !found {
			obj, err := getObj(path, d)
			if err == ErrSkipObj {
				return nil
			}
			if err != nil {
				return fmt.Errorf("file to object %q: %w", path, err)
			}
			objects = append(objects, obj)
			if (len(objects) + len(cpmap)) == max {
				pastMax = true
			}
			return nil
		}

		// Common prefixes are a set, so should not have duplicates.
		// These are abstractly a "directory", so need to include the
		// delimiter at the end.
		cpmap[prefix+before+delimiter] = struct{}{}
		if (len(objects) + len(cpmap)) == max {
			pastMax = true
		}

		return nil
	})
	if err != nil {
		return WalkResults{}, err
	}

	var commonPrefixStrings []string
	for k := range cpmap {
		commonPrefixStrings = append(commonPrefixStrings, k)
	}
	sort.Strings(commonPrefixStrings)
	commonPrefixes := make([]types.CommonPrefix, 0, len(commonPrefixStrings))
	for _, cp := range commonPrefixStrings {
		pfx := cp
		commonPrefixes = append(commonPrefixes, types.CommonPrefix{
			Prefix: &pfx,
		})
	}

	return WalkResults{
		CommonPrefixes: commonPrefixes,
		Objects:        objects,
		Truncated:      truncated,
		NextMarker:     newMarker,
	}, nil
}

func contains(a string, strs []string) bool {
	for _, s := range strs {
		if s == a {
			return true
		}
	}
	return false
}
