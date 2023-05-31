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

// Walk walks the supplied fs.FS and returns results compatible with list
// objects responses
func Walk(fileSystem fs.FS, prefix, delimiter, marker string, max int) (WalkResults, error) {
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

			// If prefix is defined and the directory does not match prefix,
			// do not descend into the directory because nothing will
			// match this prefix.  Make sure to append the / at the end of
			// directories since this is implied as a directory path name.
			if prefix != "" && !strings.HasPrefix(path+string(os.PathSeparator), prefix) {
				return fs.SkipDir
			}

			// TODO: special case handling if directory is empty
			// and was "PUT" explicitly
			return nil
		}

		if !pastMarker {
			if path != marker {
				return nil
			}
			pastMarker = true
		}

		// If object doesnt have prefix, dont include in results.
		if prefix != "" && !strings.HasPrefix(path, prefix) {
			return nil
		}

		if delimiter == "" {
			// If no delimeter specified, then all files with matching
			// prefix are included in results
			fi, err := d.Info()
			if err != nil {
				return fmt.Errorf("get info for %v: %w", path, err)
			}

			objects = append(objects, types.Object{
				ETag:         new(string),
				Key:          &path,
				LastModified: GetTimePtr(fi.ModTime()),
				Size:         fi.Size(),
			})
			if (len(objects) + len(cpmap)) == max {
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
		// delimeter = /
		// and objects:
		// A/file
		// A/B/file
		// B/C
		// would return:
		// objects: A/file
		// common prefix: A/B/
		//
		// Note: No obects are included past the common prefix since
		// these are all rolled up into the common prefix.
		// Note: The delimeter can be anything, so we have to operate on
		// the full path without any assumptions on posix directory heirarchy
		// here.  Usually the delimeter with be "/", but thats not required.
		suffix := strings.TrimPrefix(path, prefix)
		before, _, found := strings.Cut(suffix, delimiter)
		if !found {
			fi, err := d.Info()
			if err != nil {
				return fmt.Errorf("get info for %v: %w", path, err)
			}
			objects = append(objects, types.Object{
				ETag:         new(string),
				Key:          &path,
				LastModified: GetTimePtr(fi.ModTime()),
				Size:         fi.Size(),
			})
			if (len(objects) + len(cpmap)) == max {
				pastMax = true
			}
			return nil
		}

		// Common prefixes are a set, so should not have duplicates.
		// These are abstractly a "directory", so need to include the
		// delimeter at the end.
		cpmap[prefix+before+delimiter] = struct{}{}
		if (len(objects) + len(cpmap)) == max {
			pastMax = true
		}

		return nil
	})
	if err != nil {
		return WalkResults{}, err
	}

	commonPrefixStrings := make([]string, 0, len(cpmap))
	for k := range cpmap {
		commonPrefixStrings = append(commonPrefixStrings, k)
	}
	sort.Strings(commonPrefixStrings)
	commonPrefixes := make([]types.CommonPrefix, 0, len(commonPrefixStrings))
	for _, cp := range commonPrefixStrings {
		commonPrefixes = append(commonPrefixes, types.CommonPrefix{
			Prefix: &cp,
		})
	}

	return WalkResults{
		CommonPrefixes: commonPrefixes,
		Objects:        objects,
		Truncated:      truncated,
		NextMarker:     newMarker,
	}, nil
}
