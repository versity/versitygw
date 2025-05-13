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
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"syscall"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3response"
)

type WalkResults struct {
	CommonPrefixes []types.CommonPrefix
	Objects        []s3response.Object
	Truncated      bool
	NextMarker     string
}

type GetObjFunc func(path string, d fs.DirEntry) (s3response.Object, error)

var ErrSkipObj = errors.New("skip this object")

// map to store object common prefixes
type cpMap map[string]int

func (c cpMap) Add(key string) {
	_, ok := c[key]
	if !ok {
		c[key] = len(c)
	}
}

// Len returns the length of the map
func (c cpMap) Len() int {
	return len(c)
}

// CpArray converts the map into a sorted []types.CommonPrefixes array
func (c cpMap) CpArray() []types.CommonPrefix {
	commonPrefixes := make([]types.CommonPrefix, c.Len())
	for cp, i := range c {
		pfx := cp
		commonPrefixes[i] = types.CommonPrefix{
			Prefix: &pfx,
		}
	}

	return commonPrefixes
}

// Walk walks the supplied fs.FS and returns results compatible with list
// objects responses
func Walk(ctx context.Context, fileSystem fs.FS, prefix, delimiter, marker string, max int32, getObj GetObjFunc, skipdirs []string) (WalkResults, error) {
	cpmap := cpMap{}
	var objects []s3response.Object

	// if max is 0, it should return empty non-truncated result
	if max == 0 {
		return WalkResults{
			Truncated: false,
		}, nil
	}

	var pastMarker bool
	if marker == "" {
		pastMarker = true
	}

	var pastMax bool
	var newMarker string
	var truncated bool

	root := "."
	if strings.Contains(prefix, "/") {
		idx := strings.LastIndex(prefix, "/")
		if idx > 0 {
			root = prefix[:idx]
		}
	}

	err := fs.WalkDir(fileSystem, root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Ignore the root directory
		if path == "." {
			return nil
		}
		if contains(d.Name(), skipdirs) {
			return fs.SkipDir
		}

		// After this point, return skipflag instead of nil
		// so we can skip a directory without an early return
		var skipflag error
		if d.IsDir() {
			// If prefix is defined and the directory does not match prefix,
			// do not descend into the directory because nothing will
			// match this prefix. Make sure to append the / at the end of
			// directories since this is implied as a directory path name.
			// If path is a prefix of prefix, then path could still be
			// building to match. So only skip if path isn't a prefix of prefix
			// and prefix isn't a prefix of path.
			if prefix != "" &&
				!strings.HasPrefix(path+"/", prefix) &&
				!strings.HasPrefix(prefix, path+"/") {
				return fs.SkipDir
			}

			// Don't recurse into subdirectories which contain the delimiter
			// after reaching the prefix
			if delimiter != "" &&
				strings.HasPrefix(path+"/", prefix) &&
				strings.Contains(strings.TrimPrefix(path+"/", prefix), delimiter) {
				skipflag = fs.SkipDir
			} else {
				if delimiter == "" {
					dirobj, err := getObj(path+"/", d)
					if err == ErrSkipObj {
						return skipflag
					}
					if err != nil {
						return fmt.Errorf("directory to object %q: %w", path, err)
					}
					if pastMax {
						truncated = true
						return fs.SkipAll
					}
					objects = append(objects, dirobj)
					if (len(objects) + cpmap.Len()) == int(max) {
						newMarker = path
						pastMax = true
					}

					return skipflag
				}

				// TODO: can we do better here rather than a second readdir
				// per directory?
				ents, err := fs.ReadDir(fileSystem, path)
				if err != nil {
					return fmt.Errorf("readdir %q: %w", path, err)
				}

				if len(ents) != 0 {
					return skipflag
				}
			}
			path += "/"
		}

		if !pastMarker {
			if path == marker {
				pastMarker = true
				return skipflag
			}
			if path < marker {
				return skipflag
			}
		}

		// If object doesn't have prefix, don't include in results.
		if prefix != "" && !strings.HasPrefix(path, prefix) {
			return skipflag
		}

		if delimiter == "" {
			// If no delimiter specified, then all files with matching
			// prefix are included in results
			obj, err := getObj(path, d)
			if err == ErrSkipObj {
				return skipflag
			}
			if err != nil {
				return fmt.Errorf("file to object %q: %w", path, err)
			}
			if pastMax {
				truncated = true
				return fs.SkipAll
			}

			objects = append(objects, obj)

			if (len(objects) + cpmap.Len()) == int(max) {
				newMarker = path
				pastMax = true
			}

			return skipflag
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
				return skipflag
			}
			if err != nil {
				return fmt.Errorf("file to object %q: %w", path, err)
			}
			if pastMax {
				truncated = true
				return fs.SkipAll
			}
			objects = append(objects, obj)
			if (len(objects) + cpmap.Len()) == int(max) {
				newMarker = path
				pastMax = true
			}
			return skipflag
		}

		// Common prefixes are a set, so should not have duplicates.
		// These are abstractly a "directory", so need to include the
		// delimiter at the end when we add to the map.
		cprefNoDelim := prefix + before
		cpref := prefix + before + delimiter
		if cpref == marker {
			pastMarker = true
			return skipflag
		}

		if marker != "" && strings.HasPrefix(marker, cprefNoDelim) {
			// skip common prefixes that are before the marker
			return skipflag
		}

		if pastMax {
			truncated = true
			return fs.SkipAll
		}
		cpmap.Add(cpref)
		if (len(objects) + cpmap.Len()) == int(max) {
			newMarker = cpref
			pastMax = true
		}

		return skipflag
	})
	if err != nil {
		// suppress file not found caused by user's prefix
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
			return WalkResults{}, nil
		}
		return WalkResults{}, err
	}

	if !truncated {
		newMarker = ""
	}

	return WalkResults{
		CommonPrefixes: cpmap.CpArray(),
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

type WalkVersioningResults struct {
	CommonPrefixes      []types.CommonPrefix
	ObjectVersions      []s3response.ObjectVersion
	DelMarkers          []types.DeleteMarkerEntry
	Truncated           bool
	NextMarker          string
	NextVersionIdMarker string
}

type ObjVersionFuncResult struct {
	ObjectVersions      []s3response.ObjectVersion
	DelMarkers          []types.DeleteMarkerEntry
	NextVersionIdMarker string
	Truncated           bool
}

type GetVersionsFunc func(path, versionIdMarker string, pastVersionIdMarker *bool, availableObjCount int, d fs.DirEntry) (*ObjVersionFuncResult, error)

// WalkVersions walks the supplied fs.FS and returns results compatible with
// ListObjectVersions action response
func WalkVersions(ctx context.Context, fileSystem fs.FS, prefix, delimiter, keyMarker, versionIdMarker string, max int, getObj GetVersionsFunc, skipdirs []string) (WalkVersioningResults, error) {
	cpmap := cpMap{}
	var objects []s3response.ObjectVersion
	var delMarkers []types.DeleteMarkerEntry

	var pastMarker bool
	if keyMarker == "" {
		pastMarker = true
	}
	var nextMarker string
	var nextVersionIdMarker string
	var truncated bool

	pastVersionIdMarker := versionIdMarker == ""

	err := fs.WalkDir(fileSystem, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Ignore the root directory
		if path == "." {
			return nil
		}
		if contains(d.Name(), skipdirs) {
			return fs.SkipDir
		}

		if !pastMarker {
			if path == keyMarker {
				pastMarker = true
			}
			if path < keyMarker {
				return nil
			}
		}

		if d.IsDir() {
			// If prefix is defined and the directory does not match prefix,
			// do not descend into the directory because nothing will
			// match this prefix. Make sure to append the / at the end of
			// directories since this is implied as a directory path name.
			// If path is a prefix of prefix, then path could still be
			// building to match. So only skip if path isn't a prefix of prefix
			// and prefix isn't a prefix of path.
			if prefix != "" &&
				!strings.HasPrefix(path+"/", prefix) &&
				!strings.HasPrefix(prefix, path+"/") {
				return fs.SkipDir
			}

			// Don't recurse into subdirectories when listing with delimiter.
			if delimiter == "/" &&
				prefix != path+"/" &&
				strings.HasPrefix(path+"/", prefix) {
				cpmap.Add(path + "/")
				return fs.SkipDir
			}

			res, err := getObj(path, versionIdMarker, &pastVersionIdMarker, max-len(objects)-len(delMarkers)-cpmap.Len(), d)
			if err == ErrSkipObj {
				return nil
			}
			if err != nil {
				return fmt.Errorf("directory to object %q: %w", path, err)
			}
			objects = append(objects, res.ObjectVersions...)
			delMarkers = append(delMarkers, res.DelMarkers...)
			if res.Truncated {
				truncated = true
				nextMarker = path
				nextVersionIdMarker = res.NextVersionIdMarker
				return fs.SkipAll
			}

			return nil
		}

		// If object doesn't have prefix, don't include in results.
		if prefix != "" && !strings.HasPrefix(path, prefix) {
			return nil
		}

		if delimiter == "" {
			// If no delimiter specified, then all files with matching
			// prefix are included in results
			res, err := getObj(path, versionIdMarker, &pastVersionIdMarker, max-len(objects)-len(delMarkers)-cpmap.Len(), d)
			if err == ErrSkipObj {
				return nil
			}
			if err != nil {
				return fmt.Errorf("file to object %q: %w", path, err)
			}
			objects = append(objects, res.ObjectVersions...)
			delMarkers = append(delMarkers, res.DelMarkers...)
			if res.Truncated {
				truncated = true
				nextMarker = path
				nextVersionIdMarker = res.NextVersionIdMarker
				return fs.SkipAll
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
			res, err := getObj(path, versionIdMarker, &pastVersionIdMarker, max-len(objects)-len(delMarkers)-cpmap.Len(), d)
			if err == ErrSkipObj {
				return nil
			}
			if err != nil {
				return fmt.Errorf("file to object %q: %w", path, err)
			}
			objects = append(objects, res.ObjectVersions...)
			delMarkers = append(delMarkers, res.DelMarkers...)

			if res.Truncated {
				truncated = true
				nextMarker = path
				nextVersionIdMarker = res.NextVersionIdMarker
				return fs.SkipAll
			}
			return nil
		}

		// Common prefixes are a set, so should not have duplicates.
		// These are abstractly a "directory", so need to include the
		// delimiter at the end.
		cpmap.Add(prefix + before + delimiter)
		if (len(objects) + cpmap.Len()) == int(max) {
			nextMarker = path
			truncated = true

			return fs.SkipAll
		}

		return nil
	})
	if err != nil {
		return WalkVersioningResults{}, err
	}

	return WalkVersioningResults{
		CommonPrefixes:      cpmap.CpArray(),
		ObjectVersions:      objects,
		DelMarkers:          delMarkers,
		Truncated:           truncated,
		NextMarker:          nextMarker,
		NextVersionIdMarker: nextVersionIdMarker,
	}, nil
}
