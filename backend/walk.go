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
	"log"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3response"
)

var (
	pathSeparator = "/"
	pathDot       = "."
)

type WalkResults struct {
	CommonPrefixes []types.CommonPrefix
	Objects        []s3response.Object
	Truncated      bool
	NextMarker     string
}

// walkState holds the state needed during directory traversal
type walkState struct {
	ctx        context.Context
	fileSystem fs.FS
	prefix     string
	delimiter  string
	marker     string
	max        int32
	getObj     GetObjFunc
	skipdirs   []string

	// Mutable state
	cpmap      cpMap
	objects    []s3response.Object
	pastMarker bool
	pastMax    bool
	newMarker  string
	truncated  bool
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
	// if max is 0, it should return empty non-truncated result
	if max == 0 {
		return WalkResults{
			Truncated: false,
		}, nil
	}

	state := &walkState{
		ctx:        ctx,
		fileSystem: fileSystem,
		prefix:     prefix,
		delimiter:  delimiter,
		marker:     marker,
		max:        max,
		getObj:     getObj,
		skipdirs:   skipdirs,
		cpmap:      cpMap{},
		pastMarker: marker == "",
	}

	qwErr := quickWalk(state)
	if qwErr != nil {
		return WalkResults{}, qwErr
	}

	return WalkResults{
		CommonPrefixes: state.cpmap.CpArray(),
		Objects:        state.objects,
		Truncated:      state.truncated,
		NextMarker:     state.newMarker,
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

	err := WalkDir(fileSystem, ".", func(path string, d fs.DirEntry, err error) error {
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
func readDir(path string, walkstate *walkState) {
	entries, err := fs.ReadDir(walkstate.fileSystem, path)
	if err != nil {
		log.Print(err)
		return
	}

	entriesIndex := 0
	maxEntries := len(entries)

	for entriesIndex < maxEntries {
		if shouldSkip(entries[entriesIndex].Name(), walkstate) {
			entriesIndex++
			continue
		}
		if walkstate.pastMax {
			walkstate.truncated = true
			return
		}
		if entries[entriesIndex].IsDir() {
			entriesIndex = processDir(
				entries,
				entriesIndex,
				maxEntries,
				path,
				walkstate,
			)
		} else {

			// this is a leaf entry so check if it needs to go
			// in common prefixes, if not then add to results list
			currentObjectName := makeFullObjectName(path, entries[entriesIndex].Name())
			if currentObjectName > walkstate.marker {
				if !checkAndMaybeAddCommonPrefix(currentObjectName, walkstate) {
					addContentEntry(currentObjectName, entries[entriesIndex], walkstate)
				}
			}
			entriesIndex++
		}
	}
}

func processDir(
	entries []os.DirEntry,
	currentEntry int,
	maxEntries int,
	path string,
	walkstate *walkState,
) int {
	currentDirectoryName := entries[currentEntry].Name() + "/"

	// check for later entries that should lexically sort before this directory
	entriesIndex := currentEntry + 1
	for entriesIndex < maxEntries {
		if walkstate.pastMax {
			walkstate.truncated = true
			return entriesIndex
		}

		if entries[entriesIndex].Name() < currentDirectoryName {
			// this entry precedes
			// if it is a directory, we
			// need to call recursively to
			// check for further preceding entries
			if entries[entriesIndex].IsDir() {
				entriesIndex = processDir(
					entries,
					entriesIndex,
					maxEntries,
					path,
					walkstate,
				)
			} else {
				// this is a leaf entry so check if it needs to go
				// in common prefixes, if not then add to results list
				currentObjectName := makeFullObjectName(path, entries[entriesIndex].Name())
				if currentObjectName > walkstate.marker {
					if !checkAndMaybeAddCommonPrefix(currentObjectName, walkstate) {
						addContentEntry(currentObjectName, entries[entriesIndex], walkstate)
					}
				}
				entriesIndex++
			}
		} else {
			// this entry does not precede, so no further ones will
			// we can resume the dir that was current when we were called
			break
		}
	}

	// now read and process the dir we were originally called for
	if walkstate.pastMax {
		walkstate.truncated = true
		return entriesIndex
	}

	// add directory to common prefixes if required
	fullDirectoryName := makeFullObjectName(path, entries[currentEntry].Name())
	fullObjectName := fullDirectoryName + "/"
	if fullObjectName > walkstate.marker {
		if checkAndMaybeAddCommonPrefix(fullObjectName, walkstate) {
			// we can cut short here UNLESS the current directory
			// forms part of the prefix - in which case we must keep
			// searching it in case the prefix is below
			if !strings.HasPrefix(walkstate.prefix, fullObjectName) {
				return entriesIndex
			}
		} else {
			if walkstate.prefix == "" || strings.HasPrefix(fullObjectName, walkstate.prefix) {
				dirobj, err := walkstate.getObj(fullObjectName, entries[currentEntry])
				if err == nil {
					walkstate.addObject(dirobj, fullObjectName)
				}
			}
		}
	} else {
		// if this directory is before startAfter,
		// we can assume all its children are also before startAfter
		// UNLESS this directory and startAfter share a
		// common prefix
		if !(strings.HasPrefix(fullObjectName, walkstate.marker) ||
			strings.HasPrefix(walkstate.marker, fullObjectName)) {
			return entriesIndex
		}
	}
	readDir(fullDirectoryName, walkstate)
	return entriesIndex
}

func makeFullObjectName(path string, entry string) string {
	if path == "." {
		return entry
	}
	return path + "/" + entry
}

// checkAndMaybeAddCommonPrefix returns true if the object
// has been added as a common prefix or discarded because
// it doesn't match the prefix at all
//
// otherwise returns false, and the caller should add it to
// the full results set
func checkAndMaybeAddCommonPrefix(objectName string, walkstate *walkState,
) bool {
	// check prefix
	if walkstate.prefix != "" && !strings.HasPrefix(objectName, walkstate.prefix) {
		return true // doesn't match prefix - discard
	}

	// check delimiter
	if walkstate.delimiter != "" {
		objectNameAfterPrefix := strings.TrimPrefix(objectName, walkstate.prefix) // remove prefix from name
		objectNameBeforeDelimiter, _, delimiterFound := strings.Cut(objectNameAfterPrefix, walkstate.delimiter)
		if delimiterFound {
			// this object contributes to the common prefix list,
			// but not the full results
			commonPrefix := walkstate.prefix + objectNameBeforeDelimiter + walkstate.delimiter
			if commonPrefix > walkstate.marker {
				walkstate.addCommonPrefix(commonPrefix)
			}
			return true
		}
	}

	return false
}

func shouldSkip(name string, walkstate *walkState) bool {
	for _, skip := range walkstate.skipdirs {
		if name == skip {
			return true
		}
	}
	return false
}

func addContentEntry(objectName string, dirEntry fs.DirEntry, walkstate *walkState) bool {
	obj, err := walkstate.getObj(objectName, dirEntry)
	if err == ErrSkipObj {
		return false
	}
	if err != nil {
		fmt.Printf("file to object %s error %s", objectName, err)
		return false
	}

	walkstate.addObject(obj, objectName)
	return true
}

func checkDirectoryNotEmpty(dirName string, walkstate *walkState) bool {
	entries, err := fs.ReadDir(walkstate.fileSystem, dirName)
	return (err == nil && len(entries) > 0)
}

// addObject adds an object to the results and checks if limits are reached
func (w *walkState) addObject(obj s3response.Object, path string) bool {
	w.objects = append(w.objects, obj)
	if len(w.objects)+w.cpmap.Len() >= int(w.max) {
		w.newMarker = path
		w.pastMax = true
		// Don't set truncated here - wait until we know there are more items
		return true
	}
	return false
}

// addCommonPrefix adds a common prefix and checks if limits are reached
func (w *walkState) addCommonPrefix(cpref string) bool {
	w.cpmap.Add(cpref)
	if len(w.objects)+w.cpmap.Len() >= int(w.max) {
		w.newMarker = cpref
		w.pastMax = true
		// Don't set truncated here - wait until we know there are more items
		return true
	}
	return false
}
func quickWalk(walkstate *walkState) error {
	rootDir := pathDot

	// see if we can jump straight into the prefix if it is a valid non-empty directory
	if strings.Contains(walkstate.prefix, pathSeparator) {
		if idx := strings.LastIndex(walkstate.prefix, pathSeparator); idx > 0 {
			prefixDir := walkstate.prefix[:idx]
			if checkDirectoryNotEmpty(prefixDir, walkstate) {
				rootDir = walkstate.prefix[:idx]
			}
		}
	}

	readDir(rootDir, walkstate)
	if !walkstate.truncated {
		walkstate.newMarker = ""
	}
	return nil
}
