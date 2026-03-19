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
	"path"
	"slices"
	"strings"
	"syscall"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3response"
)

const (
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
	cpmap     cpMap
	objects   []s3response.Object
	pastMax   bool
	newMarker string
	truncated bool
	walkErr   error
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

	err := walkDirRoot(fileSystem, ".", func(path string, d fs.DirEntry, err error) error {
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
		if slices.Contains(skipdirs, d.Name()) {
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

			// Skip ancestor directories of the specified prefix; only process
			// the directory that exactly matches the prefix.
			// At this point we know strings.HasPrefix(prefix, path+"/") holds
			// (i.e. path is an ancestor of the prefix directory). Skip it
			// unless it is the exact prefix directory.
			// Note: WalkVersions always walks from "." (unlike Walk, which
			// narrows the root) because versioning marker semantics require
			// visiting all entries in order, so this guard is needed instead.
			if prefix != "" && strings.HasPrefix(prefix, path+"/") && path+"/" != prefix {
				return nil
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
	err := walkstate.ctx.Err()
	if err != nil {
		walkstate.walkErr = err
		return
	}

	entries, err := fs.ReadDir(walkstate.fileSystem, path)
	if err != nil {
		// Suppress not-found / not-a-dir errors: they indicate either a
		// user-supplied prefix that doesn't exist on disk, or a directory
		// that was removed concurrently during the walk. In both cases,
		// treat the subtree as empty rather than surfacing an error.
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
			return
		}
		walkstate.walkErr = fmt.Errorf("readdir %q: %w", path, err)
		return
	}

	readDirEntries(path, entries, walkstate)
}

func readDirEntries(path string, entries []fs.DirEntry, walkstate *walkState) {

	entriesIndex := 0
	maxEntries := len(entries)

	for entriesIndex < maxEntries {
		err := walkstate.ctx.Err()
		if err != nil {
			walkstate.walkErr = err
			return
		}

		if shouldSkip(entries[entriesIndex].Name(), walkstate) {
			entriesIndex++
			continue
		}
		if walkstate.pastMax {
			walkstate.truncated = true
			return
		}
		if entries[entriesIndex].IsDir() {
			// processDir returns the index of the next unprocessed entry
			// (the first sibling that lexically follows the directory);
			// the directory itself is fully consumed inside processDir,
			// so we must NOT increment entriesIndex after this call.
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
	entries []fs.DirEntry,
	currentEntry int,
	maxEntries int,
	path string,
	walkstate *walkState,
) int {
	currentDirectoryName := entries[currentEntry].Name() + "/"

	// check for later entries that should lexically sort before this directory
	entriesIndex := currentEntry + 1
	for entriesIndex < maxEntries {
		err := walkstate.ctx.Err()
		if err != nil {
			walkstate.walkErr = err
			return entriesIndex
		}

		if walkstate.pastMax {
			walkstate.truncated = true
			return entriesIndex
		}

		if entries[entriesIndex].Name() < currentDirectoryName {
			// this entry precedes
			// if it is a directory, we
			// need to call recursively to
			// check for further preceding entries
			if shouldSkip(entries[entriesIndex].Name(), walkstate) {
				entriesIndex++
				continue
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
			if !strings.HasPrefix(walkstate.prefix, fullObjectName) || walkstate.pastMax {
				return entriesIndex
			}
		} else {
			dirobj, err := walkstate.getObj(fullObjectName, entries[currentEntry])
			if err == ErrSkipObj {
				// Directory exists in the filesystem but is not an object.
			} else if err != nil {
				walkstate.walkErr = fmt.Errorf("directory to object %q: %w", fullObjectName, err)
				return entriesIndex
			} else {
				walkstate.addObject(dirobj, fullObjectName)
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
	if walkstate.pastMax {
		walkstate.truncated = true
		return entriesIndex
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
	return slices.Contains(walkstate.skipdirs, name)
}

func addContentEntry(objectName string, dirEntry fs.DirEntry, walkstate *walkState) bool {
	obj, err := walkstate.getObj(objectName, dirEntry)
	if err == ErrSkipObj {
		return false
	}
	if err != nil {
		walkstate.walkErr = fmt.Errorf("file to object %q: %w", objectName, err)
		return false
	}

	walkstate.addObject(obj, objectName)
	return true
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
	var rootEntries []fs.DirEntry
	useRootEntries := false

	// see if we can jump straight into the prefix if it is a valid non-empty directory
	if strings.Contains(walkstate.prefix, pathSeparator) {
		if idx := strings.LastIndex(walkstate.prefix, pathSeparator); idx > 0 {
			prefixDir := walkstate.prefix[:idx]
			// If successful and non-empty, start from prefixDir and reuse entries
			// to avoid a second ReadDir call.
			entries, err := fs.ReadDir(walkstate.fileSystem, prefixDir)
			if err == nil && len(entries) > 0 {
				rootDir = prefixDir
				rootEntries = entries
				useRootEntries = true
			}
		}
	}

	if useRootEntries {
		// keep fast-path semantics but still honor skipdirs for the prefixed root
		if !shouldSkip(path.Base(rootDir), walkstate) {
			// Mirror processDir: offer the root directory itself to getObj whenever
			// its key sorts after the marker, using checkAndMaybeAddCommonPrefix to
			// handle the delimiter case. This replaces the previous guards that
			// incorrectly skipped "a/" when hasSubdirs==true or marker!="".
			fullObjectName := rootDir + pathSeparator
			if fullObjectName > walkstate.marker {
				if !checkAndMaybeAddCommonPrefix(fullObjectName, walkstate) {
					rootInfo, err := fs.Stat(walkstate.fileSystem, rootDir)
					if err != nil {
						walkstate.walkErr = fmt.Errorf("stat %q: %w", rootDir, err)
					} else {
						dirobj, err := walkstate.getObj(fullObjectName, fs.FileInfoToDirEntry(rootInfo))
						if err == ErrSkipObj {
							// Directory exists in the filesystem but is not an object.
						} else if err != nil {
							walkstate.walkErr = fmt.Errorf("directory to object %q: %w", fullObjectName, err)
						} else {
							walkstate.addObject(dirobj, fullObjectName)
						}
					}
				}
			}
			if walkstate.walkErr == nil {
				readDirEntries(rootDir, rootEntries, walkstate)
			}
		}
	} else {
		readDir(rootDir, walkstate)
	}
	if walkstate.walkErr != nil {
		return walkstate.walkErr
	}
	if !walkstate.truncated {
		walkstate.newMarker = ""
	}
	return nil
}
