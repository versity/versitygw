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
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"

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

var (
	pathSeparator = "/"
	pathDot       = "."
)

// fakeDirEntry implements fs.DirEntry for implied directories
type fakeDirEntry struct {
	name  string
	isDir bool
}

func (f *fakeDirEntry) Name() string {
	return f.name
}

func (f *fakeDirEntry) IsDir() bool {
	return f.isDir
}

func (f *fakeDirEntry) Type() fs.FileMode {
	if f.isDir {
		return fs.ModeDir
	}
	return 0
}

func (f *fakeDirEntry) Info() (fs.FileInfo, error) {
	return &fakeDirInfo{name: f.name, isDir: f.isDir}, nil
}

// fakeDirInfo implements fs.FileInfo for implied directories
type fakeDirInfo struct {
	name  string
	isDir bool
}

func (f *fakeDirInfo) Name() string {
	return f.name
}

func (f *fakeDirInfo) Size() int64 {
	return 0
}

func (f *fakeDirInfo) Mode() fs.FileMode {
	if f.isDir {
		return fs.ModeDir
	}
	return 0
}

func (f *fakeDirInfo) ModTime() time.Time {
	return time.Time{} // Return zero time for fake directories
}

func (f *fakeDirInfo) IsDir() bool {
	return f.isDir
}

func (f *fakeDirInfo) Sys() any {
	return nil
}

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

// entryWithSortKey represents a directory entry with its lexicographic sort key
type entryWithSortKey struct {
	d       fs.DirEntry
	path    string
	sortKey string
}

// shouldSkipDirectory checks if a directory should be skipped based on prefix matching
func shouldSkipDirectory(dirPath, prefix string) bool {
	if prefix == "" {
		return false
	}
	return !strings.HasPrefix(dirPath, prefix) && !strings.HasPrefix(prefix, dirPath)
}

// constructPath builds the full path for a directory entry
func constructPath(dir, entryName string) string {
	if dir == pathDot {
		return entryName
	}
	return dir + pathSeparator + entryName
}

// createSortKey creates a lexicographic sort key for an entry
func createSortKey(path string, isDir bool) string {
	if isDir {
		return path + pathSeparator
	}
	return path
}

// buildSortedEntries reads directory entries and sorts them lexicographically
func buildSortedEntries(fileSystem fs.FS, dir string, skipdirs []string) ([]entryWithSortKey, error) {
	entries, err := fs.ReadDir(fileSystem, dir)
	if err != nil {
		return nil, err
	}

	var entriesWithKeys []entryWithSortKey
	for _, d := range entries {
		if slices.Contains(skipdirs, d.Name()) {
			continue
		}

		path := constructPath(dir, d.Name())
		sortKey := createSortKey(path, d.IsDir())

		entriesWithKeys = append(entriesWithKeys, entryWithSortKey{
			d:       d,
			path:    path,
			sortKey: sortKey,
		})
	}

	// Sort by the sort key to ensure proper lexicographic ordering
	sort.Slice(entriesWithKeys, func(i, j int) bool {
		return entriesWithKeys[i].sortKey < entriesWithKeys[j].sortKey
	})

	return entriesWithKeys, nil
}

// checkLimits returns true if we've hit our limits and should stop processing
func (w *walkState) checkLimits() bool {
	return w.pastMax || w.ctx.Err() != nil
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

// isBeforeMarker checks if a path is before the current marker
func (w *walkState) isBeforeMarker(path string) bool {
	return !w.pastMarker && path < w.marker
}

// isAtMarker checks if a path matches the current marker
func (w *walkState) isAtMarker(path string) bool {
	return !w.pastMarker && path == w.marker
}

// Walk walks the supplied fs.FS and returns results compatible with list
// objects responses
func Walk(ctx context.Context, fileSystem fs.FS, prefix, delimiter, marker string, max int32, getObj GetObjFunc, skipdirs []string) (WalkResults, error) {
	// Early return for zero max
	if max == 0 {
		return WalkResults{Truncated: false}, nil
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

	root := pathDot
	if strings.Contains(prefix, pathSeparator) {
		if idx := strings.LastIndex(prefix, pathSeparator); idx > 0 {
			root = prefix[:idx]
		}
	}

	// Special case: if prefix ends with delimiter and refers to an empty single directory,
	// we need to start from parent to find the directory as an entry
	if delimiter != "" && prefix != "" && strings.HasSuffix(prefix, delimiter) {
		prefixDir := strings.TrimSuffix(prefix, delimiter)
		if !strings.Contains(prefixDir, delimiter) {
			// Check if this directory exists and is empty
			if entries, err := fs.ReadDir(fileSystem, prefixDir); err == nil && len(entries) == 0 {
				// Single-level empty directory like "a" with prefix "a/"
				root = pathDot
			}
		}
	}

	// Handle special case for prefix directories in non-delimiter mode
	if delimiter == "" && prefix != "" && strings.HasSuffix(prefix, pathSeparator) {
		err := state.handlePrefixDirectory(prefix)
		if err != nil {
			return WalkResults{}, err
		}
	}

	if err := state.walkLexSort(root); err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
			return WalkResults{}, nil
		}
		return WalkResults{}, err
	}

	if !state.truncated {
		state.newMarker = ""
	}

	return WalkResults{
		CommonPrefixes: state.cpmap.CpArray(),
		Objects:        state.objects,
		Truncated:      state.truncated,
		NextMarker:     state.newMarker,
	}, nil
}

// handlePrefixDirectory handles the special case where we need to include the root directory itself
func (w *walkState) handlePrefixDirectory(prefix string) error {
	if w.pastMarker || w.marker == "" || prefix <= w.marker {
		if w.marker == "" || prefix < w.marker || prefix == w.marker {
			if prefix != w.marker {
				prefixDir := strings.TrimSuffix(prefix, pathSeparator)
				dirInfo := &fakeDirEntry{name: prefixDir, isDir: true}
				dirobj, err := w.getObj(prefix, dirInfo)
				switch err {
				case ErrSkipObj:
					// Skip this directory
				case nil:
					if w.addObject(dirobj, prefix) {
						return nil
					}
				default:
					return fmt.Errorf("prefix directory to object %q: %w",
						prefix, err)
				}
			}
			if prefix == w.marker {
				w.pastMarker = true
			}
		}
	}
	return nil
}

// walkLexSort performs lexicographically ordered directory traversal
func (w *walkState) walkLexSort(dir string) error {
	if w.ctx.Err() != nil {
		return w.ctx.Err()
	}

	entries, err := buildSortedEntries(w.fileSystem, dir, w.skipdirs)
	if err != nil {
		return err
	}

	for i, entry := range entries {
		if w.checkLimits() {
			return w.ctx.Err()
		}

		if w.pastMax {
			// We have more entries to process, so mark as truncated
			w.truncated = true
			return nil
		}

		if err := w.processEntry(entry); err != nil {
			return err
		}

		// After processing an entry, check if we hit the limit
		if w.pastMax {
			// We hit the limit. Check if there are more entries after this one
			if i+1 < len(entries) {
				// There are more entries in this directory
				w.truncated = true
			} else {
				// This was the last entry in this directory, but there might be more dirs to recurse into
				// Let the higher level determine if we're truly done
			}
			return nil
		}
	}

	return nil
}

// processEntry processes a single directory entry
func (w *walkState) processEntry(entry entryWithSortKey) error {
	path := entry.path
	d := entry.d

	if d.IsDir() {
		return w.processDirectory(path, d)
	}
	return w.processFile(path, d)
}

// processDirectory handles directory processing logic
func (w *walkState) processDirectory(path string, d fs.DirEntry) error {
	dirPath := path + pathSeparator

	// Check if we should skip this directory based on prefix
	if shouldSkipDirectory(dirPath, w.prefix) {
		return nil
	}

	// Handle marker logic for directories
	if w.isBeforeMarker(dirPath) {
		// Before marker - only recurse if marker could be inside
		if strings.HasPrefix(w.marker, dirPath) {
			return w.walkLexSort(path)
		}
		return nil
	}

	if w.isAtMarker(dirPath) {
		// At marker - recurse but don't include as common prefix
		w.pastMarker = true
		return w.walkLexSort(path)
	}

	// Apply prefix filter
	if w.prefix != "" && !strings.HasPrefix(dirPath, w.prefix) {
		return w.walkLexSort(path)
	}

	if w.delimiter != "" {
		return w.processDirectoryWithDelimiter(path, dirPath)
	}
	return w.processDirectoryWithoutDelimiter(path, dirPath, d)
}

// processDirectoryWithDelimiter handles directory processing when delimiter is specified
func (w *walkState) processDirectoryWithDelimiter(path, dirPath string) error {
	// Special case: if the directory path exactly matches the prefix, return it as an object
	if dirPath == w.prefix {
		dirobj, err := w.getObj(dirPath, &fakeDirEntry{name: path, isDir: true})
		switch err {
		case ErrSkipObj:
			// Skip but continue to recurse
		case nil:
			if w.addObject(dirobj, dirPath) {
				return nil
			}
		default:
			return fmt.Errorf("directory to object %q: %w", dirPath, err)
		}
	}

	// Handle delimiter logic for directories
	suffix := strings.TrimPrefix(dirPath, w.prefix)
	before, _, found := strings.Cut(suffix, w.delimiter)

	if found {
		// Directory creates a common prefix
		cprefNoDelim := w.prefix + before
		cpref := w.prefix + before + w.delimiter

		if w.isBeforeMarker(cpref) {
			if w.marker != "" && strings.HasPrefix(w.marker, cprefNoDelim) {
				return w.walkLexSort(path)
			}
			return nil
		}

		if w.isAtMarker(cpref) {
			w.pastMarker = true
			return w.walkLexSort(path)
		}

		// Skip if this common prefix is <= marker (for when pastMarker is already true)
		if w.marker != "" && cpref <= w.marker {
			return w.walkLexSort(path)
		}

		if w.pastMax {
			w.truncated = true
			return nil
		}

		if w.addCommonPrefix(cpref) {
			return nil
		}
	}

	return w.walkLexSort(path)
}

// processDirectoryWithoutDelimiter handles directory processing when no delimiter is specified
func (w *walkState) processDirectoryWithoutDelimiter(path, dirPath string, d fs.DirEntry) error {
	// Include directory as object if it matches prefix
	if w.prefix == "" || strings.HasPrefix(dirPath, w.prefix) {
		dirobj, err := w.getObj(dirPath, d)
		switch err {
		case ErrSkipObj:
			// Skip but continue to recurse
		case nil:
			if w.addObject(dirobj, dirPath) {
				return nil
			}
		default:
			return fmt.Errorf("directory to object %q: %w", dirPath, err)
		}
	}

	return w.walkLexSort(path)
}

func (w *walkState) processFile(path string, d fs.DirEntry) error {
	if w.isBeforeMarker(path) {
		return nil
	}

	if w.isAtMarker(path) {
		w.pastMarker = true
		return nil
	}

	if w.prefix != "" && !strings.HasPrefix(path, w.prefix) {
		return nil
	}

	if w.delimiter != "" {
		return w.processFileWithDelimiter(path, d)
	}
	return w.processFileWithoutDelimiter(path, d)
}

// processFileWithDelimiter handles file processing when delimiter is specified
func (w *walkState) processFileWithDelimiter(path string, d fs.DirEntry) error {
	suffix := strings.TrimPrefix(path, w.prefix)
	before, _, found := strings.Cut(suffix, w.delimiter)

	if !found {
		// File doesn't contain delimiter after prefix - include it
		obj, err := w.getObj(path, d)
		if err == ErrSkipObj {
			return nil
		}
		if err != nil {
			return fmt.Errorf("file to object %q: %w", path, err)
		}
		if w.pastMax {
			w.truncated = true
			return nil
		}

		if w.addObject(obj, path) {
			return nil
		}

		return nil
	}

	// File contains delimiter after prefix - add to common prefixes
	cprefNoDelim := w.prefix + before
	cpref := w.prefix + before + w.delimiter

	if w.isBeforeMarker(cpref) {
		if w.marker != "" && strings.HasPrefix(w.marker, cprefNoDelim) {
			return nil
		}
		return nil
	}

	if w.isAtMarker(cpref) {
		w.pastMarker = true
		return nil
	}

	// Skip if this common prefix is <= marker (for when pastMarker is already true)
	if w.marker != "" && cpref <= w.marker {
		return nil
	}

	if w.pastMax {
		w.truncated = true
		return nil
	}

	w.addCommonPrefix(cpref)

	return nil
}

// processFileWithoutDelimiter handles file processing when no delimiter is specified
func (w *walkState) processFileWithoutDelimiter(path string, d fs.DirEntry) error {
	obj, err := w.getObj(path, d)
	if err == ErrSkipObj {
		return nil
	}
	if err != nil {
		return fmt.Errorf("file to object %q: %w", path, err)
	}

	w.addObject(obj, path)
	return nil
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
	// Early return for zero max
	if max == 0 {
		return WalkVersioningResults{}, nil
	}

	// Reuse the same lexicographic traversal strategy as Walk() to guarantee
	// ordering of directory "objects" (dir/) vs files (dir/file) where the
	// filesystem readdir order may differ from full-path lexical ordering.

	type versionWalkState struct {
		ctx                 context.Context
		fileSystem          fs.FS
		prefix              string
		delimiter           string
		keyMarker           string
		versionIdMarker     string
		max                 int
		getVersions         GetVersionsFunc
		skipdirs            []string
		cpmap               cpMap
		objectVersions      []s3response.ObjectVersion
		delMarkers          []types.DeleteMarkerEntry
		pastMarker          bool
		pastVersionIdMarker bool
		pastMax             bool
		newMarker           string
		newVersionIdMarker  string
		truncated           bool
	}

	state := &versionWalkState{
		ctx:                 ctx,
		fileSystem:          fileSystem,
		prefix:              prefix,
		delimiter:           delimiter,
		keyMarker:           keyMarker,
		versionIdMarker:     versionIdMarker,
		max:                 max,
		getVersions:         getObj,
		skipdirs:            skipdirs,
		cpmap:               cpMap{},
		pastMarker:          keyMarker == "",
		pastVersionIdMarker: versionIdMarker == "",
	}

	// Helper methods
	available := func() int { return state.max - (len(state.objectVersions) + len(state.delMarkers) + state.cpmap.Len()) }
	checkLimits := func() bool { return state.pastMax || state.ctx.Err() != nil }
	isBeforeMarker := func(path string) bool { return !state.pastMarker && path < state.keyMarker }
	isAtMarker := func(path string) bool { return !state.pastMarker && path == state.keyMarker }
	addVersions := func(path string, d fs.DirEntry) error {
		if available() <= 0 {
			state.pastMax = true
			return nil
		}
		res, err := state.getVersions(path, state.versionIdMarker, &state.pastVersionIdMarker, available(), d)
		if err == ErrSkipObj {
			return nil
		}
		if err != nil {
			return fmt.Errorf("version object for %q: %w", path, err)
		}
		state.objectVersions = append(state.objectVersions, res.ObjectVersions...)
		state.delMarkers = append(state.delMarkers, res.DelMarkers...)
		if res.Truncated {
			state.truncated = true
			state.newMarker = path
			state.newVersionIdMarker = res.NextVersionIdMarker
			state.pastMax = true
			return nil
		}
		if available() <= 0 {
			state.newMarker = path
			state.pastMax = true
		}
		return nil
	}
	addCommonPrefix := func(cpref string) {
		if state.pastMax {
			return
		}
		state.cpmap.Add(cpref)
		if available() <= 0 {
			state.newMarker = cpref
			state.pastMax = true
		}
	}

	var walkLexSort func(dir string) error

	walkLexSort = func(dir string) error {
		if state.ctx.Err() != nil {
			return state.ctx.Err()
		}
		entries, err := buildSortedEntries(state.fileSystem, dir, state.skipdirs)
		if err != nil {
			return err
		}
		for i, entry := range entries {
			if checkLimits() {
				if state.pastMax {
					// There are more entries -> truncated
					if i < len(entries)-1 || len(entries) > 0 {
						state.truncated = true
					}
				}
				return state.ctx.Err()
			}
			if state.pastMax {
				state.truncated = true
				return nil
			}
			path := entry.path
			d := entry.d
			if d.IsDir() {
				// Directory processing
				dirPath := path + pathSeparator
				if shouldSkipDirectory(dirPath, state.prefix) {
					continue
				}
				if isBeforeMarker(path) { // marker comparisons use raw path (without trailing slash)
					// Only recurse if marker could be inside
					if strings.HasPrefix(state.keyMarker, dirPath) {
						if err := walkLexSort(path); err != nil {
							return err
						}
					}
					continue
				}
				if isAtMarker(path) {
					state.pastMarker = true
					if err := walkLexSort(path); err != nil {
						return err
					}
					continue
				}
				// Prefix logic
				if state.prefix != "" && !strings.HasPrefix(dirPath, state.prefix) {
					if err := walkLexSort(path); err != nil {
						return err
					}
					continue
				}
				if state.delimiter != "" {
					// Delimiter mode
					if dirPath == state.prefix { // include the prefix dir itself as an object
						if err := addVersions(path, d); err != nil {
							return err
						}
						if state.pastMax {
							state.truncated = true
							return nil
						}
					}
					suffix := strings.TrimPrefix(dirPath, state.prefix)
					before, _, found := strings.Cut(suffix, state.delimiter)
					if found { // forms common prefix
						cprefNoDelim := state.prefix + before
						cpref := cprefNoDelim + state.delimiter
						if isBeforeMarker(cpref) {
							if state.keyMarker != "" && strings.HasPrefix(state.keyMarker, cprefNoDelim) {
								if err := walkLexSort(path); err != nil {
									return err
								}
							}
							continue
						}
						if isAtMarker(cpref) {
							state.pastMarker = true
							if err := walkLexSort(path); err != nil {
								return err
							}
							continue
						}
						if state.keyMarker != "" && cpref <= state.keyMarker {
							if err := walkLexSort(path); err != nil {
								return err
							}
							continue
						}
						addCommonPrefix(cpref)
						if state.pastMax {
							state.truncated = true
							return nil
						}
						if err := walkLexSort(path); err != nil {
							return err
						}
						continue
					}
					// Recurse deeper
					if err := walkLexSort(path); err != nil {
						return err
					}
					continue
				}
				// No delimiter: include directory as object version
				if err := addVersions(path, d); err != nil {
					return err
				}
				if state.pastMax {
					state.truncated = true
					return nil
				}
				if err := walkLexSort(path); err != nil {
					return err
				}
				continue
			}
			// File processing
			if isBeforeMarker(path) {
				continue
			}
			if isAtMarker(path) {
				state.pastMarker = true
				continue
			}
			if state.prefix != "" && !strings.HasPrefix(path, state.prefix) {
				continue
			}
			if state.delimiter != "" {
				suffix := strings.TrimPrefix(path, state.prefix)
				before, _, found := strings.Cut(suffix, state.delimiter)
				if !found { // include file
					if err := addVersions(path, d); err != nil {
						return err
					}
					if state.pastMax {
						state.truncated = true
						return nil
					}
				} else { // add common prefix
					cprefNoDelim := state.prefix + before
					cpref := cprefNoDelim + state.delimiter
					if isBeforeMarker(cpref) {
						continue
					}
					if isAtMarker(cpref) {
						state.pastMarker = true
						continue
					}
					if state.keyMarker != "" && cpref <= state.keyMarker {
						continue
					}
					addCommonPrefix(cpref)
					if state.pastMax {
						state.truncated = true
						return nil
					}
				}
				continue
			}
			// No delimiter
			if err := addVersions(path, d); err != nil {
				return err
			}
			if state.pastMax {
				state.truncated = true
				return nil
			}
		}
		return nil
	}

	root := pathDot
	if strings.Contains(prefix, pathSeparator) {
		if idx := strings.LastIndex(prefix, pathSeparator); idx > 0 {
			root = prefix[:idx]
		}
	}

	// Special handling: if no delimiter and prefix ends with a separator, include the
	// directory object for that prefix before traversing children (mirrors Walk()).
	if state.delimiter == "" && state.prefix != "" && strings.HasSuffix(state.prefix, pathSeparator) {
		prefixDir := strings.TrimSuffix(state.prefix, pathSeparator)
		// Determine entry name (last element)
		name := prefixDir
		if idx := strings.LastIndex(prefixDir, pathSeparator); idx >= 0 {
			name = prefixDir[idx+1:]
		}
		// Marker logic similar to Walk.handlePrefixDirectory
		if state.pastMarker || state.keyMarker == "" || prefixDir <= state.keyMarker {
			if state.keyMarker == "" || prefixDir < state.keyMarker || prefixDir == state.keyMarker {
				if prefixDir != state.keyMarker {
					// Use fakeDirEntry to represent the directory
					if err := addVersions(prefixDir, &fakeDirEntry{name: name, isDir: true}); err != nil {
						return WalkVersioningResults{}, err
					}
				}
				if prefixDir == state.keyMarker {
					state.pastMarker = true
				}
			}
		}
	}

	if err := walkLexSort(root); err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
			return WalkVersioningResults{}, nil
		}
		return WalkVersioningResults{}, err
	}

	if !state.truncated {
		state.newMarker = ""
	}

	return WalkVersioningResults{
		CommonPrefixes:      state.cpmap.CpArray(),
		ObjectVersions:      state.objectVersions,
		DelMarkers:          state.delMarkers,
		Truncated:           state.truncated,
		NextMarker:          state.newMarker,
		NextVersionIdMarker: state.newVersionIdMarker,
	}, nil
}
