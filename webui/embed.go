// Copyright 2026 Versity Software
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

package webui

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"path/filepath"
	"time"
)

// webFiles embeds the admin GUI static files from web/.
// The "all:" prefix recursively includes all files and subdirectories.
//
//go:embed all:web
var webFiles embed.FS

// webFS is an alias for webFiles for consistency with server.go
var webFS = webFiles

func replaceInEmbedFS(original embed.FS, old, pathPrefix string) (*mapFS, error) {
	m := &mapFS{files: make(map[string][]byte), pathPrefix: pathPrefix}
	err := fs.WalkDir(original, "web", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := fs.ReadFile(original, path)
		if err != nil {
			return err
		}
		m.files[path] = bytes.ReplaceAll(data, []byte(old), []byte(pathPrefix))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return m, nil
}

type mapFS struct {
	files      map[string][]byte
	pathPrefix string
}

func (m *mapFS) Open(name string) (fs.File, error) {
	data, ok := m.files[filepath.Clean(name)]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return &byteFile{Reader: bytes.NewReader(data), name: name, size: int64(len(data))}, nil
}

type byteFile struct {
	*bytes.Reader
	name string
	size int64
}

func (b *byteFile) Stat() (fs.FileInfo, error) {
	return &byteFileInfo{name: b.name, size: b.size}, nil
}

func (b *byteFile) Close() error {
	return nil
}

type byteFileInfo struct {
	name string
	size int64
}

func (f *byteFileInfo) Name() string       { return f.name }
func (f *byteFileInfo) Size() int64        { return f.size }
func (f *byteFileInfo) Mode() fs.FileMode  { return 0444 }
func (f *byteFileInfo) ModTime() time.Time { return time.Time{} }
func (f *byteFileInfo) IsDir() bool        { return false }
func (f *byteFileInfo) Sys() any           { return nil }
