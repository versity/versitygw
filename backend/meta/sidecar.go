// Copyright 2025 Versity Software
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

package meta

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// SideCar is a metadata storer that uses sidecar files to store metadata.
type SideCar struct {
	dir string
}

const (
	sidecarmeta = "meta"
)

// NewSideCar creates a new SideCar metadata storer.
func NewSideCar(dir string) (SideCar, error) {
	fi, err := os.Lstat(dir)
	if err != nil {
		return SideCar{}, fmt.Errorf("failed to stat directory: %v", err)
	}
	if !fi.IsDir() {
		return SideCar{}, fmt.Errorf("not a directory")
	}

	return SideCar{dir: dir}, nil
}

// RetrieveAttribute retrieves the value of a specific attribute for an object or a bucket.
func (s SideCar) RetrieveAttribute(_ *os.File, bucket, object, attribute string) ([]byte, error) {
	metadir := filepath.Join(s.dir, bucket, object, sidecarmeta)
	if object == "" {
		metadir = filepath.Join(s.dir, bucket, sidecarmeta)
	}
	attr := filepath.Join(metadir, attribute)

	value, err := os.ReadFile(attr)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoSuchKey
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read attribute: %v", err)
	}

	return value, nil
}

// StoreAttribute stores the value of a specific attribute for an object or a bucket.
func (s SideCar) StoreAttribute(_ *os.File, bucket, object, attribute string, value []byte) error {
	metadir := filepath.Join(s.dir, bucket, object, sidecarmeta)
	if object == "" {
		metadir = filepath.Join(s.dir, bucket, sidecarmeta)
	}
	err := os.MkdirAll(metadir, 0777)
	if err != nil {
		return fmt.Errorf("failed to create metadata directory: %v", err)
	}

	attr := filepath.Join(metadir, attribute)
	err = os.WriteFile(attr, value, 0666)
	if err != nil {
		return fmt.Errorf("failed to write attribute: %v", err)
	}

	return nil
}

// DeleteAttribute removes the value of a specific attribute for an object or a bucket.
func (s SideCar) DeleteAttribute(bucket, object, attribute string) error {
	metadir := filepath.Join(s.dir, bucket, object, sidecarmeta)
	if object == "" {
		metadir = filepath.Join(s.dir, bucket, sidecarmeta)
	}
	attr := filepath.Join(metadir, attribute)

	err := os.Remove(attr)
	if errors.Is(err, os.ErrNotExist) {
		return ErrNoSuchKey
	}
	if err != nil {
		return fmt.Errorf("failed to remove attribute: %v", err)
	}

	return nil
}

// ListAttributes lists all attributes for an object or a bucket.
func (s SideCar) ListAttributes(bucket, object string) ([]string, error) {
	metadir := filepath.Join(s.dir, bucket, object, sidecarmeta)
	if object == "" {
		metadir = filepath.Join(s.dir, bucket, sidecarmeta)
	}

	ents, err := os.ReadDir(metadir)
	if errors.Is(err, os.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to list attributes: %v", err)
	}

	var attrs []string
	for _, ent := range ents {
		attrs = append(attrs, ent.Name())
	}

	return attrs, nil
}

// DeleteAttributes removes all attributes for an object or a bucket.
func (s SideCar) DeleteAttributes(bucket, object string) error {
	metadir := filepath.Join(s.dir, bucket, object, sidecarmeta)
	if object == "" {
		metadir = filepath.Join(s.dir, bucket, sidecarmeta)
	}

	err := os.RemoveAll(metadir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to remove attributes: %v", err)
	}
	return nil
}
