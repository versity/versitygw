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
	"encoding/json"
)

// SideCar is a metadata storer that uses sidecar files to store metadata.
type SideCar struct {
	dir string
}

const (
	sidecarmeta = ".meta"
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

// Sidecar JSON file for storing attributes
func sidecarFileGen(root string, bucket string, object string) string {
	if object == "" {
		return filepath.Join(root, bucket + sidecarmeta)
	} else {
		return filepath.Join(root, bucket, object + sidecarmeta)
	}
}

// Load sidecar file
func sidecarFileLoad(sidecarFile string) (map[string][]byte, error) {
	//Read JSON file
	jsonData, err := os.ReadFile(sidecarFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoSuchKey
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read sidecar file: %v", err)
	}
	if len(jsonData) == 0 {
		return nil, ErrNoSuchKey
	}

	// Decode JSON file
	data := map[string][]byte{}
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return nil, fmt.Errorf("error unmarshaling existing JSON: %v", err)
	}

	//Return data
	return data, nil

}

// Write sidecar file
func sidecarFileSave(sidecarFile string, data map[string][]byte) error {

	// Re-serialize
	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling JSON: %v", err)
	}

	// Write file back
	if err := os.WriteFile(sidecarFile, jsonBytes, 0644); err != nil {
		return fmt.Errorf("failed to write sidecar file: %v", err)
	}

	return nil

}

// RetrieveAttribute retrieves the value of a specific attribute for an object or a bucket.
func (s SideCar) RetrieveAttribute(_ *os.File, bucket, object, attribute string) ([]byte, error) {
	//Sidecar file
	sidecarFile := sidecarFileGen(s.dir, bucket, object)

	//Read JSON file
	data, err := sidecarFileLoad(sidecarFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read attribute: %v", err)
	}

	//If the attribute exist, return it
	value, ok := data[attribute]
	if !ok {
		return nil, ErrNoSuchKey
	}

	return value, nil
}

// StoreAttribute stores the value of a specific attribute for an object or a bucket.
func (s SideCar) StoreAttribute(_ *os.File, bucket, object, attribute string, value []byte) error {
	//Sidecar file
	sidecarFile :=  sidecarFileGen(s.dir, bucket, object)

	//Create directory if it does not exist
	err := os.MkdirAll(filepath.Dir(sidecarFile), 0777)
	if err != nil {
		return fmt.Errorf("failed to create metadata directory: %v", err)
	}

	// Try reading existing file
	data, err := sidecarFileLoad(sidecarFile)
	if err != nil {
		// File does not exist, using empty data
		data = map[string][]byte{}
	}

	// Set or replace the attribute entry
	data[attribute] = value

	// Write file back
	if err := sidecarFileSave(sidecarFile, data); err != nil {
		return fmt.Errorf("failed to write attribute: %v", err)
	}

	return nil
}

// DeleteAttribute removes the value of a specific attribute for an object or a bucket.
func (s SideCar) DeleteAttribute(bucket, object, attribute string) error {
	//Sidecar file
	sidecarFile :=  sidecarFileGen(s.dir, bucket, object)

	// Try reading existing file
	data, err := sidecarFileLoad(sidecarFile)
	if err != nil {
		// File does not exist, all is fine
		return nil
	}

	// Delete the key (no error if missing)
	delete(data, attribute)

	// Delete the file if there are no attributes left
	if len(data) == 0 {
		if err := os.Remove(sidecarFile); err != nil {
			return fmt.Errorf("error removing empty JSON file: %w", err)
		}
		return nil
	}

	// Write file back
	if err := sidecarFileSave(sidecarFile, data); err != nil {
		return err
	}

	return nil
}

// ListAttributes lists all attributes for an object or a bucket.
func (s SideCar) ListAttributes(bucket, object string) ([]string, error) {
	//Sidecar file
	sidecarFile :=  sidecarFileGen(s.dir, bucket, object)

	// Try reading existing file
	data, err := sidecarFileLoad(sidecarFile)
	if errors.Is(err, os.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to list attributes: %v", err)
	}

	// Collect keys
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}

	return keys, nil

}

// DeleteAttributes removes all attributes for an object or a bucket.
func (s SideCar) DeleteAttributes(bucket, object string) error {
	//Sidecar file
	sidecarFile :=  sidecarFileGen(s.dir, bucket, object)

	//Delete metadata file
	if err := os.Remove(sidecarFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("error removing empty JSON file: %w", err)
	}
	return nil

}
