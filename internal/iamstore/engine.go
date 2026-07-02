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

package iamstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

const (
	iamMode  = 0600
	backoff  = 100 * time.Millisecond
	maxretry = 300
)

// UpdateFunc accepts the current JSON data and returns the new JSON data to store.
type UpdateFunc func([]byte) ([]byte, error)

type NormalizeFunc[T any] func(*T)

type Engine[T any] struct {
	dir           string
	iamFile       string
	iamBackupFile string
	defaultConfig T
	normalize     NormalizeFunc[T]
}

func New[T any](dir, iamFile, iamBackupFile string, defaultConfig T, normalize NormalizeFunc[T]) (*Engine[T], error) {
	engine := &Engine[T]{
		dir:           dir,
		iamFile:       iamFile,
		iamBackupFile: iamBackupFile,
		defaultConfig: defaultConfig,
		normalize:     normalize,
	}

	if err := engine.InitIAM(); err != nil {
		return nil, err
	}

	return engine, nil
}

func (e *Engine[T]) InitIAM() error {
	fname := filepath.Join(e.dir, e.iamFile)

	_, err := os.ReadFile(fname)
	if errors.Is(err, fs.ErrNotExist) {
		b, err := json.Marshal(e.defaultConfig)
		if err != nil {
			return fmt.Errorf("marshal default iam: %w", err)
		}
		err = os.WriteFile(fname, b, iamMode)
		if err != nil {
			return fmt.Errorf("write default iam: %w", err)
		}
	}

	return nil
}

func (e *Engine[T]) GetIAM() (T, error) {
	b, err := e.ReadIAMData()
	if err != nil {
		var zero T
		return zero, err
	}

	return e.ParseIAM(b)
}

func (e *Engine[T]) ParseIAM(b []byte) (T, error) {
	return ParseIAM(b, e.normalize)
}

func ParseIAM[T any](b []byte, normalize NormalizeFunc[T]) (T, error) {
	var conf T
	if err := json.Unmarshal(b, &conf); err != nil {
		return conf, fmt.Errorf("failed to parse the config file: %w", err)
	}

	if normalize != nil {
		normalize(&conf)
	}

	return conf, nil
}

func (e *Engine[T]) ReadIAMData() ([]byte, error) {
	// We are going to be racing with other running gateways without any
	// coordination. So we might find the file does not exist at times.
	// For this case we need to retry for a while assuming the other gateway
	// will eventually write the file. If it doesn't after the max retries,
	// then we will return the error.

	retries := 0

	for {
		b, err := os.ReadFile(filepath.Join(e.dir, e.iamFile))
		if errors.Is(err, fs.ErrNotExist) {
			// racing with someone else updating
			// keep retrying after backoff
			retries++
			if retries < maxretry {
				time.Sleep(backoff)
				continue
			}
			return nil, fmt.Errorf("read iam file: %w", err)
		}
		if err != nil {
			return nil, err
		}

		return b, nil
	}
}

func (e *Engine[T]) StoreIAM(update UpdateFunc) error {
	// We are going to be racing with other running gateways without any
	// coordination. So the strategy here is to read the current file data,
	// update the data, write back out to a temp file, then rename the
	// temp file to the original file. This rename will replace the
	// original file with the new file. This is atomic and should always
	// allow for a consistent view of the data. There is a small
	// window where the file could be read and then updated by
	// another process. In this case any updates the other process did
	// will be lost. This is a limitation of the internal IAM service.
	// This should be rare, and even when it does happen should result
	// in a valid IAM file, just without the other process's updates.

	iamFname := filepath.Join(e.dir, e.iamFile)
	backupFname := filepath.Join(e.dir, e.iamBackupFile)

	b, err := os.ReadFile(iamFname)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("read iam file: %w", err)
	}

	err = e.writeUsingTempFile(b, backupFname)
	if err != nil {
		return fmt.Errorf("write backup iam file: %w", err)
	}

	b, err = update(b)
	if err != nil {
		return fmt.Errorf("update iam data: %w", err)
	}

	err = e.writeUsingTempFile(b, iamFname)
	if err != nil {
		return fmt.Errorf("write iam file: %w", err)
	}

	return nil
}

func (e *Engine[T]) writeUsingTempFile(b []byte, fname string) error {
	f, err := os.CreateTemp(e.dir, e.iamFile)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(f.Name())

	_, err = f.Write(b)
	f.Close()
	if err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}

	err = os.Rename(f.Name(), fname)
	if err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}

	return nil
}
