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

//go:build !linux

package posix

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3err"
)

const (
	initialBackoffMs = 1
	maxBackoffMs     = 1024 // ~1 second
)

type tmpfile struct {
	f          *os.File
	bucket     string
	objname    string
	size       int64
	newDirPerm fs.FileMode
	uid        int
	gid        int
	doChown    bool
}

func (p *Posix) openTmpFile(dir, bucket, obj string, size int64, acct auth.Account, _ bool, _ bool) (*tmpfile, error) {
	uid, gid, doChown := p.getChownIDs(acct)

	// Create a temp file for upload while in progress (see link comments below).
	var err error
	err = backend.MkdirAll(dir, uid, gid, doChown, p.newDirPerm)
	if err != nil {
		if errors.Is(err, syscall.EROFS) {
			return nil, s3err.GetAPIError(s3err.ErrMethodNotAllowed)
		}
		return nil, fmt.Errorf("make temp dir: %w", err)
	}
	f, err := os.CreateTemp(dir,
		fmt.Sprintf("%x.", sha256.Sum256([]byte(obj))))
	if err != nil {
		if errors.Is(err, syscall.EROFS) {
			return nil, s3err.GetAPIError(s3err.ErrMethodNotAllowed)
		}
		return nil, fmt.Errorf("create temp file: %w", err)
	}

	if doChown {
		err := f.Chown(uid, gid)
		if err != nil {
			f.Close()
			os.Remove(f.Name())
			return nil, fmt.Errorf("set temp file ownership: %w", err)
		}
	}

	return &tmpfile{
		f:          f,
		bucket:     bucket,
		objname:    obj,
		size:       size,
		newDirPerm: p.newDirPerm,
		uid:        uid,
		gid:        gid,
		doChown:    doChown,
	}, nil
}

var (
	// TODO: make this configurable
	defaultFilePerm fs.FileMode = 0644
)

func (tmp *tmpfile) link() error {
	tempname := tmp.f.Name()

	objPath := filepath.Join(tmp.bucket, tmp.objname)

	// reset default file mode because CreateTemp uses 0600
	tmp.f.Chmod(defaultFilePerm)

	err := tmp.f.Close()
	if err != nil {
		return fmt.Errorf("close tmpfile: %w", err)
	}

	backoffMs := initialBackoffMs
	for {
		err = backend.MoveFile(tempname, objPath, defaultFilePerm)
		if !errors.Is(err, syscall.ENOENT) {
			break
		}
		// The parent directory may have been concurrently removed; backoff and retry.
		// Add jitter to avoid synchronized retry waves.
		sleepWithJitter(backoffMs)
		backoffMs = min((backoffMs * 2), maxBackoffMs)

		err = backend.MkdirAll(filepath.Dir(objPath), tmp.uid, tmp.gid,
			tmp.doChown, tmp.newDirPerm)
		if err != nil {
			return fmt.Errorf("recreate parent dir: %w", err)
		}
	}
	return err
}

func (tmp *tmpfile) cleanup() {
	tmp.f.Close()
	os.Remove(tmp.f.Name())
}
