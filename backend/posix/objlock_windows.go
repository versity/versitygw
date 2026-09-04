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

//go:build windows

package posix

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// lockFileExclusive takes an exclusive lock on f via LockFileEx, polling with
// backoff so that context cancellation is honored while waiting. The lock is
// released when f is closed or the process exits.
func lockFileExclusive(ctx context.Context, f *os.File, mode ObjectLockMode) error {
	if mode != ObjectLockModeFlock {
		return errors.New("object lock mode fcntl is not supported on Windows")
	}
	backoff := objLockInitialBackoff
	for {
		ol := new(windows.Overlapped)
		err := windows.LockFileEx(windows.Handle(f.Fd()),
			windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
			0, 1, 0, ol)
		if err == nil {
			return nil
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, objLockMaxBackoff)
	}
}

func validateObjectLockMode(mode ObjectLockMode) error {
	if mode == ObjectLockModeFcntl {
		return fmt.Errorf("object lock mode %q is not supported on Windows; use flock, local, or none", mode)
	}
	return nil
}
