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

//go:build !windows

package posix

import (
	"context"
	"errors"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// lockFileExclusive takes the configured exclusive advisory lock on f,
// polling with backoff so that context cancellation is honored while waiting.
func lockFileExclusive(ctx context.Context, f *os.File, mode ObjectLockMode) error {
	backoff := objLockInitialBackoff
	for {
		var err error
		switch mode {
		case ObjectLockModeFlock:
			err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		case ObjectLockModeFcntl:
			err = unix.FcntlFlock(f.Fd(), unix.F_SETLK, &unix.Flock_t{
				Type:   unix.F_WRLCK,
				Whence: int16(io.SeekStart),
			})
		default:
			return errors.New("unsupported object lock mode")
		}
		if err == nil {
			return nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) &&
			!errors.Is(err, unix.EACCES) && !errors.Is(err, unix.EINTR) {
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

func validateObjectLockMode(ObjectLockMode) error {
	return nil
}
