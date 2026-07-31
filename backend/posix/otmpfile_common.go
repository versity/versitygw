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

package posix

import (
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"strconv"
	"syscall"
	"time"
)

const odirectMinWriteAlign = 512

func (tmp *tmpfile) Write(b []byte) (int, error) {
	if int64(len(b)) > tmp.size {
		return 0, fmt.Errorf("write exceeds content length %v", tmp.size)
	}

	if tmp.useODirect && !isODirectLenAligned(len(b)) {
		if err := tmp.switchToBufferedAtCurrentOffset(fmt.Sprintf("unaligned write length: len=%d len%%512=%d", len(b), len(b)%odirectMinWriteAlign)); err != nil {
			return 0, err
		}
	}

	n, err := tmp.f.Write(b)
	if err != nil && n == 0 && tmp.useODirect && isODirectRuntimeFallbackErr(err) {
		warnODirectUnsupportedOnce("tmpfile.Write", err)
		if fallbackErr := tmp.switchToBufferedAtCurrentOffset("O_DIRECT write failure"); fallbackErr != nil {
			return 0, fallbackErr
		}

		n, err = tmp.f.Write(b)
	}
	tmp.size -= int64(n)
	return n, err
}

func (tmp *tmpfile) switchToBufferedAtCurrentOffset(reason string) error {
	offset, seekErr := tmp.f.Seek(0, io.SeekCurrent)
	if seekErr != nil {
		return fmt.Errorf("capture write offset before fallback reopen: %w", seekErr)
	}

	name := tmp.f.Name()
	f, openErr := os.OpenFile(name, os.O_RDWR, 0)
	if openErr != nil {
		return fmt.Errorf("reopen temp file in buffered mode after O_DIRECT fallback (%s): %w", reason, openErr)
	}

	if _, seekErr = f.Seek(offset, io.SeekStart); seekErr != nil {
		f.Close()
		return fmt.Errorf("restore write offset after fallback reopen: %w", seekErr)
	}

	if closeErr := tmp.f.Close(); closeErr != nil {
		f.Close()
		return fmt.Errorf("close O_DIRECT temp file after fallback reopen: %w", closeErr)
	}

	tmp.f = f
	if tmp.isOTmp {
		tmp.procFDName = strconv.Itoa(int(f.Fd()))
	}
	tmp.useODirect = false

	return nil
}

func isODirectLenAligned(n int) bool {
	return n%odirectMinWriteAlign == 0
}

func isODirectRuntimeFallbackErr(err error) bool {
	return errors.Is(err, syscall.EINVAL) ||
		errors.Is(err, syscall.EOPNOTSUPP) ||
		errors.Is(err, syscall.ENOTSUP)
}

func (tmp *tmpfile) File() *os.File {
	return tmp.f
}

func sleepWithJitter(backoffMs int) {
	if backoffMs <= 1 {
		time.Sleep(1 * time.Millisecond)
		return
	}

	maxJitter := max(1, backoffMs/4)
	jitter := rand.Intn((maxJitter*2)+1) - maxJitter
	sleepMs := max(backoffMs+jitter, 1)
	time.Sleep(time.Duration(sleepMs) * time.Millisecond)
}
