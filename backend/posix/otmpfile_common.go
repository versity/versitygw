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
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/debuglogger"
)

// maxDirRecreateRetries bounds how many times publishing an object makes its
// parent directory again after a concurrent delete removed it
const maxDirRecreateRetries = 10

// odirectAlign covers both 512e and 4Kn logical block sizes for O_DIRECT
// offsets, lengths, and memory.
const odirectAlign = 4096

// alignedBuffer returns a size-byte slice whose first byte is odirectAlign aligned.
func alignedBuffer(size int) []byte {
	b := make([]byte, size+odirectAlign)
	off := 0
	if rem := int(uintptr(unsafe.Pointer(&b[0])) % odirectAlign); rem != 0 {
		off = odirectAlign - rem
	}
	return b[off : off+size : off+size]
}

func isODirectMemAligned(b []byte) bool {
	return len(b) == 0 || uintptr(unsafe.Pointer(&b[0]))%odirectAlign == 0
}

func (tmp *tmpfile) Write(b []byte) (int, error) {
	if int64(len(b)) > tmp.size {
		return 0, fmt.Errorf("write exceeds content length %v", tmp.size)
	}

	if tmp.useODirect && !isODirectLenAligned(len(b)) {
		reason := fmt.Sprintf("unaligned write length: len=%d len%%%d=%d", len(b), odirectAlign, len(b)%odirectAlign)
		debuglogger.Logf("O_DIRECT tmpfile falling back to buffered I/O (%s/%s): %s", tmp.bucket, tmp.objname, reason)
		if err := tmp.switchToBufferedAtCurrentOffset(reason); err != nil {
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

// copyFrom copies r into tmp. With O_DIRECT it fills buf completely before
// each write so that only the final tail of the object is unaligned.
func (tmp *tmpfile) copyFrom(r io.Reader, buf []byte) (int64, error) {
	if !tmp.useODirect || len(buf) < odirectAlign {
		return io.CopyBuffer(tmp, r, buf)
	}
	if !isODirectMemAligned(buf) {
		buf = alignedBuffer(len(buf))
	}
	buf = buf[:len(buf)-len(buf)%odirectAlign]

	var written int64
	for {
		// Not io.ReadFull: it drops errors returned alongside a full buffer,
		// which is how HashReader reports checksum mismatches.
		n := 0
		var rerr error
		for n < len(buf) && rerr == nil {
			var nn int
			nn, rerr = r.Read(buf[n:])
			n += nn
		}

		if n > 0 {
			w, werr := tmp.writeAlignedThenTail(buf[:n])
			written += int64(w)
			if werr != nil {
				return written, werr
			}
		}

		if rerr == io.EOF {
			return written, nil
		}
		if rerr != nil {
			return written, rerr
		}
	}
}

// writeAlignedThenTail writes the block-aligned prefix of b with O_DIRECT and
// any unaligned remainder buffered, without treating the tail as a fallback.
func (tmp *tmpfile) writeAlignedThenTail(b []byte) (int, error) {
	if !tmp.useODirect || isODirectLenAligned(len(b)) {
		return tmp.Write(b)
	}

	aligned := len(b) - len(b)%odirectAlign
	n := 0
	if aligned > 0 {
		var err error
		n, err = tmp.Write(b[:aligned])
		if err != nil {
			return n, err
		}
	}

	if tmp.useODirect {
		if err := tmp.switchToBufferedAtCurrentOffset("final unaligned tail"); err != nil {
			return n, err
		}
	}

	m, err := tmp.Write(b[aligned:])
	return n + m, err
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
	return n%odirectAlign == 0
}

func isODirectRuntimeFallbackErr(err error) bool {
	return errors.Is(err, syscall.EINVAL) ||
		errors.Is(err, syscall.EOPNOTSUPP) ||
		errors.Is(err, syscall.ENOTSUP)
}

func (tmp *tmpfile) File() *os.File {
	return tmp.f
}

// setModTime makes link() publish the file with the modification time t
// instead of the time it was last written
func (tmp *tmpfile) setModTime(t time.Time) {
	tmp.modTime = t
}

// applyModTime sets the modification time requested with setModTime on the
// file at path. Windows updates the last write time when a handle the file
// was written through is closed, so it has to be set after that handle is
// closed.
func (tmp *tmpfile) applyModTime(path string) error {
	if tmp.modTime.IsZero() {
		return nil
	}
	return os.Chtimes(path, time.Now(), tmp.modTime)
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

// publishInDir runs publish, which places the object in its parent directory
// dir, and makes dir when publish finds it missing. The implicit parent
// directories of objects are removed by deletes of other objects under them
// without any coordination with uploads, so dir can be removed again before
// publish places the object in it. Making dir only right before publish keeps
// the time it spends empty, and removable, short.
func (tmp *tmpfile) publishInDir(dir string, publish func() error) error {
	backoffMs := initialBackoffMs
	for attempt := 0; ; attempt++ {
		err := publish()
		if err == nil || !isParentDirGone(err) || attempt == maxDirRecreateRetries {
			return err
		}
		if attempt > 0 {
			// Add jitter to avoid synchronized retry waves.
			sleepWithJitter(backoffMs)
			backoffMs = min(backoffMs*2, maxBackoffMs)
		}
		// MkdirAll gives up when the directories keep disappearing; the
		// next attempt makes them again after a longer wait.
		err = backend.MkdirAll(dir, tmp.uid, tmp.gid, tmp.doChown, tmp.newDirPerm)
		if err != nil && !isParentDirGone(err) && !isDirDeletePending(err) {
			return fmt.Errorf("make parent dir: %w", err)
		}
	}
}

// openTmpFile opens a temporary file in dir (a filesystem path) that link()
// later publishes as obj within bucket. bucket is a bucket name or, for the
// versioning code, the absolute path of a bucket's versioning directory.
func (p *Posix) openTmpFile(dir, bucket, obj string, size int64, acct auth.Account, dofalloc, forceNoTmpFile bool, allowODirect odirectPolicy) (*tmpfile, error) {
	return p.openTmpFileIn(dir, dir, bucket, obj, size, acct, dofalloc, forceNoTmpFile, false, allowODirect)
}

// openObjectTmpFile opens the temporary file that link() publishes as the
// object obj in bucket. It is made in the bucket's MetaTmpDir, or with
// inheritDefaultACL as an O_TMPFILE in the directory obj is published in, so
// that the directory's default ACL applies to it.
func (p *Posix) openObjectTmpFile(bucket, obj string, size int64, acct auth.Account, dofalloc bool, allowODirect odirectPolicy) (*tmpfile, error) {
	tmpDir := p.ObjectPath(bucket, MetaTmpDir)
	if !p.inheritDefaultACL {
		return p.openTmpFile(tmpDir, bucket, obj, size, acct, dofalloc, p.forceNoTmpFile, allowODirect)
	}
	objDir := filepath.Dir(filepath.Join(p.BucketPath(bucket), obj))
	return p.openTmpFileIn(objDir, tmpDir, bucket, obj, size, acct, dofalloc, p.forceNoTmpFile, true, allowODirect)
}

// closestDir returns dir when it is a directory, or else its closest parent
// that is, up to bucketPath, which is returned as is. dir must be
// bucketPath or below it. The directories between them are made when the object is published
// and inherit the default ACL of the parent returned. A path component that
// is a file is skipped the same way as a missing one: the publish fails
// later with the error it already returns for that case. Any other error,
// such as EACCES, is returned.
func closestDir(bucketPath, dir string) (string, error) {
	rel, err := filepath.Rel(bucketPath, dir)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%v is not below %v", dir, bucketPath)
	}
	for {
		path := filepath.Join(bucketPath, rel)
		fi, err := os.Stat(path)
		if (err == nil && fi.IsDir()) || rel == "." {
			return path, nil
		}
		if err != nil && !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, syscall.ENOTDIR) {
			return "", fmt.Errorf("stat %v: %w", path, err)
		}
		rel = filepath.Dir(rel)
	}
}
