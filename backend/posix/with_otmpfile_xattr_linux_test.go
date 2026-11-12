//go:build linux
// +build linux

package posix

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend/meta"
)

// TestOTmpFileXattrProbe checks that a filesystem that opens an O_TMPFILE but
// can't set xattrs on it uses a named temporary file, and that errors that
// are not about xattr support are not hidden by the fallback.
func TestOTmpFileXattrProbe(t *testing.T) {
	root := t.TempDir()
	p, err := New(root, meta.XattrMeta{}, PosixOpts{AbsolutePaths: true})
	if err != nil {
		t.Fatalf("new posix: %v", err)
	}
	bucket := "bucket"
	createTestBucket(t, p, bucket)
	skipWithoutOTmpfile(t, filepath.Join(root, bucket))
	tmpDir := filepath.Join(root, bucket, MetaTmpDir)
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		t.Fatal(err)
	}

	probes := 0
	t.Cleanup(func() { probeTmpFileXattr = origProbeTmpFileXattr })

	for _, tc := range []struct {
		name     string
		err      error
		wantName bool
	}{
		{name: "supported"},
		{name: "ENODATA", err: syscall.ENODATA, wantName: true},
		{name: "EOPNOTSUPP", err: syscall.EOPNOTSUPP, wantName: true},
		{name: "ENOSPC", err: syscall.ENOSPC},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probes = 0
			p.otmpXattr.Delete(p.BucketPath(bucket))
			probeTmpFileXattr = func(f *os.File) error {
				probes++
				if tc.err != nil {
					return tc.err
				}
				return origProbeTmpFileXattr(f)
			}
			f, err := p.openObjectTmpFile(bucket, "object", 5, auth.Account{}, false, odirectNotAllowed)
			if err != nil {
				t.Fatalf("open tmp file: %v", err)
			}
			defer f.cleanup()
			if named := filepath.Dir(f.File().Name()) == tmpDir; named != tc.wantName {
				t.Errorf("temp file %v is named: %v, want %v", f.File().Name(), named, tc.wantName)
			}
			if tc.err == nil || tc.wantName {
				if err := p.meta.StoreAttribute(f.File(), bucket, "object", "probe-check", []byte("v")); err != nil {
					t.Errorf("store attribute: %v", err)
				}
			}

			// A second upload to the same bucket must not probe again,
			// and must use the named file if the first one did.
			f.cleanup()
			f2, err := p.openObjectTmpFile(bucket, "object2", 5, auth.Account{}, false, odirectNotAllowed)
			if err != nil {
				t.Fatalf("open second tmp file: %v", err)
			}
			defer f2.cleanup()
			if named := filepath.Dir(f2.File().Name()) == tmpDir; named != tc.wantName {
				t.Errorf("second temp file %v is named: %v, want %v", f2.File().Name(), named, tc.wantName)
			}
			wantProbes := 1
			if tc.err != nil && !tc.wantName {
				wantProbes = 2 // errors unrelated to xattr support are not remembered
			}
			if probes != wantProbes {
				t.Errorf("probed %d times for 2 opens, want %d", probes, wantProbes)
			}
		})
	}
}
