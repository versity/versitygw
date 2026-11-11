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
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

// stalePathEtagMeta returns a different value for a path read of an
// attribute of the object than for a read on the open file. The path read
// stands for the attribute of the inode the name pointed at before a PUT
// linked a new one; the read on the open file returns the attribute stored
// on the inode that was opened. It diverges for the attributes in stale, and
// fails a read on the open file of failAttr with failErr.
type stalePathEtagMeta struct {
	meta.XattrMeta
	object   string
	pathEtag string
	stale    map[string][]byte
	failAttr string
	failErr  error
}

func (m stalePathEtagMeta) WithRootDir(rootdir string) meta.MetadataStorer {
	m.XattrMeta = m.XattrMeta.WithRootDir(rootdir).(meta.XattrMeta)
	return m
}

func (m stalePathEtagMeta) RetrieveAttribute(f *os.File, bucket, object, attribute string) ([]byte, error) {
	if f == nil && object == m.object && attribute == etagkey && m.pathEtag != "" {
		return []byte(m.pathEtag), nil
	}
	if f == nil && object == m.object {
		if b, ok := m.stale[attribute]; ok {
			return b, nil
		}
	}
	if f != nil && m.failErr != nil && attribute == m.failAttr {
		return nil, m.failErr
	}
	return m.XattrMeta.RetrieveAttribute(f, bucket, object, attribute)
}

// TestGetObjectETagMatchesOpenedFile checks that the ETag of a GET, and the
// If-Match decision, belong to the inode whose bytes are returned.
func TestGetObjectETagMatchesOpenedFile(t *testing.T) {
	const (
		bucket   = "testbucket"
		key      = "obj"
		body     = "body-of-the-opened-object"
		pathEtag = `"stale-etag"`
	)
	p := newTestPosix(t, func(t *testing.T) (meta.MetadataStorer, PosixOpts) {
		return stalePathEtagMeta{object: key, pathEtag: pathEtag}, PosixOpts{NewDirPerm: 0755}
	})
	createTestBucket(t, p, bucket)

	res, err := testPut(p, bucket, key, []byte(body), nil, nil)
	if err != nil {
		t.Fatalf("put object: %v", err)
	}
	inodeEtag := res.ETag
	if inodeEtag == "" || inodeEtag == pathEtag {
		t.Fatalf("put etag = %q, want the inode etag distinct from %q", inodeEtag, pathEtag)
	}

	t.Run("etag of the opened object", func(t *testing.T) {
		data, etag := getTestObject(t, p, bucket, key)
		if !bytes.Equal(data, []byte(body)) {
			t.Fatalf("body = %q, want %q", data, body)
		}
		if etag != inodeEtag {
			t.Fatalf("etag = %q, want the opened object's %q", etag, inodeEtag)
		}
	})

	t.Run("if-match with the opened object etag", func(t *testing.T) {
		out, err := p.GetObject(context.Background(), &s3.GetObjectInput{
			Bucket:  aws.String(bucket),
			Key:     aws.String(key),
			IfMatch: aws.String(trimEtag(inodeEtag)),
		})
		if err != nil {
			t.Fatalf("get with If-Match of the opened object: %v", err)
		}
		defer out.Body.Close()
		data, err := io.ReadAll(out.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if !bytes.Equal(data, []byte(body)) || aws.ToString(out.ETag) != inodeEtag {
			t.Fatalf("got body %q etag %q, want body %q etag %q", data, aws.ToString(out.ETag), body, inodeEtag)
		}
	})

	t.Run("if-match with the path etag", func(t *testing.T) {
		out, err := p.GetObject(context.Background(), &s3.GetObjectInput{
			Bucket:  aws.String(bucket),
			Key:     aws.String(key),
			IfMatch: aws.String(trimEtag(pathEtag)),
		})
		if out != nil && out.Body != nil {
			out.Body.Close()
		}
		want := s3err.GetPreconditionFailedErr(s3err.ConditionIfMatch)
		if !errors.Is(err, want) {
			t.Fatalf("get with If-Match of the replaced object: %v, want %v", err, want)
		}
	})

	t.Run("if-none-match with the opened object etag", func(t *testing.T) {
		out, err := p.GetObject(context.Background(), &s3.GetObjectInput{
			Bucket:      aws.String(bucket),
			Key:         aws.String(key),
			IfNoneMatch: aws.String(trimEtag(inodeEtag)),
		})
		if !errors.Is(err, s3err.GetAPIError(s3err.ErrNotModified)) {
			t.Fatalf("get with If-None-Match of the opened object: %v, want not modified", err)
		}
		if out == nil || aws.ToString(out.ETag) != inodeEtag {
			t.Fatalf("304 output = %+v, want etag %q", out, inodeEtag)
		}
	})
}

// TestGetObjectAttributesMatchOpenedFile checks that the version id and the
// parts count of a GET, and of its 304, come from the inode that was opened
// and not from a path read that a PUT can have redirected to another inode.
func TestGetObjectAttributesMatchOpenedFile(t *testing.T) {
	const (
		bucket = "testbucket"
		key    = "obj"
	)
	staleMp, err := backend.MarshalMpUploadMetadata(backend.MpUploadMetadata{UploadID: "stale", Parts: []int64{4}}, false)
	if err != nil {
		t.Fatalf("marshal stale mp metadata: %v", err)
	}
	p := newTestPosix(t, func(t *testing.T) (meta.MetadataStorer, PosixOpts) {
		return stalePathEtagMeta{
			object: key,
			stale: map[string][]byte{
				versionIdKey: []byte("stale-version"),
				mpMetaKey:    staleMp,
				cacheCtrlHdr: []byte("stale-cache"),
			},
		}, PosixOpts{NewDirPerm: 0755, VersioningDir: t.TempDir()}
	})
	createTestBucket(t, p, bucket)
	ctx := context.Background()
	if err := p.PutBucketVersioning(ctx, bucket, types.BucketVersioningStatusEnabled); err != nil {
		t.Fatalf("put bucket versioning: %v", err)
	}
	res, err := testPut(p, bucket, key, []byte("aaaabbbb"), nil, nil)
	if err != nil {
		t.Fatalf("put object: %v", err)
	}
	// make the object look multipart with two parts of 4 bytes
	mp, err := backend.MarshalMpUploadMetadata(backend.MpUploadMetadata{UploadID: "id", Parts: []int64{4, 8}}, false)
	if err != nil {
		t.Fatalf("marshal mp metadata: %v", err)
	}
	if err := p.meta.StoreAttribute(nil, bucket, key, mpMetaKey, mp); err != nil {
		t.Fatalf("store mp metadata: %v", err)
	}

	if err := p.meta.StoreAttribute(nil, bucket, key, cacheCtrlHdr, []byte("max-age=60")); err != nil {
		t.Fatal(err)
	}

	t.Run("version id", func(t *testing.T) {
		out, err := p.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
		if err != nil {
			t.Fatalf("get object: %v", err)
		}
		out.Body.Close()
		if got := aws.ToString(out.VersionId); got != res.VersionID {
			t.Fatalf("version id = %q, want the opened object's %q", got, res.VersionID)
		}
	})

	t.Run("version id of a 304", func(t *testing.T) {
		out, err := p.GetObject(ctx, &s3.GetObjectInput{
			Bucket:      aws.String(bucket),
			Key:         aws.String(key),
			IfNoneMatch: aws.String(trimEtag(res.ETag)),
		})
		if !errors.Is(err, s3err.GetAPIError(s3err.ErrNotModified)) {
			t.Fatalf("get object: %v, want not modified", err)
		}
		if got := aws.ToString(out.CacheControl); got != "max-age=60" {
			t.Fatalf("304 CacheControl = %q", got)
		}
		if got := aws.ToString(out.VersionId); got != res.VersionID {
			t.Fatalf("304 version id = %q, want the opened object's %q", got, res.VersionID)
		}
	})

	t.Run("part number", func(t *testing.T) {
		out, err := p.GetObject(ctx, &s3.GetObjectInput{
			Bucket:     aws.String(bucket),
			Key:        aws.String(key),
			PartNumber: aws.Int32(2),
		})
		if err != nil {
			t.Fatalf("get part 2: %v", err)
		}
		defer out.Body.Close()
		data, err := io.ReadAll(out.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if string(data) != "bbbb" || aws.ToInt32(out.PartsCount) != 2 {
			t.Fatalf("part 2 = %q of %d parts, want bbbb of 2 parts", data, aws.ToInt32(out.PartsCount))
		}
	})

	t.Run("parts count of a 304", func(t *testing.T) {
		out, err := p.GetObject(ctx, &s3.GetObjectInput{
			Bucket:      aws.String(bucket),
			Key:         aws.String(key),
			PartNumber:  aws.Int32(1),
			IfNoneMatch: aws.String(trimEtag(res.ETag)),
		})
		if !errors.Is(err, s3err.GetAPIError(s3err.ErrNotModified)) {
			t.Fatalf("get object: %v, want not modified", err)
		}
		if got := aws.ToInt32(out.PartsCount); got != 2 {
			t.Fatalf("304 parts count = %d, want 2", got)
		}
	})
}

// TestGetObjectETagReadError checks that an error reading the ETag of the
// opened object other than a missing attribute fails the GET instead of
// serving the object with the default ETag.
func TestGetObjectETagReadError(t *testing.T) {
	const (
		bucket = "testbucket"
		key    = "obj"
	)
	readErr := errors.New("etag read failed")
	p := newTestPosix(t, func(t *testing.T) (meta.MetadataStorer, PosixOpts) {
		return stalePathEtagMeta{object: key, failAttr: etagkey, failErr: readErr}, PosixOpts{NewDirPerm: 0755}
	})
	createTestBucket(t, p, bucket)
	if _, err := testPut(p, bucket, key, []byte("data"), nil, nil); err != nil {
		t.Fatalf("put object: %v", err)
	}
	out, err := p.GetObject(context.Background(), &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err == nil {
		out.Body.Close()
	}
	if !errors.Is(err, readErr) {
		t.Fatalf("get object: %v, want %v", err, readErr)
	}
}

// TestGetObjectVersionMovedAfterLookup checks that a GET of a version that
// was the live object when the request looked up its version id, and was
// moved to the versioning directory by a PUT before the open, returns that
// version's bytes and not the new live object's.
func TestGetObjectVersionMovedAfterLookup(t *testing.T) {
	const (
		bucket = "testbucket"
		key    = "obj"
	)
	var replace func()
	p := newTestPosix(t, func(t *testing.T) (meta.MetadataStorer, PosixOpts) {
		return removeAfterReadMeta{object: key, attribute: versionIdKey, remove: &replace},
			PosixOpts{NewDirPerm: 0755, VersioningDir: t.TempDir()}
	})
	createTestBucket(t, p, bucket)
	ctx := context.Background()
	if err := p.PutBucketVersioning(ctx, bucket, types.BucketVersioningStatusEnabled); err != nil {
		t.Fatalf("put bucket versioning: %v", err)
	}
	first, err := testPut(p, bucket, key, []byte("first"), nil, nil)
	if err != nil {
		t.Fatalf("put first: %v", err)
	}

	replace = func() {
		_, err := p.PutObject(ctx, s3response.PutObjectInput{
			Bucket:        aws.String(bucket),
			Key:           aws.String(key),
			Body:          strings.NewReader("second"),
			ContentLength: aws.Int64(6),
		})
		if err != nil {
			t.Errorf("put second: %v", err)
		}
	}
	out, err := p.GetObject(ctx, &s3.GetObjectInput{
		Bucket:    aws.String(bucket),
		Key:       aws.String(key),
		VersionId: aws.String(first.VersionID),
	})
	if err != nil {
		t.Fatalf("get first version: %v", err)
	}
	defer out.Body.Close()
	if replace != nil {
		t.Fatal("get object did not look up the version id")
	}
	data, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(data) != "first" || aws.ToString(out.VersionId) != first.VersionID {
		t.Fatalf("got %q of version %q, want %q of version %q", data, aws.ToString(out.VersionId), "first", first.VersionID)
	}
}

// beforeReadMeta runs run, once it is set, right before the next read of
// attribute of object, so that the object is changed between the open of the
// object and that read.
type beforeReadMeta struct {
	meta.XattrMeta
	object    string
	attribute string
	run       *func()
}

func (m beforeReadMeta) RetrieveAttribute(f *os.File, bucket, object, attribute string) ([]byte, error) {
	if object == m.object && attribute == m.attribute && *m.run != nil {
		run := *m.run
		*m.run = nil
		run()
	}
	return m.XattrMeta.RetrieveAttribute(f, bucket, object, attribute)
}

// TestGetObjectLiveVersionIdFromOpenedFile checks that a GET without a
// version id of a versioned bucket reports the version id of the object it
// opened, for the 200 and for the 304, when the object is replaced after the
// open and before the version id is read: a version id read by path would be
// the new object's. When the object is removed there, the answer is
// NoSuchKey.
func TestGetObjectLiveVersionIdFromOpenedFile(t *testing.T) {
	const (
		bucket = "testbucket"
		key    = "obj"
	)
	for _, tc := range []struct {
		name        string
		remove      bool
		notModified bool
	}{
		{"replaced 200", false, false},
		{"replaced 304", false, true},
		{"removed 200", true, false},
		{"removed 304", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var change func()
			p := newTestPosix(t, func(t *testing.T) (meta.MetadataStorer, PosixOpts) {
				return beforeReadMeta{object: key, attribute: versionIdKey, run: &change},
					PosixOpts{NewDirPerm: 0755, VersioningDir: t.TempDir()}
			})
			createTestBucket(t, p, bucket)
			ctx := context.Background()
			if err := p.PutBucketVersioning(ctx, bucket, types.BucketVersioningStatusEnabled); err != nil {
				t.Fatalf("put bucket versioning: %v", err)
			}
			first, err := testPut(p, bucket, key, []byte("first"), nil, nil)
			if err != nil {
				t.Fatalf("put first: %v", err)
			}

			change = func() {
				if tc.remove {
					if err := os.Remove(p.ObjectPath(bucket, key)); err != nil {
						t.Errorf("remove object: %v", err)
					}
					return
				}
				if _, err := testPut(p, bucket, key, []byte("second"), nil, nil); err != nil {
					t.Errorf("put second: %v", err)
				}
			}
			input := &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)}
			if tc.notModified {
				input.IfNoneMatch = aws.String(trimEtag(first.ETag))
			}
			out, err := p.GetObject(ctx, input)
			if change != nil {
				t.Fatal("get object did not read the version id")
			}
			if tc.remove {
				// the object's tags and attributes are read by path, so a
				// removed object is a 404, never a 200 or 304 of a removed one
				if err == nil {
					out.Body.Close()
				}
				if !errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchKey)) {
					t.Fatalf("get object: expected NoSuchKey, got %v", err)
				}
				return
			}
			if tc.notModified {
				if !errors.Is(err, s3err.GetAPIError(s3err.ErrNotModified)) {
					t.Fatalf("get object: expected NotModified, got %v", err)
				}
			} else {
				if err != nil {
					t.Fatalf("get object: %v", err)
				}
				defer out.Body.Close()
				data, err := io.ReadAll(out.Body)
				if err != nil {
					t.Fatalf("read body: %v", err)
				}
				if string(data) != "first" {
					t.Fatalf("got body %q, want %q", data, "first")
				}
			}
			if got := aws.ToString(out.VersionId); got != first.VersionID {
				t.Fatalf("got version id %q, want %q of the opened object", got, first.VersionID)
			}
		})
	}
}

// TestGetObjectDeleteMarkerMovedAfterLookup checks that a GET of a version
// that is a delete marker still answers with the marker when it is moved to
// the versioning dir between the lookup and the delete-marker check.
func TestGetObjectDeleteMarkerMovedAfterLookup(t *testing.T) {
	const bucket, key = "testbucket", "obj"
	var replace func()
	p := newTestPosix(t, func(t *testing.T) (meta.MetadataStorer, PosixOpts) {
		return beforeReadMeta{object: key, attribute: deleteMarkerKey, run: &replace}, PosixOpts{NewDirPerm: 0755, VersioningDir: t.TempDir()}
	})
	createTestBucket(t, p, bucket)
	ctx := context.Background()
	if err := p.PutBucketVersioning(ctx, bucket, types.BucketVersioningStatusEnabled); err != nil {
		t.Fatal(err)
	}
	if _, err := testPut(p, bucket, key, []byte("hidden"), nil, nil); err != nil {
		t.Fatal(err)
	}
	marker, err := p.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		t.Fatal(err)
	}
	replace = func() {
		if _, err := testPut(p, bucket, key, []byte("new"), nil, nil); err != nil {
			t.Error(err)
		}
	}
	out, err := p.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), VersionId: marker.VersionId})
	if out != nil && out.Body != nil {
		out.Body.Close()
	}
	if !errors.Is(err, s3err.GetAPIError(s3err.ErrMethodNotAllowed)) {
		t.Fatalf("get marker: %v, want MethodNotAllowed", err)
	}
	if out == nil || !aws.ToBool(out.DeleteMarker) || out.LastModified == nil {
		t.Fatalf("marker output = %+v", out)
	}
	if replace != nil {
		t.Fatal("delete marker lookup did not run")
	}
}
