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
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/s3err"
)

// stalePathEtagMeta is the window a GET has when it reads the ETag by path
// and opens the body afterwards. A path read still sees the ETag of the
// object that the name used to point at; a read on the opened file sees the
// ETag stored on the inode that was opened, which is the inode of the body.
type stalePathEtagMeta struct {
	meta.XattrMeta
	object   string
	pathEtag string
}

func (m stalePathEtagMeta) WithRootDir(rootdir string) meta.MetadataStorer {
	m.XattrMeta = m.XattrMeta.WithRootDir(rootdir).(meta.XattrMeta)
	return m
}

func (m stalePathEtagMeta) RetrieveAttribute(f *os.File, bucket, object, attribute string) ([]byte, error) {
	if f == nil && object == m.object && attribute == etagkey {
		return []byte(m.pathEtag), nil
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

	t.Run("etag is the opened object's", func(t *testing.T) {
		data, etag := getTestObject(t, p, bucket, key)
		if !bytes.Equal(data, []byte(body)) {
			t.Fatalf("body = %q, want %q", data, body)
		}
		if etag != inodeEtag {
			t.Fatalf("etag = %q, want the opened object's %q", etag, inodeEtag)
		}
	})

	t.Run("if-match of the opened object", func(t *testing.T) {
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

	t.Run("if-match of the path etag", func(t *testing.T) {
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
}
