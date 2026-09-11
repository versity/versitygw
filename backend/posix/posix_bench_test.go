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
	"context"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/s3response"
)

// Metadata-heavy object operations on small objects, where filesystem path
// resolution and metadata lookups dominate rather than data transfer. Run
// with -bench 'Posix' to compare path resolution strategies across branches.

func benchPosix(b *testing.B, mkMeta func(*testing.B) (meta.MetadataStorer, PosixOpts)) (*Posix, context.Context) {
	b.Helper()
	// New chdirs into the root in default mode; run from a scratch directory
	// so the cwd is restored when the benchmark ends.
	b.Chdir(b.TempDir())
	storer, opts := mkMeta(b)
	p, err := New(b.TempDir(), storer, opts)
	if err != nil {
		b.Fatalf("new posix: %v", err)
	}
	ctx := context.Background()
	bucket := "bucket"
	err = p.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket:                    &bucket,
		CreateBucketConfiguration: &types.CreateBucketConfiguration{},
	}, []byte{})
	if err != nil {
		b.Fatalf("create bucket: %v", err)
	}
	return p, ctx
}

// benchMetaModes returns a constructor per metadata storer and path mode:
// "xattr"/"sidecar" use the default chdir-relative paths, "xattr-abs" and
// "sidecar-abs" set PosixOpts.AbsolutePaths.
func benchMetaModes(b *testing.B) map[string]func(*testing.B) (meta.MetadataStorer, PosixOpts) {
	modes := map[string]func(*testing.B) (meta.MetadataStorer, PosixOpts){}
	for _, abs := range []bool{false, true} {
		suffix := ""
		if abs {
			suffix = "-abs"
		}
		modes["xattr"+suffix] = func(b *testing.B) (meta.MetadataStorer, PosixOpts) {
			return meta.XattrMeta{}, PosixOpts{NewDirPerm: 0755, AbsolutePaths: abs}
		}
		modes["sidecar"+suffix] = func(b *testing.B) (meta.MetadataStorer, PosixOpts) {
			dir := b.TempDir()
			sc, err := meta.NewSideCar(dir)
			if err != nil {
				b.Fatalf("new sidecar: %v", err)
			}
			return sc, PosixOpts{NewDirPerm: 0755, SideCarDir: dir, AbsolutePaths: abs}
		}
	}
	return modes
}

func benchPut(b *testing.B, p *Posix, ctx context.Context, key, body string) {
	b.Helper()
	bucket := "bucket"
	_, err := p.PutObject(ctx, s3response.PutObjectInput{
		Bucket:        &bucket,
		Key:           &key,
		Body:          strings.NewReader(body),
		ContentLength: aws.Int64(int64(len(body))),
	})
	if err != nil {
		b.Fatalf("put %q: %v", key, err)
	}
}

func BenchmarkPosixHeadObject(b *testing.B) {
	for name, mkMeta := range benchMetaModes(b) {
		b.Run(name, func(b *testing.B) {
			p, ctx := benchPosix(b, mkMeta)
			bucket, key := "bucket", "dir/sub/object"
			benchPut(b, p, ctx, key, "hello")
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := p.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: &key}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkPosixGetObject(b *testing.B) {
	for name, mkMeta := range benchMetaModes(b) {
		b.Run(name, func(b *testing.B) {
			p, ctx := benchPosix(b, mkMeta)
			bucket, key := "bucket", "dir/sub/object"
			benchPut(b, p, ctx, key, "hello")
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				out, err := p.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &key})
				if err != nil {
					b.Fatal(err)
				}
				if _, err := io.Copy(io.Discard, out.Body); err != nil {
					b.Fatal(err)
				}
				out.Body.Close()
			}
		})
	}
}

func BenchmarkPosixPutObject(b *testing.B) {
	for name, mkMeta := range benchMetaModes(b) {
		b.Run(name, func(b *testing.B) {
			p, ctx := benchPosix(b, mkMeta)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchPut(b, p, ctx, fmt.Sprintf("dir/sub/object-%d", i%64), "hello")
			}
		})
	}
}

func BenchmarkPosixListObjectsV2(b *testing.B) {
	for name, mkMeta := range benchMetaModes(b) {
		b.Run(name, func(b *testing.B) {
			p, ctx := benchPosix(b, mkMeta)
			bucket := "bucket"
			for i := 0; i < 100; i++ {
				benchPut(b, p, ctx, fmt.Sprintf("dir/object-%03d", i), "hello")
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				res, err := p.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &bucket, MaxKeys: aws.Int32(1000), StartAfter: aws.String("")})
				if err != nil {
					b.Fatal(err)
				}
				if len(res.Contents) != 100 {
					b.Fatalf("listed %d objects", len(res.Contents))
				}
			}
		})
	}
}

func BenchmarkPosixHeadBucket(b *testing.B) {
	for name, mkMeta := range benchMetaModes(b) {
		b.Run(name, func(b *testing.B) {
			p, ctx := benchPosix(b, mkMeta)
			bucket := "bucket"
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := p.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &bucket}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
