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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

// TestRootEntriesThatAreNotBuckets checks that only directories under the
// root, and with BucketLinks symlinks to directories, are buckets. The root of
// a dataset the gateway did not create may hold files and symlinks next to the
// bucket directories: every bucket request naming one fails with NoSuchBucket
// and CreateBucket with BucketAlreadyExists, without changing the entry,
// storing metadata for it or writing through it.
func TestRootEntriesThatAreNotBuckets(t *testing.T) {
	for mode, mkMeta := range metaModes(t) {
		for _, bucketlinks := range []bool{false, true} {
			t.Run(fmt.Sprintf("%v/bucketlinks=%v", mode, bucketlinks), func(t *testing.T) {
				root := t.TempDir()
				t.Chdir(root)
				linked := t.TempDir()

				const fileData = "not a bucket"
				if err := os.WriteFile(filepath.Join(root, "file"), []byte(fileData), 0644); err != nil {
					t.Fatalf("write root file: %v", err)
				}
				if err := os.WriteFile(filepath.Join(linked, "obj"), []byte(fileData), 0644); err != nil {
					t.Fatalf("write linked directory file: %v", err)
				}
				for link, target := range map[string]string{
					"linkfile": "file",
					"danglink": "missing",
					"looplink": "looplink",
					"linkdir":  linked,
				} {
					if err := os.Symlink(target, filepath.Join(root, link)); err != nil {
						t.Skip(err)
					}
				}
				notBuckets := []string{"file", "linkfile", "danglink", "looplink"}
				if !bucketlinks {
					notBuckets = append(notBuckets, "linkdir")
				}

				storer, opts := mkMeta(t)
				opts.BucketLinks = bucketlinks
				opts.VersioningDir = t.TempDir()
				p, err := New(root, storer, opts)
				if err != nil {
					t.Fatalf("new posix: %v", err)
				}
				defer p.Shutdown()

				ctx := context.Background()
				bucket, object := "bucket", "obj"
				createTestBucket(t, p, bucket)
				if _, err := testPut(p, bucket, object, []byte(fileData), nil, nil); err != nil {
					t.Fatalf("put object: %v", err)
				}
				mp, err := p.CreateMultipartUpload(ctx, s3response.CreateMultipartUploadInput{Bucket: &bucket, Key: &object})
				if err != nil {
					t.Fatalf("create multipart upload: %v", err)
				}

				calls := bucketCalls(ctx, p, bucket, object, mp.UploadId)
				for _, name := range notBuckets {
					for _, call := range calls {
						err := call.run(name)
						if !errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)) {
							t.Errorf("%v on %q: got %v, want NoSuchBucket", call.name, name, err)
						}
					}

					err := p.CreateBucket(ctx, &s3.CreateBucketInput{
						Bucket:                    &name,
						CreateBucketConfiguration: &types.CreateBucketConfiguration{},
					}, []byte{})
					if !errors.Is(err, s3err.GetAPIError(s3err.ErrBucketAlreadyExists)) {
						t.Errorf("CreateBucket on %q: got %v, want BucketAlreadyExists", name, err)
					}

					if _, err := os.Lstat(filepath.Join(root, name)); err != nil {
						t.Errorf("root entry %q: %v", name, err)
					}
					attrs, err := p.meta.ListAttributes(name, "")
					if err == nil && len(attrs) != 0 {
						t.Errorf("attributes stored for %q: %v", name, attrs)
					}
				}

				data, err := os.ReadFile(filepath.Join(root, "file"))
				if err != nil || string(data) != fileData {
					t.Errorf("root file content = %q, %v; want %q", data, err, fileData)
				}
				if opts.SideCarDir != "" {
					ents, err := os.ReadDir(opts.SideCarDir)
					if err != nil {
						t.Fatalf("read sidecar directory: %v", err)
					}
					for _, ent := range ents {
						if ent.Name() != bucket {
							t.Errorf("sidecar metadata stored for %q", ent.Name())
						}
					}
				}

				if !bucketlinks {
					ents, err := os.ReadDir(linked)
					if err != nil {
						t.Fatalf("read linked directory: %v", err)
					}
					if len(ents) != 1 || ents[0].Name() != "obj" {
						t.Errorf("linked directory entries = %v, want just %q", ents, "obj")
					}
					return
				}

				// With BucketLinks the symlinked directory is a bucket.
				linkBucket := "linkdir"
				if _, err := p.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &linkBucket}); err != nil {
					t.Fatalf("head symlinked bucket: %v", err)
				}
				if _, err := testPut(p, linkBucket, "new", []byte(fileData), nil, nil); err != nil {
					t.Fatalf("put object in symlinked bucket: %v", err)
				}
				if _, err := os.Stat(filepath.Join(linked, "new")); err != nil {
					t.Fatalf("object not written to the linked directory: %v", err)
				}
			})
		}
	}
}

type bucketCall struct {
	name string
	run  func(bucket string) error
}

// bucketCalls returns a call to every backend method that addresses a bucket,
// except CreateBucket. A call runs against the bucket it is passed; the copies
// also run with that bucket as the source, copying object into bucket or into
// the upload uploadID.
func bucketCalls(ctx context.Context, p *Posix, bucket, object, uploadID string) []bucketCall {
	key := aws.String(object)
	copySource := aws.String(bucket + "/" + object)
	body := func() *strings.Reader { return strings.NewReader("data") }

	return []bucketCall{
		{"HeadBucket", func(b string) error {
			_, err := p.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &b})
			return err
		}},
		{"DeleteBucket", func(b string) error {
			return p.DeleteBucket(ctx, b)
		}},
		{"GetBucketAcl", func(b string) error {
			_, err := p.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: &b})
			return err
		}},
		{"PutBucketAcl", func(b string) error {
			return p.PutBucketAcl(ctx, b, []byte("{}"))
		}},
		{"ChangeBucketOwner", func(b string) error {
			return p.ChangeBucketOwner(ctx, b, "owner")
		}},
		{"PutBucketOwnershipControls", func(b string) error {
			return p.PutBucketOwnershipControls(ctx, b, types.ObjectOwnershipBucketOwnerEnforced)
		}},
		{"GetBucketOwnershipControls", func(b string) error {
			_, err := p.GetBucketOwnershipControls(ctx, b)
			return err
		}},
		{"DeleteBucketOwnershipControls", func(b string) error {
			return p.DeleteBucketOwnershipControls(ctx, b)
		}},
		{"PutBucketVersioning", func(b string) error {
			return p.PutBucketVersioning(ctx, b, types.BucketVersioningStatusEnabled)
		}},
		{"GetBucketVersioning", func(b string) error {
			_, err := p.GetBucketVersioning(ctx, b)
			return err
		}},
		{"PutBucketTagging", func(b string) error {
			return p.PutBucketTagging(ctx, b, map[string]string{"k": "v"})
		}},
		{"GetBucketTagging", func(b string) error {
			_, err := p.GetBucketTagging(ctx, b)
			return err
		}},
		{"DeleteBucketTagging", func(b string) error {
			return p.DeleteBucketTagging(ctx, b)
		}},
		{"PutBucketPolicy", func(b string) error {
			return p.PutBucketPolicy(ctx, b, []byte("{}"))
		}},
		{"GetBucketPolicy", func(b string) error {
			_, err := p.GetBucketPolicy(ctx, b)
			return err
		}},
		{"DeleteBucketPolicy", func(b string) error {
			return p.DeleteBucketPolicy(ctx, b)
		}},
		{"PutBucketCors", func(b string) error {
			return p.PutBucketCors(ctx, b, []byte("<CORSConfiguration/>"))
		}},
		{"GetBucketCors", func(b string) error {
			_, err := p.GetBucketCors(ctx, b)
			return err
		}},
		{"DeleteBucketCors", func(b string) error {
			return p.DeleteBucketCors(ctx, b)
		}},
		{"PutBucketWebsite", func(b string) error {
			return p.PutBucketWebsite(ctx, b, []byte("<WebsiteConfiguration/>"))
		}},
		{"GetBucketWebsite", func(b string) error {
			_, err := p.GetBucketWebsite(ctx, b)
			return err
		}},
		{"DeleteBucketWebsite", func(b string) error {
			return p.DeleteBucketWebsite(ctx, b)
		}},
		{"PutObjectLockConfiguration", func(b string) error {
			return p.PutObjectLockConfiguration(ctx, b, []byte(`{"Enabled":true}`))
		}},
		{"GetObjectLockConfiguration", func(b string) error {
			_, err := p.GetObjectLockConfiguration(ctx, b)
			return err
		}},
		{"ListObjects", func(b string) error {
			_, err := p.ListObjects(ctx, &s3.ListObjectsInput{Bucket: &b, MaxKeys: aws.Int32(1000)})
			return err
		}},
		{"ListObjectsV2", func(b string) error {
			_, err := p.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &b, MaxKeys: aws.Int32(1000), StartAfter: aws.String("")})
			return err
		}},
		{"ListObjectVersions", func(b string) error {
			_, err := p.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: &b, MaxKeys: aws.Int32(1000)})
			return err
		}},
		{"ListMultipartUploads", func(b string) error {
			_, err := p.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: &b, MaxUploads: aws.Int32(1000)})
			return err
		}},
		{"PutObject", func(b string) error {
			_, err := p.PutObject(ctx, s3response.PutObjectInput{Bucket: &b, Key: key, Body: body(), ContentLength: aws.Int64(4)})
			return err
		}},
		{"PutObjectDirectory", func(b string) error {
			_, err := p.PutObject(ctx, s3response.PutObjectInput{Bucket: &b, Key: aws.String("dir/"), Body: strings.NewReader(""), ContentLength: aws.Int64(0)})
			return err
		}},
		{"GetObject", func(b string) error {
			_, err := p.GetObject(ctx, &s3.GetObjectInput{Bucket: &b, Key: key})
			return err
		}},
		{"HeadObject", func(b string) error {
			_, err := p.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &b, Key: key})
			return err
		}},
		{"GetObjectAttributes", func(b string) error {
			_, err := p.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{Bucket: &b, Key: key})
			return err
		}},
		{"DeleteObject", func(b string) error {
			_, err := p.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &b, Key: key})
			return err
		}},
		{"DeleteObjects", func(b string) error {
			_, err := p.DeleteObjects(ctx, &s3.DeleteObjectsInput{Bucket: &b, Delete: &types.Delete{Objects: []types.ObjectIdentifier{{Key: key}}}})
			return err
		}},
		{"CopyObjectDestination", func(b string) error {
			_, err := p.CopyObject(ctx, s3response.CopyObjectInput{Bucket: &b, Key: key, CopySource: copySource, ExpectedBucketOwner: aws.String("")})
			return err
		}},
		{"CopyObjectSource", func(b string) error {
			_, err := p.CopyObject(ctx, s3response.CopyObjectInput{Bucket: &bucket, Key: aws.String("copy"), CopySource: aws.String(b + "/" + object), ExpectedBucketOwner: aws.String("")})
			return err
		}},
		{"PutObjectTagging", func(b string) error {
			return p.PutObjectTagging(ctx, b, object, "", map[string]string{"k": "v"})
		}},
		{"GetObjectTagging", func(b string) error {
			_, err := p.GetObjectTagging(ctx, b, object, "")
			return err
		}},
		{"DeleteObjectTagging", func(b string) error {
			return p.DeleteObjectTagging(ctx, b, object, "")
		}},
		{"PutObjectLegalHold", func(b string) error {
			return p.PutObjectLegalHold(ctx, b, object, "", true)
		}},
		{"GetObjectLegalHold", func(b string) error {
			_, err := p.GetObjectLegalHold(ctx, b, object, "")
			return err
		}},
		{"PutObjectRetention", func(b string) error {
			return p.PutObjectRetention(ctx, b, object, "", []byte(`{"Mode":"GOVERNANCE"}`))
		}},
		{"GetObjectRetention", func(b string) error {
			_, err := p.GetObjectRetention(ctx, b, object, "")
			return err
		}},
		{"CreateMultipartUpload", func(b string) error {
			_, err := p.CreateMultipartUpload(ctx, s3response.CreateMultipartUploadInput{Bucket: &b, Key: key})
			return err
		}},
		{"UploadPart", func(b string) error {
			_, err := p.UploadPart(ctx, &s3.UploadPartInput{Bucket: &b, Key: key, UploadId: &uploadID, PartNumber: aws.Int32(1), Body: body(), ContentLength: aws.Int64(4)})
			return err
		}},
		{"UploadPartCopyDestination", func(b string) error {
			_, err := p.UploadPartCopy(ctx, &s3.UploadPartCopyInput{Bucket: &b, Key: key, UploadId: &uploadID, PartNumber: aws.Int32(1), CopySource: copySource, CopySourceRange: aws.String("")})
			return err
		}},
		{"UploadPartCopySource", func(b string) error {
			_, err := p.UploadPartCopy(ctx, &s3.UploadPartCopyInput{Bucket: &bucket, Key: key, UploadId: &uploadID, PartNumber: aws.Int32(1), CopySource: aws.String(b + "/" + object), CopySourceRange: aws.String("")})
			return err
		}},
		{"ListParts", func(b string) error {
			_, err := p.ListParts(ctx, &s3.ListPartsInput{Bucket: &b, Key: key, UploadId: &uploadID, MaxParts: aws.Int32(1000)})
			return err
		}},
		{"CompleteMultipartUpload", func(b string) error {
			_, _, err := p.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{Bucket: &b, Key: key, UploadId: &uploadID, MultipartUpload: &types.CompletedMultipartUpload{}})
			return err
		}},
		{"AbortMultipartUpload", func(b string) error {
			return p.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{Bucket: &b, Key: key, UploadId: &uploadID})
		}},
	}
}
