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
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

const condRaceWriters = 32

// metaModes returns the metadata backends supported by the posix backend
// that should both be exercised by the conditional-put tests.
func metaModes(t *testing.T) map[string]func(t *testing.T) (meta.MetadataStorer, PosixOpts) {
	t.Helper()
	return map[string]func(t *testing.T) (meta.MetadataStorer, PosixOpts){
		"xattr": func(t *testing.T) (meta.MetadataStorer, PosixOpts) {
			return meta.XattrMeta{}, PosixOpts{NewDirPerm: 0755}
		},
		"sidecar": func(t *testing.T) (meta.MetadataStorer, PosixOpts) {
			dir := t.TempDir()
			sc, err := meta.NewSideCar(dir)
			if err != nil {
				t.Fatalf("new sidecar: %v", err)
			}
			return sc, PosixOpts{NewDirPerm: 0755, SideCarDir: dir}
		},
	}
}

func newTestPosix(t *testing.T, mkMeta func(t *testing.T) (meta.MetadataStorer, PosixOpts)) *Posix {
	t.Helper()
	root := t.TempDir()
	storer, opts := mkMeta(t)
	p, err := New(root, storer, opts)
	if err != nil {
		t.Fatalf("new posix: %v", err)
	}
	return p
}

func createTestBucket(t *testing.T, p *Posix, bucket string) {
	t.Helper()
	err := p.CreateBucket(context.Background(), &s3.CreateBucketInput{
		Bucket:                    &bucket,
		CreateBucketConfiguration: &types.CreateBucketConfiguration{},
	}, []byte{})
	if err != nil {
		t.Fatalf("create bucket: %v", err)
	}
}

func testPut(p *Posix, bucket, key string, body []byte, ifMatch, ifNoneMatch *string) (s3response.PutObjectOutput, error) {
	return p.PutObject(context.Background(), s3response.PutObjectInput{
		Bucket:        &bucket,
		Key:           &key,
		Body:          bytes.NewReader(body),
		ContentLength: aws.Int64(int64(len(body))),
		IfMatch:       ifMatch,
		IfNoneMatch:   ifNoneMatch,
	})
}

func getTestObject(t *testing.T, p *Posix, bucket, key string) ([]byte, string) {
	t.Helper()
	out, err := p.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
	if err != nil {
		t.Fatalf("get object: %v", err)
	}
	defer out.Body.Close()
	data, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatalf("read object body: %v", err)
	}
	return data, *out.ETag
}

// trimEtag strips the surrounding quotes the same way the s3api layer does
// before passing If-Match values to the backend.
func trimEtag(etag string) string {
	return strings.Trim(etag, "\"")
}

func isPreconditionFailed(err error) bool {
	var pe s3err.PreconditionFailedError
	if errors.As(err, &pe) {
		return pe.HTTPStatusCode == http.StatusPreconditionFailed
	}
	var ae s3err.APIError
	return errors.As(err, &ae) && ae.HTTPStatusCode == http.StatusPreconditionFailed
}

type raceOutcome struct {
	idx  int
	etag string
	err  error
}

// runRace launches one goroutine per writer, releases them all through a
// common start barrier, and collects the outcome of each writer.
func runRace(t *testing.T, n int, writer func(i int) (string, error)) []raceOutcome {
	t.Helper()
	start := make(chan struct{})
	var ready, done sync.WaitGroup
	results := make([]raceOutcome, n)
	for i := range n {
		ready.Add(1)
		done.Add(1)
		go func(i int) {
			defer done.Done()
			ready.Done()
			<-start
			etag, err := writer(i)
			results[i] = raceOutcome{idx: i, etag: etag, err: err}
		}(i)
	}
	ready.Wait()
	close(start)
	done.Wait()
	return results
}

// classifyRace asserts exactly one winner and all losers 412, returning the
// winner outcome.
func classifyRace(t *testing.T, results []raceOutcome) raceOutcome {
	t.Helper()
	var winners []raceOutcome
	for _, r := range results {
		switch {
		case r.err == nil:
			winners = append(winners, r)
		case isPreconditionFailed(r.err):
		default:
			t.Errorf("writer %d: unexpected error (want nil or 412): %v", r.idx, r.err)
		}
	}
	if len(winners) != 1 {
		t.Fatalf("expected exactly 1 winner among %d classified writers, got %d",
			len(results), len(winners))
	}
	return winners[0]
}

func raceBody(i int) []byte {
	return fmt.Appendf(nil, "conditional-race-writer-%02d-%s", i,
		string(bytes.Repeat([]byte{byte('a' + i%26)}, 64)))
}

func TestPosixConditionalPutIfNoneMatchRace(t *testing.T) {
	for mode, mkMeta := range metaModes(t) {
		t.Run(mode, func(t *testing.T) {
			p := newTestPosix(t, mkMeta)
			bucket := "testbucket"
			createTestBucket(t, p, bucket)

			for round := range 3 {
				key := fmt.Sprintf("obj-inm-%d", round)
				results := runRace(t, condRaceWriters, func(i int) (string, error) {
					res, err := testPut(p, bucket, key, raceBody(i), nil, aws.String("*"))
					return res.ETag, err
				})
				winner := classifyRace(t, results)

				data, etag := getTestObject(t, p, bucket, key)
				if !bytes.Equal(data, raceBody(winner.idx)) {
					t.Errorf("round %d: final object bytes do not match winner %d",
						round, winner.idx)
				}
				if etag != winner.etag {
					t.Errorf("round %d: final etag %q does not match winner etag %q",
						round, etag, winner.etag)
				}
			}
		})
	}
}

func TestPosixConditionalPutIfMatchRace(t *testing.T) {
	for mode, mkMeta := range metaModes(t) {
		t.Run(mode, func(t *testing.T) {
			p := newTestPosix(t, mkMeta)
			bucket := "testbucket"
			key := "obj-ifmatch"
			createTestBucket(t, p, bucket)

			seed, err := testPut(p, bucket, key, []byte("seed"), nil, nil)
			if err != nil {
				t.Fatalf("seed put: %v", err)
			}
			curEtag := seed.ETag

			// several rounds to make timing-sensitive failures visible;
			// each round races against the previous round's winner etag.
			// bodies are unique per round and per writer so that every
			// successful write necessarily changes the etag
			for round := range 5 {
				raceBody := func(i int) []byte {
					return fmt.Appendf(nil, "round-%d-%s", round, raceBody(i))
				}
				results := runRace(t, condRaceWriters, func(i int) (string, error) {
					res, err := testPut(p, bucket, key, raceBody(i), aws.String(trimEtag(curEtag)), nil)
					return res.ETag, err
				})
				winner := classifyRace(t, results)

				data, etag := getTestObject(t, p, bucket, key)
				if !bytes.Equal(data, raceBody(winner.idx)) {
					t.Errorf("round %d: final object bytes do not match winner %d",
						round, winner.idx)
				}
				if etag != winner.etag {
					t.Errorf("round %d: final etag %q does not match winner etag %q",
						round, etag, winner.etag)
				}
				curEtag = winner.etag
			}
		})
	}
}

func TestPosixConditionalPutSequential(t *testing.T) {
	for mode, mkMeta := range metaModes(t) {
		t.Run(mode, func(t *testing.T) {
			p := newTestPosix(t, mkMeta)
			bucket := "testbucket"
			createTestBucket(t, p, bucket)

			// if-none-match on absent object succeeds
			res, err := testPut(p, bucket, "obj", []byte("first"), nil, aws.String("*"))
			if err != nil {
				t.Fatalf("if-none-match create: %v", err)
			}

			// if-none-match on existing object fails 412
			_, err = testPut(p, bucket, "obj", []byte("second"), nil, aws.String("*"))
			if !isPreconditionFailed(err) {
				t.Errorf("if-none-match on existing object: want 412, got %v", err)
			}

			// stale if-match fails 412
			_, err = testPut(p, bucket, "obj", []byte("third"),
				aws.String("\"deadbeefdeadbeefdeadbeefdeadbeef\""), nil)
			if !isPreconditionFailed(err) {
				t.Errorf("stale if-match: want 412, got %v", err)
			}

			// correct if-match succeeds
			res2, err := testPut(p, bucket, "obj", []byte("fourth"), aws.String(trimEtag(res.ETag)), nil)
			if err != nil {
				t.Fatalf("valid if-match: %v", err)
			}
			data, etag := getTestObject(t, p, bucket, "obj")
			if string(data) != "fourth" || etag != res2.ETag {
				t.Errorf("unexpected final state after if-match put")
			}

			// if-match on missing object keeps existing project behavior (NoSuchKey)
			_, err = testPut(p, bucket, "missing", []byte("x"), aws.String(trimEtag(res2.ETag)), nil)
			if !errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchKey)) {
				t.Errorf("if-match on missing object: want NoSuchKey, got %v", err)
			}

			// object content untouched by the failed attempts
			data, _ = getTestObject(t, p, bucket, "obj")
			if string(data) != "fourth" {
				t.Errorf("failed conditional puts modified the object: %q", data)
			}
		})
	}
}

// TestPosixConditionalPutUnconditionalRace races an unconditional PUT with an
// If-None-Match create. Per S3 semantics some serial order must exist: the
// conditional writer may win or lose, but since the unconditional write always
// succeeds and any valid serialization orders the unconditional write after a
// successful conditional create (otherwise the conditional write would have
// observed the object and failed), the final object must always be the
// unconditional writer's.
func TestPosixConditionalPutUnconditionalRace(t *testing.T) {
	for mode, mkMeta := range metaModes(t) {
		t.Run(mode, func(t *testing.T) {
			p := newTestPosix(t, mkMeta)
			bucket := "testbucket"
			createTestBucket(t, p, bucket)

			for round := range 10 {
				key := fmt.Sprintf("obj-mixed-%d", round)
				uncondBody := fmt.Appendf(nil, "unconditional-%d", round)
				condBody := fmt.Appendf(nil, "conditional-%d", round)

				var uncondEtag string
				results := runRace(t, 2, func(i int) (string, error) {
					if i == 0 {
						res, err := testPut(p, bucket, key, uncondBody, nil, nil)
						uncondEtag = res.ETag
						return res.ETag, err
					}
					res, err := testPut(p, bucket, key, condBody, nil, aws.String("*"))
					return res.ETag, err
				})

				if results[0].err != nil {
					t.Fatalf("round %d: unconditional put failed: %v", round, results[0].err)
				}
				if results[1].err != nil && !isPreconditionFailed(results[1].err) {
					t.Fatalf("round %d: conditional put unexpected error: %v", round, results[1].err)
				}

				data, etag := getTestObject(t, p, bucket, key)
				if !bytes.Equal(data, uncondBody) || etag != uncondEtag {
					t.Errorf("round %d: final object is not the unconditional writer's "+
						"(cond err=%v)", round, results[1].err)
				}
			}
		})
	}
}

func TestPosixConditionalPutDistinctKeysConcurrent(t *testing.T) {
	for mode, mkMeta := range metaModes(t) {
		t.Run(mode, func(t *testing.T) {
			p := newTestPosix(t, mkMeta)
			bucket := "testbucket"
			createTestBucket(t, p, bucket)

			results := runRace(t, condRaceWriters, func(i int) (string, error) {
				key := fmt.Sprintf("distinct-key-%02d", i)
				res, err := testPut(p, bucket, key, raceBody(i), nil, aws.String("*"))
				return res.ETag, err
			})
			for _, r := range results {
				if r.err != nil {
					t.Errorf("writer %d to its own key failed: %v", r.idx, r.err)
				}
			}
			for i := range condRaceWriters {
				key := fmt.Sprintf("distinct-key-%02d", i)
				data, _ := getTestObject(t, p, bucket, key)
				if !bytes.Equal(data, raceBody(i)) {
					t.Errorf("key %s has wrong content", key)
				}
			}
		})
	}
}

func testCompleteMultipart(t *testing.T, p *Posix, bucket, key string, body []byte, ifMatch, ifNoneMatch *string) (string, func() (string, error)) {
	t.Helper()
	ctx := context.Background()
	mp, err := p.CreateMultipartUpload(ctx, s3response.CreateMultipartUploadInput{
		Bucket: &bucket,
		Key:    &key,
	})
	if err != nil {
		t.Fatalf("create multipart upload: %v", err)
	}
	uploadID := mp.UploadId
	part, err := p.UploadPart(ctx, &s3.UploadPartInput{
		Bucket:        &bucket,
		Key:           &key,
		UploadId:      &uploadID,
		PartNumber:    aws.Int32(1),
		ContentLength: aws.Int64(int64(len(body))),
		Body:          bytes.NewReader(body),
	})
	if err != nil {
		t.Fatalf("upload part: %v", err)
	}
	return uploadID, func() (string, error) {
		res, _, err := p.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &key,
			UploadId: &uploadID,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: []types.CompletedPart{
					{ETag: part.ETag, PartNumber: aws.Int32(1)},
				},
			},
			IfMatch:     ifMatch,
			IfNoneMatch: ifNoneMatch,
		})
		if err != nil {
			return "", err
		}
		return *res.ETag, nil
	}
}

func TestPosixCompleteMultipartUploadIfNoneMatchRace(t *testing.T) {
	for mode, mkMeta := range metaModes(t) {
		t.Run(mode, func(t *testing.T) {
			p := newTestPosix(t, mkMeta)
			bucket := "testbucket"
			key := "obj-mp-inm"
			createTestBucket(t, p, bucket)

			completes := make([]func() (string, error), condRaceWriters)
			bodies := make([][]byte, condRaceWriters)
			for i := range condRaceWriters {
				bodies[i] = raceBody(i)
				_, completes[i] = testCompleteMultipart(t, p, bucket, key,
					bodies[i], nil, aws.String("*"))
			}

			results := runRace(t, condRaceWriters, func(i int) (string, error) {
				return completes[i]()
			})
			winner := classifyRace(t, results)

			data, etag := getTestObject(t, p, bucket, key)
			if !bytes.Equal(data, bodies[winner.idx]) {
				t.Errorf("final object bytes do not match winning completer %d", winner.idx)
			}
			if etag != winner.etag {
				t.Errorf("final etag %q does not match winner etag %q", etag, winner.etag)
			}
		})
	}
}

func TestPosixCompleteMultipartUploadIfMatchRace(t *testing.T) {
	for mode, mkMeta := range metaModes(t) {
		t.Run(mode, func(t *testing.T) {
			p := newTestPosix(t, mkMeta)
			bucket := "testbucket"
			key := "obj-mp-ifmatch"
			createTestBucket(t, p, bucket)

			seed, err := testPut(p, bucket, key, []byte("seed"), nil, nil)
			if err != nil {
				t.Fatalf("seed put: %v", err)
			}

			completes := make([]func() (string, error), condRaceWriters)
			bodies := make([][]byte, condRaceWriters)
			for i := range condRaceWriters {
				bodies[i] = raceBody(i)
				_, completes[i] = testCompleteMultipart(t, p, bucket, key,
					bodies[i], aws.String(trimEtag(seed.ETag)), nil)
			}

			results := runRace(t, condRaceWriters, func(i int) (string, error) {
				return completes[i]()
			})
			winner := classifyRace(t, results)

			data, etag := getTestObject(t, p, bucket, key)
			if !bytes.Equal(data, bodies[winner.idx]) {
				t.Errorf("final object bytes do not match winning completer %d", winner.idx)
			}
			if etag != winner.etag {
				t.Errorf("final etag %q does not match winner etag %q", etag, winner.etag)
			}
		})
	}
}

// strayTmpFiles returns any regular files under the bucket's temp dir that are
// not part of the multipart staging area or the object lock directory. Any
// leftover file here indicates a leaked staging tmpfile.
func strayTmpFiles(t *testing.T, bucket string) []string {
	t.Helper()
	var stray []string
	root := filepath.Join(bucket, MetaTmpDir)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.IsDir() {
			base := filepath.Base(path)
			if base == "multipart" || base == "objlock" {
				return filepath.SkipDir
			}
			return nil
		}
		stray = append(stray, path)
		return nil
	})
	if err != nil {
		t.Fatalf("walk tmp dir: %v", err)
	}
	return stray
}

func TestPosixConditionalPutFailureCleanup(t *testing.T) {
	for mode, mkMeta := range metaModes(t) {
		t.Run(mode, func(t *testing.T) {
			p := newTestPosix(t, mkMeta)
			bucket := "testbucket"
			key := "obj-cleanup"
			createTestBucket(t, p, bucket)

			res, err := testPut(p, bucket, key, []byte("base"), nil, nil)
			if err != nil {
				t.Fatalf("seed put: %v", err)
			}

			// failed precondition leaves no staging garbage behind
			_, err = testPut(p, bucket, key, []byte("cond"), nil, aws.String("*"))
			if !isPreconditionFailed(err) {
				t.Fatalf("want 412, got %v", err)
			}
			if stray := strayTmpFiles(t, bucket); len(stray) != 0 {
				t.Errorf("stray tmp files after 412: %v", stray)
			}

			// injected publication failure: the post-process hook fails after
			// staging, before publication. The object must be unchanged, no
			// garbage left, and the key must still be writable afterwards
			// (i.e. no stale lock is left behind).
			_, err = p.PutObjectWithPostFunc(context.Background(), s3response.PutObjectInput{
				Bucket:        &bucket,
				Key:           &key,
				Body:          bytes.NewReader([]byte("injected")),
				ContentLength: aws.Int64(int64(len("injected"))),
				IfMatch:       aws.String(trimEtag(res.ETag)),
			}, func(*os.File) error { return errors.New("injected publication failure") })
			if err == nil {
				t.Fatalf("expected injected publication failure to propagate")
			}
			data, _ := getTestObject(t, p, bucket, key)
			if string(data) != "base" {
				t.Errorf("object modified by failed publication: %q", data)
			}
			if stray := strayTmpFiles(t, bucket); len(stray) != 0 {
				t.Errorf("stray tmp files after injected failure: %v", stray)
			}

			// key still writable, conditional protocol still functional
			res2, err := testPut(p, bucket, key, []byte("after"), aws.String(trimEtag(res.ETag)), nil)
			if err != nil {
				t.Fatalf("put after injected failure: %v", err)
			}
			data, etag := getTestObject(t, p, bucket, key)
			if string(data) != "after" || etag != res2.ETag {
				t.Errorf("unexpected final state after recovery put")
			}
		})
	}
}
