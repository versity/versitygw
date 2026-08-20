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

// Package conditionalrace is an external, S3-level verification of
// conditional-write atomicity against a live versitygw process. It sends real
// SigV4-authenticated requests through the standard AWS SDK and replicates
// the algorithm of Buzz's git object-store A3 conformance probe
// (https://github.com/block/buzz, crates/buzz-relay/src/api/git/store.rs):
//
//   - sequential object round-trip with etag consistency checks
//   - 32-way concurrent If-Match races, expecting exactly 1×2xx + 31×412
//   - 32-way concurrent If-None-Match: * races, expecting 1×2xx + 31×412
//   - three rounds of each race
//
// It also verifies ordinary operations: bucket create/stat, PUT, HEAD, GET,
// DELETE, and a 20 MiB multipart upload with SHA-256 download comparison.
//
// The test is skipped unless the following environment variables are set
// (credentials are never logged or persisted):
//
//	VERSITY_ENDPOINT    e.g. http://127.0.0.1:7070
//	VERSITY_ACCESS_KEY
//	VERSITY_SECRET_KEY
//	VERSITY_BUCKET
//
// Optionally, VERSITY_ENDPOINT2 may point to a second gateway process
// sharing the same backend directory; racing writers are then spread across
// both processes, which verifies cross-process (filesystem lock based)
// conditional-write exclusion.
package conditionalrace

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const (
	raceWriters = 32
	raceRounds  = 3
)

type liveEnv struct {
	client  *s3.Client
	clients []*s3.Client
	bucket  string
}

// raceClient returns the client a racing writer should use, spreading
// writers across all configured gateway endpoints.
func (e *liveEnv) raceClient(i int) *s3.Client {
	return e.clients[i%len(e.clients)]
}

func newLiveEnv(t *testing.T) *liveEnv {
	t.Helper()
	endpoint := os.Getenv("VERSITY_ENDPOINT")
	access := os.Getenv("VERSITY_ACCESS_KEY")
	secret := os.Getenv("VERSITY_SECRET_KEY")
	bucket := os.Getenv("VERSITY_BUCKET")
	if endpoint == "" || access == "" || secret == "" || bucket == "" {
		t.Skip("VERSITY_ENDPOINT, VERSITY_ACCESS_KEY, VERSITY_SECRET_KEY, " +
			"and VERSITY_BUCKET must be set for the live S3 race test")
	}

	newClient := func(endpoint string) *s3.Client {
		return s3.New(s3.Options{
			BaseEndpoint: aws.String(endpoint),
			Region:       "us-east-1",
			UsePathStyle: true,
			Credentials:  credentials.NewStaticCredentialsProvider(access, secret, ""),
		})
	}

	client := newClient(endpoint)
	clients := []*s3.Client{client}
	if endpoint2 := os.Getenv("VERSITY_ENDPOINT2"); endpoint2 != "" {
		clients = append(clients, newClient(endpoint2))
	}

	env := &liveEnv{client: client, clients: clients, bucket: bucket}
	env.ensureBucket(t)
	return env
}

func (e *liveEnv) ensureBucket(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	_, err := e.client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &e.bucket})
	if err == nil {
		return
	}
	_, err = e.client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &e.bucket})
	if err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	_, err = e.client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &e.bucket})
	if err != nil {
		t.Fatalf("stat bucket after create: %v", err)
	}
}

func httpStatus(err error) int {
	var re *awshttp.ResponseError
	if errors.As(err, &re) {
		return re.HTTPStatusCode()
	}
	return 0
}

func (e *liveEnv) get(t *testing.T, key string) ([]byte, string) {
	t.Helper()
	out, err := e.client.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: &e.bucket,
		Key:    &key,
	})
	if err != nil {
		t.Fatalf("get %q: %v", key, err)
	}
	defer out.Body.Close()
	data, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatalf("read %q: %v", key, err)
	}
	return data, aws.ToString(out.ETag)
}

type outcome struct {
	idx    int
	etag   string
	err    error
	status int
}

// racePut launches n concurrent conditional PUTs released through a common
// start barrier.
func racePut(t *testing.T, n int, put func(i int) (string, error)) []outcome {
	t.Helper()
	start := make(chan struct{})
	var ready, done sync.WaitGroup
	results := make([]outcome, n)
	for i := range n {
		ready.Add(1)
		done.Add(1)
		go func(i int) {
			defer done.Done()
			ready.Done()
			<-start
			etag, err := put(i)
			results[i] = outcome{idx: i, etag: etag, err: err, status: httpStatus(err)}
		}(i)
	}
	ready.Wait()
	close(start)
	done.Wait()
	return results
}

func classify(t *testing.T, results []outcome) outcome {
	t.Helper()
	var winners []outcome
	failed := 0
	for _, r := range results {
		switch {
		case r.err == nil:
			winners = append(winners, r)
		case r.status == http.StatusPreconditionFailed:
			failed++
		default:
			t.Errorf("writer %d: unexpected error (want 2xx or 412): %v", r.idx, r.err)
		}
	}
	if len(winners) != 1 || failed != len(results)-1 {
		t.Fatalf("expected exactly 1×2xx + %d×412 among %d classified observers, got %d×2xx + %d×412",
			len(results)-1, len(results), len(winners), failed)
	}
	return winners[0]
}

func body(round, i int) []byte {
	return fmt.Appendf(nil, "buzz-a3-replica-round-%d-writer-%02d-%s",
		round, i, string(bytes.Repeat([]byte{byte('a' + i%26)}, 128)))
}

// TestLiveSequentialRoundTrip is the sequential portion of the Buzz probe:
// create-only PUT, GET with etag consistency, and delete.
func TestLiveSequentialRoundTrip(t *testing.T) {
	e := newLiveEnv(t)
	ctx := context.Background()
	key := "cond-race/sequential-roundtrip"
	content := []byte("sequential-round-trip-payload")

	_, _ = e.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &e.bucket, Key: &key})

	put, err := e.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      &e.bucket,
		Key:         &key,
		Body:        bytes.NewReader(content),
		IfNoneMatch: aws.String("*"),
	})
	if err != nil {
		t.Fatalf("create-only put: %v", err)
	}

	// duplicate create-only put must fail 412
	_, err = e.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      &e.bucket,
		Key:         &key,
		Body:        bytes.NewReader([]byte("other")),
		IfNoneMatch: aws.String("*"),
	})
	if httpStatus(err) != http.StatusPreconditionFailed {
		t.Fatalf("duplicate create-only put: want 412, got %v", err)
	}

	// stale if-match must fail 412
	_, err = e.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:  &e.bucket,
		Key:     &key,
		Body:    bytes.NewReader([]byte("other")),
		IfMatch: aws.String("\"deadbeefdeadbeefdeadbeefdeadbeef\""),
	})
	if httpStatus(err) != http.StatusPreconditionFailed {
		t.Fatalf("stale if-match put: want 412, got %v", err)
	}

	data, etag := e.get(t, key)
	if !bytes.Equal(data, content) {
		t.Fatalf("round-trip content mismatch")
	}
	if etag != aws.ToString(put.ETag) {
		t.Fatalf("round-trip etag mismatch: put %q get %q", aws.ToString(put.ETag), etag)
	}

	head, err := e.client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &e.bucket, Key: &key})
	if err != nil {
		t.Fatalf("head object: %v", err)
	}
	if aws.ToString(head.ETag) != etag {
		t.Fatalf("head etag mismatch")
	}

	_, err = e.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &e.bucket, Key: &key})
	if err != nil {
		t.Fatalf("delete object: %v", err)
	}
	_, err = e.client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &e.bucket, Key: &key})
	if httpStatus(err) != http.StatusNotFound {
		t.Fatalf("head after delete: want 404, got %v", err)
	}
}

// TestLiveIfMatchRace replicates the Buzz probe's if_match_race phase.
func TestLiveIfMatchRace(t *testing.T) {
	e := newLiveEnv(t)
	ctx := context.Background()
	key := "cond-race/if-match-race"

	for round := range raceRounds {
		seedBody := fmt.Appendf(nil, "if-match-seed-round-%d", round)
		seed, err := e.client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: &e.bucket,
			Key:    &key,
			Body:   bytes.NewReader(seedBody),
		})
		if err != nil {
			t.Fatalf("round %d: seed put: %v", round, err)
		}

		results := racePut(t, raceWriters, func(i int) (string, error) {
			res, err := e.raceClient(i).PutObject(ctx, &s3.PutObjectInput{
				Bucket:  &e.bucket,
				Key:     &key,
				Body:    bytes.NewReader(body(round, i)),
				IfMatch: seed.ETag,
			})
			if err != nil {
				return "", err
			}
			return aws.ToString(res.ETag), nil
		})
		winner := classify(t, results)

		data, etag := e.get(t, key)
		if !bytes.Equal(data, body(round, winner.idx)) {
			t.Errorf("round %d: final bytes are not the winner's", round)
		}
		if etag != winner.etag {
			t.Errorf("round %d: final etag %q != winner etag %q", round, etag, winner.etag)
		}
	}
}

// TestLiveIfNoneMatchRace replicates the Buzz probe's if_none_match_race phase.
func TestLiveIfNoneMatchRace(t *testing.T) {
	e := newLiveEnv(t)
	ctx := context.Background()

	for round := range raceRounds {
		key := fmt.Sprintf("cond-race/if-none-match-race-%d", round)
		_, _ = e.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &e.bucket, Key: &key})

		results := racePut(t, raceWriters, func(i int) (string, error) {
			res, err := e.raceClient(i).PutObject(ctx, &s3.PutObjectInput{
				Bucket:      &e.bucket,
				Key:         &key,
				Body:        bytes.NewReader(body(round, i)),
				IfNoneMatch: aws.String("*"),
			})
			if err != nil {
				return "", err
			}
			return aws.ToString(res.ETag), nil
		})
		winner := classify(t, results)

		data, etag := e.get(t, key)
		if !bytes.Equal(data, body(round, winner.idx)) {
			t.Errorf("round %d: final bytes are not the winner's", round)
		}
		if etag != winner.etag {
			t.Errorf("round %d: final etag %q != winner etag %q", round, etag, winner.etag)
		}
	}
}

// TestLiveBasicOpsAndMultipart verifies ordinary operations still work:
// PUT/HEAD/GET/DELETE and a 20 MiB multipart upload with SHA-256 comparison.
func TestLiveBasicOpsAndMultipart(t *testing.T) {
	e := newLiveEnv(t)
	ctx := context.Background()

	key := "cond-race/multipart-20mib"
	const partSize = 5 * 1024 * 1024
	const numParts = 4

	payload := make([]byte, partSize*numParts)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("generate payload: %v", err)
	}
	wantSum := sha256.Sum256(payload)

	mp, err := e.client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: &e.bucket,
		Key:    &key,
	})
	if err != nil {
		t.Fatalf("create multipart upload: %v", err)
	}

	var completed []types.CompletedPart
	for part := 1; part <= numParts; part++ {
		chunk := payload[(part-1)*partSize : part*partSize]
		res, err := e.client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:     &e.bucket,
			Key:        &key,
			UploadId:   mp.UploadId,
			PartNumber: aws.Int32(int32(part)),
			Body:       bytes.NewReader(chunk),
		})
		if err != nil {
			t.Fatalf("upload part %d: %v", part, err)
		}
		completed = append(completed, types.CompletedPart{
			ETag:       res.ETag,
			PartNumber: aws.Int32(int32(part)),
		})
	}

	_, err = e.client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:          &e.bucket,
		Key:             &key,
		UploadId:        mp.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: completed},
	})
	if err != nil {
		t.Fatalf("complete multipart upload: %v", err)
	}

	data, _ := e.get(t, key)
	if gotSum := sha256.Sum256(data); gotSum != wantSum {
		t.Fatalf("multipart download sha256 mismatch (%d bytes)", len(data))
	}

	_, err = e.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &e.bucket, Key: &key})
	if err != nil {
		t.Fatalf("delete multipart object: %v", err)
	}
}
