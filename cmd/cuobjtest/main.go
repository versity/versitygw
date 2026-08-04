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

package main

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	s3lib "github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/versity/versitygw/cuobjclient"
)

var (
	endpoint   = flag.String("endpoint", "http://localhost:7070", "cuserver S3 endpoint URL")
	bucket     = flag.String("bucket", "cuobjtest", "S3 bucket (created if absent)")
	key        = flag.String("key", "cuobjtest-object", "S3 object key prefix")
	sizeStr    = flag.String("size", "64MiB", "Transfer size per iteration: e.g. 4MiB, 256MiB, 1GiB")
	access     = flag.String("access", "admin", "S3 access key")
	secret     = flag.String("secret", "", "S3 secret key (default: $AWS_SECRET_ACCESS_KEY); prefer the environment variable over this flag, which is visible in shell history and process listings")
	region     = flag.String("region", "us-east-1", "S3 region")
	iterations = flag.Int("n", 3, "Number of benchmark iterations")
	putOnly    = flag.Bool("put-only", false, "Run PUT only (skip GET and checksum verification)")
	getOnly    = flag.Bool("get-only", false, "Run GET only (assumes object already exists)")
	stdS3      = flag.Bool("std-s3", false, "Use standard S3 PUT/GET (no cuObject RDMA transfer)")
)

func main() {
	flag.Parse()

	if *secret == "" {
		*secret = os.Getenv("AWS_SECRET_ACCESS_KEY")
	}
	if *secret == "" {
		fmt.Fprintln(os.Stderr, "cuobjtest: -secret or AWS_SECRET_ACCESS_KEY is required")
		flag.Usage()
		os.Exit(1)
	}
	if *putOnly && *getOnly {
		fatalf("cuobjtest: -put-only and -get-only are mutually exclusive")
	}
	if *iterations < 1 {
		fatalf("cuobjtest: -n must be >= 1")
	}

	size, err := parseSize(*sizeStr)
	if err != nil {
		fatalf("cuobjtest: -size: %v", err)
	}
	if size <= 0 || size > cuobjclient.MaxTransferSize {
		fatalf("cuobjtest: -size must be between 1 B and %d bytes", cuobjclient.MaxTransferSize)
	}

	if err := runBenchmark(size); err != nil {
		fatalf("cuobjtest: %v", err)
	}
}

type iterationResult struct {
	index  int
	putDur time.Duration
	getDur time.Duration
	status string
	err    error
}

type benchmarkStats struct {
	putDurs  []time.Duration
	getDurs  []time.Duration
	mismatch int
}

func runBenchmark(size int) error {
	base := newS3Client(*endpoint, *access, *secret, *region)
	if err := ensureBucket(base, *bucket); err != nil {
		return err
	}

	printRunHeader(size)

	stats := benchmarkStats{}
	var results []iterationResult
	var benchmarkDur time.Duration
	if *stdS3 {
		results, benchmarkDur = runConcurrentStdS3(base, size)
	} else {
		results, benchmarkDur = runConcurrent(base, size)
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].index < results[j].index
	})
	for _, r := range results {
		if r.err != nil {
			return fmt.Errorf("iter %d: %w", r.index, r.err)
		}
		accumulateStats(&stats, r)
		printIterationResult(size, r)
	}

	return printSummary(stats, benchmarkDur, size)
}

func printRunHeader(size int) {
	mode := runModeLabel()
	if *stdS3 {
		mode = "standard-s3"
	}
	fmt.Printf("\ncuobjtest    endpoint=%-28s  size=%s  iterations=%d\n", *endpoint, formatSize(size), *iterations)
	fmt.Printf("            mode=%s\n\n", mode)
	if *putOnly {
		fmt.Printf("%-4s  %-14s %-10s\n", "#", "PUT latency", "PUT GB/s")
	} else if *getOnly {
		fmt.Printf("%-4s  %-14s %-10s\n", "#", "GET latency", "GET GB/s")
	} else {
		fmt.Printf("%-4s  %-14s %-10s   %-14s %-10s   %s\n",
			"#", "PUT latency", "PUT GB/s", "GET latency", "GET GB/s", "checksum")
	}
	fmt.Printf("%s\n", strings.Repeat("-", 70))
}

func accumulateStats(stats *benchmarkStats, r iterationResult) {
	if !*getOnly {
		stats.putDurs = append(stats.putDurs, r.putDur)
	}
	if !*putOnly {
		stats.getDurs = append(stats.getDurs, r.getDur)
	}
	if r.status != "OK" {
		stats.mismatch++
	}
}

func printSummary(stats benchmarkStats, benchmarkDur time.Duration, size int) error {

	fmt.Printf("%s\n", strings.Repeat("-", 70))
	putCount := len(stats.putDurs)
	getCount := len(stats.getDurs)
	putBytes := int64(putCount * size)
	getBytes := int64(getCount * size)
	totalBytes := putBytes + getBytes
	// PUT/GET throughput is measured against the time actually spent in
	// PUT/GET calls, not the combined benchmarkDur (which also includes
	// the other operation and buffer preparation).
	putDur := sumDurs(stats.putDurs)
	getDur := sumDurs(stats.getDurs)

	fmt.Printf("OVERALL elapsed=%s", fmtDur(benchmarkDur))
	if putCount > 0 {
		fmt.Printf("  PUT agg=%s (%d ops, %.2f ops/s)",
			fmt.Sprintf("%.3f GB/s", float64(putBytes)/putDur.Seconds()/1e9),
			putCount,
			float64(putCount)/putDur.Seconds())
	}
	if getCount > 0 {
		fmt.Printf("  GET agg=%s (%d ops, %.2f ops/s)",
			fmt.Sprintf("%.3f GB/s", float64(getBytes)/getDur.Seconds()/1e9),
			getCount,
			float64(getCount)/getDur.Seconds())
	}
	if putCount > 0 && getCount > 0 {
		fmt.Printf("  COMBINED=%s",
			fmt.Sprintf("%.3f GB/s", float64(totalBytes)/benchmarkDur.Seconds()/1e9))
	}
	fmt.Printf("\n")

	if *iterations > 1 {
		if !*getOnly {
			pa, plo, phi := durStats(stats.putDurs)
			fmt.Printf("PUT  avg=%-10s  min=%-10s  max=%-10s  avg %s\n",
				fmtDur(pa), fmtDur(plo), fmtDur(phi), fmtGBps(size, pa))
		}
		if !*putOnly {
			ga, glo, ghi := durStats(stats.getDurs)
			fmt.Printf("GET  avg=%-10s  min=%-10s  max=%-10s  avg %s\n",
				fmtDur(ga), fmtDur(glo), fmtDur(ghi), fmtGBps(size, ga))
		}
	}

	if *getOnly {
		fmt.Printf("\nGET-only run complete.\n")
		return nil
	}
	if *putOnly {
		fmt.Printf("\nPUT-only run complete.\n")
		return nil
	}
	if stats.mismatch > 0 {
		return fmt.Errorf("%d/%d iterations had checksum mismatches", stats.mismatch, *iterations)
	}
	fmt.Printf("\nAll checksums OK.\n")
	return nil
}

func runConcurrent(base *s3lib.Client, size int) ([]iterationResult, time.Duration) {
	session, err := cuobjclient.NewSession(size)
	if err != nil {
		return []iterationResult{{index: 1, err: fmt.Errorf("init cuObj session: %w", err)}}, 0
	}
	defer session.Close()

	putHost := make([]byte, size)
	getHost := make([]byte, size)
	out := make([]iterationResult, 0, *iterations)

	benchmarkStart := time.Now()
	for i := 1; i <= *iterations; i++ {
		res := iterationResult{index: i, status: "OK"}
		iterKey := *key

		if !*getOnly {
			if _, err := crand.Read(putHost); err != nil {
				res.err = fmt.Errorf("fill PUT buffer: %w", err)
				out = append(out, res)
				continue
			}
			putCRC := crc32.ChecksumIEEE(putHost)

			putStart := time.Now()
			err := session.Upload(base, *bucket, iterKey, putHost)
			res.putDur = time.Since(putStart)
			if err != nil {
				res.err = fmt.Errorf("PUT: %w", err)
				out = append(out, res)
				continue
			}

			if *putOnly {
				out = append(out, res)
				continue
			}

			getStart := time.Now()
			err = session.Download(base, *bucket, iterKey, getHost)
			res.getDur = time.Since(getStart)
			if err != nil {
				res.err = fmt.Errorf("GET: %w", err)
				out = append(out, res)
				continue
			}
			getCRC := crc32.ChecksumIEEE(getHost)
			if getCRC != putCRC {
				res.status = fmt.Sprintf("MISMATCH put=%08x get=%08x", putCRC, getCRC)
			}
			out = append(out, res)
			continue
		}

		getStart := time.Now()
		err := session.Download(base, *bucket, iterKey, getHost)
		res.getDur = time.Since(getStart)
		if err != nil {
			res.err = fmt.Errorf("GET: %w", err)
		}
		out = append(out, res)
	}

	return out, time.Since(benchmarkStart)
}

// runConcurrentStdS3 exercises plain S3 PUT/GET (request body carries the
// actual data, no RDMA headers) so it can be benchmarked against the
// cuObject RDMA path in runConcurrent.
func runConcurrentStdS3(base *s3lib.Client, size int) ([]iterationResult, time.Duration) {
	putHost := make([]byte, size)
	getHost := make([]byte, size)
	out := make([]iterationResult, 0, *iterations)

	benchmarkStart := time.Now()
	for i := 1; i <= *iterations; i++ {
		res := iterationResult{index: i, status: "OK"}
		iterKey := *key

		if !*getOnly {
			if _, err := crand.Read(putHost); err != nil {
				res.err = fmt.Errorf("fill PUT buffer: %w", err)
				out = append(out, res)
				continue
			}
			putCRC := crc32.ChecksumIEEE(putHost)

			putStart := time.Now()
			err := s3PutObject(base, *bucket, iterKey, putHost)
			res.putDur = time.Since(putStart)
			if err != nil {
				res.err = fmt.Errorf("PUT: %w", err)
				out = append(out, res)
				continue
			}

			if *putOnly {
				out = append(out, res)
				continue
			}

			getStart := time.Now()
			err = s3GetObject(base, *bucket, iterKey, getHost)
			res.getDur = time.Since(getStart)
			if err != nil {
				res.err = fmt.Errorf("GET: %w", err)
				out = append(out, res)
				continue
			}
			getCRC := crc32.ChecksumIEEE(getHost)
			if getCRC != putCRC {
				res.status = fmt.Sprintf("MISMATCH put=%08x get=%08x", putCRC, getCRC)
			}
			out = append(out, res)
			continue
		}

		getStart := time.Now()
		err := s3GetObject(base, *bucket, iterKey, getHost)
		res.getDur = time.Since(getStart)
		if err != nil {
			res.err = fmt.Errorf("GET: %w", err)
		}
		out = append(out, res)
	}

	return out, time.Since(benchmarkStart)
}

// s3PutObject issues a standard S3 PUT carrying data in the request body.
func s3PutObject(base *s3lib.Client, bucket, key string, data []byte) error {
	_, err := base.PutObject(context.Background(), &s3lib.PutObjectInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(key),
		Body:          bytes.NewReader(data),
		ContentLength: aws.Int64(int64(len(data))),
	})
	return err
}

// s3GetObject issues a standard S3 GET and reads the full body into dst.
func s3GetObject(base *s3lib.Client, bucket, key string, dst []byte) error {
	out, err := base.GetObject(context.Background(), &s3lib.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return err
	}
	defer out.Body.Close()
	// io.ReadFull only guarantees len(dst) bytes were read; it doesn't
	// notice a larger object whose extra bytes are simply left unread.
	// Compare against the reported object size so a too-small dst is
	// caught instead of silently benchmarking a truncated prefix.
	if out.ContentLength != nil && *out.ContentLength != int64(len(dst)) {
		return fmt.Errorf("object size %d does not match expected size %d", *out.ContentLength, len(dst))
	}
	_, err = io.ReadFull(out.Body, dst)
	return err
}

func newS3Client(endpoint, access, secret, region string) *s3lib.Client {
	return s3lib.New(s3lib.Options{
		BaseEndpoint: aws.String(endpoint),
		Region:       region,
		Credentials:  aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(access, secret, "")),
		UsePathStyle: true,
	})
}

func ensureBucket(c *s3lib.Client, bucket string) error {
	_, err := c.HeadBucket(context.Background(), &s3lib.HeadBucketInput{Bucket: aws.String(bucket)})
	if err == nil {
		return nil
	}
	var notFound *s3types.NotFound
	if !errors.As(err, &notFound) {
		return fmt.Errorf("head bucket %q: %w", bucket, err)
	}
	_, err = c.CreateBucket(context.Background(), &s3lib.CreateBucketInput{
		Bucket:                    aws.String(bucket),
		CreateBucketConfiguration: &s3types.CreateBucketConfiguration{},
	})
	if err != nil {
		return fmt.Errorf("create bucket %q: %w", bucket, err)
	}
	fmt.Printf("cuobjtest: created bucket %q\n", bucket)
	return nil
}

// printIterationResult renders one benchmark iteration according to mode.
func printIterationResult(size int, r iterationResult) {
	if *putOnly {
		fmt.Printf("%-4d  %-14s %-10s\n", r.index, fmtDur(r.putDur), fmtGBps(size, r.putDur))
		return
	}
	if *getOnly {
		fmt.Printf("%-4d  %-14s %-10s\n", r.index, fmtDur(r.getDur), fmtGBps(size, r.getDur))
		return
	}
	fmt.Printf("%-4d  %-14s %-10s   %-14s %-10s   %s\n",
		r.index,
		fmtDur(r.putDur), fmtGBps(size, r.putDur),
		fmtDur(r.getDur), fmtGBps(size, r.getDur),
		r.status)
}

// fmtDur renders a human-friendly duration.
func fmtDur(d time.Duration) string {
	ms := d.Seconds() * 1000
	if ms >= 1000 {
		return fmt.Sprintf("%.2f s", d.Seconds())
	}
	return fmt.Sprintf("%.2f ms", ms)
}

// fmtGBps formats bytes-per-second throughput as decimal GB/s.
func fmtGBps(bytes int, d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	return fmt.Sprintf("%.3f GB/s", float64(bytes)/d.Seconds()/1e9)
}

// formatSize renders a byte size using binary units when evenly divisible.
func formatSize(n int) string {
	switch {
	case n >= 1<<30 && n%(1<<30) == 0:
		return fmt.Sprintf("%d GiB", n>>30)
	case n >= 1<<20 && n%(1<<20) == 0:
		return fmt.Sprintf("%d MiB", n>>20)
	case n >= 1<<10 && n%(1<<10) == 0:
		return fmt.Sprintf("%d KiB", n>>10)
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// durStats returns average, minimum, and maximum durations.
func durStats(ds []time.Duration) (avg, min, max time.Duration) {
	min = time.Duration(math.MaxInt64)
	var sum time.Duration
	for _, d := range ds {
		sum += d
		if d < min {
			min = d
		}
		if d > max {
			max = d
		}
	}
	avg = sum / time.Duration(len(ds))
	return
}

// sumDurs returns the sum of the given durations.
func sumDurs(ds []time.Duration) time.Duration {
	var sum time.Duration
	for _, d := range ds {
		sum += d
	}
	return sum
}

// parseSize parses byte sizes like 64MiB, 1GiB, or 1000000.
func parseSize(s string) (int, error) {
	units := []struct {
		suffix string
		mult   int64
	}{
		{"GiB", 1 << 30}, {"GB", 1_000_000_000},
		{"MiB", 1 << 20}, {"MB", 1_000_000},
		{"KiB", 1 << 10}, {"KB", 1_000},
		{"G", 1 << 30}, {"M", 1 << 20}, {"K", 1 << 10},
		{"B", 1},
	}
	upper := strings.ToUpper(strings.TrimSpace(s))
	for _, u := range units {
		if strings.HasSuffix(upper, strings.ToUpper(u.suffix)) {
			numStr := strings.TrimSpace(s[:len(s)-len(u.suffix)])
			n, err := strconv.ParseFloat(numStr, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid size %q", s)
			}
			return int(n * float64(u.mult)), nil
		}
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	return n, nil
}

// fatalf prints an error and exits with status code 1.
func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
