// Copyright 2023 Versity Software
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

package integration

import (
	"context"
	"fmt"
	"io"
	"math"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type prefResult struct {
	elapsed time.Duration
	size    int64
	err     error
}

func TestUpload(s *S3Conf, files int, objSize int64, bucket, prefix string) error {
	var sg sync.WaitGroup
	results := make([]prefResult, files)
	start := time.Now()
	if objSize == 0 {
		return fmt.Errorf("must specify object size for upload")
	}

	if objSize > (int64(10000) * s.PartSize) {
		return fmt.Errorf("object size can not exceed 10000 * chunksize")
	}

	runF("performance test: upload objects")

	for i := 0; i < files; i++ {
		sg.Add(1)
		go func(i int) {
			var r io.Reader = NewDataReader(int(objSize), int(s.PartSize))

			start := time.Now()
			err := s.UploadData(r, bucket, fmt.Sprintf("%v%v", prefix, i))
			results[i].elapsed = time.Since(start)
			results[i].err = err
			results[i].size = objSize
			sg.Done()
		}(i)
	}
	sg.Wait()
	elapsed := time.Since(start)

	var tot int64
	for i, res := range results {
		if res.err != nil {
			failF("%v: %v\n", i, res.err)
			break
		}
		tot += res.size
		fmt.Printf("%v: %v in %v (%v MB/s)\n",
			i, res.size, res.elapsed,
			int(math.Ceil(float64(res.size)/res.elapsed.Seconds())/1048576))
	}

	fmt.Println()
	passF("run upload: %v in %v (%v MB/s)\n",
		tot, elapsed, int(math.Ceil(float64(tot)/elapsed.Seconds())/1048576))

	return nil
}

func TestDownload(s *S3Conf, files int, objSize int64, bucket, prefix string) error {
	var sg sync.WaitGroup
	results := make([]prefResult, files)
	start := time.Now()

	runF("performance test: download objects")

	for i := 0; i < files; i++ {
		sg.Add(1)
		go func(i int) {
			nw := NewNullWriter()
			start := time.Now()
			n, err := s.DownloadData(nw, bucket, fmt.Sprintf("%v%v", prefix, i))
			results[i].elapsed = time.Since(start)
			results[i].err = err
			results[i].size = n
			sg.Done()
		}(i)
	}
	sg.Wait()
	elapsed := time.Since(start)

	var tot int64
	for i, res := range results {
		if res.err != nil {
			failF("%v: %v\n", i, res.err)
			break
		}
		tot += res.size
		fmt.Printf("%v: %v in %v (%v MB/s)\n",
			i, res.size, res.elapsed,
			int(math.Ceil(float64(res.size)/res.elapsed.Seconds())/1048576))
	}

	fmt.Println()
	passF("run download: %v in %v (%v MB/s)\n",
		tot, elapsed, int(math.Ceil(float64(tot)/elapsed.Seconds())/1048576))

	return nil
}

func TestReqPerSec(s *S3Conf, totalReqs int, bucket string) error {
	client := s3.NewFromConfig(s.Config())
	var wg sync.WaitGroup
	var resErr error

	// Record the start time
	startTime := time.Now()
	runF("performance test: measuring request per second")

	for i := 0; i < s.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < totalReqs/s.Concurrency; i++ {
				_, err := client.HeadBucket(context.Background(), &s3.HeadBucketInput{Bucket: &bucket})
				if err != nil && resErr != nil {
					resErr = err
				}
			}
		}()
	}

	wg.Wait()
	if resErr != nil {
		failF("performance test failed with error: %w", resErr)
		return nil
	}
	elapsedTime := time.Since(startTime)
	rps := int(float64(totalReqs) / elapsedTime.Seconds())

	passF("Success\nTotal Requests: %d,\nConcurrency Level: %d,\nTime Taken: %s,\nRequests Per Second: %dreq/sec", totalReqs, s.Concurrency, elapsedTime, rps)
	return nil
}
