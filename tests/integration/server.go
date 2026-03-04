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

package integration

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func Server_large_http_header(s *S3Conf) error {
	testName := "Server_large_http_header"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, bucket string) error {
		req, err := createSignedReq(http.MethodPut, s.endpoint, "/bucket/object", s.awsID, s.awsSecret, "s3", s.awsRegion, nil, time.Now(), map[string]string{
			"x-amz-custom-header": strings.Repeat("d", 1024*8),
		})
		if err != nil {
			return err
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusBadRequest {
			return fmt.Errorf("expected the response status to be %v, instead got %v", http.StatusBadRequest, resp.StatusCode)
		}

		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		if len(body) != 0 {
			return fmt.Errorf("expected empty response body, instead got %s", body)
		}

		return nil
	})
}
