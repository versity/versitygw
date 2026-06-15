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
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/versity/versitygw/s3err"
)

func Server_large_http_header(s *S3Conf) error {
	testName := "Server_large_http_header"
	return actionHandlerNoSetup(s, testName, func(s3client *s3.Client, bucket string) error {
		req, err := createSignedReq(http.MethodPut, s.endpoint, "/bucket/object", s.awsID, s.awsSecret, "s3", s.awsRegion, "", nil, time.Now(), map[string]string{
			"x-amz-custom-header": strings.Repeat("d", 1024*8),
		})
		if err != nil {
			return err
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		expectedErr := s3err.GetRequestHeaderSectionTooLargeErr(8 * 1024)
		if resp.StatusCode != expectedErr.StatusCode() {
			return fmt.Errorf("expected the response status to be %v, instead got %v", expectedErr.StatusCode(), resp.StatusCode)
		}

		return checkHTTPResponseApiErr(resp, expectedErr)
	})
}
