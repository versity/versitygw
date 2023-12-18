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

package auth

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

type IAMServiceS3 struct {
	access   string
	secret   string
	region   string
	bucket   string
	endpoint string
}

var _ IAMService = &IAMServiceS3{}

func NewS3(access, secret, region, bucket, endpoint string) (IAMService, error) {
	if access == "" {
		return nil, fmt.Errorf("must provide s3 IAM service access key")
	}
	if secret == "" {
		return nil, fmt.Errorf("must provide s3 IAM service secret key")
	}
	if region == "" {
		return nil, fmt.Errorf("must provide s3 IAM service region")
	}
	if bucket == "" {
		return nil, fmt.Errorf("must provide s3 IAM service bucket")
	}
	if endpoint == "" {
		return nil, fmt.Errorf("must provide s3 IAM service endpoint")
	}

	return &IAMServiceS3{
		access:   access,
		secret:   secret,
		region:   region,
		bucket:   bucket,
		endpoint: endpoint,
	}, nil
}

func (s *IAMServiceS3) CreateAccount(account Account) error {
	accJson, err := json.Marshal(account)
	if err != nil {
		return fmt.Errorf("failed to parse user data: %w", err)
	}

	req, err := http.NewRequest(http.MethodPatch, fmt.Sprintf("%v/create-user", s.endpoint), bytes.NewBuffer(accJson))
	if err != nil {
		return fmt.Errorf("failed to send the request: %w", err)
	}

	signer := v4.NewSigner()

	hashedPayload := sha256.Sum256(accJson)
	hexPayload := hex.EncodeToString(hashedPayload[:])

	req.Header.Set("X-Amz-Content-Sha256", hexPayload)

	signErr := signer.SignHTTP(req.Context(), aws.Credentials{AccessKeyID: s.access, SecretAccessKey: s.secret}, req, hexPayload, "s3", s.region, time.Now())
	if signErr != nil {
		return fmt.Errorf("failed to sign the request: %w", err)
	}

	client := http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send the request: %w", err)
	}

	if resp.StatusCode > 300 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		return fmt.Errorf(string(body))
	}

	return nil
}

func (s *IAMServiceS3) GetUserAccount(access string) (Account, error) {
	return Account{
		Access: s.access,
		Secret: s.secret,
		Role:   "admin",
	}, nil
}

func (s *IAMServiceS3) DeleteUserAccount(access string) error {
	req, err := http.NewRequest(http.MethodPatch, fmt.Sprintf("%v/delete-user?access=%v", s.endpoint, access), nil)
	if err != nil {
		return fmt.Errorf("failed to send the request: %w", err)
	}

	signer := v4.NewSigner()

	hashedPayload := sha256.Sum256([]byte{})
	hexPayload := hex.EncodeToString(hashedPayload[:])

	req.Header.Set("X-Amz-Content-Sha256", hexPayload)

	signErr := signer.SignHTTP(req.Context(), aws.Credentials{AccessKeyID: s.access, SecretAccessKey: s.secret}, req, hexPayload, "s3", s.region, time.Now())
	if signErr != nil {
		return fmt.Errorf("failed to sign the request: %w", err)
	}

	client := http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send the request: %w", err)
	}

	if resp.StatusCode > 300 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		return fmt.Errorf(string(body))
	}

	return nil
}

func (s *IAMServiceS3) ListUserAccounts() ([]Account, error) {
	req, err := http.NewRequest(http.MethodPatch, fmt.Sprintf("%v/list-users", s.endpoint), nil)
	if err != nil {
		return []Account{}, fmt.Errorf("failed to send the request: %w", err)
	}

	signer := v4.NewSigner()

	hashedPayload := sha256.Sum256([]byte{})
	hexPayload := hex.EncodeToString(hashedPayload[:])

	req.Header.Set("X-Amz-Content-Sha256", hexPayload)

	signErr := signer.SignHTTP(req.Context(), aws.Credentials{AccessKeyID: s.access, SecretAccessKey: s.secret}, req, hexPayload, "s3", s.region, time.Now())
	if signErr != nil {
		return []Account{}, fmt.Errorf("failed to sign the request: %w", err)
	}

	client := http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		return []Account{}, fmt.Errorf("failed to send the request: %w", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return []Account{}, err
	}
	defer resp.Body.Close()

	var accs []Account
	if err := json.Unmarshal(body, &accs); err != nil {
		return []Account{}, err
	}

	return accs, nil
}

func (IAMServiceS3) Shutdown() error {
	return nil
}
