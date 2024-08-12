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
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// IAMServiceS3 stores user accounts in an S3 object
// The endpoint, credentials, bucket, and region are provided
// from cli configuration.
// The object format and name is the same as the internal IAM service:
// coming from iAMConfig and iamFile in iam_internal.

type IAMServiceS3 struct {
	// This mutex will help with racing updates to the IAM data
	// from multiple requests to this gateway instance, but
	// will not help with racing updates to multiple load balanced
	// gateway instances. This is a limitation of the internal
	// IAM service. All account updates should be sent to a single
	// gateway instance if possible.
	sync.RWMutex

	access        string
	secret        string
	region        string
	bucket        string
	endpoint      string
	sslSkipVerify bool
	debug         bool
	rootAcc       Account
	client        *s3.Client
}

var _ IAMService = &IAMServiceS3{}

func NewS3(rootAcc Account, access, secret, region, bucket, endpoint string, sslSkipVerify, debug bool) (*IAMServiceS3, error) {
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

	i := &IAMServiceS3{
		access:        access,
		secret:        secret,
		region:        region,
		bucket:        bucket,
		endpoint:      endpoint,
		sslSkipVerify: sslSkipVerify,
		debug:         debug,
		rootAcc:       rootAcc,
	}

	cfg, err := i.getConfig()
	if err != nil {
		return nil, fmt.Errorf("init s3 IAM: %v", err)
	}

	if endpoint != "" {
		i.client = s3.NewFromConfig(cfg, func(o *s3.Options) {
			o.BaseEndpoint = &endpoint
		})
		return i, nil
	}

	i.client = s3.NewFromConfig(cfg)
	return i, nil
}

func (s *IAMServiceS3) CreateAccount(account Account) error {
	if s.rootAcc.Access == account.Access {
		return ErrUserExists
	}

	s.Lock()
	defer s.Unlock()

	conf, err := s.getAccounts()
	if err != nil {
		return err
	}

	_, ok := conf.AccessAccounts[account.Access]
	if ok {
		return ErrUserExists
	}
	conf.AccessAccounts[account.Access] = account

	return s.storeAccts(conf)
}

func (s *IAMServiceS3) GetUserAccount(access string) (Account, error) {
	if access == s.rootAcc.Access {
		return s.rootAcc, nil
	}

	s.RLock()
	defer s.RUnlock()

	conf, err := s.getAccounts()
	if err != nil {
		return Account{}, err
	}

	acct, ok := conf.AccessAccounts[access]
	if !ok {
		return Account{}, ErrNoSuchUser
	}

	return acct, nil
}

func (s *IAMServiceS3) UpdateUserAccount(access string, props MutableProps) error {
	s.Lock()
	defer s.Unlock()

	conf, err := s.getAccounts()
	if err != nil {
		return err
	}

	acc, ok := conf.AccessAccounts[access]
	if !ok {
		return ErrNoSuchUser
	}

	updateAcc(&acc, props)
	conf.AccessAccounts[access] = acc

	return s.storeAccts(conf)
}

func (s *IAMServiceS3) DeleteUserAccount(access string) error {
	s.Lock()
	defer s.Unlock()

	conf, err := s.getAccounts()
	if err != nil {
		return err
	}

	_, ok := conf.AccessAccounts[access]
	if !ok {
		return fmt.Errorf("account does not exist")
	}
	delete(conf.AccessAccounts, access)

	return s.storeAccts(conf)
}

func (s *IAMServiceS3) ListUserAccounts() ([]Account, error) {
	s.RLock()
	defer s.RUnlock()

	conf, err := s.getAccounts()
	if err != nil {
		return nil, err
	}

	keys := make([]string, 0, len(conf.AccessAccounts))
	for k := range conf.AccessAccounts {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var accs []Account
	for _, k := range keys {
		accs = append(accs, Account{
			Access:  k,
			Secret:  conf.AccessAccounts[k].Secret,
			Role:    conf.AccessAccounts[k].Role,
			UserID:  conf.AccessAccounts[k].UserID,
			GroupID: conf.AccessAccounts[k].GroupID,
		})
	}

	return accs, nil
}

func (s *IAMServiceS3) Shutdown() error {
	return nil
}

func (s *IAMServiceS3) getConfig() (aws.Config, error) {
	creds := credentials.NewStaticCredentialsProvider(s.access, s.secret, "")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: s.sslSkipVerify},
	}
	client := &http.Client{Transport: tr}

	opts := []func(*config.LoadOptions) error{
		config.WithRegion(s.region),
		config.WithCredentialsProvider(creds),
		config.WithHTTPClient(client),
	}

	if s.debug {
		opts = append(opts,
			config.WithClientLogMode(aws.LogSigning|aws.LogRetries|aws.LogRequest|aws.LogResponse|aws.LogRequestEventMessage|aws.LogResponseEventMessage))
	}

	return config.LoadDefaultConfig(context.Background(), opts...)
}

func (s *IAMServiceS3) getAccounts() (iAMConfig, error) {
	obj := iamFile

	out, err := s.client.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: &s.bucket,
		Key:    &obj,
	})
	if err != nil {
		// if the error is object not exists,
		// init empty accounts struct and return that
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			return iAMConfig{AccessAccounts: map[string]Account{}}, nil
		}
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			if apiErr.ErrorCode() == "NotFound" {
				return iAMConfig{AccessAccounts: map[string]Account{}}, nil
			}
		}

		// all other errors, return the error
		return iAMConfig{}, fmt.Errorf("get %v: %w", obj, err)
	}

	defer out.Body.Close()

	b, err := io.ReadAll(out.Body)
	if err != nil {
		return iAMConfig{}, fmt.Errorf("read %v: %w", obj, err)
	}

	conf, err := parseIAM(b)
	if err != nil {
		return iAMConfig{}, fmt.Errorf("parse iam data: %w", err)
	}

	return conf, nil
}

func (s *IAMServiceS3) storeAccts(conf iAMConfig) error {
	b, err := json.Marshal(conf)
	if err != nil {
		return fmt.Errorf("failed to serialize iam: %w", err)
	}

	obj := iamFile
	uploader := manager.NewUploader(s.client)
	upinfo := &s3.PutObjectInput{
		Body:   bytes.NewReader(b),
		Bucket: &s.bucket,
		Key:    &obj,
	}
	_, err = uploader.Upload(context.Background(), upinfo)
	if err != nil {
		return fmt.Errorf("store accounts in %v: %w", iamFile, err)
	}

	return nil
}
