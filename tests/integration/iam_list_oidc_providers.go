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
	"context"
	"errors"
	"fmt"

	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

func IAMListOpenIDConnectProviders_success(s *S3Conf) error {
	testName := "IAMListOpenIDConnectProviders_success"
	return iamActionHandler(s, testName, func(client *iam.Client) (err error) {
		before, err := listIAMOIDCProviders(client)
		if err != nil {
			return err
		}
		if requestID, ok := awsmiddleware.GetRequestIDMetadata(before.ResultMetadata); !ok || requestID == "" {
			return fmt.Errorf("expected ListOpenIDConnectProviders response request id")
		}
		baseline := oidcProviderArnSet(before)

		arnA, err := createTestOIDCProvider(client)
		if err != nil {
			return err
		}

		arnB, err := createTestOIDCProvider(client)
		if err != nil {
			delErr := deleteOIDCProvider(client, arnA)
			return errors.Join(err, delErr)
		}

		cleanup := func(arns ...string) error {
			var errs error
			for _, arn := range arns {
				if delErr := deleteOIDCProvider(client, arn); delErr != nil {
					errs = errors.Join(errs, delErr)
				}
			}
			return errs
		}

		afterCreate, err := listIAMOIDCProviders(client)
		if err != nil {
			return errors.Join(err, cleanup(arnA, arnB))
		}
		createdSet := oidcProviderArnSet(afterCreate)
		if _, ok := createdSet[arnA]; !ok {
			return errors.Join(fmt.Errorf("expected %q in ListOpenIDConnectProviders after create", arnA), cleanup(arnA, arnB))
		}
		if _, ok := createdSet[arnB]; !ok {
			return errors.Join(fmt.Errorf("expected %q in ListOpenIDConnectProviders after create", arnB), cleanup(arnA, arnB))
		}
		for arn := range baseline {
			if _, ok := createdSet[arn]; !ok {
				return errors.Join(fmt.Errorf("expected pre-existing %q to still be listed", arn), cleanup(arnA, arnB))
			}
		}

		if err := deleteOIDCProvider(client, arnA); err != nil {
			return errors.Join(err, cleanup(arnB))
		}

		afterDeleteA, err := listIAMOIDCProviders(client)
		if err != nil {
			return errors.Join(err, cleanup(arnB))
		}
		afterDeleteASet := oidcProviderArnSet(afterDeleteA)
		if _, ok := afterDeleteASet[arnA]; ok {
			return errors.Join(fmt.Errorf("expected %q to be absent after delete", arnA), cleanup(arnB))
		}
		if _, ok := afterDeleteASet[arnB]; !ok {
			return errors.Join(fmt.Errorf("expected %q still listed", arnB), cleanup(arnB))
		}

		if err := deleteOIDCProvider(client, arnB); err != nil {
			return err
		}

		afterDeleteB, err := listIAMOIDCProviders(client)
		if err != nil {
			return err
		}
		if _, ok := oidcProviderArnSet(afterDeleteB)[arnB]; ok {
			return fmt.Errorf("expected %q to be absent after delete", arnB)
		}

		return nil
	})
}

func listIAMOIDCProviders(client *iam.Client) (*iam.ListOpenIDConnectProvidersOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	return client.ListOpenIDConnectProviders(ctx, &iam.ListOpenIDConnectProvidersInput{})
}

func oidcProviderArnSet(out *iam.ListOpenIDConnectProvidersOutput) map[string]struct{} {
	set := make(map[string]struct{}, len(out.OpenIDConnectProviderList))
	for _, p := range out.OpenIDConnectProviderList {
		if p.Arn != nil {
			set[*p.Arn] = struct{}{}
		}
	}
	return set
}
