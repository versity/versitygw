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
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
)

func PublicBucket_default_private_bucket(s *S3Conf) error {
	testName := "PublicBucket_default_private_bucket"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		partNumber := int32(1)

		for _, test := range []PublicBucketTestCase{
			{
				Action: "ListBuckets",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListBuckets(ctx, &s3.ListBucketsInput{})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "HeadBucket",
				Call: func(ctx context.Context) error {
					_, err := s3client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetBucketAcl",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "CreateBucket",
				Call: func(ctx context.Context) error {
					_, err := s3client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: getPtr("new-bucket")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousRequest),
			},
			{
				Action: "PutBucketAcl",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
						Bucket: &bucket,
						ACL:    types.BucketCannedACLPublicRead,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousRequest),
			},
			{
				Action: "DeleteBucket",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutBucketVersioning",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{
						Bucket: &bucket,
						VersioningConfiguration: &types.VersioningConfiguration{
							Status: types.BucketVersioningStatusSuspended,
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetBucketVersioning",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutBucketPolicy",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: &bucket, Policy: getPtr("{}")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetBucketPolicy",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "DeleteBucketPolicy",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucketPolicy(ctx, &s3.DeleteBucketPolicyInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutBucketOwnershipControls",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketOwnershipControls(ctx, &s3.PutBucketOwnershipControlsInput{
						Bucket: &bucket,
						OwnershipControls: &types.OwnershipControls{
							Rules: []types.OwnershipControlsRule{
								{
									ObjectOwnership: types.ObjectOwnershipBucketOwnerEnforced,
								},
							},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousPutBucketOwnership),
			},
			{
				Action: "GetBucketOwnershipControls",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketOwnershipControls(ctx, &s3.GetBucketOwnershipControlsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousGetBucketOwnership),
			},
			{
				Action: "DeleteBucketOwnershipControls",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucketOwnershipControls(ctx, &s3.DeleteBucketOwnershipControlsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousPutBucketOwnership),
			},
			{
				Action: "PutBucketCors",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketCors(ctx, &s3.PutBucketCorsInput{
						Bucket: &bucket,
						CORSConfiguration: &types.CORSConfiguration{
							CORSRules: []types.CORSRule{
								{
									AllowedMethods: []string{http.MethodPut},
									AllowedOrigins: []string{"my origin"},
								},
							},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetBucketCors",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketCors(ctx, &s3.GetBucketCorsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "DeleteBucketCors",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucketCors(ctx, &s3.DeleteBucketCorsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "CreateMultipartUpload",
				Call: func(ctx context.Context) error {
					_, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: &bucket, Key: getPtr("object-key")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousCreateMp),
			},
			{
				Action: "CompleteMultipartUpload",
				Call: func(ctx context.Context) error {
					_, err := s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{Bucket: &bucket, Key: getPtr("object-key"), UploadId: getPtr("upload-id")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "AbortMultipartUpload",
				Call: func(ctx context.Context) error {
					_, err := s3client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{Bucket: &bucket, Key: getPtr("object-key"), UploadId: getPtr("upload-id")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "ListMultipartUploads",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "ListParts",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListParts(ctx, &s3.ListPartsInput{Bucket: &bucket, Key: getPtr("object-key"), UploadId: getPtr("upload-id")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "UploadPart",
				Call: func(ctx context.Context) error {
					_, err := s3client.UploadPart(ctx, &s3.UploadPartInput{
						Bucket:     &bucket,
						Key:        getPtr("object-key"),
						UploadId:   getPtr("upload-id"),
						PartNumber: &partNumber,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "UploadPartCopy",
				Call: func(ctx context.Context) error {
					_, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
						Bucket:     &bucket,
						Key:        getPtr("object-key"),
						UploadId:   getPtr("upload-id"),
						PartNumber: &partNumber,
						CopySource: getPtr("source-bucket/source-key")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "HeadObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: getPtr("object-key")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("object-key")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetObjectAcl",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectAcl(ctx, &s3.GetObjectAclInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetObjectAttributes",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
						ObjectAttributes: []types.ObjectAttributes{
							types.ObjectAttributesEtag,
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "CopyObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.CopyObject(ctx, &s3.CopyObjectInput{
						Bucket:     &bucket,
						Key:        getPtr("copy-key"),
						CopySource: getPtr("bucket-name/object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousCopyObject),
			},
			{
				Action: "ListObjects",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "ListObjectsV2",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "DeleteObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "DeleteObjects",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
						Bucket: &bucket,
						Delete: &types.Delete{
							Objects: []types.ObjectIdentifier{
								{Key: getPtr("object-key")},
							},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutObjectAcl",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectAcl(ctx, &s3.PutObjectAclInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
						ACL:    types.ObjectCannedACLPublicRead,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousRequest),
			},
			{
				Action: "ListObjectVersions",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "RestoreObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.RestoreObject(ctx, &s3.RestoreObjectInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
						RestoreRequest: &types.RestoreRequest{
							Days: aws.Int32(1),
							GlacierJobParameters: &types.GlacierJobParameters{
								Tier: types.TierStandard,
							},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "SelectObjectContent",
				Call: func(ctx context.Context) error {
					_, err := s3client.SelectObjectContent(ctx, &s3.SelectObjectContentInput{
						Bucket:         &bucket,
						Key:            getPtr("object-key"),
						ExpressionType: types.ExpressionTypeSql,
						Expression:     getPtr("SELECT * FROM S3Object"),
						InputSerialization: &types.InputSerialization{
							CSV: &types.CSVInput{},
						},
						OutputSerialization: &types.OutputSerialization{
							CSV: &types.CSVOutput{},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousRequest),
			},
			{
				Action: "GetBucketTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutBucketTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{
						Bucket: &bucket,
						Tagging: &types.Tagging{
							TagSet: []types.Tag{{Key: getPtr("key"), Value: getPtr("value")}},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "DeleteBucketTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucketTagging(ctx, &s3.DeleteBucketTaggingInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetObjectTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutObjectTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
						Tagging: &types.Tagging{
							TagSet: []types.Tag{{Key: getPtr("key"), Value: getPtr("value")}},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "DeleteObjectTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteObjectTagging(ctx, &s3.DeleteObjectTaggingInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutObjectLockConfiguration",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
						Bucket: &bucket,
						ObjectLockConfiguration: &types.ObjectLockConfiguration{
							ObjectLockEnabled: types.ObjectLockEnabledEnabled,
							Rule: &types.ObjectLockRule{
								DefaultRetention: &types.DefaultRetention{
									Days: aws.Int32(1),
									Mode: types.ObjectLockRetentionModeCompliance,
								},
							},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetObjectLockConfiguration",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutObjectRetention",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
						Retention: &types.ObjectLockRetention{
							Mode:            types.ObjectLockRetentionModeCompliance,
							RetainUntilDate: aws.Time(time.Now().Add(24 * time.Hour)),
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetObjectRetention",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutObjectLegalHold",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
						LegalHold: &types.ObjectLockLegalHold{
							Status: types.ObjectLockLegalHoldStatusOn,
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetObjectLegalHold",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectLegalHold(ctx, &s3.GetObjectLegalHoldInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
		} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			err := test.Call(ctx)
			cancel()
			if err == nil && test.ExpectedErr != nil {
				return fmt.Errorf("%v: expected err %v, instead got successful response", test.Action, test.ExpectedErr)
			}
			if err != nil {
				if test.ExpectedErr == nil {
					return fmt.Errorf("%v: expected no error, instead got %v", test.Action, err)
				}

				apiErr, ok := test.ExpectedErr.(s3err.APIError)
				if !ok {
					return fmt.Errorf("invalid error type provided in the test, expected s3err.APIError")
				}

				// The head requests doesn't have request body, thus only the status needs to be checked
				if test.Action == "HeadBucket" || test.Action == "HeadObject" {
					if err := checkSdkApiErr(err, http.StatusText(apiErr.HTTPStatusCode)); err != nil {
						return err
					}
					continue
				}

				if err := checkApiErr(err, apiErr); err != nil {
					return err
				}
			}
		}

		return nil
	}, withAnonymousClient())
}

func PublicBucket_public_bucket_policy(s *S3Conf) error {
	testName := "PublicBucket_public_bucket_policy"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		rootClient := s.GetClient()
		// Grant public access to the bucket for bucket operations
		err := grantPublicBucketPolicy(rootClient, bucket, policyTypeBucket)
		if err != nil {
			return err
		}
		partNumber := int32(1)

		for _, test := range []PublicBucketTestCase{
			{
				Action: "ListBuckets",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListBuckets(ctx, &s3.ListBucketsInput{})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "HeadBucket",
				Call: func(ctx context.Context) error {
					_, err := s3client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "GetBucketAcl",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "CreateBucket",
				Call: func(ctx context.Context) error {
					_, err := s3client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: getPtr("new-bucket")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousRequest),
			},
			{
				Action: "PutBucketAcl",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
						Bucket: &bucket,
						ACL:    types.BucketCannedACLPublicRead,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousRequest),
			},
			{
				Action: "PutBucketPolicy",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: &bucket, Policy: getPtr("{}")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrMethodNotAllowed),
			},
			{
				Action: "GetBucketPolicy",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrMethodNotAllowed),
			},
			{
				Action: "DeleteBucketPolicy",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucketPolicy(ctx, &s3.DeleteBucketPolicyInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrMethodNotAllowed),
			},
			{
				Action: "PutBucketOwnershipControls",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketOwnershipControls(ctx, &s3.PutBucketOwnershipControlsInput{
						Bucket: &bucket,
						OwnershipControls: &types.OwnershipControls{
							Rules: []types.OwnershipControlsRule{
								{
									ObjectOwnership: types.ObjectOwnershipBucketOwnerEnforced,
								},
							},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousPutBucketOwnership),
			},
			{
				Action: "GetBucketOwnershipControls",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketOwnershipControls(ctx, &s3.GetBucketOwnershipControlsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousGetBucketOwnership),
			},
			{
				Action: "DeleteBucketOwnershipControls",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucketOwnershipControls(ctx, &s3.DeleteBucketOwnershipControlsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousPutBucketOwnership),
			},
			{
				Action: "PutBucketCors",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketCors(ctx, &s3.PutBucketCorsInput{
						Bucket: &bucket,
						CORSConfiguration: &types.CORSConfiguration{
							CORSRules: []types.CORSRule{
								{
									AllowedMethods: []string{http.MethodPut},
									AllowedOrigins: []string{"my origin"},
								},
							},
						},
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "GetBucketCors",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketCors(ctx, &s3.GetBucketCorsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "DeleteBucketCors",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucketCors(ctx, &s3.DeleteBucketCorsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "CreateMultipartUpload",
				Call: func(ctx context.Context) error {
					_, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: &bucket, Key: getPtr("object-key")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousCreateMp),
			},
			{
				Action: "CompleteMultipartUpload",
				Call: func(ctx context.Context) error {
					_, err := s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{Bucket: &bucket, Key: getPtr("object-key"), UploadId: getPtr("upload-id")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "AbortMultipartUpload",
				Call: func(ctx context.Context) error {
					_, err := s3client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{Bucket: &bucket, Key: getPtr("object-key"), UploadId: getPtr("upload-id")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "ListMultipartUploads",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "ListParts",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListParts(ctx, &s3.ListPartsInput{Bucket: &bucket, Key: getPtr("object-key"), UploadId: getPtr("upload-id")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "UploadPart",
				Call: func(ctx context.Context) error {
					_, err := s3client.UploadPart(ctx, &s3.UploadPartInput{
						Bucket:     &bucket,
						Key:        getPtr("object-key"),
						UploadId:   getPtr("upload-id"),
						PartNumber: &partNumber,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "UploadPartCopy",
				Call: func(ctx context.Context) error {
					_, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
						Bucket:     &bucket,
						Key:        getPtr("object-key"),
						UploadId:   getPtr("upload-id"),
						PartNumber: &partNumber,
						CopySource: getPtr("source-bucket/source-key")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "HeadObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: getPtr("object-key")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: getPtr("object-key")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetObjectAcl",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectAcl(ctx, &s3.GetObjectAclInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetObjectAttributes",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
						ObjectAttributes: []types.ObjectAttributes{
							types.ObjectAttributesEtag,
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "CopyObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.CopyObject(ctx, &s3.CopyObjectInput{
						Bucket:     &bucket,
						Key:        getPtr("copy-key"),
						CopySource: getPtr("bucket-name/object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousCopyObject),
			},
			{
				Action: "ListObjects",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "ListObjectsV2",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "DeleteObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "DeleteObjects",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
						Bucket: &bucket,
						Delete: &types.Delete{
							Objects: []types.ObjectIdentifier{
								{Key: getPtr("object-key")},
							},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutObjectAcl",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectAcl(ctx, &s3.PutObjectAclInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
						ACL:    types.ObjectCannedACLPublicRead,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousRequest),
			},
			{
				Action: "ListObjectVersions",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "RestoreObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.RestoreObject(ctx, &s3.RestoreObjectInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
						RestoreRequest: &types.RestoreRequest{
							Days: aws.Int32(1),
							GlacierJobParameters: &types.GlacierJobParameters{
								Tier: types.TierStandard,
							},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "SelectObjectContent",
				Call: func(ctx context.Context) error {
					_, err := s3client.SelectObjectContent(ctx, &s3.SelectObjectContentInput{
						Bucket:         &bucket,
						Key:            getPtr("object-key"),
						ExpressionType: types.ExpressionTypeSql,
						Expression:     getPtr("SELECT * FROM S3Object"),
						InputSerialization: &types.InputSerialization{
							CSV: &types.CSVInput{},
						},
						OutputSerialization: &types.OutputSerialization{
							CSV: &types.CSVOutput{},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousRequest),
			},
			{
				Action: "PutBucketTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{
						Bucket: &bucket,
						Tagging: &types.Tagging{
							TagSet: []types.Tag{{Key: getPtr("key"), Value: getPtr("value")}},
						},
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "GetBucketTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "DeleteBucketTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucketTagging(ctx, &s3.DeleteBucketTaggingInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "GetObjectTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutObjectTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
						Tagging: &types.Tagging{
							TagSet: []types.Tag{{Key: getPtr("key"), Value: getPtr("value")}},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "DeleteObjectTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteObjectTagging(ctx, &s3.DeleteObjectTaggingInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutObjectLockConfiguration",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
						Bucket: &bucket,
						ObjectLockConfiguration: &types.ObjectLockConfiguration{
							ObjectLockEnabled: types.ObjectLockEnabledEnabled,
							Rule: &types.ObjectLockRule{
								DefaultRetention: &types.DefaultRetention{
									Days: aws.Int32(1),
									Mode: types.ObjectLockRetentionModeGovernance,
								},
							},
						},
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "GetObjectLockConfiguration",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "PutObjectRetention",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
						Retention: &types.ObjectLockRetention{
							Mode:            types.ObjectLockRetentionModeCompliance,
							RetainUntilDate: aws.Time(time.Now().Add(24 * time.Hour)),
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetObjectRetention",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutObjectLegalHold",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
						LegalHold: &types.ObjectLockLegalHold{
							Status: types.ObjectLockLegalHoldStatusOn,
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetObjectLegalHold",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectLegalHold(ctx, &s3.GetObjectLegalHoldInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "DeleteBucket",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: nil,
			},
		} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			err := test.Call(ctx)
			cancel()
			if err == nil && test.ExpectedErr != nil {
				return fmt.Errorf("%v: expected err %v, instead got successful response", test.Action, test.ExpectedErr)
			}
			if err != nil {
				if test.ExpectedErr == nil {
					return fmt.Errorf("%v: expected no error, instead got %v", test.Action, err)
				}

				apiErr, ok := test.ExpectedErr.(s3err.APIError)
				if !ok {
					return fmt.Errorf("invalid error type provided in the test, expected s3err.APIError")
				}

				// The head requests doesn't have request body, thus only the status needs to be checked
				if test.Action == "HeadBucket" || test.Action == "HeadObject" {
					if err := checkSdkApiErr(err, http.StatusText(apiErr.HTTPStatusCode)); err != nil {
						return err
					}
					continue
				}

				if err := checkApiErr(err, apiErr); err != nil {
					return err
				}
			}
		}

		return nil
	}, withAnonymousClient(), withLock(), withSkipTearDown())
}

func PublicBucket_public_object_policy(s *S3Conf) error {
	testName := "PublicBucket_public_object_policy"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		rootClient := s.GetClient()
		// Grant public access to the bucket for bucket operations
		err := grantPublicBucketPolicy(rootClient, bucket, policyTypeObject)
		if err != nil {
			return err
		}

		mpKey := "my-mp"

		mp1, err := createMp(rootClient, bucket, mpKey)
		if err != nil {
			return err
		}

		mp2, err := createMp(rootClient, bucket, mpKey)
		if err != nil {
			return err
		}

		partNumber := int32(1)
		var partEtag *string

		for _, test := range []PublicBucketTestCase{
			{
				Action: "ListBuckets",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListBuckets(ctx, &s3.ListBucketsInput{})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "HeadBucket",
				Call: func(ctx context.Context) error {
					_, err := s3client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetBucketAcl",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "CreateBucket",
				Call: func(ctx context.Context) error {
					_, err := s3client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: getPtr("new-bucket")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousRequest),
			},
			{
				Action: "PutBucketAcl",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
						Bucket: &bucket,
						ACL:    types.BucketCannedACLPublicRead,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousRequest),
			},
			{
				Action: "PutBucketPolicy",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: &bucket, Policy: getPtr("{}")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetBucketPolicy",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "DeleteBucketPolicy",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucketPolicy(ctx, &s3.DeleteBucketPolicyInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutBucketOwnershipControls",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketOwnershipControls(ctx, &s3.PutBucketOwnershipControlsInput{
						Bucket: &bucket,
						OwnershipControls: &types.OwnershipControls{
							Rules: []types.OwnershipControlsRule{
								{
									ObjectOwnership: types.ObjectOwnershipBucketOwnerEnforced,
								},
							},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousPutBucketOwnership),
			},
			{
				Action: "GetBucketOwnershipControls",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketOwnershipControls(ctx, &s3.GetBucketOwnershipControlsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousGetBucketOwnership),
			},
			{
				Action: "DeleteBucketOwnershipControls",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucketOwnershipControls(ctx, &s3.DeleteBucketOwnershipControlsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousPutBucketOwnership),
			},
			{
				Action: "PutBucketCors",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketCors(ctx, &s3.PutBucketCorsInput{
						Bucket: &bucket,
						CORSConfiguration: &types.CORSConfiguration{
							CORSRules: []types.CORSRule{
								{
									AllowedMethods: []string{http.MethodPut},
									AllowedOrigins: []string{"my origin"},
								},
							},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetBucketCors",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketCors(ctx, &s3.GetBucketCorsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "DeleteBucketCors",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucketCors(ctx, &s3.DeleteBucketCorsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "CreateMultipartUpload",
				Call: func(ctx context.Context) error {
					_, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: &bucket, Key: getPtr("object-key")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousCreateMp),
			},
			{
				Action: "AbortMultipartUpload",
				Call: func(ctx context.Context) error {
					_, err := s3client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
						Bucket:   &bucket,
						Key:      &mpKey,
						UploadId: mp1.UploadId,
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "ListMultipartUploads",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "ListParts",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListParts(ctx, &s3.ListPartsInput{
						Bucket:   &bucket,
						Key:      &mpKey,
						UploadId: mp2.UploadId,
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "UploadPart",
				Call: func(ctx context.Context) error {
					partBuffer := make([]byte, 5*1024*1024)
					rand.Read(partBuffer)
					res, err := s3client.UploadPart(ctx, &s3.UploadPartInput{
						Bucket:     &bucket,
						Key:        &mpKey,
						UploadId:   mp2.UploadId,
						PartNumber: &partNumber,
						Body:       bytes.NewReader(partBuffer),
					})
					if err == nil {
						partEtag = res.ETag
					}
					return err
				},
				ExpectedErr: nil,
			},
			//FIXME: should be fixed after implementing the source bucket public access check
			// return AccessDenied for now
			{
				Action: "UploadPartCopy",
				Call: func(ctx context.Context) error {
					_, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
						Bucket:     &bucket,
						Key:        &mpKey,
						UploadId:   mp2.UploadId,
						PartNumber: &partNumber,
						CopySource: getPtr("source-bucket/source-key")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "CompleteMultipartUpload",
				Call: func(ctx context.Context) error {
					_, err := s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
						Bucket:   &bucket,
						Key:      &mpKey,
						UploadId: mp2.UploadId,
						MultipartUpload: &types.CompletedMultipartUpload{
							Parts: []types.CompletedPart{
								{
									ETag:       partEtag,
									PartNumber: &partNumber,
								},
							},
						},
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "PutObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
						Bucket: &bucket,
						Key:    &mpKey,
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "HeadObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: &mpKey})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "GetObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &mpKey})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "GetObjectAcl",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectAcl(ctx, &s3.GetObjectAclInput{
						Bucket: &bucket,
						Key:    &mpKey,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrNotImplemented),
			},
			{
				Action: "GetObjectAttributes",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
						Bucket: &bucket,
						Key:    &mpKey,
						ObjectAttributes: []types.ObjectAttributes{
							types.ObjectAttributesEtag,
						},
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "CopyObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.CopyObject(ctx, &s3.CopyObjectInput{
						Bucket:     &bucket,
						Key:        getPtr("copy-key"),
						CopySource: getPtr("bucket-name/object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousCopyObject),
			},
			{
				Action: "ListObjects",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "ListObjectsV2",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			// FIXME: should be fixed with https://github.com/versity/versitygw/issues/1327
			{
				Action: "DeleteObjects",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
						Bucket: &bucket,
						Delete: &types.Delete{
							Objects: []types.ObjectIdentifier{
								{Key: getPtr("object-key")},
							},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutObjectAcl",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectAcl(ctx, &s3.PutObjectAclInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
						ACL:    types.ObjectCannedACLPublicRead,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousRequest),
			},
			{
				Action: "ListObjectVersions",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "RestoreObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.RestoreObject(ctx, &s3.RestoreObjectInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
						RestoreRequest: &types.RestoreRequest{
							Days: aws.Int32(1),
							GlacierJobParameters: &types.GlacierJobParameters{
								Tier: types.TierStandard,
							},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrNotImplemented),
			},
			{
				Action: "SelectObjectContent",
				Call: func(ctx context.Context) error {
					_, err := s3client.SelectObjectContent(ctx, &s3.SelectObjectContentInput{
						Bucket:         &bucket,
						Key:            getPtr("object-key"),
						ExpressionType: types.ExpressionTypeSql,
						Expression:     getPtr("SELECT * FROM S3Object"),
						InputSerialization: &types.InputSerialization{
							CSV: &types.CSVInput{},
						},
						OutputSerialization: &types.OutputSerialization{
							CSV: &types.CSVOutput{},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousRequest),
			},
			{
				Action: "PutBucketTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{
						Bucket: &bucket,
						Tagging: &types.Tagging{
							TagSet: []types.Tag{{Key: getPtr("key"), Value: getPtr("value")}},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetBucketTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "DeleteBucketTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucketTagging(ctx, &s3.DeleteBucketTaggingInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutObjectTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
						Bucket: &bucket,
						Key:    &mpKey,
						Tagging: &types.Tagging{
							TagSet: []types.Tag{{Key: getPtr("key"), Value: getPtr("value")}},
						},
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "GetObjectTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
						Bucket: &bucket,
						Key:    &mpKey,
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "DeleteObjectTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteObjectTagging(ctx, &s3.DeleteObjectTaggingInput{
						Bucket: &bucket,
						Key:    &mpKey,
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "PutObjectLockConfiguration",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
						Bucket: &bucket,
						ObjectLockConfiguration: &types.ObjectLockConfiguration{
							ObjectLockEnabled: types.ObjectLockEnabledEnabled,
							Rule: &types.ObjectLockRule{
								DefaultRetention: &types.DefaultRetention{
									Days: aws.Int32(1),
									Mode: types.ObjectLockRetentionModeGovernance,
								},
							},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetObjectLockConfiguration",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutObjectRetention",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
						Bucket: &bucket,
						Key:    &mpKey,
						Retention: &types.ObjectLockRetention{
							Mode:            types.ObjectLockRetentionModeGovernance,
							RetainUntilDate: aws.Time(time.Now().Add(24 * time.Hour)),
						},
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "GetObjectRetention",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
						Bucket: &bucket,
						Key:    &mpKey,
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "PutObjectLegalHold",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
						Bucket: &bucket,
						Key:    &mpKey,
						LegalHold: &types.ObjectLockLegalHold{
							Status: types.ObjectLockLegalHoldStatusOff,
						},
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "GetObjectLegalHold",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectLegalHold(ctx, &s3.GetObjectLegalHoldInput{
						Bucket: &bucket,
						Key:    &mpKey,
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "DeleteObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
						Bucket:                    &bucket,
						Key:                       &mpKey,
						BypassGovernanceRetention: getBoolPtr(true),
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "DeleteBucket",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
		} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			err := test.Call(ctx)
			cancel()
			if err == nil && test.ExpectedErr != nil {
				return fmt.Errorf("%v: expected err %v, instead got successful response", test.Action, test.ExpectedErr)
			}
			if err != nil {
				if test.ExpectedErr == nil {
					return fmt.Errorf("%v: expected no error, instead got %v", test.Action, err)
				}

				apiErr, ok := test.ExpectedErr.(s3err.APIError)
				if !ok {
					return fmt.Errorf("invalid error type provided in the test, expected s3err.APIError")
				}

				// The head requests doesn't have request body, thus only the status needs to be checked
				if test.Action == "HeadBucket" || test.Action == "HeadObject" {
					if err := checkSdkApiErr(err, http.StatusText(apiErr.HTTPStatusCode)); err != nil {
						return err
					}
					continue
				}

				if err := checkApiErr(err, apiErr); err != nil {
					return err
				}
			}
		}

		return nil
	}, withAnonymousClient(), withLock())
}

func PublicBucket_public_acl(s *S3Conf) error {
	testName := "PublicBucket_public_acl"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		partNumber := int32(1)
		var etag *string
		obj := "my-obj"

		// grant public access with acl
		rootClient := s.GetClient()
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := rootClient.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket: &bucket,
			ACL:    types.BucketCannedACLPublicReadWrite,
		})
		cancel()
		if err != nil {
			return err
		}

		mp, err := createMp(rootClient, bucket, obj)
		if err != nil {
			return err
		}

		for _, test := range []PublicBucketTestCase{
			{
				Action: "ListBuckets",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListBuckets(ctx, &s3.ListBucketsInput{})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "HeadBucket",
				Call: func(ctx context.Context) error {
					_, err := s3client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "GetBucketAcl",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "CreateBucket",
				Call: func(ctx context.Context) error {
					_, err := s3client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: getPtr("new-bucket")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousRequest),
			},
			{
				Action: "PutBucketAcl",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
						Bucket: &bucket,
						ACL:    types.BucketCannedACLPublicRead,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousRequest),
			},
			{
				Action: "DeleteBucket",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			//FIXME: implement tests for versioning enabled gateway
			// {
			// 	Action: "PutBucketVersioning",
			// 	Call: func(ctx context.Context) error {
			// 		_, err := s3client.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{
			// 			Bucket: &bucket,
			// 			VersioningConfiguration: &types.VersioningConfiguration{
			// 				Status: types.BucketVersioningStatusSuspended,
			// 			},
			// 		})
			// 		return err
			// 	},
			// 	ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			// },
			// {
			// 	Action: "GetBucketVersioning",
			// 	Call: func(ctx context.Context) error {
			// 		_, err := s3client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: &bucket})
			// 		return err
			// 	},
			// 	ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			// },
			{
				Action: "PutBucketPolicy",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: &bucket, Policy: getPtr("{}")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetBucketPolicy",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "DeleteBucketPolicy",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucketPolicy(ctx, &s3.DeleteBucketPolicyInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutBucketOwnershipControls",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketOwnershipControls(ctx, &s3.PutBucketOwnershipControlsInput{
						Bucket: &bucket,
						OwnershipControls: &types.OwnershipControls{
							Rules: []types.OwnershipControlsRule{
								{
									ObjectOwnership: types.ObjectOwnershipBucketOwnerEnforced,
								},
							},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousPutBucketOwnership),
			},
			{
				Action: "GetBucketOwnershipControls",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketOwnershipControls(ctx, &s3.GetBucketOwnershipControlsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousGetBucketOwnership),
			},
			{
				Action: "DeleteBucketOwnershipControls",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucketOwnershipControls(ctx, &s3.DeleteBucketOwnershipControlsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousPutBucketOwnership),
			},
			{
				Action: "PutBucketCors",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketCors(ctx, &s3.PutBucketCorsInput{
						Bucket: &bucket,
						CORSConfiguration: &types.CORSConfiguration{
							CORSRules: []types.CORSRule{
								{
									AllowedMethods: []string{http.MethodPut},
									AllowedOrigins: []string{"my origin"},
								},
							},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetBucketCors",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketCors(ctx, &s3.GetBucketCorsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "DeleteBucketCors",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucketCors(ctx, &s3.DeleteBucketCorsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "CreateMultipartUpload",
				Call: func(ctx context.Context) error {
					_, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: &bucket, Key: getPtr("object-key")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousCreateMp),
			},
			{
				Action: "AbortMultipartUpload",
				Call: func(ctx context.Context) error {
					_, err := s3client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
						Bucket:   &bucket,
						Key:      &obj,
						UploadId: mp.UploadId,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "ListMultipartUploads",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: &bucket})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "ListParts",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListParts(ctx, &s3.ListPartsInput{Bucket: &bucket, Key: getPtr("object-key"), UploadId: getPtr("upload-id")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "UploadPart",
				Call: func(ctx context.Context) error {
					partBuffer := make([]byte, 5*1024*1024)
					rand.Read(partBuffer)
					res, err := s3client.UploadPart(ctx, &s3.UploadPartInput{
						Bucket:     &bucket,
						Key:        &obj,
						UploadId:   mp.UploadId,
						PartNumber: &partNumber,
						Body:       bytes.NewReader(partBuffer),
					})
					if err == nil {
						etag = res.ETag
					}
					return err
				},
				ExpectedErr: nil,
			},
			//FIXME: should be fixed after implementing the source bucket public access check
			// return AccessDenied for now
			{
				Action: "UploadPartCopy",
				Call: func(ctx context.Context) error {
					_, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
						Bucket:     &bucket,
						Key:        &obj,
						UploadId:   mp.UploadId,
						PartNumber: &partNumber,
						CopySource: getPtr("source-bucket/source-key")})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "CompleteMultipartUpload",
				Call: func(ctx context.Context) error {
					_, err := s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
						Bucket:   &bucket,
						Key:      &obj,
						UploadId: mp.UploadId,
						MultipartUpload: &types.CompletedMultipartUpload{
							Parts: []types.CompletedPart{
								{
									ETag:       etag,
									PartNumber: &partNumber,
								},
							},
						},
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "PutObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
						Bucket: &bucket,
						Key:    &obj,
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "HeadObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: &obj})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "GetObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &obj})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "GetObjectAcl",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectAcl(ctx, &s3.GetObjectAclInput{
						Bucket: &bucket,
						Key:    &obj,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetObjectAttributes",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
						Bucket: &bucket,
						Key:    &obj,
						ObjectAttributes: []types.ObjectAttributes{
							types.ObjectAttributesEtag,
						},
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "CopyObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.CopyObject(ctx, &s3.CopyObjectInput{
						Bucket:     &bucket,
						Key:        getPtr("copy-key"),
						CopySource: getPtr("bucket-name/object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousCopyObject),
			},
			{
				Action: "ListObjects",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "ListObjectsV2",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "DeleteObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
						Bucket: &bucket,
						Key:    &obj,
					})
					return err
				},
				ExpectedErr: nil,
			},
			// FIXME: should be fixed with https://github.com/versity/versitygw/issues/1327
			{
				Action: "DeleteObjects",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
						Bucket: &bucket,
						Delete: &types.Delete{
							Objects: []types.ObjectIdentifier{
								{Key: getPtr("object-key")},
							},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutObjectAcl",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectAcl(ctx, &s3.PutObjectAclInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
						ACL:    types.ObjectCannedACLPublicRead,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousRequest),
			},
			{
				Action: "ListObjectVersions",
				Call: func(ctx context.Context) error {
					_, err := s3client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: nil,
			},
			{
				Action: "RestoreObject",
				Call: func(ctx context.Context) error {
					_, err := s3client.RestoreObject(ctx, &s3.RestoreObjectInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
						RestoreRequest: &types.RestoreRequest{
							Days: aws.Int32(1),
							GlacierJobParameters: &types.GlacierJobParameters{
								Tier: types.TierStandard,
							},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "SelectObjectContent",
				Call: func(ctx context.Context) error {
					_, err := s3client.SelectObjectContent(ctx, &s3.SelectObjectContentInput{
						Bucket:         &bucket,
						Key:            getPtr("object-key"),
						ExpressionType: types.ExpressionTypeSql,
						Expression:     getPtr("SELECT * FROM S3Object"),
						InputSerialization: &types.InputSerialization{
							CSV: &types.CSVInput{},
						},
						OutputSerialization: &types.OutputSerialization{
							CSV: &types.CSVOutput{},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAnonymousRequest),
			},
			{
				Action: "GetBucketTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutBucketTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{
						Bucket: &bucket,
						Tagging: &types.Tagging{
							TagSet: []types.Tag{{Key: getPtr("key"), Value: getPtr("value")}},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "DeleteBucketTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteBucketTagging(ctx, &s3.DeleteBucketTaggingInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetObjectTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutObjectTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
						Tagging: &types.Tagging{
							TagSet: []types.Tag{{Key: getPtr("key"), Value: getPtr("value")}},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "DeleteObjectTagging",
				Call: func(ctx context.Context) error {
					_, err := s3client.DeleteObjectTagging(ctx, &s3.DeleteObjectTaggingInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutObjectLockConfiguration",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
						Bucket: &bucket,
						ObjectLockConfiguration: &types.ObjectLockConfiguration{
							ObjectLockEnabled: types.ObjectLockEnabledEnabled,
							Rule: &types.ObjectLockRule{
								DefaultRetention: &types.DefaultRetention{
									Days: aws.Int32(1),
									Mode: types.ObjectLockRetentionModeCompliance,
								},
							},
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetObjectLockConfiguration",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{
						Bucket: &bucket,
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutObjectRetention",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
						Retention: &types.ObjectLockRetention{
							Mode:            types.ObjectLockRetentionModeCompliance,
							RetainUntilDate: aws.Time(time.Now().Add(24 * time.Hour)),
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetObjectRetention",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "PutObjectLegalHold",
				Call: func(ctx context.Context) error {
					_, err := s3client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
						LegalHold: &types.ObjectLockLegalHold{
							Status: types.ObjectLockLegalHoldStatusOn,
						},
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
			{
				Action: "GetObjectLegalHold",
				Call: func(ctx context.Context) error {
					_, err := s3client.GetObjectLegalHold(ctx, &s3.GetObjectLegalHoldInput{
						Bucket: &bucket,
						Key:    getPtr("object-key"),
					})
					return err
				},
				ExpectedErr: s3err.GetAPIError(s3err.ErrAccessDenied),
			},
		} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			err := test.Call(ctx)
			cancel()
			if err == nil && test.ExpectedErr != nil {
				return fmt.Errorf("%v: expected err %v, instead got successful response", test.Action, test.ExpectedErr)
			}
			if err != nil {
				if test.ExpectedErr == nil {
					return fmt.Errorf("%v: expected no error, instead got %v", test.Action, err)
				}

				apiErr, ok := test.ExpectedErr.(s3err.APIError)
				if !ok {
					return fmt.Errorf("invalid error type provided in the test, expected s3err.APIError")
				}

				// The head requests doesn't have request body, thus only the status needs to be checked
				if test.Action == "HeadBucket" || test.Action == "HeadObject" {
					if err := checkSdkApiErr(err, http.StatusText(apiErr.HTTPStatusCode)); err != nil {
						return fmt.Errorf("%v: %w", test.Action, err)
					}
					continue
				}

				if err := checkApiErr(err, apiErr); err != nil {
					return fmt.Errorf("%v: %w", test.Action, err)
				}
			}
		}

		return nil
	}, withAnonymousClient(), withOwnership(types.ObjectOwnershipBucketOwnerPreferred))
}

func PublicBucket_signed_streaming_payload(s *S3Conf) error {
	testName := "PublicBucket_signed_streaming_payload"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := grantPublicBucketPolicy(s3client, bucket, policyTypeFull)
		if err != nil {
			return err
		}

		req, err := http.NewRequest(http.MethodPut, fmt.Sprintf("%s/%s/%s", s.endpoint, bucket, "obj"), nil)
		if err != nil {
			return err
		}

		req.Header.Add("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrUnsupportedAnonymousSignedStreaming))
	})
}

func PublicBucket_incorrect_sha256_hash(s *S3Conf) error {
	testName := "PublicBucket_incorrect_sha256_hash"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := grantPublicBucketPolicy(s3client, bucket, policyTypeFull)
		if err != nil {
			return err
		}

		req, err := http.NewRequest(http.MethodPut, fmt.Sprintf("%s/%s/%s", s.endpoint, bucket, "obj"), nil)
		if err != nil {
			return err
		}

		// in anonymous requests the sha256 hash validity is not checked
		// so for any invalid values, the server calculates the hash
		// and compares with the provided one
		req.Header.Add("x-amz-content-sha256", "incorrect_hash")

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrContentSHA256Mismatch))
	})
}
