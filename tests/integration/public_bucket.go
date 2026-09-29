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
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
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

func PublicBucket_policy_deny_overrides_public_acl(s *S3Conf) error {
	testName := "PublicBucket_policy_deny_overrides_public_acl"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		rootClient := s.GetClient()
		publicKey := "public/object"
		privateKey := "private/secret"

		for _, key := range []string{publicKey, privateKey} {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := rootClient.PutObject(ctx, &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    &key,
				Body:   bytes.NewReader([]byte(key)),
			})
			cancel()
			if err != nil {
				return err
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := rootClient.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket: &bucket,
			ACL:    types.BucketCannedACLPublicRead,
		})
		cancel()
		if err != nil {
			return err
		}

		policy := genPolicyDoc("Deny", `"*"`, `"s3:GetObject"`, fmt.Sprintf(`"arn:aws:s3:::%s/private/*"`, bucket))
		if err := putBucketPolicy(rootClient, bucket, policy); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &publicKey,
		})
		cancel()
		if err != nil {
			return fmt.Errorf("expected public-read ACL to allow non-denied object: %w", err)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &privateKey,
		})
		cancel()
		return checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied))
	}, withAnonymousClient(), withOwnership(types.ObjectOwnershipBucketOwnerPreferred))
}

// PublicBucket_post_object_policy covers anonymous POST uploads to a bucket
// whose policy grants public s3:PutObject on a key prefix. The POST is
// addressed to the bucket, but it is authorized against the ARN of the
// object its key field names, as PutObject is: a key under uploads/ is
// allowed and any other denied.
func PublicBucket_post_object_policy(s *S3Conf) error {
	testName := "PublicBucket_post_object_policy"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		if err := putBucketPolicyDoc(s, bucket, bucketStatement{
			Effect:    "Allow",
			Principal: "*",
			Action:    "s3:PutObject",
			Resource:  fmt.Sprintf("arn:aws:s3:::%s/uploads/*", bucket),
		}); err != nil {
			return err
		}

		allowedKey := "uploads/my-obj"
		resp, err := sendAnonymousPostObject(s, bucket, allowedKey, []byte("data"))
		if err != nil {
			return err
		}
		if err := checkPostObjectSuccess(resp); err != nil {
			return fmt.Errorf("POST %s: %w", allowedKey, err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &allowedKey,
		})
		cancel()
		if err != nil {
			return fmt.Errorf("expected %s to be uploaded: %w", allowedKey, err)
		}

		resp, err = sendAnonymousPostObject(s, bucket, "private/my-obj", []byte("data"))
		if err != nil {
			return err
		}
		return checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrAccessDenied))
	})
}

// PublicBucket_post_object_policy_deny_overrides_public_acl covers a public
// Deny scoped to a key prefix on a bucket whose ACL is public-read-write:
// an anonymous POST to a key under private/ matches the Deny on its object
// ARN and is refused, rather than falling through to the ACL's public
// write grant, which still allows a POST to any other key.
func PublicBucket_post_object_policy_deny_overrides_public_acl(s *S3Conf) error {
	testName := "PublicBucket_post_object_policy_deny_overrides_public_acl"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket: &bucket,
			ACL:    types.BucketCannedACLPublicReadWrite,
		})
		cancel()
		if err != nil {
			return err
		}

		if err := putBucketPolicyDoc(s, bucket, bucketStatement{
			Effect:    "Deny",
			Principal: "*",
			Action:    "s3:PutObject",
			Resource:  fmt.Sprintf("arn:aws:s3:::%s/private/*", bucket),
		}); err != nil {
			return err
		}

		allowedKey := "public/my-obj"
		resp, err := sendAnonymousPostObject(s, bucket, allowedKey, []byte("data"))
		if err != nil {
			return err
		}
		if err := checkPostObjectSuccess(resp); err != nil {
			return fmt.Errorf("POST %s: %w", allowedKey, err)
		}

		resp, err = sendAnonymousPostObject(s, bucket, "private/my-obj", []byte("data"))
		if err != nil {
			return err
		}
		return checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrAccessDenied))
	}, withOwnership(types.ObjectOwnershipBucketOwnerPreferred))
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
		const incorrectPayloadHash = "incorrect_hash"
		req.Header.Add("x-amz-content-sha256", incorrectPayloadHash)

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}

		return checkHTTPResponseApiErr(resp, s3err.GetContentSHA256MismatchErr(incorrectPayloadHash, emptySHA256Hash))
	})
}

// PublicBucket_put_object_tagging covers anonymous PutObject uploads that
// tag the object they create. Tagging it takes s3:PutObjectTagging on top of
// s3:PutObject: a policy granting public s3:PutObject alone denies the
// tagged upload but not an untagged one, granting both allows it, and an
// explicit public Deny of s3:PutObjectTagging denies it again.
func PublicBucket_put_object_tagging(s *S3Conf) error {
	testName := "PublicBucket_put_object_tagging"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objectArn := fmt.Sprintf("arn:aws:s3:::%s/*", bucket)
		if err := putBucketPolicyDoc(s, bucket, bucketStatement{
			Effect:    "Allow",
			Principal: "*",
			Action:    "s3:PutObject",
			Resource:  objectArn,
		}); err != nil {
			return err
		}

		key := "my-obj"
		put := func(tagging *string) error {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
				Bucket:  &bucket,
				Key:     &key,
				Tagging: tagging,
			})
			cancel()
			return err
		}

		err := put(getPtr("env=test"))
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return fmt.Errorf("tagged PutObject with public s3:PutObject only: %w", err)
		}
		if err := put(nil); err != nil {
			return fmt.Errorf("untagged PutObject with public s3:PutObject only: %w", err)
		}

		allowBoth := bucketStatement{
			Effect:    "Allow",
			Principal: "*",
			Action:    []string{"s3:PutObject", "s3:PutObjectTagging"},
			Resource:  objectArn,
		}
		if err := putBucketPolicyDoc(s, bucket, allowBoth); err != nil {
			return err
		}

		if err := put(getPtr("env=test")); err != nil {
			return fmt.Errorf("tagged PutObject with public s3:PutObject and s3:PutObjectTagging: %w", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		tagging, err := s.GetClient().GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
			Bucket: &bucket,
			Key:    &key,
		})
		cancel()
		if err != nil {
			return err
		}

		expectedTagging := []types.Tag{{Key: getPtr("env"), Value: getPtr("test")}}
		if !areTagsSame(expectedTagging, tagging.TagSet) {
			return fmt.Errorf("expected %v tagging, instead got %v", expectedTagging, tagging.TagSet)
		}

		if err := putBucketPolicyDoc(s, bucket, allowBoth, bucketStatement{
			Effect:    "Deny",
			Principal: "*",
			Action:    "s3:PutObjectTagging",
			Resource:  objectArn,
		}); err != nil {
			return err
		}

		err = put(getPtr("env=test"))
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return fmt.Errorf("tagged PutObject with s3:PutObjectTagging publicly denied: %w", err)
		}

		return nil
	}, withAnonymousClient())
}

// PublicBucket_put_object_tagging_public_acl covers anonymous tagged
// PutObject uploads to a bucket whose ACL is public-read-write. The ACL's
// write grant covers s3:PutObject alone, so a tagged upload is denied until
// the bucket policy publicly grants s3:PutObjectTagging, and allowed once it
// does: each action is granted on its own, by the policy or the ACL.
func PublicBucket_put_object_tagging_public_acl(s *S3Conf) error {
	testName := "PublicBucket_put_object_tagging_public_acl"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s.GetClient().PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket: &bucket,
			ACL:    types.BucketCannedACLPublicReadWrite,
		})
		cancel()
		if err != nil {
			return err
		}

		key := "my-obj"
		put := func(tagging *string) error {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := s3client.PutObject(ctx, &s3.PutObjectInput{
				Bucket:  &bucket,
				Key:     &key,
				Tagging: tagging,
			})
			cancel()
			return err
		}

		if err := put(nil); err != nil {
			return fmt.Errorf("untagged PutObject with public-read-write ACL: %w", err)
		}
		err = put(getPtr("env=test"))
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return fmt.Errorf("tagged PutObject with public-read-write ACL only: %w", err)
		}

		if err := putBucketPolicyDoc(s, bucket, bucketStatement{
			Effect:    "Allow",
			Principal: "*",
			Action:    "s3:PutObjectTagging",
			Resource:  fmt.Sprintf("arn:aws:s3:::%s/*", bucket),
		}); err != nil {
			return err
		}

		if err := put(getPtr("env=test")); err != nil {
			return fmt.Errorf("tagged PutObject with public-read-write ACL and public s3:PutObjectTagging: %w", err)
		}

		return nil
	}, withAnonymousClient(), withOwnership(types.ObjectOwnershipBucketOwnerPreferred))
}

// PublicBucket_put_object_lock covers anonymous PutObject uploads carrying
// Object Lock parameters, which only a signed upload may set. The bucket
// publicly grants the upload and its lock actions alike, and still a legal
// hold of either status or a retention is refused: as an invalid argument
// when the upload carries an integrity check of its body, and for the
// missing integrity check when it doesn't.
func PublicBucket_put_object_lock(s *S3Conf) error {
	testName := "PublicBucket_put_object_lock"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		if err := putBucketPolicyDoc(s, bucket, bucketStatement{
			Effect:    "Allow",
			Principal: "*",
			Action:    []string{"s3:PutObject", "s3:PutObjectLegalHold", "s3:PutObjectRetention"},
			Resource:  fmt.Sprintf("arn:aws:s3:::%s/*", bucket),
		}); err != nil {
			return err
		}

		retainUntilDate := time.Now().Add(time.Hour)

		for _, lock := range []struct {
			name  string
			input s3.PutObjectInput
		}{
			{
				name:  "legal hold ON",
				input: s3.PutObjectInput{ObjectLockLegalHoldStatus: types.ObjectLockLegalHoldStatusOn},
			},
			{
				name:  "legal hold OFF",
				input: s3.PutObjectInput{ObjectLockLegalHoldStatus: types.ObjectLockLegalHoldStatusOff},
			},
			{
				name: "retention",
				input: s3.PutObjectInput{
					ObjectLockMode:            types.ObjectLockModeGovernance,
					ObjectLockRetainUntilDate: &retainUntilDate,
				},
			},
		} {
			for _, upload := range []struct {
				name     string
				opts     []putObjectOpt
				expected s3err.S3Error
			}{
				{
					name:     "without an integrity check",
					expected: s3err.GetAPIError(s3err.ErrObjectLockChecksumRequired),
				},
				{
					name:     "with a checksum",
					opts:     []putObjectOpt{withPutObjectChecksumAlgo(types.ChecksumAlgorithmCrc32)},
					expected: s3err.GetInvalidArgumentErr(s3err.InvalidArgAnonymousObjectLock, ""),
				},
			} {
				input := lock.input
				input.Bucket = &bucket
				input.Key = getPtr("my-obj")
				_, err := putObjectWithData(10, &input, s3client, upload.opts...)
				if err := checkApiErr(err, upload.expected); err != nil {
					return fmt.Errorf("%s %s: %w", lock.name, upload.name, err)
				}
			}
		}

		return nil
	}, withAnonymousClient(), withLock())
}

// PublicBucket_put_object_lock_missing_bucket_lock covers anonymous PutObject
// uploads carrying Object Lock parameters to a bucket without Object Lock,
// which rejects the parameters themselves, as it does for a signed upload.
func PublicBucket_put_object_lock_missing_bucket_lock(s *S3Conf) error {
	testName := "PublicBucket_put_object_lock_missing_bucket_lock"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		if err := putBucketPolicyDoc(s, bucket, bucketStatement{
			Effect:    "Allow",
			Principal: "*",
			Action:    []string{"s3:PutObject", "s3:PutObjectLegalHold", "s3:PutObjectRetention"},
			Resource:  fmt.Sprintf("arn:aws:s3:::%s/*", bucket),
		}); err != nil {
			return err
		}

		retainUntilDate := time.Now().Add(time.Hour)
		for _, lock := range []struct {
			name  string
			input s3.PutObjectInput
		}{
			{
				name:  "legal hold ON",
				input: s3.PutObjectInput{ObjectLockLegalHoldStatus: types.ObjectLockLegalHoldStatusOn},
			},
			{
				name:  "legal hold OFF",
				input: s3.PutObjectInput{ObjectLockLegalHoldStatus: types.ObjectLockLegalHoldStatusOff},
			},
			{
				name: "retention",
				input: s3.PutObjectInput{
					ObjectLockMode:            types.ObjectLockModeGovernance,
					ObjectLockRetainUntilDate: &retainUntilDate,
				},
			},
		} {
			input := lock.input
			input.Bucket = &bucket
			input.Key = getPtr("my-obj")
			_, err := putObjectWithData(10, &input, s3client)
			if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrMissingObjectLockConfigurationNoSpaces)); err != nil {
				return fmt.Errorf("%s: %w", lock.name, err)
			}
		}

		return nil
	}, withAnonymousClient())
}

// PublicBucket_put_object_default_retention covers anonymous uploads to a
// bucket with a default retention rule, which gives every object written to
// it Object Lock parameters. Only a signed PutObject may lock the object it
// writes, so even a plain anonymous one is refused, and before any
// authorization: the bucket grants no public access yet.
func PublicBucket_put_object_default_retention(s *S3Conf) error {
	testName := "PublicBucket_put_object_default_retention"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s.GetClient().PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
			Bucket: &bucket,
			ObjectLockConfiguration: &types.ObjectLockConfiguration{
				ObjectLockEnabled: types.ObjectLockEnabledEnabled,
				Rule: &types.ObjectLockRule{
					DefaultRetention: &types.DefaultRetention{
						Mode: types.ObjectLockRetentionModeGovernance,
						Days: getPtr(int32(1)),
					},
				},
			},
		})
		cancel()
		if err != nil {
			return err
		}

		for _, upload := range []struct {
			name     string
			opts     []putObjectOpt
			expected s3err.S3Error
		}{
			{
				name:     "without an integrity check",
				expected: s3err.GetAPIError(s3err.ErrObjectLockChecksumRequired),
			},
			{
				name:     "with a checksum",
				opts:     []putObjectOpt{withPutObjectChecksumAlgo(types.ChecksumAlgorithmCrc32)},
				expected: s3err.GetInvalidArgumentErr(s3err.InvalidArgAnonymousObjectLock, ""),
			},
		} {
			_, err := putObjectWithData(10, &s3.PutObjectInput{
				Bucket: &bucket,
				Key:    getPtr("my-obj"),
			}, s3client, upload.opts...)
			if err := checkApiErr(err, upload.expected); err != nil {
				return fmt.Errorf("PutObject %s: %w", upload.name, err)
			}
		}

		if err := putBucketPolicyDoc(s, bucket, bucketStatement{
			Effect:    "Allow",
			Principal: "*",
			Action:    "s3:PutObject",
			Resource:  fmt.Sprintf("arn:aws:s3:::%s/*", bucket),
		}); err != nil {
			return err
		}

		resp, err := sendAnonymousPostObject(s, bucket, "my-obj", []byte("data"))
		if err != nil {
			return err
		}
		if err := checkPostObjectSuccess(resp); err != nil {
			return fmt.Errorf("POST: %w", err)
		}

		return nil
	}, withAnonymousClient(), withLock())
}

// PublicBucket_upload_part_object_lock covers anonymous parts of a multipart
// upload created with a legal hold. Unlike an anonymous PutObject, an
// anonymous part may go into an upload with Object Lock parameters, but it
// needs an integrity check of its body like any other part of one.
func PublicBucket_upload_part_object_lock(s *S3Conf) error {
	testName := "PublicBucket_upload_part_object_lock"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		rootClient := s.GetClient()
		obj := "my-obj"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		mp, err := rootClient.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket:                    &bucket,
			Key:                       &obj,
			ObjectLockLegalHoldStatus: types.ObjectLockLegalHoldStatusOn,
		})
		cancel()
		if err != nil {
			return err
		}

		if err := putBucketPolicyDoc(s, bucket, bucketStatement{
			Effect:    "Allow",
			Principal: "*",
			Action:    "s3:PutObject",
			Resource:  fmt.Sprintf("arn:aws:s3:::%s/*", bucket),
		}); err != nil {
			return err
		}

		data := []byte("data")
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:     &bucket,
			Key:        &obj,
			UploadId:   mp.UploadId,
			PartNumber: getPtr(int32(1)),
			Body:       bytes.NewReader(data),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLockPartChecksumRequired)); err != nil {
			return fmt.Errorf("part without an integrity check: %w", err)
		}

		md5sum := md5.Sum(data)
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:     &bucket,
			Key:        &obj,
			UploadId:   mp.UploadId,
			PartNumber: getPtr(int32(1)),
			Body:       bytes.NewReader(data),
			ContentMD5: getPtr(base64.StdEncoding.EncodeToString(md5sum[:])),
		})
		cancel()
		if err != nil {
			return fmt.Errorf("part with Content-MD5: %w", err)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = rootClient.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
		})
		cancel()
		return err
	}, withAnonymousClient(), withLock())
}

// PublicBucket_post_object_tagging covers anonymous POST uploads that tag
// the object they create. The public grant has to cover
// s3:PutObjectTagging too: under a policy granting public s3:PutObject
// alone, a tagged upload is denied while one with an empty tag set, which
// tags nothing, is not, and the tagged upload succeeds once the policy
// grants both actions.
func PublicBucket_post_object_tagging(s *S3Conf) error {
	testName := "PublicBucket_post_object_tagging"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		if err := putBucketPolicyDoc(s, bucket, bucketStatement{
			Effect:    "Allow",
			Principal: "*",
			Action:    "s3:PutObject",
			Resource:  fmt.Sprintf("arn:aws:s3:::%s/*", bucket),
		}); err != nil {
			return err
		}

		key := "my-obj"
		post := func(taggingXML string) (*http.Response, error) {
			return sendPostObject(PostRequestConfig{
				bucket:      bucket,
				key:         key,
				s3Conf:      s,
				fileContent: []byte("data"),
				extraFields: map[string]string{
					"x-amz-algorithm":  "",
					"x-amz-credential": "",
					"x-amz-date":       "",
					"policy":           "",
					"x-amz-signature":  "",
					"tagging":          taggingXML,
				},
			})
		}
		taggingXML := `<Tagging><TagSet><Tag><Key>env</Key><Value>test</Value></Tag></TagSet></Tagging>`

		resp, err := post(taggingXML)
		if err != nil {
			return err
		}
		if err := checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return fmt.Errorf("tagged POST with public s3:PutObject only: %w", err)
		}

		resp, err = post(`<Tagging><TagSet></TagSet></Tagging>`)
		if err != nil {
			return err
		}
		if err := checkPostObjectSuccess(resp); err != nil {
			return fmt.Errorf("POST with an empty tag set: %w", err)
		}

		if err := putBucketPolicyDoc(s, bucket, bucketStatement{
			Effect:    "Allow",
			Principal: "*",
			Action:    []string{"s3:PutObject", "s3:PutObjectTagging"},
			Resource:  fmt.Sprintf("arn:aws:s3:::%s/*", bucket),
		}); err != nil {
			return err
		}

		resp, err = post(taggingXML)
		if err != nil {
			return err
		}
		if err := checkPostObjectSuccess(resp); err != nil {
			return fmt.Errorf("tagged POST with public s3:PutObject and s3:PutObjectTagging: %w", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		tagging, err := s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
			Bucket: &bucket,
			Key:    &key,
		})
		cancel()
		if err != nil {
			return err
		}

		expectedTagging := []types.Tag{{Key: getPtr("env"), Value: getPtr("test")}}
		if !areTagsSame(expectedTagging, tagging.TagSet) {
			return fmt.Errorf("expected %v tagging, instead got %v", expectedTagging, tagging.TagSet)
		}

		return nil
	})
}

// PublicBucket_object_version_actions covers anonymous requests naming an
// object version, each authorized as the version's own action:
// s3:GetObjectVersion for GetObject and HeadObject, the version tagging
// actions for the tagging APIs and s3:DeleteObjectVersion for DeleteObject.
// A policy granting the plain actions allows only the requests naming no
// version, and one granting the version actions only those that do.
func PublicBucket_object_version_actions(s *S3Conf) error {
	testName := "PublicBucket_object_version_actions"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		key := "my-obj"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s.GetClient().PutObject(ctx, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &key,
		})
		cancel()
		if err != nil {
			return err
		}

		// DeleteObject goes last: the plain delete the first policy allows
		// only adds a delete marker, which leaves the version itself for the
		// second policy's requests.
		requests := []struct {
			action string
			call   func(ctx context.Context, versionId *string) error
		}{
			{"GetObject", func(ctx context.Context, versionId *string) error {
				_, err := s3client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &key, VersionId: versionId})
				return err
			}},
			{"HeadObject", func(ctx context.Context, versionId *string) error {
				_, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: &key, VersionId: versionId})
				return err
			}},
			{"GetObjectTagging", func(ctx context.Context, versionId *string) error {
				_, err := s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{Bucket: &bucket, Key: &key, VersionId: versionId})
				return err
			}},
			{"PutObjectTagging", func(ctx context.Context, versionId *string) error {
				_, err := s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
					Bucket:    &bucket,
					Key:       &key,
					VersionId: versionId,
					Tagging: &types.Tagging{
						TagSet: []types.Tag{{Key: getPtr("env"), Value: getPtr("test")}},
					},
				})
				return err
			}},
			{"DeleteObjectTagging", func(ctx context.Context, versionId *string) error {
				_, err := s3client.DeleteObjectTagging(ctx, &s3.DeleteObjectTaggingInput{Bucket: &bucket, Key: &key, VersionId: versionId})
				return err
			}},
			{"DeleteObject", func(ctx context.Context, versionId *string) error {
				_, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: &key, VersionId: versionId})
				return err
			}},
		}

		for _, policy := range []struct {
			actions        []string
			allowVersioned bool
		}{
			{
				actions:        []string{"s3:GetObject", "s3:GetObjectTagging", "s3:PutObjectTagging", "s3:DeleteObjectTagging", "s3:DeleteObject"},
				allowVersioned: false,
			},
			{
				actions:        []string{"s3:GetObjectVersion", "s3:GetObjectVersionTagging", "s3:PutObjectVersionTagging", "s3:DeleteObjectVersionTagging", "s3:DeleteObjectVersion"},
				allowVersioned: true,
			},
		} {
			if err := putBucketPolicyDoc(s, bucket, bucketStatement{
				Effect:    "Allow",
				Principal: "*",
				Action:    policy.actions,
				Resource:  fmt.Sprintf("arn:aws:s3:::%s/*", bucket),
			}); err != nil {
				return err
			}

			for _, req := range requests {
				for _, versionId := range []*string{out.VersionId, nil} {
					ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
					err := req.call(ctx, versionId)
					cancel()

					name := req.action
					if versionId != nil {
						name += " with versionId"
					}
					if (versionId != nil) == policy.allowVersioned {
						if err != nil {
							return fmt.Errorf("%s with public %v: expected success, instead got %w", name, policy.actions, err)
						}
						continue
					}

					if err == nil {
						return fmt.Errorf("%s with public %v: expected AccessDenied, instead got nil", name, policy.actions)
					}
					// A HEAD response has no body, so only its status is checked
					if req.action == "HeadObject" {
						err = checkSdkApiErr(err, http.StatusText(http.StatusForbidden))
					} else {
						err = checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied))
					}
					if err != nil {
						return fmt.Errorf("%s with public %v: %w", name, policy.actions, err)
					}
				}
			}
		}

		return nil
	}, withAnonymousClient(), withVersioning(types.BucketVersioningStatusEnabled))
}

// PublicBucket_object_version_actions_public_acl covers anonymous requests
// naming an object version on a bucket whose ACL is public-read-write. The
// ACL's READ grant covers s3:GetObjectVersion as it does s3:GetObject, so
// versioned reads are allowed, but its WRITE grant never gives an anonymous
// requester s3:DeleteObjectVersion: a versioned delete is denied, while a
// plain one, which only adds a delete marker, is allowed.
func PublicBucket_object_version_actions_public_acl(s *S3Conf) error {
	testName := "PublicBucket_object_version_actions_public_acl"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
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

		key := "my-obj"
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err := rootClient.PutObject(ctx, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &key,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket:    &bucket,
			Key:       &key,
			VersionId: out.VersionId,
		})
		cancel()
		if err != nil {
			return fmt.Errorf("GetObject with versionId: %w", err)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket:    &bucket,
			Key:       &key,
			VersionId: out.VersionId,
		})
		cancel()
		if err != nil {
			return fmt.Errorf("HeadObject with versionId: %w", err)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket:    &bucket,
			Key:       &key,
			VersionId: out.VersionId,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return fmt.Errorf("DeleteObject with versionId: %w", err)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    &key,
		})
		cancel()
		if err != nil {
			return fmt.Errorf("DeleteObject: %w", err)
		}

		return nil
	}, withAnonymousClient(), withOwnership(types.ObjectOwnershipBucketOwnerPreferred), withVersioning(types.BucketVersioningStatusEnabled))
}
