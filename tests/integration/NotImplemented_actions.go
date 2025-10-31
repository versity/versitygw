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

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
)

func PutBucketAnalyticsConfiguration_not_implemented(s *S3Conf) error {
	testName := "PutBucketAnalyticsConfiguration_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketAnalyticsConfiguration(ctx,
			&s3.PutBucketAnalyticsConfigurationInput{
				Bucket: &bucket,
				Id:     getPtr("uniquie_id"),
				AnalyticsConfiguration: &types.AnalyticsConfiguration{
					Id: getPtr("my-id"),
					StorageClassAnalysis: &types.StorageClassAnalysis{
						DataExport: &types.StorageClassAnalysisDataExport{
							OutputSchemaVersion: types.StorageClassAnalysisSchemaVersionV1,
							Destination: &types.AnalyticsExportDestination{
								S3BucketDestination: &types.AnalyticsS3BucketDestination{
									Bucket: &bucket,
									Format: types.AnalyticsS3ExportFileFormatCsv,
								},
							},
						},
					},
				},
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func GetBucketAnalyticsConfiguration_not_implemented(s *S3Conf) error {
	testName := "GetBucketAnalyticsConfiguration_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetBucketAnalyticsConfiguration(ctx,
			&s3.GetBucketAnalyticsConfigurationInput{
				Bucket: &bucket,
				Id:     getPtr("uniquie_id"),
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func ListBucketAnalyticsConfiguration_not_implemented(s *S3Conf) error {
	testName := "ListBucketAnalyticsConfiguration_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.ListBucketAnalyticsConfigurations(ctx,
			&s3.ListBucketAnalyticsConfigurationsInput{
				Bucket: &bucket,
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func DeleteBucketAnalyticsConfiguration_not_implemented(s *S3Conf) error {
	testName := "DeleteBucketAnalyticsConfiguration_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.DeleteBucketAnalyticsConfiguration(ctx,
			&s3.DeleteBucketAnalyticsConfigurationInput{
				Bucket: &bucket,
				Id:     getPtr("uniquie_id"),
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func PutBucketEncryption_not_implemented(s *S3Conf) error {
	testName := "PutBucketEncryption_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketEncryption(ctx,
			&s3.PutBucketEncryptionInput{
				Bucket: &bucket,
				ServerSideEncryptionConfiguration: &types.ServerSideEncryptionConfiguration{
					Rules: []types.ServerSideEncryptionRule{
						{
							ApplyServerSideEncryptionByDefault: &types.ServerSideEncryptionByDefault{
								SSEAlgorithm: types.ServerSideEncryptionAes256,
							},
						},
					},
				},
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func GetBucketEncryption_not_implemented(s *S3Conf) error {
	testName := "GetBucketEncryption_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetBucketEncryption(ctx,
			&s3.GetBucketEncryptionInput{
				Bucket: &bucket,
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func DeleteBucketEncryption_not_implemented(s *S3Conf) error {
	testName := "DeleteBucketEncryption_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.DeleteBucketEncryption(ctx,
			&s3.DeleteBucketEncryptionInput{
				Bucket: &bucket,
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func PutBucketIntelligentTieringConfiguration_not_implemented(s *S3Conf) error {
	testName := "PutBucketIntelligentTieringConfiguration_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		days := int32(32)
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketIntelligentTieringConfiguration(ctx,
			&s3.PutBucketIntelligentTieringConfigurationInput{
				Bucket: &bucket,
				Id:     getPtr("unique_id"),
				IntelligentTieringConfiguration: &types.IntelligentTieringConfiguration{
					Id:     getPtr("my-id"),
					Status: types.IntelligentTieringStatusEnabled,
					Tierings: []types.Tiering{
						{
							AccessTier: types.IntelligentTieringAccessTierArchiveAccess,
							Days:       &days,
						},
					},
				},
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func GetBucketIntelligentTieringConfiguration_not_implemented(s *S3Conf) error {
	testName := "GetBucketIntelligentTieringConfiguration_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetBucketIntelligentTieringConfiguration(ctx,
			&s3.GetBucketIntelligentTieringConfigurationInput{
				Bucket: &bucket,
				Id:     getPtr("unique_id"),
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func ListBucketIntelligentTieringConfiguration_not_implemented(s *S3Conf) error {
	testName := "ListBucketIntelligentTieringConfiguration_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.ListBucketIntelligentTieringConfigurations(ctx,
			&s3.ListBucketIntelligentTieringConfigurationsInput{
				Bucket: &bucket,
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func DeleteBucketIntelligentTieringConfiguration_not_implemented(s *S3Conf) error {
	testName := "DeleteBucketIntelligentTieringConfiguration_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.DeleteBucketIntelligentTieringConfiguration(ctx,
			&s3.DeleteBucketIntelligentTieringConfigurationInput{
				Bucket: &bucket,
				Id:     getPtr("unique_id"),
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func PutBucketInventoryConfiguration_not_implemented(s *S3Conf) error {
	testName := "PutBucketInventoryConfiguration_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		enabled := true
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketInventoryConfiguration(ctx,
			&s3.PutBucketInventoryConfigurationInput{
				Bucket: &bucket,
				Id:     getPtr("unique_id"),
				InventoryConfiguration: &types.InventoryConfiguration{
					Destination: &types.InventoryDestination{
						S3BucketDestination: &types.InventoryS3BucketDestination{
							Bucket: &bucket,
							Format: types.InventoryFormatCsv,
							Encryption: &types.InventoryEncryption{
								SSEKMS: &types.SSEKMS{
									KeyId: getPtr("my-key-id"),
								},
							},
						},
					},
					Id:                     getPtr("my-id"),
					IncludedObjectVersions: types.InventoryIncludedObjectVersionsAll,
					IsEnabled:              &enabled,
					Schedule: &types.InventorySchedule{
						Frequency: types.InventoryFrequencyDaily,
					},
				},
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func GetBucketInventoryConfiguration_not_implemented(s *S3Conf) error {
	testName := "GetBucketInventoryConfiguration_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetBucketInventoryConfiguration(ctx,
			&s3.GetBucketInventoryConfigurationInput{
				Bucket: &bucket,
				Id:     getPtr("unique_id"),
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func ListBucketInventoryConfiguration_not_implemented(s *S3Conf) error {
	testName := "ListBucketInventoryConfiguration_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.ListBucketInventoryConfigurations(ctx,
			&s3.ListBucketInventoryConfigurationsInput{
				Bucket: &bucket,
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func DeleteBucketInventoryConfiguration_not_implemented(s *S3Conf) error {
	testName := "DeleteBucketInventoryConfiguration_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.DeleteBucketInventoryConfiguration(ctx,
			&s3.DeleteBucketInventoryConfigurationInput{
				Bucket: &bucket,
				Id:     getPtr("unique_id"),
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func PutBucketLifecycleConfiguration_not_implemented(s *S3Conf) error {
	testName := "PutBucketLifecycleConfiguration_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketAnalyticsConfiguration(ctx,
			&s3.PutBucketAnalyticsConfigurationInput{
				Bucket: &bucket,
				Id:     getPtr("unique_id"),
				AnalyticsConfiguration: &types.AnalyticsConfiguration{
					Id: getPtr("my-id"),
					StorageClassAnalysis: &types.StorageClassAnalysis{
						DataExport: &types.StorageClassAnalysisDataExport{
							Destination: &types.AnalyticsExportDestination{
								S3BucketDestination: &types.AnalyticsS3BucketDestination{
									Bucket: &bucket,
									Format: types.AnalyticsS3ExportFileFormatCsv,
								},
							},
							OutputSchemaVersion: types.StorageClassAnalysisSchemaVersionV1,
						},
					},
				},
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func GetBucketLifecycleConfiguration_not_implemented(s *S3Conf) error {
	testName := "GetBucketLifecycleConfiguration_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetBucketLifecycleConfiguration(ctx,
			&s3.GetBucketLifecycleConfigurationInput{
				Bucket: &bucket,
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func DeleteBucketLifecycle_not_implemented(s *S3Conf) error {
	testName := "DeleteBucketLifecycle_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.DeleteBucketLifecycle(ctx,
			&s3.DeleteBucketLifecycleInput{
				Bucket: &bucket,
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func PutBucketLogging_not_implemented(s *S3Conf) error {
	testName := "PutBucketLogging_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketLogging(ctx,
			&s3.PutBucketLoggingInput{
				Bucket: &bucket,
				BucketLoggingStatus: &types.BucketLoggingStatus{
					LoggingEnabled: &types.LoggingEnabled{
						TargetBucket: &bucket,
						TargetGrants: []types.TargetGrant{
							{
								Grantee: &types.Grantee{
									Type: types.TypeCanonicalUser,
									ID:   getPtr("grt1"),
								},
								Permission: types.BucketLogsPermissionRead,
							},
						},
						TargetObjectKeyFormat: &types.TargetObjectKeyFormat{
							SimplePrefix: &types.SimplePrefix{},
						},
						TargetPrefix: getPtr("prefix"),
					},
				},
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func GetBucketLogging_not_implemented(s *S3Conf) error {
	testName := "GetBucketLogging_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetBucketLogging(ctx,
			&s3.GetBucketLoggingInput{
				Bucket: &bucket,
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func PutBucketRequestPayment_not_implemented(s *S3Conf) error {
	testName := "PutBucketRequestPayment_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketRequestPayment(ctx,
			&s3.PutBucketRequestPaymentInput{
				Bucket: &bucket,
				RequestPaymentConfiguration: &types.RequestPaymentConfiguration{
					Payer: types.PayerBucketOwner,
				},
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func GetBucketRequestPayment_not_implemented(s *S3Conf) error {
	testName := "GetBucketRequestPayment_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetBucketRequestPayment(ctx,
			&s3.GetBucketRequestPaymentInput{
				Bucket: &bucket,
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func PutBucketMetricsConfiguration_not_implemented(s *S3Conf) error {
	testName := "PutBucketMetricsConfiguration_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketMetricsConfiguration(ctx,
			&s3.PutBucketMetricsConfigurationInput{
				Bucket: &bucket,
				Id:     getPtr("unique_id"),
				MetricsConfiguration: &types.MetricsConfiguration{
					Id: getPtr("EntireBucket"),
				},
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func GetBucketMetricsConfiguration_not_implemented(s *S3Conf) error {
	testName := "GetBucketMetricsConfiguration_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetBucketMetricsConfiguration(ctx,
			&s3.GetBucketMetricsConfigurationInput{
				Bucket: &bucket,
				Id:     getPtr("unique_id"),
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func ListBucketMetricsConfigurations_not_implemented(s *S3Conf) error {
	testName := "ListBucketMetricsConfigurations_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.ListBucketMetricsConfigurations(ctx,
			&s3.ListBucketMetricsConfigurationsInput{
				Bucket: &bucket,
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func DeleteBucketMetricsConfiguration_not_implemented(s *S3Conf) error {
	testName := "DeleteBucketMetricsConfiguration_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.DeleteBucketMetricsConfiguration(ctx,
			&s3.DeleteBucketMetricsConfigurationInput{
				Bucket: &bucket,
				Id:     getPtr("unique_id"),
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func PutBucketReplication_not_implemented(s *S3Conf) error {
	testName := "PutBucketReplication_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketReplication(ctx,
			&s3.PutBucketReplicationInput{
				Bucket: &bucket,
				ReplicationConfiguration: &types.ReplicationConfiguration{
					Role: getPtr("arn:aws:iam::35667example:role/CrossRegionReplicationRoleForS3"),
					Rules: []types.ReplicationRule{
						{
							Destination: &types.Destination{
								Bucket: &bucket,
								AccessControlTranslation: &types.AccessControlTranslation{
									Owner: types.OwnerOverrideDestination,
								},
								Account: getPtr("grt1"),
							},
							Status: types.ReplicationRuleStatusEnabled,
						},
					},
				},
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func GetBucketReplication_not_implemented(s *S3Conf) error {
	testName := "GetBucketReplication_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetBucketReplication(ctx,
			&s3.GetBucketReplicationInput{
				Bucket: &bucket,
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func DeleteBucketReplication_not_implemented(s *S3Conf) error {
	testName := "DeleteBucketReplication_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.DeleteBucketReplication(ctx,
			&s3.DeleteBucketReplicationInput{
				Bucket: &bucket,
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func PutPublicAccessBlock_not_implemented(s *S3Conf) error {
	testName := "PutPublicAccessBlock_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutPublicAccessBlock(ctx,
			&s3.PutPublicAccessBlockInput{
				Bucket: &bucket,
				PublicAccessBlockConfiguration: &types.PublicAccessBlockConfiguration{
					BlockPublicPolicy: getPtr(true),
				},
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func GetPublicAccessBlock_not_implemented(s *S3Conf) error {
	testName := "GetPublicAccessBlock_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetPublicAccessBlock(ctx,
			&s3.GetPublicAccessBlockInput{
				Bucket: &bucket,
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func DeletePublicAccessBlock_not_implemented(s *S3Conf) error {
	testName := "DeletePublicAccessBlock_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.DeletePublicAccessBlock(ctx,
			&s3.DeletePublicAccessBlockInput{
				Bucket: &bucket,
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func PutBucketNotificationConfiguratio_not_implemented(s *S3Conf) error {
	testName := "PutBucketNotificationConfiguratio_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketNotificationConfiguration(ctx,
			&s3.PutBucketNotificationConfigurationInput{
				Bucket: &bucket,
				NotificationConfiguration: &types.NotificationConfiguration{
					EventBridgeConfiguration: &types.EventBridgeConfiguration{},
				},
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func GetBucketNotificationConfiguratio_not_implemented(s *S3Conf) error {
	testName := "GetBucketNotificationConfiguratio_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetBucketNotificationConfiguration(ctx,
			&s3.GetBucketNotificationConfigurationInput{
				Bucket: &bucket,
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func PutBucketAccelerateConfiguration_not_implemented(s *S3Conf) error {
	testName := "PutBucketAccelerateConfiguration_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketAccelerateConfiguration(ctx,
			&s3.PutBucketAccelerateConfigurationInput{
				Bucket: &bucket,
				AccelerateConfiguration: &types.AccelerateConfiguration{
					Status: types.BucketAccelerateStatusEnabled,
				},
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func GetBucketAccelerateConfiguration_not_implemented(s *S3Conf) error {
	testName := "GetBucketAccelerateConfiguration_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetBucketAccelerateConfiguration(ctx,
			&s3.GetBucketAccelerateConfigurationInput{
				Bucket: &bucket,
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func PutBucketWebsite_not_implemented(s *S3Conf) error {
	testName := "PutBucketWebsite_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketWebsite(ctx,
			&s3.PutBucketWebsiteInput{
				Bucket: &bucket,
				WebsiteConfiguration: &types.WebsiteConfiguration{
					IndexDocument: &types.IndexDocument{
						Suffix: getPtr("suffix"),
					},
				},
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func GetBucketWebsite_not_implemented(s *S3Conf) error {
	testName := "GetBucketWebsite_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetBucketWebsite(ctx,
			&s3.GetBucketWebsiteInput{
				Bucket: &bucket,
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}

func DeleteBucketWebsite_not_implemented(s *S3Conf) error {
	testName := "DeleteBucketWebsite_not_implemented"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.DeleteBucketWebsite(ctx,
			&s3.DeleteBucketWebsiteInput{
				Bucket: &bucket,
			})
		cancel()

		return checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented))
	})
}
