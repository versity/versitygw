package integration

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func setup(s *S3Conf, bucket string) error {
	s3client := s3.NewFromConfig(s.Config())

	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	_, err := s3client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: &bucket,
	})
	cancel()
	return err
}

func teardown(s *S3Conf, bucket string) error {
	s3client := s3.NewFromConfig(s.Config())

	deleteObject := func(bucket, key, versionId *string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket:    bucket,
			Key:       key,
			VersionId: versionId,
		})
		cancel()
		if err != nil {
			return fmt.Errorf("failed to delete object %v: %v", *key, err)
		}
		return nil
	}

	in := &s3.ListObjectsV2Input{Bucket: &bucket}
	for {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjectsV2(ctx, in)
		cancel()
		if err != nil {
			return fmt.Errorf("failed to list objects: %v", err)
		}

		for _, item := range out.Contents {
			err = deleteObject(&bucket, item.Key, nil)
			if err != nil {
				return err
			}
		}

		if out.IsTruncated {
			in.ContinuationToken = out.ContinuationToken
		} else {
			break
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	_, err := s3client.DeleteBucket(ctx, &s3.DeleteBucketInput{
		Bucket: &bucket,
	})
	cancel()
	return err
}

func isEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	for i, d := range a {
		if d != b[i] {
			return false
		}
	}

	return true
}

func contains(name string, list []types.Object) bool {
	for _, item := range list {
		fmt.Println(*item.Key)
		if strings.EqualFold(name, *item.Key) {
			return true
		}
	}
	return false
}

func containsUID(name, id string, list []types.MultipartUpload) bool {
	for _, item := range list {
		if strings.EqualFold(name, *item.Key) && strings.EqualFold(id, *item.UploadId) {
			return true
		}
	}
	return false
}

func containsPart(part int32, list []types.Part) bool {
	for _, item := range list {
		if item.PartNumber == part {
			return true
		}
	}
	return false
}

func isSame(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, x := range a {
		if x != b[i] {
			return false
		}
	}
	return true
}

// Checks if the slices contain the same objects, if the objects doesn't
// contain map, slice, channel.
func areTagsSame(tags1, tags2 []types.Tag) bool {
	if len(tags1) != len(tags2) {
		return false
	}

	for i, tag := range tags1 {
		if *tag.Key != *tags2[i].Key || *tag.Value != *tags2[i].Value {
			return false
		}
	}
	return true
}

func checkGrants(grts1, grts2 []types.Grant) bool {
	if len(grts1) != len(grts2) {
		return false
	}

	for i, grt := range grts1 {
		if grt.Permission != grts2[i].Permission {
			return false
		}
		if *grt.Grantee.ID != *grts2[i].Grantee.ID {
			return false
		}
	}
	return true
}

func execCommand(args ...string) ([]byte, error) {
	cmd := exec.Command("../../versitygw", args...)

	return cmd.CombinedOutput()
}
