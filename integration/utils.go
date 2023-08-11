package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/versity/versitygw/s3err"
)

var (
	bcktCount = 0
)

func getBucketName() string {
	bcktCount++
	return fmt.Sprintf("test-bucket-%v", bcktCount)
}

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

func actionHandler(s *S3Conf, testName string, handler func(s3client *s3.Client, bucket string) error) {
	runF(testName)
	bucketName := getBucketName()
	err := setup(s, bucketName)
	if err != nil {
		failF("%v: failed to create a bucket: %v", testName, err.Error())
		return
	}
	client := s3.NewFromConfig(s.Config())
	handlerErr := handler(client, bucketName)
	if handlerErr != nil {
		failF("%v: %v", testName, handlerErr.Error())
	}

	err = teardown(s, bucketName)
	if err != nil {
		if handlerErr == nil {
			failF("%v: failed to delete the bucket: %v", testName, err.Error())
		} else {
			fmt.Printf(colorRed+"%v: failed to delete the bucket: %v", testName, err.Error())
		}
	}
	if handlerErr == nil {
		passF(testName)
	}
}

func putObjects(client *s3.Client, objs []string, bucket string) error {
	for _, key := range objs {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := client.PutObject(ctx, &s3.PutObjectInput{
			Key:    &key,
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}
	}
	return nil
}

func checkApiErr(err error, apiErr s3err.APIError) error {
	if err == nil {
		return fmt.Errorf("expected %v, instead got nil", apiErr.Code)
	}
	var ae smithy.APIError
	if errors.As(err, &ae) {
		if ae.ErrorCode() == apiErr.Code && ae.ErrorMessage() == apiErr.Description {
			return nil
		}

		return fmt.Errorf("expected %v, instead got %v", apiErr.Code, ae.ErrorCode())
	} else {
		return fmt.Errorf("expected aws api error, instead got: %v", err.Error())
	}
}

func checkSdkApiErr(err error, code string) error {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		if ae.ErrorCode() != code {
			return fmt.Errorf("expected %v, instead got %v", ae.ErrorCode(), code)
		}
		return nil
	}
	return err
}

func putObjectWithData(lgth int64, input *s3.PutObjectInput, client *s3.Client) (csum [32]byte, data []byte, err error) {
	data = make([]byte, lgth)
	rand.Read(data)
	csum = sha256.Sum256(data)
	r := bytes.NewReader(data)
	input.Body = r

	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	_, err = client.PutObject(ctx, input)
	cancel()

	return
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

func areTagsSame(tags1, tags2 []types.Tag) bool {
	if len(tags1) != len(tags2) {
		return false
	}

	for _, tag := range tags1 {
		if !containsTag(tag, tags2) {
			return false
		}
	}
	return true
}

func containsTag(tag types.Tag, list []types.Tag) bool {
	for _, item := range list {
		if *item.Key == *tag.Key && *item.Value == *tag.Value {
			return true
		}
	}
	return false
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
	cmd := exec.Command("./versitygw", args...)

	return cmd.CombinedOutput()
}

func getString(str *string) string {
	if str == nil {
		return ""
	}
	return *str
}

func getPtr(str string) *string {
	return &str
}

func areMapsSame(mp1, mp2 map[string]string) bool {
	if len(mp1) != len(mp2) {
		return false
	}
	for key, val := range mp1 {
		if mp2[key] != val {
			return false
		}
	}
	return true
}

func compareObjects(list1 []string, list2 []types.Object) bool {
	if len(list1) != len(list2) {
		return false
	}

	elementMap := make(map[string]bool)

	for _, elem := range list1 {
		elementMap[elem] = true
	}

	for _, elem := range list2 {
		if _, found := elementMap[*elem.Key]; !found {
			return false
		}
	}

	return true
}

func compareDelObjects(list1 []string, list2 []types.DeletedObject) bool {
	if len(list1) != len(list2) {
		return false
	}

	elementMap := make(map[string]bool)

	for _, elem := range list1 {
		elementMap[elem] = true
	}

	for _, elem := range list2 {
		if _, found := elementMap[*elem.Key]; !found {
			return false
		}
	}

	return true
}
