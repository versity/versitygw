package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/versity/versitygw/s3err"
)

var (
	bcktCount  = 0
	succUsrCrt = "The user has been created successfully"
	failUsrCrt = "failed to create a user: update iam data: account already exists"
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

type authConfig struct {
	testName string
	path     string
	method   string
	body     []byte
	service  string
	date     time.Time
}

func authHandler(s *S3Conf, cfg *authConfig, handler func(req *http.Request) error) {
	runF(cfg.testName)
	req, err := http.NewRequest(cfg.method, fmt.Sprintf("%v/%v", s.endpoint, cfg.path), bytes.NewReader(cfg.body))
	if err != nil {
		failF("%v: failed to send the request: %v", cfg.testName, err.Error())
		return
	}

	signer := v4.NewSigner()

	hashedPayload := sha256.Sum256([]byte{})
	hexPayload := hex.EncodeToString(hashedPayload[:])

	req.Header.Set("X-Amz-Content-Sha256", hexPayload)

	signErr := signer.SignHTTP(req.Context(), aws.Credentials{AccessKeyID: s.awsID, SecretAccessKey: s.awsSecret}, req, hexPayload, cfg.service, s.awsRegion, cfg.date)
	if signErr != nil {
		failF("%v: failed to sign the request: %v", cfg.testName, err.Error())
		return
	}

	err = handler(req)
	if err != nil {
		failF("%v: %v", cfg.testName, err.Error())
		return
	}
	passF(cfg.testName)
}

func checkAuthErr(resp *http.Response, apiErr s3err.APIError) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var errResp s3err.APIErrorResponse
	err = xml.Unmarshal(body, &errResp)
	if err != nil {
		return err
	}

	if resp.StatusCode != apiErr.HTTPStatusCode {
		return fmt.Errorf("expected response status code to be %v, instead got %v", apiErr.HTTPStatusCode, resp.StatusCode)
	}
	if errResp.Code != apiErr.Code {
		return fmt.Errorf("expected error code to be %v, instead got %v", apiErr.Code, errResp.Code)
	}
	if errResp.Message != apiErr.Description {
		return fmt.Errorf("expected error message to be %v, instead got %v", apiErr.Description, errResp.Message)
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

func compareMultipartUploads(list1, list2 []types.MultipartUpload) bool {
	if len(list1) != len(list2) {
		return false
	}
	for i, item := range list1 {
		if *item.Key != *list2[i].Key || *item.UploadId != *list2[i].UploadId {
			return false
		}
	}

	return true
}

func compareParts(parts1, parts2 []types.Part) bool {
	if len(parts1) != len(parts2) {
		return false
	}

	for i, prt := range parts1 {
		if prt.PartNumber != parts2[i].PartNumber {
			return false
		}
		if *prt.ETag != *parts2[i].ETag {
			return false
		}
	}
	return true
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

func compareGrants(grts1, grts2 []types.Grant) bool {
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

func uploadParts(client *s3.Client, size, partCount int, bucket, key, uploadId string) (parts []types.Part, err error) {
	dr := NewDataReader(size, size)
	datafile := "rand.data"
	w, err := os.Create(datafile)
	if err != nil {
		return parts, err
	}
	defer w.Close()

	_, err = io.Copy(w, dr)
	if err != nil {
		return parts, err
	}

	fileInfo, err := w.Stat()
	if err != nil {
		return parts, err
	}

	partSize := fileInfo.Size() / int64(partCount)
	var offset int64

	for partNumber := int64(1); partNumber <= int64(partCount); partNumber++ {
		partStart := (partNumber - 1) * partSize
		partEnd := partStart + partSize - 1
		if partEnd > fileInfo.Size()-1 {
			partEnd = fileInfo.Size() - 1
		}
		partBuffer := make([]byte, partEnd-partStart+1)
		_, err := w.ReadAt(partBuffer, partStart)
		if err != nil {
			return parts, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:     &bucket,
			Key:        &key,
			UploadId:   &uploadId,
			Body:       bytes.NewReader(partBuffer),
			PartNumber: int32(partNumber),
		})
		cancel()
		if err != nil {
			return parts, err
		} else {
			parts = append(parts, types.Part{ETag: out.ETag, PartNumber: int32(partNumber)})
			offset += partSize
		}
	}

	return parts, err
}

type user struct {
	access string
	secret string
	role   string
}

func createUsers(s *S3Conf, users []user) error {
	for _, usr := range users {
		out, err := execCommand("admin", "-a", s.awsID, "-s", s.awsSecret, "create-user", "-a", usr.access, "-s", usr.secret, "-r", usr.role)
		if err != nil {
			return err
		}
		if !strings.Contains(string(out), succUsrCrt) && !strings.Contains(string(out), failUsrCrt) {
			return fmt.Errorf("failed to create a user account")
		}
	}
	return nil
}
