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
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/big"
	rnd "math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

var (
	bcktCount            = 0
	succUsrCrt           = "The user has been created successfully"
	failUsrCrt           = "failed to create user: update iam data: account already exists"
	adminAccessDeniedMsg = "access denied: only admin users have access to this resource"
	succDeleteUserMsg    = "The user has been deleted successfully"
)

func getBucketName() string {
	bcktCount++
	return fmt.Sprintf("test-bucket-%v", bcktCount)
}

func setup(s *S3Conf, bucket string, opts ...setupOpt) error {
	s3client := s3.NewFromConfig(s.Config())

	cfg := new(setupCfg)
	for _, opt := range opts {
		opt(cfg)
	}

	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	_, err := s3client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket:                     &bucket,
		ObjectLockEnabledForBucket: &cfg.LockEnabled,
		ObjectOwnership:            cfg.Ownership,
	})
	cancel()
	if err != nil {
		return err
	}

	if cfg.VersioningEnabled {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{
			Bucket: &bucket,
			VersioningConfiguration: &types.VersioningConfiguration{
				Status: types.BucketVersioningStatusEnabled,
			},
		})
		cancel()
		if err != nil {
			return err
		}
	}

	return nil
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
			return fmt.Errorf("failed to delete object %v: %w", *key, err)
		}
		return nil
	}

	if s.versioningEnabled {
		in := &s3.ListObjectVersionsInput{Bucket: &bucket}
		for {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.ListObjectVersions(ctx, in)
			cancel()
			if err != nil {
				return fmt.Errorf("failed to list objects: %w", err)
			}

			for _, item := range out.Versions {
				err = deleteObject(&bucket, item.Key, item.VersionId)
				if err != nil {
					return err
				}
			}
			for _, item := range out.DeleteMarkers {
				err = deleteObject(&bucket, item.Key, item.VersionId)
				if err != nil {
					return err
				}
			}

			if out.IsTruncated != nil && *out.IsTruncated {
				in.KeyMarker = out.KeyMarker
				in.VersionIdMarker = out.NextVersionIdMarker
			} else {
				break
			}
		}
	} else {
		for {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			out, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
				Bucket: &bucket,
			})
			cancel()
			if err != nil {
				return fmt.Errorf("failed to list objects: %w", err)
			}

			for _, item := range out.Contents {
				err = deleteObject(&bucket, item.Key, nil)
				if err != nil {
					return err
				}
			}

			if out.IsTruncated != nil && *out.IsTruncated {
				continue
			}
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

type setupCfg struct {
	Ownership         types.ObjectOwnership
	LockEnabled       bool
	VersioningEnabled bool
}

type setupOpt func(*setupCfg)

func withLock() setupOpt {
	return func(s *setupCfg) { s.LockEnabled = true }
}
func withOwnership(o types.ObjectOwnership) setupOpt {
	return func(s *setupCfg) { s.Ownership = o }
}
func withVersioning() setupOpt {
	return func(s *setupCfg) { s.VersioningEnabled = true }
}

func actionHandler(s *S3Conf, testName string, handler func(s3client *s3.Client, bucket string) error, opts ...setupOpt) error {
	runF(testName)
	bucketName := getBucketName()
	err := setup(s, bucketName, opts...)
	if err != nil {
		failF("%v: failed to create a bucket: %v", testName, err)
		return fmt.Errorf("%v: failed to create a bucket: %w", testName, err)
	}
	client := s3.NewFromConfig(s.Config())
	handlerErr := handler(client, bucketName)
	if handlerErr != nil {
		failF("%v: %v", testName, handlerErr)
	}

	err = teardown(s, bucketName)
	if err != nil {
		fmt.Printf(colorRed+"%v: failed to delete the bucket: %v", testName, err)
		if handlerErr == nil {
			return fmt.Errorf("%v: failed to delete the bucket: %w", testName, err)
		}
	}
	if handlerErr == nil {
		passF(testName)
	}

	return handlerErr
}

type authConfig struct {
	date     time.Time
	testName string
	path     string
	method   string
	service  string
	body     []byte
}

func authHandler(s *S3Conf, cfg *authConfig, handler func(req *http.Request) error) error {
	runF(cfg.testName)
	req, err := createSignedReq(cfg.method, s.endpoint, cfg.path, s.awsID, s.awsSecret, cfg.service, s.awsRegion, cfg.body, cfg.date, nil)
	if err != nil {
		failF("%v: %v", cfg.testName, err)
		return fmt.Errorf("%v: %w", cfg.testName, err)
	}

	err = handler(req)
	if err != nil {
		failF("%v: %v", cfg.testName, err)
		return fmt.Errorf("%v: %w", cfg.testName, err)
	}
	passF(cfg.testName)
	return nil
}

func presignedAuthHandler(s *S3Conf, testName string, handler func(client *s3.PresignClient) error) error {
	runF(testName)
	clt := s3.NewPresignClient(s3.NewFromConfig(s.Config()))

	err := handler(clt)
	if err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	passF(testName)
	return nil
}

func createSignedReq(method, endpoint, path, access, secret, service, region string, body []byte, date time.Time, headers map[string]string) (*http.Request, error) {
	req, err := http.NewRequest(method, fmt.Sprintf("%v/%v", endpoint, path), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to send the request: %w", err)
	}

	signer := v4.NewSigner()

	hashedPayload := sha256.Sum256(body)
	hexPayload := hex.EncodeToString(hashedPayload[:])

	req.Header.Set("X-Amz-Content-Sha256", hexPayload)
	for key, val := range headers {
		req.Header.Add(key, val)
	}

	signErr := signer.SignHTTP(req.Context(), aws.Credentials{AccessKeyID: access, SecretAccessKey: secret}, req, hexPayload, service, region, date)
	if signErr != nil {
		return nil, fmt.Errorf("failed to sign the request: %w", signErr)
	}

	return req, nil
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
		if ae.ErrorCode() != apiErr.Code {
			return fmt.Errorf("expected error code to be %v, instead got %v", apiErr.Code, ae.ErrorCode())
		}

		if ae.ErrorMessage() != apiErr.Description {
			return fmt.Errorf("expected error message to be %v, instead got %v", apiErr.Description, ae.ErrorMessage())
		}

		return nil
	}

	return fmt.Errorf("expected aws api error, instead got: %w", err)
}

func checkSdkApiErr(err error, code string) error {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		if ae.ErrorCode() != code {
			return fmt.Errorf("expected %v, instead got %v", code, ae.ErrorCode())
		}
		return nil
	}
	return err
}

func putObjects(client *s3.Client, objs []string, bucket string) ([]types.Object, error) {
	var contents []types.Object
	var size int64
	for _, key := range objs {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := client.PutObject(ctx, &s3.PutObjectInput{
			Key:    &key,
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return nil, err
		}
		k := key
		etag := strings.Trim(*res.ETag, `"`)
		contents = append(contents, types.Object{
			Key:          &k,
			ETag:         &etag,
			StorageClass: types.ObjectStorageClassStandard,
			Size:         &size,
		})
	}

	sort.SliceStable(contents, func(i, j int) bool {
		return *contents[i].Key < *contents[j].Key
	})

	return contents, nil
}

func listObjects(client *s3.Client, bucket, prefix, delimiter string, maxKeys int32) ([]types.Object, []types.CommonPrefix, error) {
	var contents []types.Object
	var commonPrefixes []types.CommonPrefix

	var continuationToken *string

	for {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:            &bucket,
			ContinuationToken: continuationToken,
			Prefix:            &prefix,
			Delimiter:         &delimiter,
			MaxKeys:           &maxKeys,
		})
		cancel()
		if err != nil {
			return nil, nil, err
		}
		contents = append(contents, res.Contents...)
		commonPrefixes = append(commonPrefixes, res.CommonPrefixes...)
		continuationToken = res.NextContinuationToken

		if !*res.IsTruncated {
			break
		}
	}

	return contents, commonPrefixes, nil
}

func hasObjNames(objs []types.Object, names []string) bool {
	if len(objs) != len(names) {
		return false
	}

	for _, obj := range objs {
		if contains(names, *obj.Key) {
			continue
		}
		return false
	}

	return true
}

func hasPrefixName(prefixes []types.CommonPrefix, names []string) bool {
	if len(prefixes) != len(names) {
		return false
	}

	for _, prefix := range prefixes {
		if contains(names, *prefix.Prefix) {
			continue
		}
		return false
	}

	return true
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

type putObjectOutput struct {
	res  *s3.PutObjectOutput
	data []byte
	csum [32]byte
}

func putObjectWithData(lgth int64, input *s3.PutObjectInput, client *s3.Client) (*putObjectOutput, error) {
	data := make([]byte, lgth)
	rand.Read(data)
	csum := sha256.Sum256(data)
	r := bytes.NewReader(data)
	input.Body = r

	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	res, err := client.PutObject(ctx, input)
	cancel()
	if err != nil {
		return nil, err
	}

	return &putObjectOutput{
		csum: csum,
		data: data,
		res:  res,
	}, nil
}

func createMp(s3client *s3.Client, bucket, key string) (*s3.CreateMultipartUploadOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	out, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: &bucket,
		Key:    &key,
	})
	cancel()
	return out, err
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
		if *item.Key != *list2[i].Key {
			return false
		}
		if *item.UploadId != *list2[i].UploadId {
			return false
		}
		if item.StorageClass != list2[i].StorageClass {
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
		if *prt.PartNumber != *parts2[i].PartNumber {
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
		if grt.Grantee.Type != grts2[i].Grantee.Type {
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

// mp1 needs to be the response from the server
// mp2 needs to be the expected values
// The keys from the server are always converted to lowercase
func areMapsSame(mp1, mp2 map[string]string) bool {
	if len(mp1) != len(mp2) {
		return false
	}
	for key, val := range mp2 {
		if mp1[strings.ToLower(key)] != val {
			return false
		}
	}
	return true
}

func compareBuckets(list1 []types.Bucket, list2 []s3response.ListAllMyBucketsEntry) bool {
	if len(list1) != len(list2) {
		return false
	}

	elementMap := make(map[string]bool)

	for _, elem := range list1 {
		elementMap[*elem.Name] = true
	}

	for _, elem := range list2 {
		if _, found := elementMap[elem.Name]; !found {
			return false
		}
	}

	return true
}

func compareObjects(list1, list2 []types.Object) bool {
	if len(list1) != len(list2) {
		fmt.Println("list lengths are not equal")
		return false
	}

	for i, obj := range list1 {
		if *obj.Key != *list2[i].Key {
			fmt.Printf("keys are not equal: %q != %q\n", *obj.Key, *list2[i].Key)
			return false
		}
		if *obj.ETag != *list2[i].ETag {
			fmt.Printf("etags are not equal: (%q %q)  %q != %q\n",
				*obj.Key, *list2[i].Key, *obj.ETag, *list2[i].ETag)
			return false
		}
		if *obj.Size != *list2[i].Size {
			fmt.Printf("sizes are not equal: (%q %q)  %v != %v\n",
				*obj.Key, *list2[i].Key, *obj.Size, *list2[i].Size)
			return false
		}
		if obj.StorageClass != list2[i].StorageClass {
			fmt.Printf("storage classes are not equal: (%q %q)  %v != %v\n",
				*obj.Key, *list2[i].Key, obj.StorageClass, list2[i].StorageClass)
			return false
		}
	}

	return true
}

func comparePrefixes(list1 []string, list2 []types.CommonPrefix) bool {
	if len(list1) != len(list2) {
		return false
	}

	elementMap := make(map[string]bool)

	for _, elem := range list1 {
		elementMap[elem] = true
	}

	for _, elem := range list2 {
		if _, found := elementMap[*elem.Prefix]; !found {
			return false
		}
	}

	return true
}

func compareDelObjects(list1, list2 []types.DeletedObject) bool {
	if len(list1) != len(list2) {
		return false
	}

	for i, obj := range list1 {
		if *obj.Key != *list2[i].Key {
			return false
		}

		if obj.VersionId != nil {
			if list2[i].VersionId == nil {
				return false
			}
			if *obj.VersionId != *list2[i].VersionId {
				return false
			}
		}
		if obj.DeleteMarkerVersionId != nil {
			if list2[i].DeleteMarkerVersionId == nil {
				return false
			}
			if *obj.DeleteMarkerVersionId != *list2[i].DeleteMarkerVersionId {
				return false
			}
		}
		if obj.DeleteMarker != nil {
			if list2[i].DeleteMarker == nil {
				return false
			}
			if *obj.DeleteMarker != *list2[i].DeleteMarker {
				return false
			}
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
		pn := int32(partNumber)
		out, err := client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:     &bucket,
			Key:        &key,
			UploadId:   &uploadId,
			Body:       bytes.NewReader(partBuffer),
			PartNumber: &pn,
		})
		cancel()
		if err != nil {
			return parts, err
		}
		parts = append(parts, types.Part{
			ETag:       out.ETag,
			PartNumber: &pn,
			Size:       &partSize,
		})
		offset += partSize
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
		err := deleteUser(s, usr.access)
		if err != nil {
			return err
		}
		out, err := execCommand("admin", "-a", s.awsID, "-s", s.awsSecret, "-er", s.endpoint, "create-user", "-a", usr.access, "-s", usr.secret, "-r", usr.role)
		if err != nil {
			return err
		}
		if !strings.Contains(string(out), succUsrCrt) && !strings.Contains(string(out), failUsrCrt) {
			return fmt.Errorf("failed to create user account")
		}
	}
	return nil
}

func deleteUser(s *S3Conf, access string) error {
	out, err := execCommand("admin", "-a", s.awsID, "-s", s.awsSecret, "-er", s.endpoint, "delete-user", "-a", access)
	if err != nil {
		return err
	}
	if !strings.Contains(string(out), succDeleteUserMsg) {
		return fmt.Errorf("failed to delete the user account")
	}

	return nil
}

func changeBucketsOwner(s *S3Conf, buckets []string, owner string) error {
	for _, bucket := range buckets {
		out, err := execCommand("admin", "-a", s.awsID, "-s", s.awsSecret, "-er", s.endpoint, "change-bucket-owner", "-b", bucket, "-o", owner)
		if err != nil {
			return err
		}
		if !strings.Contains(string(out), "Bucket owner has been updated successfully") {
			return fmt.Errorf("%v", string(out))
		}
	}

	return nil
}

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func genRandString(length int) string {
	source := rnd.NewSource(time.Now().UnixNano())
	random := rnd.New(source)
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[random.Intn(len(charset))]
	}
	return string(result)
}

const (
	credAccess int = iota
	credDate
	credRegion
	credService
	credTerminator
)

func changeAuthCred(uri, newVal string, index int) (string, error) {
	urlParsed, err := url.Parse(uri)
	if err != nil {
		return "", err
	}

	queries := urlParsed.Query()
	creds := strings.Split(queries.Get("X-Amz-Credential"), "/")
	creds[index] = newVal
	queries.Set("X-Amz-Credential", strings.Join(creds, "/"))
	urlParsed.RawQuery = queries.Encode()

	return urlParsed.String(), nil
}

func genPolicyDoc(effect, principal, action, resource string) string {
	jsonTemplate := `
	{
		"Statement": [
			{
				"Effect":  "%s",
				"Principal": %s,
				"Action":  %s,
				"Resource":  %s
			}
		]
	}
	`

	return fmt.Sprintf(jsonTemplate, effect, principal, action, resource)
}

func getMalformedPolicyError(msg string) s3err.APIError {
	return s3err.APIError{
		Code:           "MalformedPolicy",
		Description:    msg,
		HTTPStatusCode: http.StatusBadRequest,
	}
}

func getUserS3Client(usr user, cfg *S3Conf) *s3.Client {
	config := *cfg
	config.awsID = usr.access
	config.awsSecret = usr.secret

	return s3.NewFromConfig(config.Config())
}

// if true enables, otherwise disables
func changeBucketObjectLockStatus(client *s3.Client, bucket string, status bool) error {
	cfg := types.ObjectLockConfiguration{}
	if status {
		cfg.ObjectLockEnabled = types.ObjectLockEnabledEnabled
	}
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	_, err := client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
		Bucket:                  &bucket,
		ObjectLockConfiguration: &cfg,
	})
	cancel()
	if err != nil {
		return err
	}

	return nil
}

func checkWORMProtection(client *s3.Client, bucket, object string) error {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	_, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &bucket,
		Key:    &object,
	})
	cancel()
	if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLocked)); err != nil {
		return err
	}

	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
	_, err = client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &bucket,
		Key:    &object,
	})
	cancel()
	if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLocked)); err != nil {
		return err
	}

	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
	_, err = client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
		Bucket: &bucket,
		Delete: &types.Delete{
			Objects: []types.ObjectIdentifier{
				{
					Key: &object,
				},
			},
		},
	})
	cancel()
	if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLocked)); err != nil {
		return err
	}

	return nil
}

func objStrings(objs []types.Object) []string {
	objStrs := make([]string, len(objs))
	for i, obj := range objs {
		objStrs[i] = *obj.Key
	}
	return objStrs
}

func pfxStrings(pfxs []types.CommonPrefix) []string {
	pfxStrs := make([]string, len(pfxs))
	for i, pfx := range pfxs {
		pfxStrs[i] = *pfx.Prefix
	}
	return pfxStrs
}

func createObjVersions(client *s3.Client, bucket, object string, count int) ([]types.ObjectVersion, error) {
	versions := []types.ObjectVersion{}
	for i := 0; i < count; i++ {
		rNumber, err := rand.Int(rand.Reader, big.NewInt(100000))
		dataLength := rNumber.Int64()
		if err != nil {
			return nil, err
		}

		r, err := putObjectWithData(dataLength, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &object,
		}, client)
		if err != nil {
			return nil, err
		}

		isLatest := i == count-1

		versions = append(versions, types.ObjectVersion{
			ETag:      r.res.ETag,
			IsLatest:  &isLatest,
			Key:       &object,
			Size:      &dataLength,
			VersionId: r.res.VersionId,
		})
	}

	versions = reverseSlice(versions)

	return versions, nil
}

// ReverseSlice reverses a slice of any type
func reverseSlice[T any](s []T) []T {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}

func compareVersions(v1, v2 []types.ObjectVersion) bool {
	if len(v1) != len(v2) {
		return false
	}

	for i, version := range v1 {
		if version.Key == nil || v2[i].Key == nil {
			return false
		}
		if *version.Key != *v2[i].Key {
			return false
		}

		if version.VersionId == nil || v2[i].VersionId == nil {
			return false
		}
		if *version.VersionId != *v2[i].VersionId {
			return false
		}

		if version.IsLatest == nil || v2[i].IsLatest == nil {
			return false
		}
		if *version.IsLatest != *v2[i].IsLatest {
			return false
		}

		if version.Size == nil || v2[i].Size == nil {
			return false
		}
		if *version.Size != *v2[i].Size {
			return false
		}

		if version.ETag == nil || v2[i].ETag == nil {
			return false
		}
		if *version.ETag != *v2[i].ETag {
			return false
		}
	}

	return true
}

func compareDelMarkers(d1, d2 []types.DeleteMarkerEntry) bool {
	if len(d1) != len(d2) {
		return false
	}

	for i, dEntry := range d1 {
		if dEntry.Key == nil || d2[i].Key == nil {
			return false
		}
		if *dEntry.Key != *d2[i].Key {
			return false
		}

		if dEntry.IsLatest == nil || d2[i].IsLatest == nil {
			return false
		}
		if *dEntry.IsLatest != *d2[i].IsLatest {
			return false
		}

		if dEntry.VersionId == nil || d2[i].VersionId == nil {
			return false
		}
		if *dEntry.VersionId != *d2[i].VersionId {
			return false
		}
	}

	return true
}

func getBoolPtr(b bool) *bool {
	return &b
}
