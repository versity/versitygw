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
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"hash/crc64"
	"io"
	"math/big"
	"math/bits"
	rnd "math/rand"
	"net/http"
	"net/url"
	"os/exec"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/versity/versitygw/s3err"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
)

var (
	bcktCount        atomic.Uint64
	adminErrorPrefix = "XAdmin"
)

type user struct {
	access string
	secret string
	role   string
}

func getBucketName() string {
	bcktCount.Add(1)
	return fmt.Sprintf("test-bucket-%v", bcktCount.Load())
}

func getUser(role string) user {
	return user{
		access: fmt.Sprintf("test-user-%v", genRandString(16)),
		secret: fmt.Sprintf("test-secret-%v", genRandString(16)),
		role:   role,
	}
}

func setup(s *S3Conf, bucket string, opts ...setupOpt) error {
	s3client := s.GetClient()

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

	if cfg.VersioningStatus != "" {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{
			Bucket: &bucket,
			VersioningConfiguration: &types.VersioningConfiguration{
				Status: cfg.VersioningStatus,
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
	s3client := s.GetClient()

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
	LockEnabled      bool
	VersioningStatus types.BucketVersioningStatus
	Ownership        types.ObjectOwnership
	Anonymous        bool
	SkipTearDown     bool
}

type setupOpt func(*setupCfg)

func withLock() setupOpt {
	return func(s *setupCfg) { s.LockEnabled = true }
}
func withOwnership(o types.ObjectOwnership) setupOpt {
	return func(s *setupCfg) { s.Ownership = o }
}
func withVersioning(v types.BucketVersioningStatus) setupOpt {
	return func(s *setupCfg) { s.VersioningStatus = v }
}
func withAnonymousClient() setupOpt {
	return func(s *setupCfg) { s.Anonymous = true }
}
func withSkipTearDown() setupOpt {
	return func(s *setupCfg) { s.SkipTearDown = true }
}

func actionHandler(s *S3Conf, testName string, handler func(s3client *s3.Client, bucket string) error, opts ...setupOpt) error {
	runF(testName)
	bucketName := getBucketName()

	cfg := new(setupCfg)
	for _, opt := range opts {
		opt(cfg)
	}

	err := setup(s, bucketName, opts...)
	if err != nil {
		failF("%v: failed to create a bucket: %v", testName, err)
		return fmt.Errorf("%v: failed to create a bucket: %w", testName, err)
	}

	var client *s3.Client
	if cfg.Anonymous {
		client = s.GetAnonymousClient()
	} else {
		client = s.GetClient()
	}

	handlerErr := handler(client, bucketName)
	if handlerErr != nil {
		failF("%v: %v", testName, handlerErr)
	}

	if !cfg.SkipTearDown {
		err = teardown(s, bucketName)
		if err != nil {
			fmt.Printf(colorRed+"%v: failed to delete the bucket: %v", testName, err)
			if handlerErr == nil {
				return fmt.Errorf("%v: failed to delete the bucket: %w", testName, err)
			}
		}
	}
	if handlerErr == nil {
		passF(testName)
	}

	return handlerErr
}

func actionHandlerNoSetup(s *S3Conf, testName string, handler func(s3client *s3.Client, bucket string) error, _ ...setupOpt) error {
	runF(testName)
	client := s.GetClient()
	bucket := getBucketName()
	handlerErr := handler(client, bucket)
	if handlerErr != nil {
		failF("%v: %v", testName, handlerErr)
	}

	if handlerErr == nil {
		passF(testName)
	}

	return handlerErr
}

type authConfig struct {
	testName string
	path     string
	method   string
	body     []byte
	service  string
	date     time.Time
	headers  map[string]string
}

func authHandler(s *S3Conf, cfg *authConfig, handler func(req *http.Request) error) error {
	runF(cfg.testName)
	req, err := createSignedReq(cfg.method, s.endpoint, cfg.path, s.awsID, s.awsSecret, cfg.service, s.awsRegion, cfg.body, cfg.date, cfg.headers)
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

func presignedAuthHandler(s *S3Conf, testName string, handler func(client *s3.PresignClient, bucket string) error) error {
	runF(testName)
	bucket := getBucketName()
	err := setup(s, bucket)
	if err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}
	clt := s.GetPresignClient()

	err = handler(clt, bucket)
	if err != nil {
		failF("%v: %v", testName, err)
		return fmt.Errorf("%v: %w", testName, err)
	}

	err = teardown(s, bucket)
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

func checkHTTPResponseApiErr(resp *http.Response, apiErr s3err.APIError) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	resp.Body.Close()

	var errResp s3err.APIErrorResponse
	err = xml.Unmarshal(body, &errResp)
	if err != nil {
		return err
	}

	if resp.StatusCode != apiErr.HTTPStatusCode {
		return fmt.Errorf("expected response status code to be %v, instead got %v", apiErr.HTTPStatusCode, resp.StatusCode)
	}
	return compareS3ApiError(apiErr, &errResp)
}

func compareS3ApiError(expected s3err.APIError, received *s3err.APIErrorResponse) error {
	if received == nil {
		return fmt.Errorf("expected %w, received nil", expected)
	}

	if received.Code != expected.Code {
		return fmt.Errorf("expected error code to be %v, instead got %v", expected.Code, received.Code)
	}
	if received.Message != expected.Description {
		return fmt.Errorf("expected error message to be %v, instead got %v", expected.Description, received.Message)
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
		contents = append(contents, types.Object{
			Key:          &k,
			ETag:         res.ETag,
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

func constructObjectLocation(endpoint, bucket, object string, hostStyle bool) string {
	// Normalize endpoint (no trailing slash)
	endpoint = strings.TrimRight(endpoint, "/")

	if !hostStyle {
		// Path-style: http://endpoint/bucket/object
		return fmt.Sprintf("%s/%s/%s", endpoint, bucket, object)
	}

	// Host-style: http://bucket.endpoint/object
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		// Fallback for raw host:port endpoints (e.g. "127.0.0.1:7070")
		return fmt.Sprintf("http://%s.%s/%s", bucket, endpoint, object)
	}

	host := u.Host
	u.Host = fmt.Sprintf("%s.%s", bucket, host)

	return fmt.Sprintf("%s/%s", u.String(), object)
}

func hasObjNames(objs []types.Object, names []string) bool {
	if len(objs) != len(names) {
		return false
	}

	for _, obj := range objs {
		if slices.Contains(names, *obj.Key) {
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
		if slices.Contains(names, *prefix.Prefix) {
			continue
		}
		return false
	}

	return true
}

type putObjectOutput struct {
	csum [32]byte
	data []byte
	res  *s3.PutObjectOutput
}

func putObjectWithData(lgth int64, input *s3.PutObjectInput, client *s3.Client) (*putObjectOutput, error) {
	var csum [32]byte
	var data []byte
	if input.Body == nil {
		data = make([]byte, lgth)
		rand.Read(data)
		csum = sha256.Sum256(data)
		r := bytes.NewReader(data)
		input.Body = r
	}

	ctx, cancel := context.WithTimeout(context.Background(), longTimeout)
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

type mpCfg struct {
	checksumAlgorithm types.ChecksumAlgorithm
	checksumType      types.ChecksumType
	metadata          map[string]string
}

type mpOpt func(*mpCfg)

func withChecksum(algo types.ChecksumAlgorithm) mpOpt {
	return func(mc *mpCfg) { mc.checksumAlgorithm = algo }
}
func withChecksumType(t types.ChecksumType) mpOpt {
	return func(mc *mpCfg) { mc.checksumType = t }
}
func withMetadata(m map[string]string) mpOpt {
	return func(mc *mpCfg) { mc.metadata = m }
}

func createMp(s3client *s3.Client, bucket, key string, opts ...mpOpt) (*s3.CreateMultipartUploadOutput, error) {
	cfg := new(mpCfg)
	for _, opt := range opts {
		opt(cfg)
	}
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	out, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket:            &bucket,
		Key:               &key,
		ChecksumAlgorithm: cfg.checksumAlgorithm,
		ChecksumType:      cfg.checksumType,
		Metadata:          cfg.metadata,
	})
	cancel()
	return out, err
}

func isSameData(a, b []byte) bool {
	return bytes.Equal(a, b)
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
		if item.ChecksumAlgorithm != list2[i].ChecksumAlgorithm {
			return false
		}
		if item.ChecksumType != list2[i].ChecksumType {
			return false
		}
	}

	return true
}

func compareParts(parts1, parts2 []types.Part) bool {
	if len(parts1) != len(parts2) {
		fmt.Printf("list length are not equal: %v != %v\n", len(parts1), len(parts2))
		return false
	}

	for i, prt := range parts1 {
		if *prt.PartNumber != *parts2[i].PartNumber {
			fmt.Printf("partNumbers are not equal, %v != %v\n", *prt.PartNumber, *parts2[i].PartNumber)
			return false
		}
		if *prt.ETag != *parts2[i].ETag {
			fmt.Printf("etags are not equal, %v != %v\n", *prt.ETag, *parts2[i].ETag)
			return false
		}
		if *prt.Size != *parts2[i].Size {
			fmt.Printf("sizes are not equal, %v != %v\n", *prt.Size, *parts2[i].Size)
			return false
		}
		if prt.ChecksumCRC32 != nil {
			if *prt.ChecksumCRC32 != getString(parts2[i].ChecksumCRC32) {
				fmt.Printf("crc32 checksums are not equal, %v != %v\n", *prt.ChecksumCRC32, getString(parts2[i].ChecksumCRC32))
				return false
			}
		}
		if prt.ChecksumCRC32C != nil {
			if *prt.ChecksumCRC32C != getString(parts2[i].ChecksumCRC32C) {
				fmt.Printf("crc32c checksums are not equal, %v != %v\n", *prt.ChecksumCRC32C, getString(parts2[i].ChecksumCRC32C))
				return false
			}
		}
		if prt.ChecksumSHA1 != nil {
			if *prt.ChecksumSHA1 != getString(parts2[i].ChecksumSHA1) {
				fmt.Printf("sha1 checksums are not equal, %v != %v\n", *prt.ChecksumSHA1, getString(parts2[i].ChecksumSHA1))
				return false
			}
		}
		if prt.ChecksumSHA256 != nil {
			if *prt.ChecksumSHA256 != getString(parts2[i].ChecksumSHA256) {
				fmt.Printf("sha256 checksums are not equal, %v != %v\n", *prt.ChecksumSHA256, getString(parts2[i].ChecksumSHA256))
				return false
			}
		}
		if prt.ChecksumCRC64NVME != nil {
			if *prt.ChecksumCRC64NVME != getString(parts2[i].ChecksumCRC64NVME) {
				fmt.Printf("crc64nvme checksums are not equal, %v != %v\n", *prt.ChecksumCRC64NVME, getString(parts2[i].ChecksumCRC64NVME))
				return false
			}
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

func getPtr[T any](str T) *T {
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
		if mp1[key] != val {
			return false
		}
	}
	return true
}

func compareBuckets(list1 []types.Bucket, list2 []types.Bucket) bool {
	if len(list1) != len(list2) {
		return false
	}

	for i, elem := range list1 {
		if *elem.Name != *list2[i].Name {
			fmt.Printf("bucket names are not equal: %s != %s\n", *elem.Name, *list2[i].Name)
			return false
		}
		if *elem.BucketRegion != *list2[i].BucketRegion {
			fmt.Printf("bucket regions are not equal: %s != %s\n", *elem.BucketRegion, *list2[i].BucketRegion)
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
		if len(obj.ChecksumAlgorithm) != 0 {
			if obj.ChecksumAlgorithm[0] != list2[i].ChecksumAlgorithm[0] {
				fmt.Printf("checksum algorithms are not equal: (%q %q) %v != %v\n",
					*obj.Key, *list2[i].Key, obj.ChecksumAlgorithm[0], list2[i].ChecksumAlgorithm[0])
				return false
			}
		}
		if obj.ChecksumType != "" {
			if obj.ChecksumType[0] != list2[i].ChecksumType[0] {
				fmt.Printf("checksum types are not equal: (%q %q) %v != %v\n",
					*obj.Key, *list2[i].Key, obj.ChecksumType, list2[i].ChecksumType)
				return false
			}
		}
		if obj.Owner != nil {
			if *obj.Owner.ID != *list2[i].Owner.ID {
				fmt.Printf("object owner IDs not equal: (%q %q) %v != %v\n",
					*obj.Key, *list2[i].Key, *obj.Owner.ID, *list2[i].Owner.ID)
			}
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

func uploadParts(client *s3.Client, size, partCount int64, bucket, key, uploadId string, opts ...mpOpt) (parts []types.Part, csum string, err error) {
	partSize := size / partCount

	var hash hash.Hash

	cfg := new(mpCfg)
	for _, opt := range opts {
		opt(cfg)
	}

	switch cfg.checksumAlgorithm {
	case types.ChecksumAlgorithmCrc32:
		hash = crc32.NewIEEE()
	case types.ChecksumAlgorithmCrc32c:
		hash = crc32.New(crc32.MakeTable(crc32.Castagnoli))
	case types.ChecksumAlgorithmSha1:
		hash = sha1.New()
	case types.ChecksumAlgorithmSha256:
		hash = sha256.New()
	case types.ChecksumAlgorithmCrc64nvme:
		hash = crc64.New(crc64.MakeTable(bits.Reverse64(0xad93d23594c93659)))
	default:
		hash = sha256.New()
	}

	for partNumber := int64(1); partNumber <= partCount; partNumber++ {
		partStart := (partNumber - 1) * partSize
		partEnd := partStart + partSize - 1
		if partEnd > size-1 {
			partEnd = size - 1
		}

		partBuffer := make([]byte, partEnd-partStart+1)
		rand.Read(partBuffer)
		hash.Write(partBuffer)

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		pn := int32(partNumber)
		out, err := client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:            &bucket,
			Key:               &key,
			UploadId:          &uploadId,
			Body:              bytes.NewReader(partBuffer),
			PartNumber:        &pn,
			ChecksumAlgorithm: cfg.checksumAlgorithm,
		})
		cancel()
		if err != nil {
			return parts, "", err
		}

		part := types.Part{
			ETag:       out.ETag,
			PartNumber: &pn,
			Size:       &partSize,
		}

		switch cfg.checksumAlgorithm {
		case types.ChecksumAlgorithmCrc32:
			part.ChecksumCRC32 = out.ChecksumCRC32
		case types.ChecksumAlgorithmCrc32c:
			part.ChecksumCRC32C = out.ChecksumCRC32C
		case types.ChecksumAlgorithmSha1:
			part.ChecksumSHA1 = out.ChecksumSHA1
		case types.ChecksumAlgorithmSha256:
			part.ChecksumSHA256 = out.ChecksumSHA256
		case types.ChecksumAlgorithmCrc64nvme:
			part.ChecksumCRC64NVME = out.ChecksumCRC64NVME
		}

		parts = append(parts, part)
	}
	sum := hash.Sum(nil)

	if cfg.checksumAlgorithm == "" {
		csum = hex.EncodeToString(sum[:])
	} else {
		csum = base64.StdEncoding.EncodeToString(sum[:])
	}

	return parts, csum, err
}

func createUsers(s *S3Conf, users []user) error {
	for _, usr := range users {
		out, err := execCommand(s.getAdminCommand("-a", s.awsID, "-s", s.awsSecret, "-er", s.endpoint, "create-user", "-a", usr.access, "-s", usr.secret, "-r", usr.role)...)
		if err != nil {
			return err
		}
		if strings.Contains(string(out), adminErrorPrefix) {
			return fmt.Errorf("failed to create user account: %s", out)
		}
	}
	return nil
}

func changeBucketsOwner(s *S3Conf, buckets []string, owner string) error {
	for _, bucket := range buckets {
		out, err := execCommand(s.getAdminCommand("-a", s.awsID, "-s", s.awsSecret, "-er", s.endpoint, "change-bucket-owner", "-b", bucket, "-o", owner)...)
		if err != nil {
			return err
		}
		if strings.Contains(string(out), adminErrorPrefix) {
			return fmt.Errorf("failed to change the bucket owner: %s", out)
		}
	}

	return nil
}

func listBuckets(s *S3Conf) error {
	out, err := execCommand(s.getAdminCommand("-a", s.awsID, "-s", s.awsSecret, "-er", s.endpoint, "list-buckets")...)
	if err != nil {
		return err
	}
	if strings.Contains(string(out), adminErrorPrefix) {
		return fmt.Errorf("failed to list buckets, %s", out)
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
	jsonTemplate := `{
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

type policyType string

const (
	policyTypeBucket policyType = "bucket"
	policyTypeObject policyType = "object"
	policyTypeFull   policyType = "full"
)

func grantPublicBucketPolicy(client *s3.Client, bucket string, tp policyType) error {
	var doc string

	switch tp {
	case policyTypeBucket:
		doc = genPolicyDoc("Allow", `"*"`, `"s3:*"`, fmt.Sprintf(`"arn:aws:s3:::%s"`, bucket))
	case policyTypeObject:
		doc = genPolicyDoc("Allow", `"*"`, `"s3:*"`, fmt.Sprintf(`"arn:aws:s3:::%s/*"`, bucket))
	case policyTypeFull:
		template := `{
			"Statement": [
				{
					"Effect":  "Allow",
					"Principal": "*",
					"Action":  "s3:*",
					"Resource":  "arn:aws:s3:::%s"
				},
				{
					"Effect":  "Allow",
					"Principal": "*",
					"Action":  "s3:*",
					"Resource":  "arn:aws:s3:::%s/*"
				}
			]
		}
		`
		doc = fmt.Sprintf(template, bucket, bucket)
	}
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	_, err := client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
		Bucket: &bucket,
		Policy: &doc,
	})
	cancel()
	return err
}

func getMalformedPolicyError(msg string) s3err.APIError {
	return s3err.APIError{
		Code:           "MalformedPolicy",
		Description:    msg,
		HTTPStatusCode: http.StatusBadRequest,
	}
}

func putBucketVersioningStatus(client *s3.Client, bucket string, status types.BucketVersioningStatus) error {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	_, err := client.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{
		Bucket: &bucket,
		VersioningConfiguration: &types.VersioningConfiguration{
			Status: status,
		},
	})
	cancel()

	return err
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

type versCfg struct {
	checksumAlgorithm types.ChecksumAlgorithm
}

type versOpt func(*versCfg)

func withChecksumAlgo(algo types.ChecksumAlgorithm) versOpt {
	return func(vc *versCfg) { vc.checksumAlgorithm = algo }
}

func createObjVersions(client *s3.Client, bucket, object string, count int, opts ...versOpt) ([]types.ObjectVersion, error) {
	cfg := new(versCfg)
	for _, o := range opts {
		o(cfg)
	}

	versions := []types.ObjectVersion{}
	for i := range count {
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
		version := types.ObjectVersion{
			ETag:         r.res.ETag,
			IsLatest:     &isLatest,
			Key:          &object,
			Size:         &dataLength,
			VersionId:    r.res.VersionId,
			StorageClass: types.ObjectVersionStorageClassStandard,
			ChecksumType: r.res.ChecksumType,
		}

		switch {
		case r.res.ChecksumCRC32 != nil:
			version.ChecksumAlgorithm = []types.ChecksumAlgorithm{
				types.ChecksumAlgorithmCrc32,
			}
		case r.res.ChecksumCRC32C != nil:
			version.ChecksumAlgorithm = []types.ChecksumAlgorithm{
				types.ChecksumAlgorithmCrc32c,
			}
		case r.res.ChecksumCRC64NVME != nil:
			version.ChecksumAlgorithm = []types.ChecksumAlgorithm{
				types.ChecksumAlgorithmCrc64nvme,
			}
		case r.res.ChecksumSHA1 != nil:
			version.ChecksumAlgorithm = []types.ChecksumAlgorithm{
				types.ChecksumAlgorithmSha1,
			}
		case r.res.ChecksumSHA256 != nil:
			version.ChecksumAlgorithm = []types.ChecksumAlgorithm{
				types.ChecksumAlgorithmSha256,
			}
		}

		versions = append(versions, version)
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

		if version.StorageClass != v2[i].StorageClass {
			return false
		}
		if version.ChecksumType != "" {
			if version.ChecksumType != v2[i].ChecksumType {
				return false
			}
		}
		if len(version.ChecksumAlgorithm) != 0 {
			if len(v2[i].ChecksumAlgorithm) == 0 {
				return false
			}
			if version.ChecksumAlgorithm[0] != v2[i].ChecksumAlgorithm[0] {
				return false
			}
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

type ObjectMetaProps struct {
	ContentLength      int64
	ContentType        string
	ContentEncoding    string
	ContentDisposition string
	ContentLanguage    string
	CacheControl       string
	ExpiresString      string
	Metadata           map[string]string
}

func checkObjectMetaProps(client *s3.Client, bucket, object string, o ObjectMetaProps) error {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	out, err := client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: &bucket,
		Key:    &object,
	})
	cancel()
	if err != nil {
		return err
	}

	if o.Metadata != nil {
		if !areMapsSame(out.Metadata, o.Metadata) {
			return fmt.Errorf("expected the object metadata to be %v, instead got %v", o.Metadata, out.Metadata)
		}
	}
	if out.ContentLength == nil {
		return fmt.Errorf("expected Content-Length %v, instead got nil", o.ContentLength)
	}
	if *out.ContentLength != o.ContentLength {
		return fmt.Errorf("expected Content-Length %v, instead got %v", o.ContentLength, *out.ContentLength)
	}
	if o.ContentType != "" && getString(out.ContentType) != o.ContentType {
		return fmt.Errorf("expected Content-Type %v, instead got %v", o.ContentType, getString(out.ContentType))
	}
	if o.ContentDisposition != "" && getString(out.ContentDisposition) != o.ContentDisposition {
		return fmt.Errorf("expected Content-Disposition %v, instead got %v", o.ContentDisposition, getString(out.ContentDisposition))
	}
	if o.ContentEncoding != "" && getString(out.ContentEncoding) != o.ContentEncoding {
		return fmt.Errorf("expected Content-Encoding %v, instead got %v", o.ContentEncoding, getString(out.ContentEncoding))
	}
	if o.ContentLanguage != "" && getString(out.ContentLanguage) != o.ContentLanguage {
		return fmt.Errorf("expected Content-Language %v, instead got %v", o.ContentLanguage, getString(out.ContentLanguage))
	}
	if o.CacheControl != "" && getString(out.CacheControl) != o.CacheControl {
		return fmt.Errorf("expected Cache-Control %v, instead got %v", o.CacheControl, getString(out.CacheControl))
	}
	if o.ExpiresString != "" && getString(out.ExpiresString) != o.ExpiresString {
		return fmt.Errorf("expected Expires %v, instead got %v", o.ExpiresString, getString(out.ExpiresString))
	}
	if out.StorageClass != types.StorageClassStandard {
		return fmt.Errorf("expected the storage class to be %v, instead got %v", types.StorageClassStandard, out.StorageClass)
	}

	return nil
}

func getBoolPtr(b bool) *bool {
	return &b
}

type PublicBucketTestCase struct {
	Action      string
	Call        func(ctx context.Context) error
	ExpectedErr error
}

// randomizeCase randomizes the provided string latters case
func randomizeCase(s string) string {
	var b strings.Builder

	for _, ch := range s {
		if rnd.Intn(2) == 0 {
			b.WriteRune(unicode.ToLower(ch))
		} else {
			b.WriteRune(unicode.ToUpper(ch))
		}
	}

	return b.String()
}

func headObject_zero_len_with_range_helper(testName, obj string, s *S3Conf) error {
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objLength := int64(0)
		_, err := putObjectWithData(objLength, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		testRange := func(rg, contentRange string, cLength int64, expectErr bool) error {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			res, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket: &bucket,
				Key:    &obj,
				Range:  &rg,
			})
			cancel()
			if err == nil && expectErr {
				return fmt.Errorf("%v: expected err 'RequestedRangeNotSatisfiable' error, instead got nil", rg)
			}
			if err != nil {
				if !expectErr {
					return err
				}
				var ae smithy.APIError
				if errors.As(err, &ae) {
					if ae.ErrorCode() != "RequestedRangeNotSatisfiable" {
						return fmt.Errorf("%v: expected RequestedRangeNotSatisfiable, instead got %v", rg, ae.ErrorCode())
					}
					if ae.ErrorMessage() != "Requested Range Not Satisfiable" {
						return fmt.Errorf("%v: expected the error message to be 'Requested Range Not Satisfiable', instead got %v", rg, ae.ErrorMessage())
					}
					return nil
				}
				return fmt.Errorf("%v: invalid error got %w", rg, err)
			}

			if getString(res.AcceptRanges) != "bytes" {
				return fmt.Errorf("%v: expected accept ranges to be 'bytes', instead got %v", rg, getString(res.AcceptRanges))
			}
			if res.ContentLength == nil {
				return fmt.Errorf("%v: expected non nil content-length", rg)
			}
			if *res.ContentLength != cLength {
				return fmt.Errorf("%v: expected content-length to be %v, instead got %v", rg, cLength, *res.ContentLength)
			}
			if getString(res.ContentRange) != contentRange {
				return fmt.Errorf("%v: expected content-range to be %v, instead got %v", rg, contentRange, getString(res.ContentRange))
			}
			return nil
		}

		// Reference server expectations for a 0-byte object.
		for _, el := range []struct {
			objRange      string
			contentRange  string
			contentLength int64
			expectedErr   bool
		}{
			{"bytes=abc", "", objLength, false},
			{"bytes=a-z", "", objLength, false},
			{"bytes=,", "", objLength, false},
			{"bytes=0-0,1-2", "", objLength, false},
			{"foo=0-1", "", objLength, false},
			{"bytes=--1", "", objLength, false},
			{"bytes=0--1", "", objLength, false},
			{"bytes= -1", "", objLength, false},
			{"bytes=0 -1", "", objLength, false},
			{"bytes=-1", "", objLength, false},   // reference server returns no error, empty Content-Range
			{"bytes=00-01", "", objLength, true}, // RequestedRangeNotSatisfiable
			{"bytes=-0", "", 0, true},
			{"bytes=0-0", "", 0, true},
			{"bytes=0-", "", 0, true},
		} {
			if err := testRange(el.objRange, el.contentRange, el.contentLength, el.expectedErr); err != nil {
				return err
			}
		}
		return nil
	})
}

func getObject_zero_len_with_range_helper(testName, obj string, s *S3Conf) error {
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objLength := int64(0)
		res, err := putObjectWithData(objLength, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		testGetObjectRange := func(rng, contentRange string, cLength int64, expData []byte, expErr error) error {
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			defer cancel()
			out, err := s3client.GetObject(ctx, &s3.GetObjectInput{
				Bucket: &bucket,
				Key:    &obj,
				Range:  &rng,
			})
			if err == nil && expErr != nil {
				return fmt.Errorf("%v: expected err %v, instead got nil", rng, expErr)
			}
			if err != nil {
				if expErr == nil {
					return err
				}
				parsedErr, ok := expErr.(s3err.APIError)
				if !ok {
					return fmt.Errorf("invalid error type provided, expected s3err.APIError")
				}
				return checkApiErr(err, parsedErr)
			}

			if out.ContentLength == nil {
				return fmt.Errorf("%v: expected non nil content-length", rng)
			}
			if *out.ContentLength != cLength {
				return fmt.Errorf("%v: expected content-length to be %v, instead got %v", rng, cLength, *out.ContentLength)
			}
			if getString(out.AcceptRanges) != "bytes" {
				return fmt.Errorf("%v: expected accept-ranges to be 'bytes', instead got %v", rng, getString(out.AcceptRanges))
			}
			if getString(out.ContentRange) != contentRange {
				return fmt.Errorf("%v: expected content-range to be %v, instead got %v", rng, contentRange, getString(out.ContentRange))
			}

			data, err := io.ReadAll(out.Body)
			if err != nil {
				return fmt.Errorf("%v: read object data: %w", rng, err)
			}
			out.Body.Close()
			if !isSameData(data, expData) {
				return fmt.Errorf("%v: incorrect data retrieved", rng)
			}
			return nil
		}

		for _, el := range []struct {
			rng          string
			contentRange string
			cLength      int64
			expData      []byte
			expErr       error
		}{
			{"bytes=abc", "", objLength, res.data, nil},
			{"bytes=a-z", "", objLength, res.data, nil},
			{"bytes=,", "", objLength, res.data, nil},
			{"bytes=0-0,1-2", "", objLength, res.data, nil},
			{"foo=0-1", "", objLength, res.data, nil},
			{"bytes=--1", "", objLength, res.data, nil},
			{"bytes=0--1", "", objLength, res.data, nil},
			{"bytes= -1", "", objLength, res.data, nil},
			{"bytes=0 -1", "", objLength, res.data, nil},
			{"bytes=-1", "", objLength, res.data, nil},
			// error (RequestedRangeNotSatisfiable)
			{"bytes=00-01", "", objLength, nil, s3err.GetAPIError(s3err.ErrInvalidRange)},
			{"bytes=-0", "", 0, nil, s3err.GetAPIError(s3err.ErrInvalidRange)},
			{"bytes=0-0", "", 0, nil, s3err.GetAPIError(s3err.ErrInvalidRange)},
			{"bytes=0-", "", 0, nil, s3err.GetAPIError(s3err.ErrInvalidRange)},
		} {
			if err := testGetObjectRange(el.rng, el.contentRange, el.cLength, el.expData, el.expErr); err != nil {
				return err
			}
		}
		return nil
	})
}

func getInt32(ptr *int32) int32 {
	if ptr == nil {
		return 0
	}

	return *ptr
}

func putBucketCors(client *s3.Client, input *s3.PutBucketCorsInput) error {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	_, err := client.PutBucketCors(ctx, input)
	cancel()
	return err
}

func compareCorsConfig(expected, got []types.CORSRule) error {
	if expected == nil && got == nil {
		return nil
	}
	if got == nil {
		return errors.New("nil CORS config")
	}

	if len(expected) != len(got) {
		return fmt.Errorf("expected CORS rules length to be %v, instead got %v", len(expected), len(got))
	}

	for i, r := range expected {
		rule := got[i]
		if !slices.Equal(r.AllowedOrigins, rule.AllowedOrigins) {
			return fmt.Errorf("expected the allowed origins to be %v, instead got %v", r.AllowedOrigins, rule.AllowedOrigins)
		}
		if !slices.Equal(r.AllowedMethods, rule.AllowedMethods) {
			return fmt.Errorf("expected the allowed methods to be %v, instead got %v", r.AllowedMethods, rule.AllowedMethods)
		}
		if !slices.Equal(r.AllowedHeaders, rule.AllowedHeaders) {
			return fmt.Errorf("expected the allowed headers to be %v, instead got %v", r.AllowedHeaders, rule.AllowedHeaders)
		}
		if !slices.Equal(r.ExposeHeaders, rule.ExposeHeaders) {
			return fmt.Errorf("expected the allowed origins to be %v, instead got %v", r.ExposeHeaders, rule.ExposeHeaders)
		}
		if getInt32(r.MaxAgeSeconds) != getInt32(rule.MaxAgeSeconds) {
			return fmt.Errorf("expected the max age seconds to be %v, instead got %v", getInt32(r.MaxAgeSeconds), getInt32(rule.MaxAgeSeconds))
		}
		if getString(r.ID) != getString(rule.ID) {
			return fmt.Errorf("expected ID to be %v, instead got %v", getString(r.ID), getString(rule.ID))
		}
	}

	return nil
}

type PreflightResult struct {
	Origin           string
	Methods          string
	AllowHeaders     string
	ExposeHeaders    string
	MaxAge           string
	AllowCredentials string
	Vary             string
	err              error
}

func extractCORSHeaders(resp *http.Response) (*PreflightResult, error) {
	if resp.StatusCode >= 400 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("read response body: %w", err)
		}

		var errResp smithy.GenericAPIError
		err = xml.Unmarshal(body, &errResp)
		if err != nil {
			return nil, fmt.Errorf("unmarshal respone body: %w", err)
		}

		return &PreflightResult{
			err: &errResp,
		}, nil
	}

	return &PreflightResult{
		Origin:           resp.Header.Get("Access-Control-Allow-Origin"),
		Methods:          resp.Header.Get("Access-Control-Allow-Methods"),
		ExposeHeaders:    resp.Header.Get("Access-Control-Expose-Headers"),
		MaxAge:           resp.Header.Get("Access-Control-Max-Age"),
		AllowHeaders:     resp.Header.Get("Access-Control-Allow-Headers"),
		AllowCredentials: resp.Header.Get("Access-Control-Allow-Credentials"),
		Vary:             resp.Header.Get("Vary"),
	}, nil
}

func makeOPTIONSRequest(s *S3Conf, bucket, origin, method string, headers string) (*PreflightResult, error) {
	req, err := http.NewRequest(http.MethodOptions, fmt.Sprintf("%s/%s/object", s.endpoint, bucket), nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Add("Origin", origin)
	req.Header.Add("Access-Control-Request-Method", method)
	req.Header.Add("Access-Control-Request-Headers", headers)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}

	return extractCORSHeaders(resp)
}

func comparePreflightResult(expected, got *PreflightResult) error {
	if expected == nil {
		return fmt.Errorf("nil expected preflight request result")
	}
	if got == nil {
		return fmt.Errorf("expected the preflights result to be %v, instead got nil", *expected)
	}

	if expected.err != nil {
		if got.err == nil {
			return fmt.Errorf("expected %w error, instaed got nil", expected.err)
		}

		apiErr, ok := expected.err.(s3err.APIError)
		if !ok {
			return fmt.Errorf("expected s3err.APIError, instead got %w", expected.err)
		}

		return checkApiErr(got.err, apiErr)
	}

	if got.err != nil {
		return fmt.Errorf("expected no error, instaed got %w", got.err)
	}

	if expected.Origin != got.Origin {
		return fmt.Errorf("expected the origin to be %v, instead got %v", expected.Origin, got.Origin)
	}
	if expected.Methods != got.Methods {
		return fmt.Errorf("expected the allowed methods to be %v, instead got %v", expected.Methods, got.Methods)
	}
	if expected.AllowHeaders != got.AllowHeaders {
		return fmt.Errorf("expected the allow headers to be %v, instead got %v", expected.AllowHeaders, got.AllowHeaders)
	}
	if expected.ExposeHeaders != got.ExposeHeaders {
		return fmt.Errorf("expected the expose headers to be %v, instead got %v", expected.ExposeHeaders, got.ExposeHeaders)
	}
	if expected.MaxAge != got.MaxAge {
		return fmt.Errorf("expected the max age to be %v, instead got %v", expected.MaxAge, got.MaxAge)
	}
	if expected.AllowCredentials != got.AllowCredentials {
		return fmt.Errorf("expected the allow credentials to be %v, instead got %v", expected.AllowCredentials, got.AllowCredentials)
	}
	if expected.Vary != got.Vary {
		return fmt.Errorf("expected the Vary header to be %v, instead got %v", expected.Vary, got.Vary)
	}

	return nil
}

func testOPTIONSEdnpoint(s *S3Conf, bucket, origin, method string, headers string, expected *PreflightResult) error {
	result, err := makeOPTIONSRequest(s, bucket, origin, method, headers)
	if err != nil {
		return err
	}

	return comparePreflightResult(expected, result)
}

func calculateEtag(data []byte) (string, error) {
	h := md5.New()
	_, err := h.Write(data)
	if err != nil {
		return "", err
	}
	dataSum := h.Sum(nil)
	return fmt.Sprintf("\"%s\"", hex.EncodeToString(dataSum[:])), nil
}

func sprintBuckets(buckets []types.Bucket) string {
	if len(buckets) == 0 {
		return ""
	}

	names := make([]string, len(buckets))
	for i, bucket := range buckets {
		names[i] = *bucket.Name
	}

	return strings.Join(names, ",")
}

func sprintPrefixes(cpfx []types.CommonPrefix) string {
	if len(cpfx) == 0 {
		return ""
	}

	names := make([]string, len(cpfx))
	for i, pfx := range cpfx {
		names[i] = *pfx.Prefix
	}

	return strings.Join(names, ",")
}

func sprintVersions(objects []types.ObjectVersion) string {
	if len(objects) == 0 {
		return ""
	}

	names := make([]string, len(objects))
	for i, obj := range objects {
		names[i] = fmt.Sprintf("%v/%v", *obj.Key, obj.VersionId)
	}

	return strings.Join(names, ",")
}

// objToDelete represents the metadata of an object that needs to be deleted.
// It holds details like the key, version, and legal/compliance lock flags.
type objToDelete struct {
	key                string // Object key (name) in the bucket
	versionId          string // Specific object version ID
	removeLegalHold    bool   // Whether to remove legal hold before deletion
	removeOnlyLeglHold bool   // Whether to only remove legal hold, without deletion
	isCompliance       bool   // Whether the object is under Compliance mode retention
}

// Worker and retry configuration for deleting locked objects
const (
	maxDelObjWorkers int64         = 20              // Maximum number of concurrent delete workers
	maxRetryAttempts int           = 3               // Maximum retries for object deletion
	lockWaitTime     time.Duration = time.Second * 3 // Wait time for lock expiration before retrying delete
)

// cleanupLockedObjects removes objects from a bucket that may be protected by
// Object Lock (legal hold or retention).
// It handles both Governance and Compliance retention modes and retries deletions
// when necessary.
func cleanupLockedObjects(client *s3.Client, bucket string, objs []objToDelete) error {
	eg, ctx := errgroup.WithContext(context.Background())

	// Semaphore to limit the number of concurrent workers
	sem := semaphore.NewWeighted(maxDelObjWorkers)

	for _, obj := range objs {
		obj := obj // capture loop variable

		// Acquire worker slot before processing an object
		if err := sem.Acquire(ctx, 1); err != nil {
			return fmt.Errorf("failed to acquire worker space: %w", err)
		}

		defer sem.Release(1)

		eg.Go(func() error {
			// Remove legal hold if required
			if obj.removeLegalHold || obj.removeOnlyLeglHold {
				ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
				_, err := client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
					Bucket:    &bucket,
					Key:       &obj.key,
					VersionId: getPtr(obj.versionId),
					LegalHold: &types.ObjectLockLegalHold{
						Status: types.ObjectLockLegalHoldStatusOff, // Disable legal hold
					},
				})
				cancel()
				// If object was already deleted, ignore the error
				if errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchKey)) {
					return nil
				}
				if err != nil {
					return err
				}

				// If only the legal hold needs to be removed, stop here
				if obj.removeOnlyLeglHold {
					return nil
				}
			}

			// Apply temporary retention policy to allow deletion
			// RetainUntilDate is set a few seconds in the future to handle network delays
			retDate := time.Now().Add(lockWaitTime)
			mode := types.ObjectLockRetentionModeGovernance
			if obj.isCompliance {
				mode = types.ObjectLockRetentionModeCompliance
			}

			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			_, err := client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
				Bucket:    &bucket,
				Key:       &obj.key,
				VersionId: getPtr(obj.versionId),
				Retention: &types.ObjectLockRetention{
					Mode:            mode,
					RetainUntilDate: &retDate,
				},
			})
			cancel()

			// If object was already deleted, ignore the error
			if errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchKey)) {
				return nil
			}
			if err != nil {
				return err
			}

			// Wait until retention lock expires before attempting delete
			time.Sleep(lockWaitTime)

			// Attempt deletion with retries
			attempts := 0
			for attempts != maxRetryAttempts {
				ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
				_, err = client.DeleteObject(ctx, &s3.DeleteObjectInput{
					Bucket:    &bucket,
					Key:       &obj.key,
					VersionId: getPtr(obj.versionId),
				})
				cancel()
				if err != nil {
					// Retry after a short delay if delete fails
					time.Sleep(time.Second)
					attempts++
					continue
				}

				// Success, no more retries needed
				return nil
			}

			// Return last error if all retries failed
			return err
		})
	}

	// Wait for all goroutines to finish, return any error encountered
	return eg.Wait()
}

type objectLockMode string

const (
	objectLockModeLegalHold  = "legal-hold"
	objectLockModeGovernance = "governance"
	objectLockModeCompliance = "compliance"
)

func lockObject(client *s3.Client, mode objectLockMode, bucket, object, versionId string) error {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	var m types.ObjectLockRetentionMode
	switch mode {
	case objectLockModeLegalHold:
		_, err := client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
			Bucket:    &bucket,
			Key:       &object,
			VersionId: getPtr(versionId),
			LegalHold: &types.ObjectLockLegalHold{
				Status: types.ObjectLockLegalHoldStatusOn,
			},
		})
		return err
	case objectLockModeCompliance:
		m = types.ObjectLockRetentionModeCompliance
	case objectLockModeGovernance:
		m = types.ObjectLockRetentionModeGovernance
	default:
		return fmt.Errorf("invalid object lock mode: %s", mode)
	}

	date := time.Now().Add(time.Hour * 3)
	_, err := client.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
		Bucket:    &bucket,
		Key:       &object,
		VersionId: getPtr(versionId),
		Retention: &types.ObjectLockRetention{
			Mode:            m,
			RetainUntilDate: &date,
		},
	})
	return err
}

func NewHasher(algo types.ChecksumAlgorithm) (hash.Hash, error) {
	var hasher hash.Hash
	switch algo {
	case types.ChecksumAlgorithmSha256:
		hasher = sha256.New()
	case types.ChecksumAlgorithmSha1:
		hasher = sha1.New()
	case types.ChecksumAlgorithmCrc32:
		hasher = crc32.NewIEEE()
	case types.ChecksumAlgorithmCrc32c:
		hasher = crc32.New(crc32.MakeTable(crc32.Castagnoli))
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %s", algo)
	}

	return hasher, nil
}

func processCompositeChecksum(hasher hash.Hash, checksum string) error {
	data, err := base64.StdEncoding.DecodeString(checksum)
	if err != nil {
		return fmt.Errorf("base64 decode: %w", err)
	}

	_, err = hasher.Write(data)
	if err != nil {
		return fmt.Errorf("hash write: %w", err)
	}

	return nil
}

type mpinfo struct {
	uploadId *string
	parts    []types.CompletedPart
}

func putBucketPolicy(client *s3.Client, bucket, policy string) error {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	_, err := client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
		Bucket: &bucket,
		Policy: &policy,
	})
	cancel()
	return err
}

func sendSignedRequest(s *S3Conf, req *http.Request, cancel context.CancelFunc) (map[string]string, *s3err.APIErrorResponse, error) {
	signer := v4.NewSigner()
	signErr := signer.SignHTTP(req.Context(), aws.Credentials{AccessKeyID: s.awsID, SecretAccessKey: s.awsSecret}, req, "STREAMING-UNSIGNED-PAYLOAD-TRAILER", "s3", s.awsRegion, time.Now())
	if signErr != nil {
		cancel()
		return nil, nil, fmt.Errorf("failed to sign the request: %w", signErr)
	}

	resp, err := s.httpClient.Do(req)
	cancel()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to send the request: %w", err)
	}

	if resp.StatusCode >= 300 {
		defer resp.Body.Close()
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read the request body: %w", err)
		}

		var errResp s3err.APIErrorResponse
		err = xml.Unmarshal(bodyBytes, &errResp)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal response body: %w", err)
		}

		return nil, &errResp, nil
	}

	headers := map[string]string{}
	for key, val := range resp.Header {
		headers[strings.ToLower(key)] = val[0]
	}

	return headers, nil, nil
}

func testUnsignedStreamingPayloadTrailerObjectPut(s *S3Conf, bucket, object string, body []byte, reqHeaders map[string]string) (map[string]string, *s3err.APIErrorResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, s.endpoint+"/"+bucket+"/"+object, bytes.NewReader(body))
	if err != nil {
		cancel()
		return nil, nil, fmt.Errorf("failed to create a request: %w", err)
	}

	req.Header.Add("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
	for key, val := range reqHeaders {
		req.Header.Add(key, val)
	}

	return sendSignedRequest(s, req, cancel)
}

func testUnsignedStreamingPayloadTrailerUploadPart(s *S3Conf, bucket, object string, uploadId *string, body []byte, reqHeaders map[string]string) (map[string]string, *s3err.APIErrorResponse, error) {
	if uploadId == nil {
		return nil, nil, fmt.Errorf("empty upload id")
	}

	uri := fmt.Sprintf("%s/%s/%s?uploadId=%s&partNumber=%v", s.endpoint, bucket, object, *uploadId, 1)
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, uri, bytes.NewReader(body))
	if err != nil {
		cancel()
		return nil, nil, fmt.Errorf("failed to create a request: %w", err)
	}

	req.Header.Add("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
	for key, val := range reqHeaders {
		req.Header.Add(key, val)
	}

	return sendSignedRequest(s, req, cancel)
}

// constructUnsignedPaylod constructs an unsigned streaming upload payload
// and returns the decoded content length and the payload
func constructUnsignedPaylod(chunkSizes ...int64) (int64, []byte, error) {
	var cLength int64
	buffer := bytes.NewBuffer([]byte{})

	for _, chunkSize := range chunkSizes {
		cLength += chunkSize
		_, err := buffer.WriteString(fmt.Sprintf("%x\r\n", chunkSize))
		if err != nil {
			return 0, nil, err
		}
		_, err = buffer.WriteString(strings.Repeat("a", int(chunkSize)))
		if err != nil {
			return 0, nil, err
		}
		_, err = buffer.WriteString("\r\n")
		if err != nil {
			return 0, nil, err
		}
	}

	return cLength, buffer.Bytes(), nil
}

type signedReqCfg struct {
	headers          map[string]string
	chunkSize        int64
	modifFrom        *int
	modifTo          *int
	modifPayload     []byte
	trailingChecksum *string
	isTrailer        bool
}

type signedReqOpt func(*signedReqCfg)

func withCustomHeaders(h map[string]string) signedReqOpt {
	return func(src *signedReqCfg) { src.headers = h }
}

func withChunkSize(s int64) signedReqOpt {
	return func(src *signedReqCfg) { src.chunkSize = s }
}

func withModifyPayload(from int, to int, p []byte) signedReqOpt {
	return func(src *signedReqCfg) {
		src.modifPayload = p
		src.modifFrom = &from
		src.modifTo = &to
	}
}

func withTrailingChecksum(checksum string) signedReqOpt {
	return func(src *signedReqCfg) {
		src.trailingChecksum = &checksum
		src.isTrailer = true
	}
}

func testSignedStreamingObjectPut(s *S3Conf, bucket, object string, payload []byte, opts ...signedReqOpt) (map[string]string, *s3err.APIErrorResponse, error) {
	cfg := &signedReqCfg{
		chunkSize: 8192, // minimal valid chunk size
	}

	for _, opt := range opts {
		opt(cfg)
	}

	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	// create a request with no body
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, fmt.Sprintf("%s/%s/%s", s.endpoint, bucket, object), nil)
	if err != nil {
		return nil, nil, cancelAndError(fmt.Errorf("failed to create a request: %w", err), cancel)
	}

	var payloadOffset int64
	var trailerLength int

	// any planned modification which is going to affect the
	// Content-Length header value
	if cfg.modifFrom != nil && cfg.modifTo != nil {
		diff := len(cfg.modifPayload) - *cfg.modifTo + *cfg.modifFrom
		payloadOffset = int64(diff)
	}
	if cfg.isTrailer {
		trailerLength = len(*cfg.trailingChecksum)
	}
	// precalculated the Content-Length header to correctly sign the request
	req.ContentLength = calculateSignedReqContentLength(int64(len(payload)), cfg.chunkSize, payloadOffset, cfg.isTrailer, int64(trailerLength))
	sha256Header := "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
	if cfg.isTrailer {
		sha256Header = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
	}
	req.Header.Set("x-amz-decoded-content-length", fmt.Sprint(len(payload)))
	req.Header.Set("x-amz-content-sha256", sha256Header)

	// set custom request headers
	for key, val := range cfg.headers {
		req.Header.Set(key, val)
	}

	signer := v4.NewSigner()
	signingTime := time.Now()

	// sign the request
	err = signer.SignHTTP(ctx, aws.Credentials{AccessKeyID: s.awsID, SecretAccessKey: s.awsSecret}, req, sha256Header, "s3", s.awsRegion, signingTime)
	if err != nil {
		return nil, nil, cancelAndError(fmt.Errorf("failed to sign the request: %w", err), cancel)
	}

	// extract the seed signature
	seedSignature, err := extractSignature(req)
	if err != nil {
		return nil, nil, cancelAndError(fmt.Errorf("failed to extract seed signature: %w", err), cancel)
	}

	// initialize v4 stream signed
	streamSigner := v4.NewStreamSigner(aws.Credentials{AccessKeyID: s.awsID, SecretAccessKey: s.awsSecret}, "s3", s.awsRegion, seedSignature)
	// create the signed payload
	body, err := constructSignedStreamingPayload(ctx, streamSigner, signingTime, payload, cfg.chunkSize, cfg.trailingChecksum, s.awsRegion, s.awsSecret)
	if err != nil {
		return nil, nil, cancelAndError(fmt.Errorf("failed to encode req body: %w", err), cancel)
	}

	// overwrite body bytes by configuration
	if cfg.modifFrom != nil && cfg.modifTo != nil {
		body, err = replaceRange(body, cfg.modifPayload, *cfg.modifFrom, *cfg.modifTo)
		if err != nil {
			return nil, nil, cancelAndError(fmt.Errorf("failed replace body bytes: %w", err), cancel)
		}
	}

	// assign req.Body and req.GetBody for the http client
	// to handle the request
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}

	// send the request
	resp, err := s.httpClient.Do(req)
	cancel()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to send the request: %w", err)
	}

	if resp.StatusCode >= 300 {
		defer resp.Body.Close()
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read the response body: %w", err)
		}

		var errResp s3err.APIErrorResponse
		err = xml.Unmarshal(bodyBytes, &errResp)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal response body: %w", err)
		}
		return nil, &errResp, nil
	}

	headers := map[string]string{}
	for key, val := range resp.Header {
		headers[strings.ToLower(key)] = val[0]
	}

	return headers, nil, nil
}

func cancelAndError(err error, cancel context.CancelFunc) error {
	cancel()
	return err
}

const (
	chunkSigHdrLength int64 = 81
	trailerSigLength  int64 = 88
)

// calculateSignedReqContentLength calculates the value of `Content-Length` header
// sizeOffset marks any planned changes on the body, which will affect the size
func calculateSignedReqContentLength(decPayloadSize int64, chunkSize int64, sizeOffset int64, withTrailer bool, trailerLength int64) int64 {
	payloadSize := decPayloadSize
	var chunkHeadersLength int64

	if withTrailer {
		chunkHeadersLength += trailerLength + 4 + trailerSigLength
	}

	// special case when chunk size is greater or equal than decoded content length
	if chunkSize >= decPayloadSize {
		chSizeLgth := len(fmt.Sprintf("%x", decPayloadSize))
		return decPayloadSize + sizeOffset + int64(chSizeLgth) + 2*chunkSigHdrLength + 9 + chunkHeadersLength
	}

	for {
		if payloadSize == 0 {
			chunkHeadersLength += chunkSigHdrLength + 5
			break
		}
		if payloadSize < chunkSize {
			chunkHeadersLength += 2*chunkSigHdrLength + 9 + int64(len(fmt.Sprintf("%x", payloadSize)))
			break
		}
		chSizeLgth := len(fmt.Sprintf("%x", chunkSize))
		chunkHeadersLength += int64(chSizeLgth) + chunkSigHdrLength + 4

		payloadSize -= chunkSize
	}

	return chunkHeadersLength + decPayloadSize + sizeOffset
}

// constructSignedStreamingPayload creates chunk encoded payload with signatures.
func constructSignedStreamingPayload(ctx context.Context, signer *v4.StreamSigner, signingTime time.Time, payload []byte, chunkSize int64, trailer *string, region, secret string) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	payloadLen := int64(len(payload))

	if chunkSize > payloadLen {
		chunkSize = payloadLen
	}

	for i := int64(0); i < payloadLen; i += chunkSize {
		if i+chunkSize > payloadLen {
			offset := payloadLen - i
			sig, err := signer.GetSignature(ctx, nil, payload[i:i+offset], signingTime)
			if err != nil {
				return nil, err
			}

			_, err = buf.WriteString(fmt.Sprintf("%x;chunk-signature=%x\r\n%s\r\n", offset, sig, payload[i:i+offset]))
			if err != nil {
				return nil, err
			}
			break
		}

		sig, err := signer.GetSignature(ctx, nil, payload[i:i+chunkSize], signingTime)
		if err != nil {
			return nil, err
		}

		_, err = buf.WriteString(fmt.Sprintf("%x;chunk-signature=%x\r\n%s\r\n", chunkSize, sig, payload[i:i+chunkSize]))
		if err != nil {
			return nil, err
		}
	}

	sig, err := signer.GetSignature(ctx, nil, nil, signingTime)
	if err != nil {
		return nil, err
	}

	if trailer != nil {
		_, err = buf.WriteString(fmt.Sprintf("0;chunk-signature=%x\r\n", sig))
		if err != nil {
			return nil, err
		}

		sigKey := getSigningKey(secret, signingTime.Format("20060102"), region)
		trailerSig, err := getAWS4StreamingTrailer(sigKey, sig, signingTime, region, *trailer)
		if err != nil {
			return nil, err
		}

		_, err = buf.WriteString(fmt.Sprintf("%s\r\nx-amz-trailer-signature:%s\r\n\r\n", *trailer, trailerSig))
		if err != nil {
			return nil, err
		}

		return buf.Bytes(), nil
	}

	_, err = buf.WriteString(fmt.Sprintf("0;chunk-signature=%x\r\n\r\n", sig))
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// extractSignature extracts the signature from Authorization header
func extractSignature(req *http.Request) ([]byte, error) {
	const key = "Signature="

	authHdr := req.Header.Get("Authorization")

	i := strings.Index(authHdr, key)
	if i == -1 {
		return nil, errors.New("signature not found")
	}

	sig := authHdr[i+len(key):]

	return hex.DecodeString(sig)
}

// replaceRange replaces dst[start:end] with src and returns the modified slice.
// Used for custom overwrite of request payload bytes.
func replaceRange(dst, src []byte, start, end int) ([]byte, error) {
	if start < 0 || end < start || end > len(dst) {
		return nil, fmt.Errorf("invalid start/end indexes")
	}

	newLen := len(dst) - (end - start) + len(src)

	// Fast path: reuse dst capacity if possible
	if cap(dst) >= newLen {
		// Extend or shrink dst
		dst = dst[:newLen]

		// Move the tail if sizes differ
		copy(dst[start+len(src):], dst[end:])

		// Copy replacement
		copy(dst[start:], src)
		return dst, nil
	}

	// Fallback: allocate new slice
	out := make([]byte, newLen)
	copy(out, dst[:start])
	copy(out[start:], src)
	copy(out[start+len(src):], dst[end:])
	return out, nil
}

func getAWS4StreamingTrailer(
	signingKey,
	lastSignature []byte,
	signingTime time.Time,
	awsRegion,
	trailer string,
) (string, error) {

	// yyyyMMdd
	yearMonthDay := signingTime.Format("20060102")

	// ISO8601 basic format: yyyyMMdd'T'HHmmss'Z'
	currentDateTime := signingTime.UTC().Format("20060102T150405Z")

	// <date>/<region>/<service>/aws4_request
	serviceString := fmt.Sprintf(
		"%s/%s/s3/aws4_request",
		yearMonthDay,
		awsRegion,
	)

	// Trailer must be newline-terminated for hashing/signing
	trailerWithNL := trailer + "\n"

	// Hash of trailer
	trailerHash := sha256.Sum256([]byte(trailerWithNL))
	trailerHashHex := hex.EncodeToString(trailerHash[:])

	// String-to-sign prefix
	stringToSignPrefix := fmt.Sprintf(
		"%s\n%s\n%s",
		"AWS4-HMAC-SHA256-TRAILER",
		currentDateTime,
		serviceString,
	)

	// Full string-to-sign
	stringToSign := fmt.Sprintf(
		"%s\n%x\n%s",
		stringToSignPrefix,
		lastSignature,
		trailerHashHex,
	)

	// Final trailer signature
	finalSignature := hex.EncodeToString(
		hmacSHA256(signingKey, stringToSign),
	)

	return finalSignature, nil
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func getSigningKey(secret, yearMonthDay, region string) []byte {
	dateKey := hmacSHA256([]byte("AWS4"+secret), yearMonthDay)
	dateRegionKey := hmacSHA256(dateKey, region)
	dateRegionServiceKey := hmacSHA256(dateRegionKey, "s3")
	return hmacSHA256(dateRegionServiceKey, "aws4_request")
}
