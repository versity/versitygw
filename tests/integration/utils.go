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
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/versity/versitygw/s3err"
)

var (
	bcktCount        = 0
	adminErrorPrefix = "XAdmin"
)

func getBucketName() string {
	bcktCount++
	return fmt.Sprintf("test-bucket-%v", bcktCount)
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
	handlerErr := handler(client, "")
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
	clt := s3.NewPresignClient(s.GetClient())

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

type mpCfg struct {
	checksumAlgorithm types.ChecksumAlgorithm
	checksumType      types.ChecksumType
}

type mpOpt func(*mpCfg)

func withChecksum(algo types.ChecksumAlgorithm) mpOpt {
	return func(mc *mpCfg) { mc.checksumAlgorithm = algo }
}
func withChecksumType(t types.ChecksumType) mpOpt {
	return func(mc *mpCfg) { mc.checksumType = t }
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

func compareBuckets(list1 []types.Bucket, list2 []types.Bucket) bool {
	if len(list1) != len(list2) {
		return false
	}

	for i, elem := range list1 {
		if *elem.Name != *list2[i].Name {
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

func deleteUser(s *S3Conf, access string) error {
	out, err := execCommand(s.getAdminCommand("-a", s.awsID, "-s", s.awsSecret, "-er", s.endpoint, "delete-user", "-a", access)...)
	if err != nil {
		return err
	}
	if strings.Contains(string(out), adminErrorPrefix) {
		return fmt.Errorf("failed to delete the user account, %s", out)
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
		template := `
		{
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

func getUserS3Client(usr user, cfg *S3Conf) *s3.Client {
	config := *cfg
	config.awsID = usr.access
	config.awsSecret = usr.secret

	return config.GetClient()
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
	if err := checkSdkApiErr(err, "InvalidRequest"); err != nil {
		return err
	}
	// client sdk regression issue prevents getting full error message,
	// change back to below once this is fixed:
	// https://github.com/aws/aws-sdk-go-v2/issues/2921
	// if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLocked)); err != nil {
	// 	return err
	// }

	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
	_, err = client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &bucket,
		Key:    &object,
	})
	cancel()
	if err := checkSdkApiErr(err, "InvalidRequest"); err != nil {
		return err
	}
	// client sdk regression issue prevents getting full error message,
	// change back to below once this is fixed:
	// https://github.com/aws/aws-sdk-go-v2/issues/2921
	// if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLocked)); err != nil {
	// 	return err
	// }

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
	if err := checkSdkApiErr(err, "InvalidRequest"); err != nil {
		return err
	}
	// client sdk regression issue prevents getting full error message,
	// change back to below once this is fixed:
	// https://github.com/aws/aws-sdk-go-v2/issues/2921
	// if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectLocked)); err != nil {
	// 	return err
	// }

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
