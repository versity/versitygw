package integration

import (
	"context"
	"crypto/sha256"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

var (
	shortTimeout = 10 * time.Second
)

func Authentication_empty_auth_header(s *S3Conf) {
	testName := "Authentication_empty_auth_header"
	authHandler(s, &authConfig{
		testName: testName,
		path:     "my-bucket",
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		req.Header.Set("Authorization", "")
		client := http.Client{
			Timeout: shortTimeout,
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrAuthHeaderEmpty)); err != nil {
			return err
		}

		return nil
	})
}

func Authentication_invalid_auth_header(s *S3Conf) {
	testName := "Authentication_invalid_auth_header"
	authHandler(s, &authConfig{
		testName: testName,
		path:     "my-bucket",
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		req.Header.Set("Authorization", "invalid header")
		client := http.Client{
			Timeout: shortTimeout,
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrMissingFields)); err != nil {
			return err
		}

		return nil
	})
}

func Authentication_unsupported_signature_version(s *S3Conf) {
	testName := "Authentication_unsupported_signature_version"
	authHandler(s, &authConfig{
		testName: testName,
		path:     "my-bucket",
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		authHdr := req.Header.Get("Authorization")
		authHdr = strings.Replace(authHdr, "AWS4-HMAC-SHA256", "AWS2-HMAC-SHA1", 1)
		req.Header.Set("Authorization", authHdr)

		client := http.Client{
			Timeout: shortTimeout,
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrSignatureVersionNotSupported)); err != nil {
			return err
		}

		return nil
	})
}

func Authentication_malformed_credentials(s *S3Conf) {
	testName := "Authentication_malformed_credentials"
	authHandler(s, &authConfig{
		testName: testName,
		path:     "my-bucket",
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		authHdr := req.Header.Get("Authorization")
		regExp := regexp.MustCompile("Credential=[^,]+,")
		hdr := regExp.ReplaceAllString(authHdr, "Credential-access/32234/us-east-1/s3/aws4_request,")
		req.Header.Set("Authorization", hdr)

		client := http.Client{
			Timeout: shortTimeout,
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrCredMalformed)); err != nil {
			return err
		}

		return nil
	})
}

func Authentication_malformed_credentials_invalid_parts(s *S3Conf) {
	testName := "Authentication_malformed_credentials_invalid_parts"
	authHandler(s, &authConfig{
		testName: testName,
		path:     "my-bucket",
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		authHdr := req.Header.Get("Authorization")
		regExp := regexp.MustCompile("Credential=[^,]+,")
		hdr := regExp.ReplaceAllString(authHdr, "Credential=access/32234/us-east-1/s3,")
		req.Header.Set("Authorization", hdr)

		client := http.Client{
			Timeout: shortTimeout,
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrCredMalformed)); err != nil {
			return err
		}

		return nil
	})
}

func Authentication_credentials_terminated_string(s *S3Conf) {
	testName := "Authentication_credentials_terminated_string"
	authHandler(s, &authConfig{
		testName: testName,
		path:     "my-bucket",
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		authHdr := req.Header.Get("Authorization")
		regExp := regexp.MustCompile("Credential=[^,]+,")
		hdr := regExp.ReplaceAllString(authHdr, "Credential=access/32234/us-east-1/s3/aws_request,")
		req.Header.Set("Authorization", hdr)

		client := http.Client{
			Timeout: shortTimeout,
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrSignatureTerminationStr)); err != nil {
			return err
		}

		return nil
	})
}

func Authentication_credentials_incorrect_service(s *S3Conf) {
	testName := "Authentication_credentials_incorrect_service"
	authHandler(s, &authConfig{
		testName: testName,
		path:     "my-bucket",
		method:   http.MethodGet,
		body:     nil,
		service:  "ec2",
		date:     time.Now(),
	}, func(req *http.Request) error {
		client := http.Client{
			Timeout: shortTimeout,
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrSignatureIncorrService)); err != nil {
			return err
		}

		return nil
	})
}

func Authentication_credentials_incorrect_region(s *S3Conf) {
	testName := "Authentication_credentials_incorrect_region"
	cfg := *s
	if cfg.awsRegion == "us-east-1" {
		cfg.awsRegion = "us-west-1"
	} else {
		cfg.awsRegion = "us-east-1"
	}
	authHandler(&cfg, &authConfig{
		testName: testName,
		path:     "my-bucket",
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		client := http.Client{
			Timeout: shortTimeout,
		}
		apiErr := s3err.APIError{
			Code:           "SignatureDoesNotMatch",
			Description:    fmt.Sprintf("Credential should be scoped to a valid Region, not %v", cfg.awsRegion),
			HTTPStatusCode: http.StatusForbidden,
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := checkAuthErr(resp, apiErr); err != nil {
			return err
		}

		return nil
	})
}

func Authentication_credentials_invalid_date(s *S3Conf) {
	testName := "Authentication_credentials_invalid_date"
	authHandler(s, &authConfig{
		testName: testName,
		path:     "my-bucket",
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		authHdr := req.Header.Get("Authorization")
		regExp := regexp.MustCompile("Credential=[^,]+,")
		hdr := regExp.ReplaceAllString(authHdr, "Credential=access/3223423234/us-east-1/s3/aws4_request,")
		req.Header.Set("Authorization", hdr)

		client := http.Client{
			Timeout: shortTimeout,
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrSignatureDateDoesNotMatch)); err != nil {
			return err
		}

		return nil
	})
}

func Authentication_credentials_future_date(s *S3Conf) {
	testName := "Authentication_credentials_future_date"
	authHandler(s, &authConfig{
		testName: testName,
		path:     "my-bucket",
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now().Add(time.Duration(5) * 24 * time.Hour),
	}, func(req *http.Request) error {
		client := http.Client{
			Timeout: shortTimeout,
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		var errResp s3err.APIErrorResponse
		err = xml.Unmarshal(body, &errResp)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusForbidden {
			return fmt.Errorf("expected response status code to be %v, instead got %v", http.StatusForbidden, resp.StatusCode)
		}
		if errResp.Code != "SignatureDoesNotMatch" {
			return fmt.Errorf("expected error code to be %v, instead got %v", "SignatureDoesNotMatch", errResp.Code)
		}
		if !strings.Contains(errResp.Message, "Signature not yet current:") {
			return fmt.Errorf("expected future date error message, instead got %v", errResp.Message)
		}

		return nil
	})
}

func Authentication_credentials_past_date(s *S3Conf) {
	testName := "Authentication_credentials_past_date"
	authHandler(s, &authConfig{
		testName: testName,
		path:     "my-bucket",
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now().Add(time.Duration(-5) * 24 * time.Hour),
	}, func(req *http.Request) error {
		client := http.Client{
			Timeout: shortTimeout,
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		var errResp s3err.APIErrorResponse
		err = xml.Unmarshal(body, &errResp)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusForbidden {
			return fmt.Errorf("expected response status code to be %v, instead got %v", http.StatusForbidden, resp.StatusCode)
		}
		if errResp.Code != "SignatureDoesNotMatch" {
			return fmt.Errorf("expected error code to be %v, instead got %v", "SignatureDoesNotMatch", errResp.Code)
		}
		if !strings.Contains(errResp.Message, "Signature expired:") {
			return fmt.Errorf("expected past date error message, instead got %v", errResp.Message)
		}

		return nil
	})
}

func Authentication_credentials_non_existing_access_key(s *S3Conf) {
	testName := "Authentication_credentials_non_existing_access_key"
	authHandler(s, &authConfig{
		testName: testName,
		path:     "my-bucket",
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		authHdr := req.Header.Get("Authorization")
		regExp := regexp.MustCompile("Credential=([^/]+)")
		hdr := regExp.ReplaceAllString(authHdr, "Credential=a_rarely_existing_access_key_id_a7s86df78as6df89790a8sd7f")
		req.Header.Set("Authorization", hdr)

		client := http.Client{
			Timeout: shortTimeout,
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrInvalidAccessKeyID)); err != nil {
			return err
		}

		return nil
	})
}

func Authentication_invalid_signed_headers(s *S3Conf) {
	testName := "Authentication_invalid_signed_headers"
	authHandler(s, &authConfig{
		testName: testName,
		path:     "my-bucket",
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		authHdr := req.Header.Get("Authorization")
		regExp := regexp.MustCompile("SignedHeaders=[^,]+,")
		hdr := regExp.ReplaceAllString(authHdr, "SignedHeaders-host;x-amz-content-sha256;x-amz-date,")
		req.Header.Set("Authorization", hdr)

		client := http.Client{
			Timeout: shortTimeout,
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrCredMalformed)); err != nil {
			return err
		}

		return nil
	})
}

func Authentication_missing_date_header(s *S3Conf) {
	testName := "Authentication_missing_date_header"
	authHandler(s, &authConfig{
		testName: testName,
		path:     "my-bucket",
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		client := http.Client{
			Timeout: shortTimeout,
		}
		req.Header.Set("X-Amz-Date", "")

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrMissingDateHeader)); err != nil {
			return err
		}

		return nil
	})
}

func Authentication_invalid_date_header(s *S3Conf) {
	testName := "Authentication_invalid_date_header"
	authHandler(s, &authConfig{
		testName: testName,
		path:     "my-bucket",
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		client := http.Client{
			Timeout: shortTimeout,
		}
		req.Header.Set("X-Amz-Date", "03032006")

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrMalformedDate)); err != nil {
			return err
		}

		return nil
	})
}

func Authentication_date_mismatch(s *S3Conf) {
	testName := "Authentication_date_mismatch"
	authHandler(s, &authConfig{
		testName: testName,
		path:     "my-bucket",
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		client := http.Client{
			Timeout: shortTimeout,
		}
		req.Header.Set("X-Amz-Date", "20220830T095525Z")

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrSignatureDateDoesNotMatch)); err != nil {
			return err
		}

		return nil
	})
}

func Authentication_incorrect_payload_hash(s *S3Conf) {
	testName := "Authentication_incorrect_payload_hash"
	authHandler(s, &authConfig{
		testName: testName,
		path:     "my-bucket",
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		client := http.Client{
			Timeout: shortTimeout,
		}
		req.Header.Set("X-Amz-Content-Sha256", "7sa6df576dsa5f675sad67f")

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrContentSHA256Mismatch)); err != nil {
			return err
		}

		return nil
	})
}

func Authentication_incorrect_md5(s *S3Conf) {
	testName := "Authentication_incorrect_md5"
	authHandler(s, &authConfig{
		testName: testName,
		path:     "my-bucket",
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		client := http.Client{
			Timeout: shortTimeout,
		}

		req.Header.Set("Content-Md5", "sadfasdf87sad6f87==")

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrInvalidDigest)); err != nil {
			return err
		}

		return nil
	})
}

func Authentication_signature_error_incorrect_secret_key(s *S3Conf) {
	testName := "Authentication_signature_error_incorrect_secret_key"
	cfg := *s
	cfg.awsSecret = s.awsSecret + "a"
	authHandler(&cfg, &authConfig{
		testName: testName,
		path:     "my-bucket",
		method:   http.MethodGet,
		body:     nil,
		service:  "s3",
		date:     time.Now(),
	}, func(req *http.Request) error {
		client := http.Client{
			Timeout: shortTimeout,
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := checkAuthErr(resp, s3err.GetAPIError(s3err.ErrSignatureDoesNotMatch)); err != nil {
			return err
		}

		return nil
	})
}

func CreateBucket_invalid_bucket_name(s *S3Conf) {
	testName := "CreateBucket_invalid_bucket_name"
	runF(testName)
	err := setup(s, "aa")
	if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidBucketName)); err != nil {
		failF("%v: %v", testName, err.Error())
		return
	}

	err = setup(s, ".gitignore")
	if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidBucketName)); err != nil {
		failF("%v: %v", testName, err.Error())
		return
	}

	err = setup(s, "my-bucket.")
	if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidBucketName)); err != nil {
		failF("%v: %v", testName, err.Error())
		return
	}

	err = setup(s, "bucket-%")
	if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidBucketName)); err != nil {
		failF("%v: %v", testName, err.Error())
		return
	}
	passF(testName)
}

func CreateBucket_as_user(s *S3Conf) {
	testName := "CreateBucket_as_user"
	runF(testName)
	usr := user{
		access: "grt1",
		secret: "grt1secret",
		role:   "user",
	}
	cfg := *s
	cfg.awsID = usr.access
	cfg.awsSecret = usr.secret
	err := createUsers(s, []user{usr})
	if err != nil {
		failF("%v: %v", testName, err.Error())
		return
	}

	err = setup(&cfg, getBucketName())
	if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
		failF("%v: %v", testName, err.Error())
		return
	}

	passF(testName)
}

func CreateBucket_existing_bucket(s *S3Conf) {
	testName := "CreateBucket_existing_bucket"
	runF(testName)
	bucket := getBucketName()
	err := setup(s, bucket)
	if err != nil {
		failF("%v: %v", testName, err.Error())
		return
	}
	err = setup(s, bucket)
	var bne *types.BucketAlreadyExists
	if !errors.As(err, &bne) {
		failF("%v: %v", testName, err.Error())
	}

	err = teardown(s, bucket)
	if err != nil {
		failF("%v: %v", err.Error())
		return
	}
	passF(testName)
}

func HeadBucket_non_existing_bucket(s *S3Conf) {
	testName := "HeadBucket_non_existing_bucket"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		bcktName := getBucketName()

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.HeadBucket(ctx, &s3.HeadBucketInput{
			Bucket: &bcktName,
		})
		cancel()
		if err := checkSdkApiErr(err, "NotFound"); err != nil {
			return err
		}
		return nil
	})
}

func HeadBucket_success(s *S3Conf) {
	testName := "HeadBucket_success"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.HeadBucket(ctx, &s3.HeadBucketInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}
		return nil
	})
}

func ListBuckets_as_user(s *S3Conf) {
	testName := "ListBuckets_as_user"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		buckets := []s3response.ListAllMyBucketsEntry{{Name: bucket}}
		for i := 0; i < 6; i++ {
			bckt := getBucketName()

			err := setup(s, bckt)
			if err != nil {
				return err
			}

			buckets = append(buckets, s3response.ListAllMyBucketsEntry{
				Name: bckt,
			})
		}
		usr := user{
			access: "grt1",
			secret: "grt1secret",
			role:   "user",
		}

		err := createUsers(s, []user{usr})
		if err != nil {
			return err
		}

		cfg := *s
		cfg.awsID = usr.access
		cfg.awsSecret = usr.secret

		bckts := []string{}
		for i := 0; i < 3; i++ {
			bckts = append(bckts, buckets[i].Name)
		}

		err = changeBucketsOwner(s, bckts, usr.access)
		if err != nil {
			return err
		}

		userClient := s3.NewFromConfig(cfg.Config())

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := userClient.ListBuckets(ctx, &s3.ListBucketsInput{})
		cancel()
		if err != nil {
			return err
		}

		if *out.Owner.ID != usr.access {
			return fmt.Errorf("expected buckets owner to be %v, instead got %v", usr.access, *out.Owner.ID)
		}
		if ok := compareBuckets(out.Buckets, buckets[:3]); !ok {
			return fmt.Errorf("expected list buckets result to be %v, instead got %v", buckets[:3], out.Buckets)
		}

		for _, elem := range buckets[1:] {
			err = teardown(s, elem.Name)
			if err != nil {
				return err
			}
		}

		return nil
	})
}

func ListBuckets_as_admin(s *S3Conf) {
	testName := "ListBuckets_as_admin"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		buckets := []s3response.ListAllMyBucketsEntry{{Name: bucket}}
		for i := 0; i < 6; i++ {
			bckt := getBucketName()

			err := setup(s, bckt)
			if err != nil {
				return err
			}

			buckets = append(buckets, s3response.ListAllMyBucketsEntry{
				Name: bckt,
			})
		}
		usr := user{
			access: "grt1",
			secret: "grt1secret",
			role:   "user",
		}
		admin := user{
			access: "admin1",
			secret: "admin1secret",
			role:   "admin",
		}

		err := createUsers(s, []user{usr, admin})
		if err != nil {
			return err
		}

		cfg := *s
		cfg.awsID = admin.access
		cfg.awsSecret = admin.secret

		bckts := []string{}
		for i := 0; i < 3; i++ {
			bckts = append(bckts, buckets[i].Name)
		}

		err = changeBucketsOwner(s, bckts, usr.access)
		if err != nil {
			return err
		}

		adminClient := s3.NewFromConfig(cfg.Config())

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := adminClient.ListBuckets(ctx, &s3.ListBucketsInput{})
		cancel()
		if err != nil {
			return err
		}

		if *out.Owner.ID != admin.access {
			return fmt.Errorf("expected buckets owner to be %v, instead got %v", admin.access, *out.Owner.ID)
		}
		if ok := compareBuckets(out.Buckets, buckets); !ok {
			return fmt.Errorf("expected list buckets result to be %v, instead got %v", buckets, out.Buckets)
		}

		for _, elem := range buckets[1:] {
			err = teardown(s, elem.Name)
			if err != nil {
				return err
			}
		}

		return nil
	})
}

func ListBuckets_success(s *S3Conf) {
	testName := "ListBuckets_success"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		buckets := []s3response.ListAllMyBucketsEntry{{Name: bucket}}
		for i := 0; i < 5; i++ {
			bckt := getBucketName()

			err := setup(s, bckt)
			if err != nil {
				return err
			}

			buckets = append(buckets, s3response.ListAllMyBucketsEntry{
				Name: bckt,
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListBuckets(ctx, &s3.ListBucketsInput{})
		cancel()
		if err != nil {
			return err
		}

		if *out.Owner.ID != s.awsID {
			return fmt.Errorf("expected owner to be %v, instead got %v", s.awsID, *out.Owner.ID)
		}
		if ok := compareBuckets(out.Buckets, buckets); !ok {
			return fmt.Errorf("expected list buckets result to be %v, instead got %v", buckets, out.Buckets)
		}

		for _, elem := range buckets[1:] {
			err = teardown(s, elem.Name)
			if err != nil {
				return err
			}
		}

		return nil
	})
}

func CreateDeleteBucket_success(s *S3Conf) {
	testName := "CreateBucket_success"
	runF(testName)
	bucket := getBucketName()

	err := setup(s, bucket)
	if err != nil {
		failF("%v: %v", err.Error())
		return
	}

	err = teardown(s, bucket)
	if err != nil {
		failF("%v: %v", err.Error())
		return
	}

	passF(testName)
}

func DeleteBucket_non_existing_bucket(s *S3Conf) {
	testName := "DeleteBucket_non_existing_bucket"
	runF(testName)
	bucket := getBucketName()
	s3client := s3.NewFromConfig(s.Config())

	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	_, err := s3client.DeleteBucket(ctx, &s3.DeleteBucketInput{
		Bucket: &bucket,
	})
	cancel()
	if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
		failF("%v: %v", testName, err.Error())
		return
	}
	passF(testName)
}

func DeleteBucket_non_empty_bucket(s *S3Conf) {
	testName := "DeleteBucket_non_empty_bucket"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putObjects(s3client, []string{"foo"}, bucket)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteBucket(ctx, &s3.DeleteBucketInput{
			Bucket: &bucket,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrBucketNotEmpty)); err != nil {
			return err
		}

		return nil
	})
}

func PutObject_non_existing_bucket(s *S3Conf) {
	testName := "PutObject_non_existing_bucket"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putObjects(s3client, []string{"my-obj"}, "non-existing-bucket")
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}
		return nil
	})
}

func PutObject_special_chars(s *S3Conf) {
	testName := "PutObject_special_chars"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putObjects(s3client, []string{"foo%%", "bar^", "baz**"}, bucket)
		if err != nil {
			return err
		}
		return nil
	})
}

func PutObject_existing_dir_obj(s *S3Conf) {
	testName := "PutObject_existing_dir_obj"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putObjects(s3client, []string{"foo/bar", "foo"}, bucket)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrExistingObjectIsDirectory)); err != nil {
			return err
		}
		return nil
	})
}

func PutObject_obj_parent_is_file(s *S3Conf) {
	testName := "PutObject_obj_parent_is_file"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putObjects(s3client, []string{"foo", "foo/bar/"}, bucket)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrObjectParentIsFile)); err != nil {
			return err
		}
		return nil
	})
}

func PutObject_success(s *S3Conf) {
	testName := "PutObject_success"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putObjects(s3client, []string{"my-obj"}, bucket)
		if err != nil {
			return err
		}
		return nil
	})
}

func HeadObject_non_existing_object(s *S3Conf) {
	testName := "HeadObject_non_existing_object"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    getPtr("my-obj"),
		})
		cancel()
		if err := checkSdkApiErr(err, "NotFound"); err != nil {
			return err
		}
		return nil
	})
}

func HeadObject_success(s *S3Conf) {
	testName := "HeadObject_success"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, dataLen := "my-obj", int64(1234567)
		meta := map[string]string{
			"key1": "val1",
			"key2": "val2",
		}

		_, _, err := putObjectWithData(dataLen, &s3.PutObjectInput{Bucket: &bucket, Key: &obj, Metadata: meta}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		defer cancel()
		if err != nil {
			return err
		}

		if !areMapsSame(out.Metadata, meta) {
			return fmt.Errorf("incorrect object metadata")
		}
		if out.ContentLength != dataLen {
			return fmt.Errorf("expected data length %v, instead got %v", dataLen, out.ContentLength)
		}

		return nil
	})
}

func GetObject_non_existing_key(s *S3Conf) {
	testName := "GetObject_non_existing_key"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    getPtr("non-existing-key"),
		})
		cancel()
		var bae *types.NoSuchKey
		if !errors.As(err, &bae) {
			return err
		}
		return nil
	})
}

func GetObject_invalid_ranges(s *S3Conf) {
	testName := "GetObject_invalid_ranges"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dataLength, obj := int64(1234567), "my-obj"

		_, _, err := putObjectWithData(dataLength, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
			Range:  getPtr("bytes=invalid-range"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidRange)); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
			Range:  getPtr("bytes=33-10"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidRange)); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
			Range:  getPtr("bytes=1000000000-999999999999"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidRange)); err != nil {
			return err
		}
		return nil
	})
}

func GetObject_with_meta(s *S3Conf) {
	testName := "GetObject_with_meta"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		meta := map[string]string{
			"key1": "val1",
			"key2": "val2",
		}

		_, _, err := putObjectWithData(0, &s3.PutObjectInput{Bucket: &bucket, Key: &obj, Metadata: meta}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		defer cancel()
		if err != nil {
			return err
		}

		if !areMapsSame(out.Metadata, meta) {
			return fmt.Errorf("incorrect object metadata")
		}

		return nil
	})
}

func GetObject_success(s *S3Conf) {
	testName := "GetObject_success"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dataLength, obj := int64(1234567), "my-obj"

		csum, _, err := putObjectWithData(dataLength, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		defer cancel()
		if err != nil {
			return err
		}
		if out.ContentLength != dataLength {
			return fmt.Errorf("expected content-length %v, instead got %v", dataLength, out.ContentLength)
		}

		bdy, err := io.ReadAll(out.Body)
		if err != nil {
			return err
		}
		defer out.Body.Close()
		outCsum := sha256.Sum256(bdy)
		if outCsum != csum {
			return fmt.Errorf("invalid object data")
		}
		return nil
	})
}

func GetObject_by_range_success(s *S3Conf) {
	testName := "GetObject_by_range_success"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dataLength, obj := int64(1234567), "my-obj"

		_, data, err := putObjectWithData(dataLength, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		rangeString := "bytes=100-200"
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
			Range:  &rangeString,
		})
		defer cancel()
		if err != nil {
			return err
		}
		defer out.Body.Close()

		if getString(out.ContentRange) != fmt.Sprintf("bytes 100-200/%v", dataLength) {
			return fmt.Errorf("expected content range: %v, instead got: %v", fmt.Sprintf("bytes 100-200/%v", dataLength), getString(out.ContentRange))
		}
		if getString(out.AcceptRanges) != rangeString {
			return fmt.Errorf("expected accept range: %v, instead got: %v", rangeString, getString(out.AcceptRanges))
		}
		b, err := io.ReadAll(out.Body)
		if err != nil {
			return err
		}

		// bytes range is inclusive, go range for second value is not
		if !isEqual(b, data[100:201]) {
			return fmt.Errorf("data mismatch of range")
		}

		rangeString = "bytes=100-"

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err = s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
			Range:  &rangeString,
		})
		defer cancel()
		if err != nil {
			return err
		}
		defer out.Body.Close()

		b, err = io.ReadAll(out.Body)
		if err != nil {
			return err
		}

		// bytes range is inclusive, go range for second value is not
		if !isEqual(b, data[100:]) {
			return fmt.Errorf("data mismatch of range")
		}
		return nil
	})
}

func ListObjects_non_existing_bucket(s *S3Conf) {
	testName := "ListObjects_non_existing_bucket"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		bckt := getBucketName()
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket: &bckt,
		})
		cancel()
		if err := checkSdkApiErr(err, "NoSuchBucket"); err != nil {
			return err
		}
		return nil
	})
}

func ListObjects_with_prefix(s *S3Conf) {
	testName := "ListObjects_with_prefix"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		prefix := "obj"
		objWithPrefix := []string{prefix + "/foo", prefix + "/bar", prefix + "/baz/bla"}
		err := putObjects(s3client, append(objWithPrefix, []string{"xzy/csf", "hell"}...), bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket: &bucket,
			Prefix: &prefix,
		})
		cancel()
		if err != nil {
			return err
		}

		if *out.Prefix != prefix {
			return fmt.Errorf("expected prefix %v, instead got %v", prefix, *out.Prefix)
		}
		if !compareObjects(objWithPrefix, out.Contents) {
			return fmt.Errorf("unexpected output for list objects with prefix")
		}

		return nil
	})
}

func ListObject_truncated(s *S3Conf) {
	testName := "ListObject_truncated"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		maxKeys := int32(2)
		err := putObjects(s3client, []string{"foo", "bar", "baz"}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out1, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket:  &bucket,
			MaxKeys: maxKeys,
		})
		cancel()
		if err != nil {
			return err
		}

		if !out1.IsTruncated {
			return fmt.Errorf("expected out1put to be truncated")
		}

		if out1.MaxKeys != maxKeys {
			return fmt.Errorf("expected max-keys to be %v, instead got %v", maxKeys, out1.MaxKeys)
		}

		if *out1.NextMarker != "baz" {
			return fmt.Errorf("expected nex-marker to be baz, instead got %v", *out1.NextMarker)
		}

		if !compareObjects([]string{"bar", "baz"}, out1.Contents) {
			return fmt.Errorf("unexpected output for list objects with max-keys")
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out2, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket: &bucket,
			Marker: out1.NextMarker,
		})
		cancel()
		if err != nil {
			return err
		}

		if out2.IsTruncated {
			return fmt.Errorf("expected output not to be truncated")
		}

		if *out2.Marker != *out1.NextMarker {
			return fmt.Errorf("expected marker to be %v, instead got %v", *out1.NextMarker, *out2.Marker)
		}

		if !compareObjects([]string{"foo"}, out2.Contents) {
			return fmt.Errorf("unexpected output for list objects with max-keys")
		}
		return nil
	})
}

func ListObjects_invalid_max_keys(s *S3Conf) {
	testName := "ListObjects_invalid_max_keys"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket:  &bucket,
			MaxKeys: -5,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidMaxKeys)); err != nil {
			return err
		}

		return nil
	})
}

func ListObjects_max_keys_0(s *S3Conf) {
	testName := "ListObjects_max_keys_0"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objects := []string{"foo", "bar", "baz"}
		err := putObjects(s3client, objects, bucket)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket:  &bucket,
			MaxKeys: 0,
		})
		cancel()
		if err != nil {
			return nil
		}

		if !compareObjects(objects, out.Contents) {
			return fmt.Errorf("unexpected output for list objects with max-keys 0")
		}

		return nil
	})
}

func ListObjects_delimiter(s *S3Conf) {
	testName := "ListObjects_delimiter"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := putObjects(s3client, []string{"foo/bar/baz", "foo/bar/xyzzy", "quux/thud", "asdf"}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket:    &bucket,
			Delimiter: getPtr("/"),
		})
		cancel()
		if err != nil {
			return err
		}

		if *out.Delimiter != "/" {
			return fmt.Errorf("expected delimiter to be /, instead got %v", *out.Delimiter)
		}
		if len(out.Contents) != 1 || *out.Contents[0].Key != "asdf" {
			return fmt.Errorf("expected result [\"asdf\"], instead got %v", out.Contents)
		}

		if !comparePrefixes([]string{"foo/", "quux/"}, out.CommonPrefixes) {
			return fmt.Errorf("expected common prefixes to be %v, instead got %v", []string{"foo/", "quux/"}, out.CommonPrefixes)
		}

		return nil
	})
}

func DeleteObject_non_existing_object(s *S3Conf) {
	testName := "DeleteObject_non_existing_object"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    getPtr("my-obj"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchKey)); err != nil {
			return err
		}
		return nil
	})
}

func DeleteObject_success(s *S3Conf) {
	testName := "DeleteObject_success"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		defer cancel()
		if err := checkSdkApiErr(err, "NoSuchKey"); err != nil {
			return err
		}
		return nil
	})
}

func DeleteObjects_empty_input(s *S3Conf) {
	testName := "DeleteObjects_empty_input"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objects := []string{"foo", "bar", "baz"}
		err := putObjects(s3client, objects, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: &bucket,
			Delete: &types.Delete{
				Objects: []types.ObjectIdentifier{},
			},
		})
		cancel()
		if err != nil {
			return err
		}

		if len(out.Deleted) != 0 {
			return fmt.Errorf("expected deleted object count 0, instead got %v", len(out.Deleted))
		}
		if len(out.Errors) != 0 {
			return fmt.Errorf("expected 0 errors, instead got %v", len(out.Errors))
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareObjects(objects, res.Contents) {
			return fmt.Errorf("unexpected output for list objects with prefix")
		}

		return nil
	})
}

func DeleteObjects_non_existing_objects(s *S3Conf) {
	testName := "DeleteObjects_empty_input"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		delObjects := []types.ObjectIdentifier{{Key: getPtr("obj1")}, {Key: getPtr("obj2")}}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: &bucket,
			Delete: &types.Delete{
				Objects: delObjects,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		if len(out.Deleted) != 0 {
			return fmt.Errorf("expected deleted object count 0, instead got %v", len(out.Deleted))
		}
		if len(out.Errors) != 2 {
			return fmt.Errorf("expected 2 errors, instead got %v", len(out.Errors))
		}

		for _, delErr := range out.Errors {
			if *delErr.Code != "NoSuchKey" {
				return fmt.Errorf("expected NoSuchKey error, instead got %v", *delErr.Code)
			}
		}

		return nil
	})
}

func DeleteObjects_success(s *S3Conf) {
	testName := "DeleteObjects_success"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		objects, objToDel := []string{"obj1", "obj2", "obj3"}, []string{"foo", "bar", "baz"}
		err := putObjects(s3client, append(objToDel, objects...), bucket)
		if err != nil {
			return err
		}

		delObjects := []types.ObjectIdentifier{}
		for _, key := range objToDel {
			k := key
			delObjects = append(delObjects, types.ObjectIdentifier{Key: &k})
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: &bucket,
			Delete: &types.Delete{
				Objects: delObjects,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		if len(out.Deleted) != 3 {
			return fmt.Errorf("expected deleted object count 3, instead got %v", len(out.Deleted))
		}
		if len(out.Errors) != 0 {
			return fmt.Errorf("expected 2 errors, instead got %v", len(out.Errors))
		}

		if !compareDelObjects(objToDel, out.Deleted) {
			return fmt.Errorf("unexpected deleted output")
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListObjects(ctx, &s3.ListObjectsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if !compareObjects(objects, res.Contents) {
			return fmt.Errorf("unexpected output for list objects with prefix")
		}

		return nil
	})
}

func CopyObject_non_existing_dst_bucket(s *S3Conf) {
	testName := "CopyObject_non_existing_dst_bucket"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &bucket,
			Key:        &obj,
			CopySource: getPtr("bucket/obj"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}
		return nil
	})
}

func CopyObject_copy_to_itself(s *S3Conf) {
	testName := "CopyObject_copy_to_itself"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &bucket,
			Key:        &obj,
			CopySource: getPtr(fmt.Sprintf("%v/%v", bucket, obj)),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidCopyDest)); err != nil {
			return err
		}
		return nil
	})
}

func CopyObject_success(s *S3Conf) {
	testName := "CopyObject_success"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		dataLength, obj := int64(1234567), "my-obj"
		dstBucket := getBucketName()
		err := setup(s, dstBucket)
		if err != nil {
			return err
		}

		csum, _, err := putObjectWithData(dataLength, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		}, s3client)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &dstBucket,
			Key:        &obj,
			CopySource: getPtr(fmt.Sprintf("%v/%v", bucket, obj)),
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &dstBucket,
			Key:    &obj,
		})
		defer cancel()
		if err != nil {
			return err
		}
		if out.ContentLength != dataLength {
			return fmt.Errorf("expected content-length %v, instead got %v", dataLength, out.ContentLength)
		}

		bdy, err := io.ReadAll(out.Body)
		if err != nil {
			return err
		}
		defer out.Body.Close()
		outCsum := sha256.Sum256(bdy)
		if outCsum != csum {
			return fmt.Errorf("invalid object data")
		}

		err = teardown(s, dstBucket)
		if err != nil {
			return nil
		}

		return nil
	})
}

func PutObjectTagging_non_existing_object(s *S3Conf) {
	testName := "PutObjectTagging_non_existing_object"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
			Bucket:  &bucket,
			Key:     getPtr("my-obj"),
			Tagging: &types.Tagging{TagSet: []types.Tag{}}})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchKey)); err != nil {
			return err
		}
		return nil
	})
}

func PutObjectTagging_success(s *S3Conf) {
	testName := "PutObjectTagging_success"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		tagging := types.Tagging{TagSet: []types.Tag{{Key: getPtr("key1"), Value: getPtr("val2")}, {Key: getPtr("key2"), Value: getPtr("val2")}}}
		err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
			Bucket:  &bucket,
			Key:     &obj,
			Tagging: &tagging})
		cancel()
		if err != nil {
			return err
		}

		return nil
	})
}

func GetObjectTagging_non_existing_object(s *S3Conf) {
	testName := "GetObjectTagging_non_existing_object"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
			Bucket: &bucket,
			Key:    getPtr("my-obj"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchKey)); err != nil {
			return err
		}
		return nil
	})
}

func GetObjectTagging_success(s *S3Conf) {
	testName := "PutObjectTagging_success"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		tagging := types.Tagging{TagSet: []types.Tag{{Key: getPtr("key1"), Value: getPtr("val2")}, {Key: getPtr("key2"), Value: getPtr("val2")}}}
		err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
			Bucket:  &bucket,
			Key:     &obj,
			Tagging: &tagging})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return nil
		}

		if !areTagsSame(out.TagSet, tagging.TagSet) {
			return fmt.Errorf("expected %v instead got %v", tagging.TagSet, out.TagSet)
		}

		return nil
	})
}

func DeleteObjectTagging_non_existing_object(s *S3Conf) {
	testName := "DeleteObjectTagging_non_existing_object"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.DeleteObjectTagging(ctx, &s3.DeleteObjectTaggingInput{
			Bucket: &bucket,
			Key:    getPtr("my-obj"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchKey)); err != nil {
			return err
		}
		return nil
	})
}

func DeleteObjectTagging_success(s *S3Conf) {
	testName := "DeleteObjectTagging_success"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		tagging := types.Tagging{TagSet: []types.Tag{{Key: getPtr("key1"), Value: getPtr("val2")}, {Key: getPtr("key2"), Value: getPtr("val2")}}}
		err := putObjects(s3client, []string{obj}, bucket)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
			Bucket:  &bucket,
			Key:     &obj,
			Tagging: &tagging})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.DeleteObjectTagging(ctx, &s3.DeleteObjectTaggingInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return nil
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return nil
		}

		if len(out.TagSet) > 0 {
			return fmt.Errorf("expected empty tag set, instead got %v", out.TagSet)
		}

		return nil
	})
}

func CreateMultipartUpload_non_existing_bucket(s *S3Conf) {
	testName := "CreateMultipartUpload_non_existing_bucket"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		bucketName := getBucketName()
		_, err := CreateMp(s3client, bucketName, "my-obj")
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func CreateMultipartUpload_success(s *S3Conf) {
	testName := "CreateMultipartUpload_success"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := CreateMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		if *out.Bucket != bucket {
			return fmt.Errorf("expected bucket name %v, instead got %v", bucket, *out.Bucket)
		}
		if *out.Key != obj {
			return fmt.Errorf("expected object name %v, instead got %v", obj, *out.Key)
		}
		if _, err := uuid.Parse(*out.UploadId); err != nil {
			return err
		}

		return nil
	})
}

func UploadPart_non_existing_bucket(s *S3Conf) {
	testName := "UploadPart_non_existing_bucket"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		bucketName := getBucketName()
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:   &bucketName,
			Key:      getPtr("my-obj"),
			UploadId: getPtr("uploadId"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func UploadPart_invalid_part_number(s *S3Conf) {
	testName := "UploadPart_invalid_part_number"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:     &bucket,
			Key:        getPtr("my-obj"),
			UploadId:   getPtr("uploadId"),
			PartNumber: -10,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidPart)); err != nil {
			return err
		}
		return nil
	})
}

func UploadPart_non_existing_mp_upload(s *S3Conf) {
	testName := "UploadPart_non_existing_mp_upload"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:     &bucket,
			Key:        getPtr("my-obj"),
			UploadId:   getPtr("uploadId"),
			PartNumber: 1,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchUpload)); err != nil {
			return err
		}
		return nil
	})
}

func UploadPart_non_existing_key(s *S3Conf) {
	testName := "UploadPart_non_existing_key"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := CreateMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:     &bucket,
			Key:        getPtr("non-existing-object-key"),
			UploadId:   out.UploadId,
			PartNumber: 1,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchUpload)); err != nil {
			return err
		}
		return nil
	})
}

func UploadPart_success(s *S3Conf) {
	testName := "UploadPart_success"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := CreateMp(s3client, bucket, obj)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:     &bucket,
			Key:        &obj,
			UploadId:   out.UploadId,
			PartNumber: 1,
		})
		cancel()
		if err != nil {
			return err
		}
		if *res.ETag == "" {
			return fmt.Errorf("expected a valid etag, instead got empty")
		}
		return nil
	})
}

func UploadPartCopy_non_existing_bucket(s *S3Conf) {
	testName := "UploadPartCopy_non_existing_bucket"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		bucketName := getBucketName()

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucketName,
			CopySource: getPtr("Copy-Source"),
			UploadId:   getPtr("uploadId"),
			Key:        getPtr("my-obj"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}
		return nil
	})
}

func UploadPartCopy_incorrect_uploadId(s *S3Conf) {
	testName := "UploadPartCopy_incorrect_uploadId"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, srcBucket, srcObj := "my-obj", getBucketName(), "src-obj"
		err := setup(s, srcBucket)
		if err != nil {
			return err
		}
		err = putObjects(s3client, []string{srcObj}, srcBucket)
		if err != nil {
			return err
		}

		_, err = CreateMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucket,
			CopySource: getPtr(srcBucket + "/" + srcObj),
			UploadId:   getPtr("incorrect-upload-id"),
			Key:        &obj,
			PartNumber: 1,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchUpload)); err != nil {
			return err
		}

		err = teardown(s, srcBucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_incorrect_object_key(s *S3Conf) {
	testName := "UploadPartCopy_incorrect_object_key"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, srcBucket, srcObj := "my-obj", getBucketName(), "src-obj"
		err := setup(s, srcBucket)
		if err != nil {
			return err
		}
		err = putObjects(s3client, []string{srcObj}, srcBucket)
		if err != nil {
			return err
		}

		out, err := CreateMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucket,
			CopySource: getPtr(srcBucket + "/" + srcObj),
			UploadId:   out.UploadId,
			Key:        getPtr("non-existing-object-key"),
			PartNumber: 1,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchUpload)); err != nil {
			return err
		}

		err = teardown(s, srcBucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_invalid_part_number(s *S3Conf) {
	testName := "UploadPartCopy_invalid_part_number"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucket,
			CopySource: getPtr("Copy-Source"),
			UploadId:   getPtr("uploadId"),
			Key:        getPtr("non-existing-object-key"),
			PartNumber: -10,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidPart)); err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_invalid_copy_source(s *S3Conf) {
	testName := "UploadPartCopy_invalid_copy_source"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		out, err := CreateMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucket,
			CopySource: getPtr("invalid-copy-source"),
			UploadId:   out.UploadId,
			Key:        &obj,
			PartNumber: 1,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidCopySource)); err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_non_existing_source_bucket(s *S3Conf) {
	testName := "UploadPartCopy_non_existing_source_bucket"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"

		out, err := CreateMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucket,
			CopySource: getPtr("src/bucket/src/obj"),
			UploadId:   out.UploadId,
			Key:        &obj,
			PartNumber: 1,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_non_existing_source_object_key(s *S3Conf) {
	testName := "UploadPartCopy_non_existing_source_object_key"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, srcBucket := "my-obj", getBucketName()

		err := setup(s, srcBucket)
		if err != nil {
			return nil
		}

		out, err := CreateMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucket,
			CopySource: getPtr(srcBucket + "/non/existing/obj/key"),
			UploadId:   out.UploadId,
			Key:        &obj,
			PartNumber: 1,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchKey)); err != nil {
			return err
		}

		err = teardown(s, srcBucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_success(s *S3Conf) {
	testName := "UploadPartCopy_success"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, srcBucket, srcObj := "my-obj", getBucketName(), "src-obj"
		err := setup(s, srcBucket)
		if err != nil {
			return err
		}
		objSize := 5 * 1024 * 1024
		_, _, err = putObjectWithData(int64(objSize), &s3.PutObjectInput{
			Bucket: &srcBucket,
			Key:    &srcObj,
		}, s3client)
		if err != nil {
			return err
		}

		out, err := CreateMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		copyOut, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:     &bucket,
			CopySource: getPtr(srcBucket + "/" + srcObj),
			UploadId:   out.UploadId,
			Key:        &obj,
			PartNumber: 1,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListParts(ctx, &s3.ListPartsInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: out.UploadId,
		})
		cancel()
		if err != nil {
			return err
		}

		if len(res.Parts) != 1 {
			return fmt.Errorf("expected parts to be 1, instead got %v", len(res.Parts))
		}
		if res.Parts[0].PartNumber != 1 {
			return fmt.Errorf("expected part-number to be 1, instead got %v", res.Parts[0].PartNumber)
		}
		if res.Parts[0].Size != int64(objSize) {
			return fmt.Errorf("expected part size to be %v, instead got %v", objSize, res.Parts[0].Size)
		}
		if *res.Parts[0].ETag != *copyOut.CopyPartResult.ETag {
			return fmt.Errorf("expected part etag to be %v, instead got %v", *copyOut.CopyPartResult.ETag, *res.Parts[0].ETag)
		}

		err = teardown(s, srcBucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_by_range_invalid_range(s *S3Conf) {
	testName := "UploadPartCopy_by_range_invalid_range"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, srcBucket, srcObj := "my-obj", getBucketName(), "src-obj"
		err := setup(s, srcBucket)
		if err != nil {
			return err
		}
		objSize := 5 * 1024 * 1024
		_, _, err = putObjectWithData(int64(objSize), &s3.PutObjectInput{
			Bucket: &srcBucket,
			Key:    &srcObj,
		}, s3client)
		if err != nil {
			return err
		}

		out, err := CreateMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:          &bucket,
			CopySource:      getPtr(srcBucket + "/" + srcObj),
			UploadId:        out.UploadId,
			Key:             &obj,
			PartNumber:      1,
			CopySourceRange: getPtr("invalid-range"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidRange)); err != nil {
			return err
		}

		err = teardown(s, srcBucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func UploadPartCopy_by_range_success(s *S3Conf) {
	testName := "UploadPartCopy_by_range_success"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj, srcBucket, srcObj := "my-obj", getBucketName(), "src-obj"
		err := setup(s, srcBucket)
		if err != nil {
			return err
		}
		objSize := 5 * 1024 * 1024
		_, _, err = putObjectWithData(int64(objSize), &s3.PutObjectInput{
			Bucket: &srcBucket,
			Key:    &srcObj,
		}, s3client)
		if err != nil {
			return err
		}

		out, err := CreateMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		copyOut, err := s3client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket:          &bucket,
			CopySource:      getPtr(srcBucket + "/" + srcObj),
			CopySourceRange: getPtr("bytes=100-200"),
			UploadId:        out.UploadId,
			Key:             &obj,
			PartNumber:      1,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListParts(ctx, &s3.ListPartsInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: out.UploadId,
		})
		cancel()
		if err != nil {
			return err
		}

		if len(res.Parts) != 1 {
			return fmt.Errorf("expected parts to be 1, instead got %v", len(res.Parts))
		}
		if res.Parts[0].PartNumber != 1 {
			return fmt.Errorf("expected part-number to be 1, instead got %v", res.Parts[0].PartNumber)
		}
		if res.Parts[0].Size != 101 {
			return fmt.Errorf("expected part size to be %v, instead got %v", 101, res.Parts[0].Size)
		}
		if *res.Parts[0].ETag != *copyOut.CopyPartResult.ETag {
			return fmt.Errorf("expected part etag to be %v, instead got %v", *copyOut.CopyPartResult.ETag, *res.Parts[0].ETag)
		}

		err = teardown(s, srcBucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func ListParts_incorrect_uploadId(s *S3Conf) {
	testName := "ListParts_incorrect_uploadId"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.ListParts(ctx, &s3.ListPartsInput{
			Bucket:   &bucket,
			Key:      getPtr("my-obj"),
			UploadId: getPtr("invalid uploadId"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchUpload)); err != nil {
			return err
		}

		return nil
	})
}

func ListParts_incorrect_object_key(s *S3Conf) {
	testName := "ListParts_incorrect_object_key"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := CreateMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.ListParts(ctx, &s3.ListPartsInput{
			Bucket:   &bucket,
			Key:      getPtr("incorrect-object-key"),
			UploadId: out.UploadId,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchUpload)); err != nil {
			return err
		}

		return nil
	})
}

func ListParts_success(s *S3Conf) {
	testName := "ListParts_success"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := CreateMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		parts, err := uploadParts(s3client, 5*1024*1024, 5, bucket, obj, *out.UploadId)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListParts(ctx, &s3.ListPartsInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: out.UploadId,
		})
		cancel()
		if err != nil {
			return err
		}

		if ok := compareParts(parts, res.Parts); !ok {
			return fmt.Errorf("expected parts %+v, instead got %+v", parts, res.Parts)
		}

		return nil
	})
}

func ListMultipartUploads_non_existing_bucket(s *S3Conf) {
	testName := "ListMultipartUploads_non_existing_bucket"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		bucketName := getBucketName()
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket: &bucketName,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func ListMultipartUploads_empty_result(s *S3Conf) {
	testName := "ListMultipartUploads_empty_result"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}
		if len(out.Uploads) != 0 {
			return fmt.Errorf("expected empty uploads, instead got %+v", out.Uploads)
		}

		return nil
	})
}

func ListMultipartUploads_invalid_max_uploads(s *S3Conf) {
	testName := "ListMultipartUploads_invalid_max_uploads"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket:     &bucket,
			MaxUploads: -3,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidMaxKeys)); err != nil {
			return err
		}

		return nil
	})
}

func ListMultipartUploads_max_uploads(s *S3Conf) {
	testName := "ListMultipartUploads_max_uploads"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		uploads := []types.MultipartUpload{}
		for i := 1; i < 6; i++ {
			out, err := CreateMp(s3client, bucket, fmt.Sprintf("obj%v", i))
			if err != nil {
				return err
			}
			uploads = append(uploads, types.MultipartUpload{UploadId: out.UploadId, Key: out.Key})
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket:     &bucket,
			MaxUploads: 2,
		})
		cancel()
		if err != nil {
			return err
		}
		if !out.IsTruncated {
			return fmt.Errorf("expected the output to be truncated")
		}
		if out.MaxUploads != 2 {
			return fmt.Errorf("expected max-uploads to be 2, instead got %v", out.MaxUploads)
		}
		if ok := compareMultipartUploads(out.Uploads, uploads[:2]); !ok {
			return fmt.Errorf("expected multipart uploads to be %v, instead got %v", uploads[:2], out.Uploads)
		}
		if *out.NextKeyMarker != *uploads[1].Key {
			return fmt.Errorf("expected next-key-marker to be %v, instead got %v", *uploads[1].Key, *out.NextKeyMarker)
		}
		if *out.NextUploadIdMarker != *uploads[1].UploadId {
			return fmt.Errorf("expected next-upload-id-marker to be %v, instead got %v", *uploads[1].Key, *out.NextKeyMarker)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err = s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket:    &bucket,
			KeyMarker: out.NextKeyMarker,
		})
		cancel()
		if err != nil {
			return err
		}
		if ok := compareMultipartUploads(out.Uploads, uploads[2:]); !ok {
			return fmt.Errorf("expected multipart uploads to be %v, instead got %v", uploads[2:], out.Uploads)
		}

		return nil
	})
}

func ListMultipartUploads_incorrect_next_key_marker(s *S3Conf) {
	testName := "ListMultipartUploads_incorrect_next_key_marker"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		for i := 1; i < 6; i++ {
			_, err := CreateMp(s3client, bucket, fmt.Sprintf("obj%v", i))
			if err != nil {
				return err
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket:    &bucket,
			KeyMarker: getPtr("incorrect_object_key"),
		})
		cancel()
		if err != nil {
			return err
		}

		if len(out.Uploads) != 0 {
			return fmt.Errorf("expected empty list of multipart uploads, instead got %v", out.Uploads)
		}

		return nil
	})
}

func ListMultipartUploads_ignore_upload_id_marker(s *S3Conf) {
	testName := "ListMultipartUploads_ignore_upload_id_marker"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		uploads := []types.MultipartUpload{}
		for i := 1; i < 6; i++ {
			out, err := CreateMp(s3client, bucket, fmt.Sprintf("obj%v", i))
			if err != nil {
				return err
			}
			uploads = append(uploads, types.MultipartUpload{UploadId: out.UploadId, Key: out.Key})
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket:         &bucket,
			UploadIdMarker: uploads[2].UploadId,
		})
		cancel()
		if err != nil {
			return err
		}
		if ok := compareMultipartUploads(out.Uploads, uploads); !ok {
			return fmt.Errorf("expected multipart uploads to be %v, instead got %v", uploads, out.Uploads)
		}

		return nil
	})
}

func ListMultipartUploads_success(s *S3Conf) {
	testName := "ListMultipartUploads_max_uploads"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj1, obj2 := "my-obj-1", "my-obj-2"
		out1, err := CreateMp(s3client, bucket, obj1)
		if err != nil {
			return err
		}

		out2, err := CreateMp(s3client, bucket, obj2)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		expected := []types.MultipartUpload{
			{
				Key:      &obj1,
				UploadId: out1.UploadId,
			},
			{
				Key:      &obj2,
				UploadId: out2.UploadId,
			},
		}

		if len(out.Uploads) != 2 {
			return fmt.Errorf("expected 2 upload, instead got %v", len(out.Uploads))
		}
		if ok := compareMultipartUploads(out.Uploads, expected); !ok {
			return fmt.Errorf("expected uploads %v, instead got %v", expected, out.Uploads)
		}

		return nil
	})
}

func AbortMultipartUpload_non_existing_bucket(s *S3Conf) {
	testName := "AbortMultipartUpload_non_existing_bucket"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
			Bucket:   getPtr("incorrectBucket"),
			Key:      getPtr("my-obj"),
			UploadId: getPtr("uploadId"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func AbortMultipartUpload_incorrect_uploadId(s *S3Conf) {
	testName := "AbortMultipartUpload_incorrect_uploadId"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
			Bucket:   &bucket,
			Key:      getPtr("my-obj"),
			UploadId: getPtr("invalid uploadId"),
		})
		cancel()
		if err := checkSdkApiErr(err, "NoSuchUpload"); err != nil {
			return err
		}

		return nil
	})
}

func AbortMultipartUpload_incorrect_object_key(s *S3Conf) {
	testName := "AbortMultipartUpload_incorrect_object_key"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := CreateMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
			Bucket:   &bucket,
			Key:      getPtr("incorrect-object-key"),
			UploadId: out.UploadId,
		})
		cancel()
		if err := checkSdkApiErr(err, "NoSuchUpload"); err != nil {
			return err
		}

		return nil
	})
}

func AbortMultipartUpload_success(s *S3Conf) {
	testName := "AbortMultipartUpload_success"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := CreateMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: out.UploadId,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if len(res.Uploads) != 0 {
			return fmt.Errorf("expected 0 upload, instead got %v", len(res.Uploads))
		}

		return nil
	})
}

func CompletedMultipartUpload_non_existing_bucket(s *S3Conf) {
	testName := "CompletedMultipartUpload_non_existing_bucket"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
			Bucket:   getPtr("non-existing-bucket"),
			Key:      getPtr("some/key"),
			UploadId: getPtr("uploadId"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func CompleteMultipartUpload_invalid_part_number(s *S3Conf) {
	testName := "CompleteMultipartUpload_invalid_part_number"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := CreateMp(s3client, bucket, obj)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:     &bucket,
			Key:        &obj,
			UploadId:   out.UploadId,
			PartNumber: 1,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: out.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: []types.CompletedPart{
					{
						ETag:       res.ETag,
						PartNumber: 5,
					},
				},
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidPart)); err != nil {
			return err
		}

		return nil
	})
}

func CompleteMultipartUpload_invalid_ETag(s *S3Conf) {
	testName := "CompleteMultipartUpload_invalid_ETag"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := CreateMp(s3client, bucket, obj)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:     &bucket,
			Key:        &obj,
			UploadId:   out.UploadId,
			PartNumber: 1,
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: out.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: []types.CompletedPart{
					{
						ETag:       getPtr("invalidETag"),
						PartNumber: 1,
					},
				},
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidPart)); err != nil {
			return err
		}

		return nil
	})
}

func CompleteMultipartUpload_success(s *S3Conf) {
	testName := "CompleteMultipartUpload_success"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		obj := "my-obj"
		out, err := CreateMp(s3client, bucket, obj)
		if err != nil {
			return err
		}

		objSize := 5 * 1024 * 1024
		parts, err := uploadParts(s3client, objSize, 5, bucket, obj, *out.UploadId)
		if err != nil {
			return err
		}

		compParts := []types.CompletedPart{}
		for _, el := range parts {
			compParts = append(compParts, types.CompletedPart{
				ETag:       el.ETag,
				PartNumber: el.PartNumber,
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		res, err := s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: out.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: compParts,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		if *res.Key != obj {
			return fmt.Errorf("expected object key to be %v, instead got %v", obj, *res.Key)
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		resp, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &bucket,
			Key:    &obj,
		})
		cancel()
		if err != nil {
			return err
		}

		if *resp.ETag != *res.ETag {
			return fmt.Errorf("expected the uploaded object etag to be %v, instead got %v", *res.ETag, *resp.ETag)
		}
		if resp.ContentLength != int64(objSize) {
			return fmt.Errorf("expected the uploaded object size to be %v, instead got %v", objSize, resp.ContentLength)
		}

		return nil
	})
}

func PutBucketAcl_non_existing_bucket(s *S3Conf) {
	testName := "PutBucketAcl_non_existing_bucket"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket: getPtr(getBucketName()),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func PutBucketAcl_invalid_acl_canned_and_acp(s *S3Conf) {
	testName := "PutBucketAcl_invalid_acl_canned_and_acp"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket:    &bucket,
			ACL:       types.BucketCannedACLPrivate,
			GrantRead: getPtr("user1"),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidRequest)); err != nil {
			return err
		}

		return nil
	})
}

func PutBucketAcl_invalid_acl_canned_and_grants(s *S3Conf) {
	testName := "PutBucketAcl_invalid_acl_canned_and_grants"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket: &bucket,
			ACL:    types.BucketCannedACLPrivate,
			AccessControlPolicy: &types.AccessControlPolicy{
				Grants: []types.Grant{
					{
						Grantee: &types.Grantee{
							ID:   getPtr("awsID"),
							Type: types.TypeCanonicalUser,
						},
					},
				},
				Owner: &types.Owner{
					ID: &s.awsID,
				},
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidRequest)); err != nil {
			return err
		}

		return nil
	})
}

func PutBucketAcl_invalid_acl_acp_and_grants(s *S3Conf) {
	testName := "PutBucketAcl_invalid_acl_acp_and_grants"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket:           &bucket,
			GrantFullControl: getPtr("userAccess"),
			AccessControlPolicy: &types.AccessControlPolicy{
				Grants: []types.Grant{
					{
						Grantee: &types.Grantee{
							ID:   getPtr("awsID"),
							Type: types.TypeCanonicalUser,
						},
					},
				},
				Owner: &types.Owner{
					ID: &s.awsID,
				},
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidRequest)); err != nil {
			return err
		}

		return nil
	})
}

func PutBucketAcl_invalid_owner(s *S3Conf) {
	testName := "PutBucketAcl_invalid_acl_acp_and_grants"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket: &bucket,
			AccessControlPolicy: &types.AccessControlPolicy{
				Grants: []types.Grant{
					{
						Grantee: &types.Grantee{
							ID:   getPtr("awsID"),
							Type: types.TypeCanonicalUser,
						},
					},
				},
				Owner: &types.Owner{
					ID: getPtr("invalidOwner"),
				},
			},
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		return nil
	})
}

func PutBucketAcl_success_access_denied(s *S3Conf) {
	testName := "PutBucketAcl_success_access_denied"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := createUsers(s, []user{{"grt1", "grt1secret", "user"}})
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket: &bucket,
			AccessControlPolicy: &types.AccessControlPolicy{
				Grants: []types.Grant{
					{
						Grantee: &types.Grantee{
							ID:   getPtr("grt1"),
							Type: types.TypeCanonicalUser,
						},
						Permission: types.PermissionRead,
					},
				},
				Owner: &types.Owner{
					ID: &s.awsID,
				},
			},
		})
		cancel()
		if err != nil {
			return err
		}

		newConf := *s
		newConf.awsID = "grt1"
		newConf.awsSecret = "grt1secret"
		userClient := s3.NewFromConfig(newConf.Config())

		err = putObjects(userClient, []string{"my-obj"}, bucket)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		return nil
	})
}

func PutBucketAcl_success_canned_acl(s *S3Conf) {
	testName := "PutBucketAcl_success_canned_acl"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := createUsers(s, []user{{"grt1", "grt1secret", "user"}})
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket: &bucket,
			AccessControlPolicy: &types.AccessControlPolicy{
				Owner: &types.Owner{
					ID: &s.awsID,
				},
			},
			ACL: types.BucketCannedACLPublicReadWrite,
		})
		cancel()
		if err != nil {
			return err
		}

		newConf := *s
		newConf.awsID = "grt1"
		newConf.awsSecret = "grt1secret"
		userClient := s3.NewFromConfig(newConf.Config())

		err = putObjects(userClient, []string{"my-obj"}, bucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func PutBucketAcl_success_acp(s *S3Conf) {
	testName := "PutBucketAcl_success_acp"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := createUsers(s, []user{{"grt1", "grt1secret", "user"}})
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket: &bucket,
			AccessControlPolicy: &types.AccessControlPolicy{
				Owner: &types.Owner{
					ID: &s.awsID,
				},
			},
			GrantRead: getPtr("grt1"),
		})
		cancel()
		if err != nil {
			return err
		}

		newConf := *s
		newConf.awsID = "grt1"
		newConf.awsSecret = "grt1secret"
		userClient := s3.NewFromConfig(newConf.Config())

		err = putObjects(userClient, []string{"my-obj"}, bucket)
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.HeadBucket(ctx, &s3.HeadBucketInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		return nil
	})
}

func PutBucketAcl_success_grants(s *S3Conf) {
	testName := "PutBucketAcl_success_grants"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := createUsers(s, []user{{"grt1", "grt1secret", "user"}})
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket: &bucket,
			AccessControlPolicy: &types.AccessControlPolicy{
				Grants: []types.Grant{
					{
						Grantee: &types.Grantee{
							ID:   getPtr("grt1"),
							Type: types.TypeCanonicalUser,
						},
						Permission: types.PermissionFullControl,
					},
				},
				Owner: &types.Owner{
					ID: &s.awsID,
				},
			},
		})
		cancel()
		if err != nil {
			return err
		}

		newConf := *s
		newConf.awsID = "grt1"
		newConf.awsSecret = "grt1secret"
		userClient := s3.NewFromConfig(newConf.Config())

		err = putObjects(userClient, []string{"my-obj"}, bucket)
		if err != nil {
			return err
		}

		return nil
	})
}

func GetBucketAcl_non_existing_bucket(s *S3Conf) {
	testName := "GetBucketAcl_non_existing_bucket"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.GetBucketAcl(ctx, &s3.GetBucketAclInput{
			Bucket: getPtr(getBucketName()),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNoSuchBucket)); err != nil {
			return err
		}

		return nil
	})
}

func GetBucketAcl_access_denied(s *S3Conf) {
	testName := "GetBucketAcl_access_denied"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := createUsers(s, []user{{"grt1", "grt1secret", "user"}})
		if err != nil {
			return err
		}

		newConf := *s
		newConf.awsID = "grt1"
		newConf.awsSecret = "grt1secret"
		userClient := s3.NewFromConfig(newConf.Config())

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = userClient.GetBucketAcl(ctx, &s3.GetBucketAclInput{
			Bucket: &bucket,
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		return nil
	})
}

func GetBucketAcl_success(s *S3Conf) {
	testName := "GetBucketAcl_success"
	actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		err := createUsers(s, []user{
			{"grt1", "grt1secret", "user"},
			{"grt2", "grt2secret", "user"},
			{"grt3", "grt3secret", "user"},
		})
		if err != nil {
			return err
		}

		grants := []types.Grant{
			{
				Grantee: &types.Grantee{
					ID:   getPtr("grt1"),
					Type: types.TypeCanonicalUser,
				},
				Permission: types.PermissionFullControl,
			},
			{
				Grantee: &types.Grantee{
					ID:   getPtr("grt2"),
					Type: types.TypeCanonicalUser,
				},
				Permission: types.PermissionReadAcp,
			},
			{
				Grantee: &types.Grantee{
					ID:   getPtr("grt3"),
					Type: types.TypeCanonicalUser,
				},
				Permission: types.PermissionWrite,
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket: &bucket,
			AccessControlPolicy: &types.AccessControlPolicy{
				Grants: grants,
				Owner: &types.Owner{
					ID: &s.awsID,
				},
			},
		})
		cancel()
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.GetBucketAcl(ctx, &s3.GetBucketAclInput{
			Bucket: &bucket,
		})
		cancel()
		if err != nil {
			return err
		}

		if ok := compareGrants(out.Grants, grants); !ok {
			return fmt.Errorf("expected grants to be %v, instead got %v", grants, out.Grants)
		}
		if *out.Owner.ID != s.awsID {
			return fmt.Errorf("expected bucket owner to be %v, instead got %v", s.awsID, *out.Owner.ID)
		}

		return nil
	})
}

type prefResult struct {
	elapsed time.Duration
	size    int64
	err     error
}

func TestPerformance(s *S3Conf, upload, download bool, files int, objectSize int64, bucket, prefix string) error {
	var sg sync.WaitGroup
	results := make([]prefResult, files)
	start := time.Now()
	if upload {
		if objectSize == 0 {
			return fmt.Errorf("must specify object size for upload")
		}

		if objectSize > (int64(10000) * s.PartSize) {
			return fmt.Errorf("object size can not exceed 10000 * chunksize")
		}

		runF("performance test: upload/download objects")

		for i := 0; i < files; i++ {
			sg.Add(1)
			go func(i int) {
				var r io.Reader = NewDataReader(int(objectSize), int(s.PartSize))

				start := time.Now()
				err := s.UploadData(r, bucket, fmt.Sprintf("%v%v", prefix, i))
				results[i].elapsed = time.Since(start)
				results[i].err = err
				results[i].size = objectSize
				sg.Done()
			}(i)
		}
	}
	if download {
		for i := 0; i < files; i++ {
			sg.Add(1)
			go func(i int) {
				nw := NewNullWriter()
				start := time.Now()
				n, err := s.DownloadData(nw, bucket, fmt.Sprintf("%v%v", prefix, i))
				results[i].elapsed = time.Since(start)
				results[i].err = err
				results[i].size = n
				sg.Done()
			}(i)
		}
	}
	sg.Wait()
	elapsed := time.Since(start)

	var tot int64
	for i, res := range results {
		if res.err != nil {
			failF("%v: %v\n", i, res.err)
			break
		}
		tot += res.size
		fmt.Printf("%v: %v in %v (%v MB/s)\n",
			i, res.size, res.elapsed,
			int(math.Ceil(float64(res.size)/res.elapsed.Seconds())/1048576))
	}

	fmt.Println()
	passF("run perf: %v in %v (%v MB/s)\n",
		tot, elapsed, int(math.Ceil(float64(tot)/elapsed.Seconds())/1048576))

	return nil
}
