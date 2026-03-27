package command

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/versity/versitygw/tests/rest_scripts/logger"
	"os"
	"sort"
	"strings"
	"time"
)

type S3Request struct {
	Config *S3RequestConfigData

	currentDateTime      string
	yearMonthDay         string
	path                 string
	signedParamString    string
	signature            string
	host                 string
	headerValues         []*HeaderValue
	payloadHash          string
	dataSource           DataSource
	canonicalRequestHash string
	signingKey           []byte
}

func (s *S3Request) CalculateDateTimeParams() {
	now := time.Now().UTC()
	if s.Config.CustomDate != "" {
		s.currentDateTime = s.Config.CustomDate
	} else if s.Config.IncorrectYearMonthDay {
		s.currentDateTime = now.Add(-48 * time.Hour).Format("20060102T150405Z")
	} else {
		s.currentDateTime = now.Format("20060102T150405Z")
	}
	s.yearMonthDay = strings.Split(s.currentDateTime, "T")[0]
	if s.Config.InvalidYearMonthDay {
		s.yearMonthDay = s.yearMonthDay[:len(s.yearMonthDay)-2]
	}
}

func (s *S3Request) DeriveHost() error {
	protocolAndHost := strings.Split(s.Config.Url, "://")
	if len(protocolAndHost) != 2 {
		return fmt.Errorf("invalid URL value: %s", s.Config.Url)
	}
	s.host = protocolAndHost[1]
	return nil
}

func (s *S3Request) DeriveBucketAndKeyPath() {
	s.path = "/" + s.Config.BucketName
	if s.Config.ObjectKey != "" {
		s.path += "/" + s.Config.ObjectKey
	}
}

func (s *S3Request) CalculateSignature() error {

	if err := s.calculateCanonicalRequestHash(); err != nil {
		return fmt.Errorf("error calculating canonical request hash: %w", err)
	}

	thirdLine := fmt.Sprintf("%s/%s/%s/aws4_request", s.yearMonthDay, s.Config.AwsRegion, s.Config.ServiceName)
	stsDataLines := []string{
		s.Config.AuthorizationScheme,
		s.currentDateTime,
		thirdLine,
		s.canonicalRequestHash,
	}
	stsDataString := strings.Join(stsDataLines, "\n")

	// Derive signing key step by step
	dateKey := hmacSHA256([]byte("AWS4"+s.Config.AwsSecretAccessKey), s.yearMonthDay)
	dateRegionKey := hmacSHA256(dateKey, s.Config.AwsRegion)
	dateRegionServiceKey := hmacSHA256(dateRegionKey, s.Config.ServiceName)
	s.signingKey = hmacSHA256(dateRegionServiceKey, "aws4_request")

	// Generate signature
	signatureBytes := hmacSHA256(s.signingKey, stsDataString)
	if s.Config.IncorrectSignature {
		if signatureBytes[0] == 'a' {
			signatureBytes[0] = 'A'
		} else {
			signatureBytes[0] = 'a'
		}
	}

	// Print hex-encoded signature
	s.signature = hex.EncodeToString(signatureBytes)
	return nil
}

func (s *S3Request) calculateCanonicalRequestHash() error {
	canonicalRequestLines := []string{s.Config.Method}

	s.path = encodeS3Key(s.path)
	canonicalRequestLines = append(canonicalRequestLines, s.path)

	canonicalQuery, err := s.getCanonicalQuery()
	if err != nil {
		return fmt.Errorf("error generating canoncial query: %w", err)
	}
	canonicalRequestLines = append(canonicalRequestLines, canonicalQuery)

	var signedParams []string
	for _, headerValue := range s.headerValues {
		if headerValue.Signed {
			key := strings.ToLower(headerValue.Key)
			canonicalRequestLines = append(canonicalRequestLines, key+":"+headerValue.Value)
			signedParams = append(signedParams, key)
		}
	}

	canonicalRequestLines = append(canonicalRequestLines, "")
	s.signedParamString = strings.Join(signedParams, ";")
	canonicalRequestLines = append(canonicalRequestLines, s.signedParamString, s.payloadHash)

	canonicalRequestString := strings.Join(canonicalRequestLines, "\n")
	logger.PrintDebug("Canonical request string: %s\n", canonicalRequestString)

	canonicalRequestHashBytes := sha256.Sum256([]byte(canonicalRequestString))
	s.canonicalRequestHash = hex.EncodeToString(canonicalRequestHashBytes[:])
	return nil
}

func (s *S3Request) getCanonicalQuery() (string, error) {
	var queryRequestLine string
	if strings.Contains(s.Config.Query, "&") {
		queries := strings.Split(s.Config.Query, "&")
		if !strings.HasSuffix(queries[0], "=") && !strings.Contains(queries[0], "=") {
			queries[0] += "="
			queryRequestLine = strings.Join(queries, "&")
		}
	} else if s.Config.Query != "" && !strings.HasSuffix(s.Config.Query, "=") && !strings.Contains(s.Config.Query, "=") {
		queryRequestLine = s.Config.Query + "="
	}
	if queryRequestLine == "" {
		queryRequestLine = s.Config.Query
	}
	canonicalQuery, err := canonicalizeQuery(queryRequestLine)
	if err != nil {
		return "", fmt.Errorf("error parsing query '%s': %v", queryRequestLine, err)
	}
	return canonicalQuery, nil
}

func (s *S3Request) performBasePayloadCalculations() error {
	if s.Config.PayloadFile != "" {
		s.dataSource = NewFileDataSource(s.Config.PayloadFile)
	} else if s.Config.Payload != "" {
		s.dataSource = NewStringDataSource(s.Config.Payload)
	}
	if s.Config.CustomSHA256Hash != "" {
		s.payloadHash = s.Config.CustomSHA256Hash
	} else if s.Config.PayloadType != "" {
		s.payloadHash = s.Config.PayloadType
	} else if s.dataSource != nil {
		var err error
		s.payloadHash, err = s.dataSource.CalculateSHA256HashString()
		if err != nil {
			return fmt.Errorf("error calculating sha256 hash: %w", err)
		}
	} else {
		s.payloadHash = SHA256HashZeroBytes
	}
	return nil
}

func (s *S3Request) deriveUniversalHeaderValues() {
	if s.Config.MissingHostParam {
		s.headerValues = append(s.headerValues, &HeaderValue{"host", "", true})
	} else if s.Config.CustomHostParamSet {
		s.headerValues = append(s.headerValues, &HeaderValue{"host", s.Config.CustomHostParam, true})
	} else {
		s.headerValues = append(s.headerValues, &HeaderValue{"host", s.host, true})
	}
	if !s.Config.OmitSHA256Hash {
		s.headerValues = append(s.headerValues, &HeaderValue{"x-amz-content-sha256", s.payloadHash, true})
	}
	if !s.Config.OmitDate {
		s.headerValues = append(s.headerValues, &HeaderValue{"x-amz-date", s.currentDateTime, true})
	}
}

func (s *S3Request) deriveConfigSpecificHeaderValues() error {
	if s.Config.PayloadType == StreamingAWS4HMACSHA256PayloadTrailer && s.Config.ChecksumType != "" {
		s.headerValues = append(s.headerValues, &HeaderValue{"x-amz-trailer", fmt.Sprintf("x-amz-checksum-%s", s.Config.ChecksumType), true})
	}
	if s.dataSource != nil && s.Config.PayloadType != UnsignedPayload {
		payloadSize, err := s.dataSource.SourceDataByteSize()
		if err != nil {
			return fmt.Errorf("error getting payload size: %w", err)
		}
		s.headerValues = append(s.headerValues,
			&HeaderValue{"x-amz-decoded-content-length", fmt.Sprintf("%d", payloadSize), true})
	}
	for key, value := range s.Config.SignedParams {
		s.headerValues = append(s.headerValues, &HeaderValue{key, value, true})
	}
	if s.Config.ContentMD5 || s.Config.IncorrectContentMD5 || s.Config.CustomContentMD5 != "" {
		if err := s.addContentMD5Header(); err != nil {
			return fmt.Errorf("error adding Content-MD5 header: %w", err)
		}
	}
	for key, value := range s.Config.UnsignedParams {
		s.headerValues = append(s.headerValues, &HeaderValue{key, value, false})
	}
	sort.Slice(s.headerValues,
		func(i, j int) bool {
			return strings.ToLower(s.headerValues[i].Key) < strings.ToLower(s.headerValues[j].Key)
		})
	return nil
}

func (s *S3Request) addContentMD5Header() error {
	var payloadData []byte
	var err error
	if s.Config.PayloadFile != "" {
		if payloadData, err = os.ReadFile(s.Config.PayloadFile); err != nil {
			return fmt.Errorf("error reading file %s: %w", s.Config.PayloadFile, err)
		}
	} else {
		logger.PrintDebug("Payload: %s", s.Config.Payload)
		payloadData = []byte(strings.Replace(s.Config.Payload, "\\", "", -1))
	}

	var contentMD5 string
	if s.Config.CustomContentMD5 != "" {
		contentMD5 = s.Config.CustomContentMD5
	} else {
		hasher := md5.New()
		hasher.Write(payloadData)
		md5Hash := hasher.Sum(nil)
		if s.Config.IncorrectContentMD5 {
			modifyHash(md5Hash)
		}
		contentMD5 = base64.StdEncoding.EncodeToString(md5Hash)
	}

	s.headerValues = append(s.headerValues, &HeaderValue{"Content-MD5", contentMD5, true})
	return nil
}

func (s *S3Request) buildAuthorizationString() string {
	var credentialString string
	if s.Config.IncorrectCredential == "" {
		credentialString = fmt.Sprintf("%s/%s/%s/%s/aws4_request", s.Config.AwsAccessKeyId, s.yearMonthDay, s.Config.AwsRegion, s.Config.ServiceName)
	} else {
		credentialString = s.Config.IncorrectCredential
	}
	return fmt.Sprintf("Authorization: %s Credential=%s,SignedHeaders=%s,Signature=%s",
		s.Config.AuthorizationScheme, credentialString, s.signedParamString, s.signature)
}
