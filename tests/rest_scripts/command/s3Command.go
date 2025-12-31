package command

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	logger "github.com/versity/versitygw/tests/rest_scripts/logger"
)

const (
	CURL    = "curl"
	OPENSSL = "openssl"
)

const (
	UnsignedPayload                            = "UNSIGNED-PAYLOAD"
	StreamingAWS4HMACSHA256Payload             = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
	StreamingAWS4HMACSHA256PayloadTrailer      = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
	StreamingUnsignedPayloadTrailer            = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
	StreamingAWS4ECDSAP256SHA256Payload        = "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD"
	StreamingAWS4ECDSAP256SHA256PayloadTrailer = "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD-TRAILER"
)

type PayloadType string

const (
	ChecksumCRC32     = "crc32"
	ChecksumCRC32C    = "crc32c"
	ChecksumCRC64NVME = "crc64nvme"
	ChecksumSHA1      = "sha1"
	ChecksumSHA256    = "sha256"
)

const SHA256HashZeroBytes = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

type S3RESTCommand struct {
	Method         string
	Url            string
	Queries        map[string]string
	SignedParams   map[string]string
	UnsignedParams map[string]string
	DataSource     DataSource
}

type S3CommandErrors struct {
	IncorrectSignature           bool
	AuthorizationHeaderMalformed bool
	IncorrectCredential          string
	IncorrectYearMonthDay        bool
	InvalidYearMonthDay          bool
	IncorrectContentMD5          bool
	MissingHostParam             bool
	CustomHostParam              string
	CustomHostParamSet           bool
}

type S3Command struct {
	Client                       string
	Method                       string
	Url                          string
	BucketName                   string
	ObjectKey                    string
	Query                        string
	AwsRegion                    string
	AwsAccessKeyId               string
	AwsSecretAccessKey           string
	ServiceName                  string
	SignedParams                 map[string]string
	PayloadFile                  string
	IncorrectSignature           bool
	AuthorizationHeaderMalformed bool
	AuthorizationScheme          string
	IncorrectCredential          string
	IncorrectYearMonthDay        bool
	InvalidYearMonthDay          bool
	Payload                      string
	ContentMD5                   bool
	IncorrectContentMD5          bool
	CustomContentMD5             string
	MissingHostParam             bool
	FilePath                     string
	CustomHostParam              string
	CustomHostParamSet           bool
	PayloadType                  string
	ChunkSize                    int
	ChecksumType                 string
	OmitPayloadTrailer           bool
	OmitPayloadTrailerKey        bool
	OmitContentLength            bool

	dataSource           DataSource
	currentDateTime      string
	host                 string
	payloadHash          string
	headerValues         [][]string
	canonicalRequestHash string
	path                 string
	signedParamString    string
	yearMonthDay         string
	signature            string
	signingKey           []byte
	contentLength        int64
	payloadOpenSSL       OpenSSLPayloadManager
}

func (s *S3Command) OpenSSLCommand() error {
	if err := s.prepareForBuild(); err != nil {
		return fmt.Errorf("error preparing for command building: %w", err)
	}
	if err := s.buildOpenSSLCommand(); err != nil {
		return fmt.Errorf("error building openSSL command: %w", err)
	}
	return nil
}

func (s *S3Command) CurlShellCommand() (string, error) {
	if err := s.prepareForBuild(); err != nil {
		return "", fmt.Errorf("error preparing for command building: %w", err)
	}
	return s.buildCurlShellCommand()
}

func (s *S3Command) prepareForBuild() error {
	now := time.Now().UTC()
	if s.IncorrectYearMonthDay {
		s.currentDateTime = now.Add(-48 * time.Hour).Format("20060102T150405Z")
	} else {
		s.currentDateTime = now.Format("20060102T150405Z")
	}
	protocolAndHost := strings.Split(s.Url, "://")
	if len(protocolAndHost) != 2 {
		return fmt.Errorf("invalid URL value: %s", s.Url)
	}
	s.host = protocolAndHost[1]
	s.yearMonthDay = strings.Split(s.currentDateTime, "T")[0]
	if s.InvalidYearMonthDay {
		s.yearMonthDay = s.yearMonthDay[:len(s.yearMonthDay)-2]
	}
	s.path = "/" + s.BucketName
	if s.ObjectKey != "" {
		s.path += "/" + s.ObjectKey
	}
	if err := s.preparePayload(); err != nil {
		return fmt.Errorf("error preparing payload: %w", err)
	}
	if err := s.addHeaderValues(); err != nil {
		return fmt.Errorf("error adding header values: %w", err)
	}
	s.generateCanonicalRequestString()
	s.getStsSignature()
	return nil
}

func (s *S3Command) preparePayload() error {
	if s.PayloadFile != "" {
		s.dataSource = NewFileDataSource(s.PayloadFile)
	} else if s.Payload != "" {
		s.dataSource = NewStringDataSource(s.Payload)
	}
	if s.PayloadType != "" {
		s.payloadHash = s.PayloadType
	} else if s.dataSource != nil {
		var err error
		s.payloadHash, err = s.dataSource.CalculateSHA256HashString()
		if err != nil {
			return fmt.Errorf("error calculating sha256 hash")
		}
	} else {
		s.payloadHash = SHA256HashZeroBytes
	}
	if s.Client == OPENSSL {
		if err := s.initializeOpenSSLPayloadAndGetContentLength(); err != nil {
			return fmt.Errorf("error initializing openssl payload: %w", err)
		}
	}
	return nil
}

func (s *S3Command) initializeOpenSSLPayloadAndGetContentLength() error {
	switch s.PayloadType {
	case StreamingAWS4HMACSHA256Payload, StreamingAWS4HMACSHA256PayloadTrailer:
		serviceString := fmt.Sprintf("%s/%s/%s/aws4_request", s.yearMonthDay, s.AwsRegion, s.ServiceName)
		s.payloadOpenSSL = NewPayloadStreamingAWS4HMACSHA256(s.dataSource, int64(s.ChunkSize), PayloadType(s.PayloadType), serviceString, s.currentDateTime, s.yearMonthDay, s.ChecksumType)
	case StreamingUnsignedPayloadTrailer:
		streamingUnsignedPayloadTrailerImpl := NewStreamingUnsignedPayloadWithTrailer(s.dataSource, int64(s.ChunkSize), s.ChecksumType)
		streamingUnsignedPayloadTrailerImpl.OmitTrailerOrKey(s.OmitPayloadTrailer, s.OmitPayloadTrailerKey)
		s.payloadOpenSSL = streamingUnsignedPayloadTrailerImpl
	case UnsignedPayload, "":
		s.payloadOpenSSL = NewWholePayload(s.dataSource)
	default:
		return fmt.Errorf("unsupported OpenSSL payload type: '%s'", s.PayloadType)
	}
	var err error
	s.contentLength, err = s.payloadOpenSSL.GetContentLength()
	if err != nil {
		return fmt.Errorf("error calculating Content-Length: %w", err)
	}
	logger.PrintDebug("Predicted payload size: %d", s.contentLength)
	return nil
}

func (s *S3Command) addHeaderValues() error {
	s.headerValues = [][]string{}
	if s.MissingHostParam {
		s.headerValues = append(s.headerValues, []string{"host", ""})
	} else if s.CustomHostParamSet {
		s.headerValues = append(s.headerValues, []string{"host", s.CustomHostParam})
	} else {
		s.headerValues = append(s.headerValues, []string{"host", s.host})
	}
	if s.PayloadType == StreamingAWS4HMACSHA256PayloadTrailer && s.ChecksumType != "" {
		s.headerValues = append(s.headerValues, []string{"x-amz-trailer", fmt.Sprintf("x-amz-checksum-%s", s.ChecksumType)})
	}
	s.headerValues = append(s.headerValues,
		[]string{"x-amz-content-sha256", s.payloadHash},
		[]string{"x-amz-date", s.currentDateTime},
	)
	if s.Client == OPENSSL && !s.OmitContentLength {
		s.headerValues = append(s.headerValues,
			[]string{"Content-Length", fmt.Sprintf("%d", s.contentLength)})
	}
	if s.dataSource != nil && s.PayloadType != UnsignedPayload {
		payloadSize, err := s.dataSource.SourceDataByteSize()
		if err != nil {
			return fmt.Errorf("error getting payload size: %w", err)
		}
		s.headerValues = append(s.headerValues,
			[]string{"x-amz-decoded-content-length", fmt.Sprintf("%d", payloadSize)})
	}
	for key, value := range s.SignedParams {
		s.headerValues = append(s.headerValues, []string{key, value})
	}
	if s.ContentMD5 || s.IncorrectContentMD5 || s.CustomContentMD5 != "" {
		if err := s.addContentMD5Header(); err != nil {
			return fmt.Errorf("error adding Content-MD5 header: %w", err)
		}
	}
	sort.Slice(s.headerValues,
		func(i, j int) bool {
			return strings.ToLower(s.headerValues[i][0]) < strings.ToLower(s.headerValues[j][0])
		})
	return nil
}

func (s *S3Command) modifyHash(md5Hash []byte) {
	if md5Hash[0] == 'a' {
		md5Hash[0] = 'A'
	} else {
		md5Hash[0] = 'a'
	}
}

func (s *S3Command) addContentMD5Header() error {
	var payloadData []byte
	var err error
	if s.PayloadFile != "" {
		if payloadData, err = os.ReadFile(s.PayloadFile); err != nil {
			return fmt.Errorf("error reading file %s: %w", s.PayloadFile, err)
		}
	} else {
		logger.PrintDebug("Payload: %s", s.Payload)
		payloadData = []byte(strings.Replace(s.Payload, "\\", "", -1))
	}

	var contentMD5 string
	if s.CustomContentMD5 != "" {
		contentMD5 = s.CustomContentMD5
	} else {
		hasher := md5.New()
		hasher.Write(payloadData)
		md5Hash := hasher.Sum(nil)
		if s.IncorrectContentMD5 {
			s.modifyHash(md5Hash)
		}
		contentMD5 = base64.StdEncoding.EncodeToString(md5Hash)
	}

	s.headerValues = append(s.headerValues, []string{"Content-MD5", contentMD5})
	return nil
}

func (s *S3Command) generateCanonicalRequestString() {
	canonicalRequestLines := []string{s.Method}

	canonicalRequestLines = append(canonicalRequestLines, s.path)
	canonicalRequestLines = append(canonicalRequestLines, s.Query)

	var signedParams []string
	for _, headerValue := range s.headerValues {
		key := strings.ToLower(headerValue[0])
		canonicalRequestLines = append(canonicalRequestLines, key+":"+headerValue[1])
		signedParams = append(signedParams, key)
	}

	canonicalRequestLines = append(canonicalRequestLines, "")
	s.signedParamString = strings.Join(signedParams, ";")
	canonicalRequestLines = append(canonicalRequestLines, s.signedParamString, s.payloadHash)

	canonicalRequestString := strings.Join(canonicalRequestLines, "\n")
	logger.PrintDebug("Canonical request string: %s\n", canonicalRequestString)

	canonicalRequestHashBytes := sha256.Sum256([]byte(canonicalRequestString))
	s.canonicalRequestHash = hex.EncodeToString(canonicalRequestHashBytes[:])
}

func (s *S3Command) getStsSignature() {
	thirdLine := fmt.Sprintf("%s/%s/%s/aws4_request", s.yearMonthDay, s.AwsRegion, s.ServiceName)
	stsDataLines := []string{
		s.AuthorizationScheme,
		s.currentDateTime,
		thirdLine,
		s.canonicalRequestHash,
	}
	stsDataString := strings.Join(stsDataLines, "\n")

	// Derive signing key step by step
	dateKey := hmacSHA256([]byte("AWS4"+s.AwsSecretAccessKey), s.yearMonthDay)
	dateRegionKey := hmacSHA256(dateKey, s.AwsRegion)
	dateRegionServiceKey := hmacSHA256(dateRegionKey, s.ServiceName)
	s.signingKey = hmacSHA256(dateRegionServiceKey, "aws4_request")

	// Generate signature
	signatureBytes := hmacSHA256(s.signingKey, stsDataString)
	if s.IncorrectSignature {
		if signatureBytes[0] == 'a' {
			signatureBytes[0] = 'A'
		} else {
			signatureBytes[0] = 'a'
		}
	}

	// Print hex-encoded signature
	s.signature = hex.EncodeToString(signatureBytes)
}

func (s *S3Command) buildCurlShellCommand() (string, error) {
	if s.MissingHostParam {
		return "", fmt.Errorf("missingHostParam option only available for OpenSSL commands")
	}
	curlOpts := "-iks"
	if s.Method == "HEAD" {
		curlOpts += "I"
	}
	curlCommand := []string{"curl", curlOpts}
	if s.Method != "GET" {
		curlCommand = append(curlCommand, fmt.Sprintf("-X %s ", s.Method))
	}
	fullPath := "\"" + s.Url + s.path
	if s.Query != "" {
		fullPath += "?" + s.Query
	}
	fullPath += "\""
	curlCommand = append(curlCommand, fullPath)
	authorizationString := s.buildAuthorizationString()
	curlCommand = append(curlCommand, "-H", fmt.Sprintf("\"%s\"", authorizationString))
	for _, headerValue := range s.headerValues {
		headerString := fmt.Sprintf("\"%s: %s\"", headerValue[0], headerValue[1])
		curlCommand = append(curlCommand, "-H", headerString)
	}
	if s.PayloadFile != "" {
		curlCommand = append(curlCommand, "-T", s.PayloadFile)
	} else if s.Payload != "" {
		s.Payload = strings.Replace(s.Payload, "\"", "\\\"", -1)
		curlCommand = append(curlCommand, "-H", "\"Content-Type: application/xml\"", "-d", fmt.Sprintf("\"%s\"", s.Payload))
	}
	curlStringCommand := strings.Join(curlCommand, " ")
	logger.PrintDebug("curl command: %s", curlStringCommand)
	return curlStringCommand, nil
}

func (s *S3Command) buildAuthorizationString() string {
	var credentialString string
	if s.IncorrectCredential == "" {
		credentialString = fmt.Sprintf("%s/%s/%s/%s/aws4_request", s.AwsAccessKeyId, s.yearMonthDay, s.AwsRegion, s.ServiceName)
	} else {
		credentialString = s.IncorrectCredential
	}
	return fmt.Sprintf("Authorization: %s Credential=%s,SignedHeaders=%s,Signature=%s",
		s.AuthorizationScheme, credentialString, s.signedParamString, s.signature)
}

func (s *S3Command) buildOpenSSLCommand() error {
	if s.Query != "" {
		s.path += "?" + s.Query
	}
	openSSLCommand := []string{fmt.Sprintf("%s %s HTTP/1.1", s.Method, s.path)}
	openSSLCommand = append(openSSLCommand, s.buildAuthorizationString())
	for _, headerValue := range s.headerValues {
		if headerValue[0] == "host" && s.MissingHostParam {
			continue
		}
		openSSLCommand = append(openSSLCommand, fmt.Sprintf("%s:%s", headerValue[0], headerValue[1]))
	}

	file, err := os.Create(s.FilePath)
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}
	defer func() {
		file.Close()
	}()
	openSSLCommandBytes := []byte(strings.Join(openSSLCommand, "\r\n"))
	if _, err = file.Write(openSSLCommandBytes); err != nil {
		return fmt.Errorf("error writing to file: %w", err)
	}
	if _, err := file.Write([]byte{'\r', '\n', '\r', '\n'}); err != nil {
		return fmt.Errorf("error writing to file: %w", err)
	}
	if s.PayloadFile != "" || s.Payload != "" {
		if err = s.writeOpenSSLPayload(file); err != nil {
			return fmt.Errorf("error writing openssl payload: %w", err)
		}
	}
	return nil
}

func (s *S3Command) writeOpenSSLPayload(file *os.File) error {
	if awsPayload, ok := s.payloadOpenSSL.(*PayloadStreamingAWS4HMACSHA256); ok {
		awsPayload.AddInitialSignatureAndSigningKey(s.signature, s.signingKey)
	}
	switch s.PayloadType {
	case UnsignedPayload, "", StreamingUnsignedPayloadTrailer, StreamingAWS4HMACSHA256Payload, StreamingAWS4HMACSHA256PayloadTrailer:
		if err := s.payloadOpenSSL.WritePayload(s.FilePath); err != nil {
			return fmt.Errorf("error writing payload to openssl file: %w", err)
		}
	default:
		return fmt.Errorf("unsupported payload type: %s", s.PayloadType)
	}
	return nil
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}
