package command

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	logger "github.com/versity/versitygw/tests/rest_scripts/logger"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	UnsignedPayload                            = "UNSIGNED-PAYLOAD"
	StreamingAWS4HMACSHA256Payload             = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
	StreamingAWS4HMACSHA256PayloadTrailer      = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
	StreamingUnsignedPayloadTrailer            = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
	StreamingAWS4ECDSAP256SHA256Payload        = "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD"
	StreamingAWS4ECDSAP256SHA256PayloadTrailer = "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD-TRAILER"
)

type S3Command struct {
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
	MissingHostParam             bool
	FilePath                     string
	CustomHostParam              string
	CustomHostParamSet           bool
	PayloadType                  string
	ChunkSize                    int

	currentDateTime      string
	host                 string
	payloadHash          string
	headerValues         [][]string
	canonicalRequestHash string
	path                 string
	signedParamString    string
	yearMonthDay         string
	signature            string
}

func (s *S3Command) OpenSSLCommand() error {
	if s.FilePath == "" {
		return errors.New("for openssl command, filePath must be set")
	}
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
	if s.PayloadFile != "" && s.Payload != "" {
		return fmt.Errorf("cannot have both payload and payloadFile parameters set")
	}
	if s.IncorrectYearMonthDay {
		s.currentDateTime = time.Now().Add(-48 * time.Hour).UTC().Format("20060102T150405Z")
	} else {
		s.currentDateTime = time.Now().UTC().Format("20060102T150405Z")
	}
	protocolAndHost := strings.Split(s.Url, "://")
	if len(protocolAndHost) != 2 {
		return fmt.Errorf("invalid URL value: %s", s.Url)
	}
	s.host = protocolAndHost[1]
	if s.PayloadType != "" {
		s.payloadHash = s.PayloadType
	} else {
		var err error
		s.payloadHash, err = s.calculatePayloadSHA256()
		if err != nil {
			return fmt.Errorf("error calculating payload hash: %w", err)
		}
	}
	if err := s.addHeaderValues(); err != nil {
		return fmt.Errorf("error adding header values: %w", err)
	}
	s.path = "/" + s.BucketName
	if s.ObjectKey != "" {
		s.path += "/" + s.ObjectKey
	}
	s.generateCanonicalRequestString()

	s.yearMonthDay = strings.Split(s.currentDateTime, "T")[0]
	if s.InvalidYearMonthDay {
		s.yearMonthDay = s.yearMonthDay[:len(s.yearMonthDay)-2]
	}
	s.getStsSignature()
	return nil
}

func (s *S3Command) calculatePayloadSHA256() (string, error) {
	if s.PayloadFile != "" {
		file, err := os.Open(s.PayloadFile)
		if err != nil {
			return "", fmt.Errorf("error opening payload file '%s': %w", s.PayloadFile, err)
		}

		hasher := sha256.New()
		if _, err := io.Copy(hasher, file); err != nil {
			return "", fmt.Errorf("error copying file data of '%s' to hasher: %w", s.PayloadFile, err)
		}

		hash := hasher.Sum(nil)
		return hex.EncodeToString(hash), nil
	}
	hash := sha256.Sum256([]byte(s.Payload))
	return hex.EncodeToString(hash[:]), nil
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
	s.headerValues = append(s.headerValues,
		[]string{"x-amz-content-sha256", s.payloadHash},
		[]string{"x-amz-date", s.currentDateTime},
	)
	for key, value := range s.SignedParams {
		s.headerValues = append(s.headerValues, []string{key, value})
	}
	if s.ContentMD5 || s.IncorrectContentMD5 {
		if err := s.addContentMD5Header(); err != nil {
			return fmt.Errorf("error adding Content-MD5 header: %w", err)
		}
	}
	sort.Slice(s.headerValues,
		func(i, j int) bool {
			return s.headerValues[i][0] < s.headerValues[j][0]
		})
	return nil
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

	hasher := md5.New()
	hasher.Write(payloadData)
	md5Hash := hasher.Sum(nil)
	if s.IncorrectContentMD5 {
		if md5Hash[0] == 'a' {
			md5Hash[0] = 'A'
		} else {
			md5Hash[0] = 'a'
		}
	}
	contentMD5 := base64.StdEncoding.EncodeToString(md5Hash)

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
	signingKey := hmacSHA256(dateRegionServiceKey, "aws4_request")

	// Generate signature
	signatureBytes := hmacSHA256(signingKey, stsDataString)
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
	curlCommand := []string{"curl", "-iks"}
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
	return strings.Join(curlCommand, " "), nil
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
	if s.PayloadFile != "" || s.Payload != "" {
		payload, err := s.getWholeOrChunkedPayloadData()
		if err != nil {
			return fmt.Errorf("error getting payload data: %w", err)
		}
		openSSLCommand = append(openSSLCommand, payload...)
	}

	file, err := os.Create(s.FilePath)
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}
	openSSLCommandBytes := []byte(strings.Join(openSSLCommand, "\r\n"))
	if _, err = file.Write(openSSLCommandBytes); err != nil {
		return fmt.Errorf("error writing to file: %w", err)
	}
	return nil
}

func (s *S3Command) getWholeOrChunkedPayloadData() ([]string, error) {
	payloadBytes, err := s.getFileOrStringPayloadData()
	payloadLength := len(payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("error writing OpenSSL payload: %w", err)
	}

	var payloadStringArray []string
	if s.PayloadType == "" || s.PayloadType == UnsignedPayload {
		payloadStringArray = []string{fmt.Sprintf("Content-Length:%d", payloadLength)}
		payloadStringArray = append(payloadStringArray, "\r\n"+string(payloadBytes))

	} else {
		if s.ChunkSize <= 0 {
			return nil, errors.New("chunkSize must be greater than 0")
		}
		logger.PrintDebug("Chunked payload type: %s", s.PayloadType)
		payload := s.getOpenSSLChunkedPayload(payloadBytes, payloadLength, s.signature)
		payloadStringArray = []string{"Content-Encoding:aws-chunked"}
		payloadStringArray = append(payloadStringArray, fmt.Sprintf("x-amz-decoded-content-length:%d", payloadLength))
		payloadStringArray = append(payloadStringArray, fmt.Sprintf("Content-Length:%d", len(payload)))
		payloadStringArray = append(payloadStringArray, "\r\n"+string(payload))
	}
	return payloadStringArray, nil
}

func (s *S3Command) getFileOrStringPayloadData() ([]byte, error) {
	if s.PayloadFile != "" {
		data, err := os.ReadFile(s.PayloadFile)
		if err != nil {
			return nil, fmt.Errorf("error reading file '%s': %w", s.PayloadFile, err)
		}
		return data, nil
	}
	return []byte(s.Payload), nil
}

func (s *S3Command) getOpenSSLChunkedPayload(payload []byte, payloadLength int, firstSignature string) []byte {
	var chunkedPayload []byte
	lastSignature := firstSignature
	for startingByteIdx := 0; startingByteIdx < payloadLength; startingByteIdx += s.ChunkSize {
		var endingByteIdx int
		if startingByteIdx+s.ChunkSize < payloadLength {
			endingByteIdx = startingByteIdx + s.ChunkSize
		} else {
			endingByteIdx = payloadLength
		}
		payloadHash := sha256.Sum256(payload[startingByteIdx:endingByteIdx])
		hashString := hex.EncodeToString(payloadHash[:])
		newSignature := s.getChunkedCanonicalRequestHash(lastSignature, hashString)
		chunkedPayload = append(chunkedPayload, payload[startingByteIdx:endingByteIdx]...)
		chunkedPayload = append(chunkedPayload, '\r', '\n')
		chunkLength := fmt.Sprintf("%x;chunk-signature=", endingByteIdx-startingByteIdx)
		chunkedPayload = append(chunkedPayload, []byte(chunkLength)...)
		chunkedPayload = append(chunkedPayload, []byte(newSignature)...)
		chunkedPayload = append(chunkedPayload, '\r', '\n')
		lastSignature = newSignature
	}
	emptyHash := sha256.Sum256(nil)
	newSignature := s.getChunkedCanonicalRequestHash(lastSignature, hex.EncodeToString(emptyHash[:]))
	chunkedPayload = append(chunkedPayload, []byte("0;chunk-signature="+newSignature)...)
	return chunkedPayload
}

func (s *S3Command) getChunkedCanonicalRequestHash(lastSignature, chunkSignature string) string {
	hash := sha256.Sum256([]byte(s.Payload))
	serviceString := fmt.Sprintf("%s/%s/%s/%s/aws4_request", s.AwsAccessKeyId, s.yearMonthDay, s.AwsRegion, s.ServiceName)
	request := strings.Join([]string{"AWS4-HMAC-SHA256-PAYLOAD",
		s.currentDateTime,
		serviceString,
		lastSignature,
		hex.EncodeToString(hash[:]),
		chunkSignature}, "\n")
	canonicalRequestHashBytes := sha256.Sum256([]byte(request))
	return hex.EncodeToString(canonicalRequestHashBytes[:])
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}
