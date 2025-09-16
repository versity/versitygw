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
	"os"
	"sort"
	"strings"
	"time"
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
	s.payloadHash = "UNSIGNED-PAYLOAD"
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
	openSSLCommand := []string{fmt.Sprintf("%s %s HTTP/1.1", s.Method, s.path)}
	openSSLCommand = append(openSSLCommand, s.buildAuthorizationString())
	for _, headerValue := range s.headerValues {
		if headerValue[0] == "host" && s.MissingHostParam {
			continue
		}
		openSSLCommand = append(openSSLCommand, fmt.Sprintf("%s:%s", headerValue[0], headerValue[1]))
	}
	openSSLCommand = append(openSSLCommand, "\r\n")
	var file *os.File
	var err error
	if file, err = os.Create(s.FilePath); err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}
	openSSLCommandBytes := []byte(strings.Join(openSSLCommand, "\r\n"))
	if _, err = file.Write(openSSLCommandBytes); err != nil {
		return fmt.Errorf("error writing to file: %w", err)
	}
	return nil
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}
