package command

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	logger "github.com/versity/versitygw/tests/rest_scripts/log"
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

func (s *S3Command) CurlShellCommand() (string, error) {
	if s.PayloadFile != "" && s.Payload != "" {
		return "", fmt.Errorf("cannot have both payload and payloadFile parameters set")
	}
	if s.IncorrectYearMonthDay {
		s.currentDateTime = time.Now().Add(-48 * time.Hour).UTC().Format("20060102T150405Z")
	} else {
		s.currentDateTime = time.Now().UTC().Format("20060102T150405Z")
	}
	protocolAndHost := strings.Split(s.Url, "://")
	if len(protocolAndHost) != 2 {
		return "", fmt.Errorf("invalid URL value: %s", s.Url)
	}
	s.host = protocolAndHost[1]
	s.payloadHash = "UNSIGNED-PAYLOAD"
	s.headerValues = [][]string{
		{"host", s.host},
		{"x-amz-content-sha256", s.payloadHash},
		{"x-amz-date", s.currentDateTime},
	}
	for key, value := range s.SignedParams {
		s.headerValues = append(s.headerValues, []string{key, value})
	}
	sort.Slice(s.headerValues,
		func(i, j int) bool {
			return s.headerValues[i][0] < s.headerValues[j][0]
		})
	s.path = "/" + s.BucketName
	if s.ObjectKey != "" {
		s.path += "/" + s.ObjectKey
	}
	s.generateCanonicalRequestString()

	s.yearMonthDay = strings.Split(s.currentDateTime, "T")[0]
	if s.InvalidYearMonthDay {
		s.yearMonthDay = s.yearMonthDay[:len(s.yearMonthDay)-1]
	}
	s.getStsSignature()

	return s.buildCurlShellCommand(), nil
}

func (s *S3Command) generateCanonicalRequestString() {
	canonicalRequestLines := []string{s.Method}

	canonicalRequestLines = append(canonicalRequestLines, s.path)
	canonicalRequestLines = append(canonicalRequestLines, s.Query)
	//canonicalRequestLines = append(canonicalRequestLines, "host:"+s.host)

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

func (s *S3Command) buildCurlShellCommand() string {
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
	var credentialString string
	if s.IncorrectCredential == "" {
		credentialString = fmt.Sprintf("%s/%s/%s/%s/aws4_request", s.AwsAccessKeyId, s.yearMonthDay, s.AwsRegion, s.ServiceName)
	} else {
		credentialString = s.IncorrectCredential
	}
	authorizationString := fmt.Sprintf("\"Authorization: %s Credential=%s,SignedHeaders=%s,Signature=%s\"",
		s.AuthorizationScheme, credentialString, s.signedParamString, s.signature)
	curlCommand = append(curlCommand, "-H", authorizationString)
	for _, headerValue := range s.headerValues {
		headerString := fmt.Sprintf("\"%s: %s\"", headerValue[0], headerValue[1])
		curlCommand = append(curlCommand, "-H", headerString)
	}
	if s.PayloadFile != "" {
		curlCommand = append(curlCommand, "-T", s.PayloadFile)
	} else if s.Payload != "" {
		curlCommand = append(curlCommand, "-H", "\"Content-Type: application/xml\"", "-d", fmt.Sprintf("\"%s\"", s.Payload))
	}
	return strings.Join(curlCommand, " ")
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}
