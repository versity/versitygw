package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"strings"
	"time"
)

var method *string
var url *string
var bucketName *string
var objectKey *string
var query *string
var awsRegion *string
var awsAccessKeyId *string
var awsSecretAccessKey *string
var serviceName *string
var debug *bool

type S3Command struct {
	Method             string
	Url                string
	BucketName         string
	ObjectKey          string
	Query              string
	AwsRegion          string
	AwsAccessKeyId     string
	AwsSecretAccessKey string
	ServiceName        string

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

func main() {
	if err := checkFlags(); err != nil {
		log.Fatalf("Error checking flags: %v", err)
	}

	s3Command := &S3Command{
		Method:             *method,
		Url:                *url,
		BucketName:         *bucketName,
		ObjectKey:          *objectKey,
		Query:              *query,
		AwsRegion:          *awsRegion,
		AwsAccessKeyId:     *awsAccessKeyId,
		AwsSecretAccessKey: *awsSecretAccessKey,
		ServiceName:        *serviceName,
	}
	curlShellCommand, err := s3Command.CurlShellCommand()
	if err != nil {
		log.Fatalf("Error generating curl command: %v", err)
	}
	fmt.Println(curlShellCommand)
}

func checkFlags() error {
	method = flag.String("method", "GET", "HTTP method to use")
	url = flag.String("url", "https://localhost:7070", "S3 server URL")
	bucketName = flag.String("bucketName", "", "Bucket name")
	objectKey = flag.String("objectKey", "", "Object key")
	query = flag.String("query", "", "S3 query")
	awsAccessKeyId = flag.String("awsAccessKeyId", "", "AWS access key ID")
	awsSecretAccessKey = flag.String("awsSecretAccessKey", "", "AWS secret access key")
	awsRegion = flag.String("awsRegion", "us-east-1", "AWS region")
	serviceName = flag.String("serviceName", "s3", "Service name")
	debug = flag.Bool("debug", false, "Print debug statements")
	// Parse the flags
	flag.Parse()

	if flag.Lookup("awsAccessKeyId").Value.String() == "" {
		return fmt.Errorf("the 'awsAccessKeyId' value must be set")
	}
	if flag.Lookup("awsSecretAccessKey").Value.String() == "" {
		return fmt.Errorf("the 'awsSecretAccessKey' value must be set")
	}
	return nil
}

func printDebug(format string, args ...any) {
	if *debug {
		log.Printf(format, args...)
	}
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func (s *S3Command) CurlShellCommand() (string, error) {
	s.currentDateTime = time.Now().UTC().Format("20060102T150405Z")
	protocolAndHost := strings.Split(s.Url, "://")
	if len(protocolAndHost) != 2 {
		return "", fmt.Errorf("invalid URL value: %s", s.Url)
	}
	s.host = protocolAndHost[1]
	s.payloadHash = "UNSIGNED-PAYLOAD"
	s.headerValues = [][]string{
		{"x-amz-content-sha256", s.payloadHash},
		{"x-amz-date", s.currentDateTime},
	}
	s.path = "/" + s.BucketName
	if s.ObjectKey != "" {
		s.path += "/" + s.ObjectKey
	}
	s.generateCanonicalRequestString()

	s.yearMonthDay = strings.Split(s.currentDateTime, "T")[0]
	s.getStsSignature()

	return s.buildCurlShellCommand(), nil
}

func (s *S3Command) generateCanonicalRequestString() {
	canonicalRequestLines := []string{*method}

	canonicalRequestLines = append(canonicalRequestLines, s.path)
	canonicalRequestLines = append(canonicalRequestLines, s.Query)
	canonicalRequestLines = append(canonicalRequestLines, "host:"+s.host)

	signedParams := []string{"host"}
	for _, headerValue := range s.headerValues {
		key := headerValue[0]
		canonicalRequestLines = append(canonicalRequestLines, key+":"+headerValue[1])
		signedParams = append(signedParams, key)
	}

	canonicalRequestLines = append(canonicalRequestLines, "")
	s.signedParamString = strings.Join(signedParams, ";")
	canonicalRequestLines = append(canonicalRequestLines, s.signedParamString, s.payloadHash)

	canonicalRequestString := strings.Join(canonicalRequestLines, "\n")
	printDebug("Canonical request string: %s\n", canonicalRequestString)

	canonicalRequestHashBytes := sha256.Sum256([]byte(canonicalRequestString))
	s.canonicalRequestHash = hex.EncodeToString(canonicalRequestHashBytes[:])
}

func (s *S3Command) getStsSignature() {
	thirdLine := fmt.Sprintf("%s/%s/%s/aws4_request", s.yearMonthDay, s.AwsRegion, s.ServiceName)
	stsDataLines := []string{
		"AWS4-HMAC-SHA256",
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

	// Print hex-encoded signature
	s.signature = hex.EncodeToString(signatureBytes)
}

func (s *S3Command) buildCurlShellCommand() string {
	curlCommand := []string{"curl", "-iks"}
	if s.Method != "GET" {
		curlCommand = append(curlCommand, fmt.Sprintf("-X %s ", s.Method))
	}
	fullPath := "\"" + *url + s.path
	if *query != "" {
		fullPath += "?" + *query
	}
	fullPath += "\""
	curlCommand = append(curlCommand, fullPath)
	authorizationString := fmt.Sprintf("\"Authorization: AWS4-HMAC-SHA256 Credential=%s/%s/%s/%s/aws4_request,SignedHeaders=%s,Signature=%s\"",
		s.AwsAccessKeyId, s.yearMonthDay, s.AwsRegion, s.ServiceName, s.signedParamString, s.signature)
	curlCommand = append(curlCommand, "-H", authorizationString)
	for _, headerValue := range s.headerValues {
		headerString := fmt.Sprintf("\"%s: %s\"", headerValue[0], headerValue[1])
		curlCommand = append(curlCommand, "-H", headerString)
	}
	return strings.Join(curlCommand, " ")
}
