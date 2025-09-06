package main

import (
	"flag"
	"fmt"
	"github.com/versity/versitygw/tests/rest_scripts/command"
	logger "github.com/versity/versitygw/tests/rest_scripts/logger"
	"log"
	"strings"
)

const (
	CURL    = "curl"
	OPENSSL = "openssl"
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

var signedParamsMap restParams
var payloadFile *string
var incorrectSignature *bool
var incorrectCredential *string
var authorizationScheme *string
var incorrectYearMonthDay *bool
var invalidYearMonthDay *bool
var payload *string
var contentMD5 *bool
var incorrectContentMD5 *bool
var missingHostParam *bool
var filePath *string
var client *string
var customHostParam *string
var customHostParamSet bool = false

type restParams map[string]string

func (r *restParams) String() string {
	return fmt.Sprintf("%v", *r)
}

func (r *restParams) Set(value string) error {
	*r = make(map[string]string)
	pairs := strings.Split(value, ",")
	for _, pair := range pairs {
		kv := strings.SplitN(pair, ":", 2)
		if len(kv) != 2 {
		}
		if len(kv) != 2 {
			return fmt.Errorf("invalid key-value pair: %s", pair)
		}
		(*r)[kv[0]] = kv[1]
	}
	return nil
}

func main() {
	if err := checkFlags(); err != nil {
		log.Fatalf("Error checking flags: %v", err)
	}

	s3Command := &command.S3Command{
		Method:                *method,
		Url:                   *url,
		BucketName:            *bucketName,
		ObjectKey:             *objectKey,
		Query:                 *query,
		AwsRegion:             *awsRegion,
		AwsAccessKeyId:        *awsAccessKeyId,
		AwsSecretAccessKey:    *awsSecretAccessKey,
		ServiceName:           *serviceName,
		SignedParams:          signedParamsMap,
		PayloadFile:           *payloadFile,
		IncorrectSignature:    *incorrectSignature,
		AuthorizationScheme:   *authorizationScheme,
		IncorrectCredential:   *incorrectCredential,
		IncorrectYearMonthDay: *incorrectYearMonthDay,
		InvalidYearMonthDay:   *invalidYearMonthDay,
		Payload:               *payload,
		ContentMD5:            *contentMD5,
		IncorrectContentMD5:   *incorrectContentMD5,
		MissingHostParam:      *missingHostParam,
		FilePath:              *filePath,
		CustomHostParam:       *customHostParam,
		CustomHostParamSet:    customHostParamSet,
	}
	switch *client {
	case CURL:
		curlShellCommand, err := s3Command.CurlShellCommand()
		if err != nil {
			log.Fatalf("Error generating curl command: %v", err)
		}
		fmt.Println(curlShellCommand)
	case OPENSSL:
		if err := s3Command.OpenSSLCommand(); err != nil {
			log.Fatalf("Error generating and writing openssl command: %v", err)
		}
	default:
		log.Fatalln("Invalid client type: ", *client)
	}

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
	logger.Debug = flag.Bool("debug", false, "Print debug statements")
	flag.Var(&signedParamsMap, "signedParams", "Signed params, separated by comma")
	payloadFile = flag.String("payloadFile", "", "Payload file path, if any")
	incorrectSignature = flag.Bool("incorrectSignature", false, "Simulate an incorrect signature")
	incorrectYearMonthDay = flag.Bool("incorrectYearMonthDay", false, "Simulate an incorrect year/month/day")
	invalidYearMonthDay = flag.Bool("invalidYearMonthDay", false, "Simulate an invalid year/month/day")
	incorrectCredential = flag.String("incorrectCredential", "", "Add an incorrect credential string")
	authorizationScheme = flag.String("authorizationScheme", "AWS4-HMAC-SHA256", "Authorization Scheme")
	payload = flag.String("payload", "", "Message payload")
	contentMD5 = flag.Bool("contentMD5", false, "Include content-md5 hash")
	incorrectContentMD5 = flag.Bool("incorrectContentMD5", false, "Include incorrect content-md5 hash")
	missingHostParam = flag.Bool("missingHostParam", false, "Missing host parameter")
	customHostParam = flag.String("customHostParam", "", "Custom host parameter")
	filePath = flag.String("filePath", "", "Path to write command (stdout if none)")
	client = flag.String("client", CURL, "Command-line client to use")
	// Parse the flags
	flag.Parse()

	flag.Visit(func(f *flag.Flag) {
		if f.Name == "customHostParam" {
			customHostParamSet = true
		}
	})

	if flag.Lookup("awsAccessKeyId").Value.String() == "" {
		return fmt.Errorf("the 'awsAccessKeyId' value must be set")
	}
	if flag.Lookup("awsSecretAccessKey").Value.String() == "" {
		return fmt.Errorf("the 'awsSecretAccessKey' value must be set")
	}
	return nil
}
