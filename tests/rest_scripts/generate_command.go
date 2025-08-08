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
var query *string
var awsRegion *string
var awsAccessKeyId *string
var awsSecretAccessKey *string
var debug *bool

// Helper to create HMAC-SHA256
func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func checkFlags() error {
	method = flag.String("method", "GET", "HTTP method to use")
	url = flag.String("url", "https://localhost:7070", "S3 server URL")
	bucketName = flag.String("bucketName", "", "Bucket name")
	query = flag.String("query", "", "S3 query")
	awsAccessKeyId = flag.String("awsAccessKeyId", "", "AWS access key ID")
	awsSecretAccessKey = flag.String("awsSecretAccessKey", "", "AWS secret access key")
	awsRegion = flag.String("awsRegion", "us-east-1", "AWS region")
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

func gatherHeaderValues(payloadHash, date string) [][]string {
	headerValues := [][]string{
		{"x-amz-content-sha256", payloadHash},
		{"x-amz-date", date},
	}
	return headerValues
}

func getCanonicalRequestHash(host string, headerValues [][]string, payloadHash string) (string, string) {
	canonicalRequestLines := []string{*method}
	path := "/"
	if *bucketName != "" {
		path += *bucketName
	}
	canonicalRequestLines = append(canonicalRequestLines, path)
	canonicalRequestLines = append(canonicalRequestLines, *query)
	canonicalRequestLines = append(canonicalRequestLines, "host:"+host)
	signedParams := []string{"host"}
	for _, headerValue := range headerValues {
		key := headerValue[0]
		canonicalRequestLines = append(canonicalRequestLines, key+":"+headerValue[1])
		signedParams = append(signedParams, key)
	}
	canonicalRequestLines = append(canonicalRequestLines, "")
	signedParamList := strings.Join(signedParams, ";")
	canonicalRequestLines = append(canonicalRequestLines, signedParamList, payloadHash)

	canonicalRequestString := strings.Join(canonicalRequestLines, "\n")
	printDebug("Canonical request string: %s\n", canonicalRequestString)

	canonicalRequestHash := sha256.Sum256([]byte(canonicalRequestString))
	canonicalRequestHashString := hex.EncodeToString(canonicalRequestHash[:])
	return canonicalRequestHashString, signedParamList
}

func getStsSignature(yearMonthDay, currentDateTime, canonicalRequestHash string) string {

	thirdLine := fmt.Sprintf("%s/%s/s3/aws4_request", yearMonthDay, *awsRegion)
	stsDataLines := []string{
		"AWS4-HMAC-SHA256",
		currentDateTime,
		thirdLine,
		canonicalRequestHash,
	}
	stsDataString := strings.Join(stsDataLines, "\n")

	// Derive signing key step by step
	dateKey := hmacSHA256([]byte("AWS4"+*awsSecretAccessKey), yearMonthDay)
	dateRegionKey := hmacSHA256(dateKey, *awsRegion)
	dateRegionServiceKey := hmacSHA256(dateRegionKey, "s3")
	signingKey := hmacSHA256(dateRegionServiceKey, "aws4_request")

	// Generate signature
	signature := hmacSHA256(signingKey, stsDataString)

	// Print hex-encoded signature
	return hex.EncodeToString(signature)
}

type commandFields struct {
	yearMonthDay    string
	signedParams    string
	signature       string
	currentDateTime string
	headerValues    [][]string
}

func buildCurlCommand(fields *commandFields) string {
	curlCommand := []string{"curl", "-iks"}
	if *method != "GET" {
		curlCommand = append(curlCommand, fmt.Sprintf("-X %s ", *method))
	}
	path := "\"" + *url + "/" + *bucketName
	if *query != "" {
		path += "?" + *query
	}
	path += "\""
	curlCommand = append(curlCommand, path)
	authorizationString := fmt.Sprintf("\"Authorization: AWS4-HMAC-SHA256 Credential=%s/%s/%s/s3/aws4_request,SignedHeaders=%s,Signature=%s\"",
		*awsAccessKeyId, fields.yearMonthDay, *awsRegion, fields.signedParams, fields.signature)
	curlCommand = append(curlCommand, "-H", authorizationString)
	for _, headerValue := range fields.headerValues {
		headerString := fmt.Sprintf("\"%s: %s\"", headerValue[0], headerValue[1])
		curlCommand = append(curlCommand, "-H", headerString)
	}
	return strings.Join(curlCommand, " ")
}

func printDebug(format string, args ...any) {
	if *debug {
		log.Printf(format, args...)
	}
}

func main() {
	if err := checkFlags(); err != nil {
		log.Fatalf("Error checking flags: %v", err)
	}

	currentDateTime := time.Now().UTC().Format("20060102T150405Z")
	protocolAndHost := strings.Split(*url, "://")
	if len(protocolAndHost) != 2 {
		log.Fatalf("invalid URL value: %s", *url)
	}
	host := protocolAndHost[1]
	payloadHash := "UNSIGNED-PAYLOAD"

	headerValues := gatherHeaderValues(payloadHash, currentDateTime)
	canonicalRequestHash, signedParams := getCanonicalRequestHash(host, headerValues, payloadHash)

	// Output result
	printDebug("Canonical Request Hash: %s\n", canonicalRequestHash)

	yearMonthDay := strings.Split(currentDateTime, "T")[0]
	signature := getStsSignature(yearMonthDay, currentDateTime, canonicalRequestHash)

	// Print hex-encoded signature
	printDebug("Signature: %s\n", signature)

	curlCommand := buildCurlCommand(&commandFields{
		yearMonthDay:    yearMonthDay,
		signedParams:    signedParams,
		signature:       signature,
		currentDateTime: currentDateTime,
		headerValues:    headerValues,
	})
	fmt.Println(curlCommand)
}
