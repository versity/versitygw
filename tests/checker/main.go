package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

const TemplateIdDefault = "default"

var dataFile *string
var batsTestFileName *string
var batsTestName *string
var templateId *string
var serverName *string
var matrixFile *string

type Templates map[string]string

type BatsTest map[string]Templates

type BatsFile map[string]BatsTest

type BatsFiles map[string]BatsFile

type S3ErrorTemplate struct {
	Error ErrorInner `yaml:"Error"`
}

type S3ErrorXML struct {
	XMLName xml.Name `xml:"Error"`
	ErrorInner
}

type TemplateBody struct {
	Type string    `yaml:"type"`
	Data yaml.Node `yaml:"data"`
}

type ExpectTemplate struct {
	Status  int               `yaml:"status"`
	Headers map[string]string `yaml:"headers"`
	Body    TemplateBody      `yaml:"body"`
}

type ErrorInner struct {
	Code    string `yaml:"Code" xml:"Code"`
	Message string `yaml:"Message" xml:"Message"`
}

type ListAnalyticsConfigurationsResultTemplate struct {
	IsTruncated bool `yaml:"IsTruncated"`
}

type ListAnalyticsConfigurationsResultXML struct {
	XMLName     xml.Name `xml:"ListBucketAnalyticsConfigurationsResult"`
	IsTruncated bool     `xml:"IsTruncated"`
}

func main() {
	if err := checkFlags(); err != nil {
		fmt.Println("Error checking command flags", err)
		os.Exit(1)
	}

	// 1) Read the YAML template file
	b, err := loadTemplate()
	if err != nil {
		fmt.Println("Error loading template", err)
		os.Exit(1)
	}

	expected, decodedBody, err := loadExpectedValues(b)
	if err != nil {
		fmt.Println("Error converting template data into struct", err)
		os.Exit(1)
	}
	fmt.Printf("type of decoded body: %v\n", reflect.TypeOf(decodedBody))

	actual, err := loadResponseFromFile(*dataFile, reflect.TypeOf(decodedBody))
	if err != nil {
		fmt.Printf("error loading response from %s: %v\n", *dataFile, err)
		os.Exit(1)
	}
	if err = compare(expected, decodedBody, actual); err != nil {
		fmt.Printf("comparison error: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func checkFlags() error {
	dataFile = flag.String("dataFile", "", "String containing CURL or OPENSSL response")
	batsTestFileName = flag.String("batsTestFileName", "", "Name of bats test file")
	batsTestName = flag.String("batsTestName", "", "Name of bats test")
	templateId = flag.String("templateId", "", "Specific ID within test, if any")
	serverName = flag.String("serverName", "", "Name of S3 gateway server being tested against")
	matrixFile = flag.String("matrixFile", "", "File which maps test calls to templates")

	flag.Parse()

	if *dataFile == "" {
		return errors.New("'dataFile' parameter cannot be blank")
	}
	if *batsTestFileName == "" {
		return errors.New("'batsTestFileName' parameter cannot be blank")
	}
	if *batsTestName == "" {
		return errors.New("'batsTestName' parameter cannot be blank")
	}
	if *serverName == "" {
		return errors.New("'serverName' parameter cannot be blank")
	}
	if *matrixFile == "" {
		return errors.New("'matrixFile' parameter cannot be blank")
	}
	return nil
}

func loadTemplate() ([]byte, error) {
	matrixFileData, err := os.ReadFile(*matrixFile)
	if err != nil {
		return nil, fmt.Errorf("error reading matrix file: %w", err)
	}

	batsFiles := &BatsFiles{}
	if err = yaml.Unmarshal([]byte(matrixFileData), batsFiles); err != nil {
		return nil, fmt.Errorf("error unmarshalling matrix YAML data: %w", err)
	}

	batsTestFile := filepath.Base(*batsTestFileName)
	batsFileYaml, ok := (*batsFiles)[filepath.Base(*batsTestFileName)]
	if !ok {
		return nil, fmt.Errorf("cannot find bats file name of '%s' in matrix", batsTestFile)
	}
	batsTestYaml, ok := batsFileYaml[*batsTestName]
	if !ok {
		return nil, fmt.Errorf("cannot find bats test name of '%s' in matrix under file name '%s'", *batsTestName, batsTestFile)
	}
	testTemplateId := getTestTemplateId()
	batsCallIdYaml, ok := batsTestYaml[testTemplateId]
	if !ok {
		return nil, fmt.Errorf("cannot find bats template ID of '%s' in matrix under file name '%s', test name '%s'",
			testTemplateId, batsTestFile, *batsTestName)
	}
	templateName, ok := batsCallIdYaml[*serverName]
	if !ok {
		return nil, fmt.Errorf("cannot find bats server name of '%s' in matrix under file name '%s', test name '%s', template ID '%s'",
			*serverName, batsTestFile, *batsTestName, testTemplateId)
	}

	templateFileBytes, err := os.ReadFile("tests/templates/" + *serverName + "/" + templateName)
	if err != nil {
		return nil, fmt.Errorf("error loading template file bytes: %w", err)
	}
	return templateFileBytes, nil
}

func getTestTemplateId() string {
	if *templateId != "" {
		return *templateId
	}
	return TemplateIdDefault
}

func loadExpectedValues(b []byte) (*ExpectTemplate, any, error) {
	var exp ExpectTemplate
	if err := yaml.Unmarshal(b, &exp); err != nil {
		return nil, nil, fmt.Errorf("error unmarshaling template YAML: %w", err)
	}

	decoded, err := exp.Body.Decode()
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding data part of template: %w", err)
	}
	return &exp, decoded, nil
}

func (b TemplateBody) Decode() (any, error) {
	switch b.Type {
	case "s3_error":
		var t S3ErrorTemplate
		if err := b.Data.Decode(&t); err != nil {
			return nil, fmt.Errorf("decode s3_error body: %w", err)
		}
		return t, nil
	case "list_bucket_analytics_configuration_result":
		var t ListAnalyticsConfigurationsResultTemplate
		if err := b.Data.Decode(&t); err != nil {
			return nil, fmt.Errorf("decode s3_error body: %w", err)
		}
		return t, nil

	// add more kinds here:
	// case "list_bucket_result": ...
	default:
		return nil, fmt.Errorf("unknown body kind: %q", b.Type)
	}
}

type Actual struct {
	Status  int
	Headers map[string][]string // multi-value headers
	Body    any
}

func loadResponseFromFile(fileName string, bodyType reflect.Type) (*Actual, error) {
	data, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	var headerPart, bodyPart []byte

	if bytes.Contains(data, []byte("\r\n\r\n")) {
		parts := bytes.SplitN(data, []byte("\r\n\r\n"), 2)
		headerPart = parts[0]
		bodyPart = parts[1]
	} else {
		parts := bytes.SplitN(data, []byte("\n\n"), 2)
		headerPart = parts[0]
		bodyPart = parts[1]
	}

	lines := bytes.Split(headerPart, []byte("\n"))
	statusLine := strings.TrimSpace(string(lines[0]))

	return readActualFromStrings(statusLine, lines, bodyPart, bodyType)
}

func readActualFromStrings(statusData string, headerData [][]byte, body []byte, bodyType reflect.Type) (*Actual, error) {
	var status int
	var err error
	statusLineValues := strings.Split(statusData, " ")
	if len(statusLineValues) > 1 {
		if status, err = strconv.Atoi(statusLineValues[1]); err != nil {
			return nil, fmt.Errorf("error converting status value '%s' to integer: %w", statusLineValues[1], err)
		}
	}

	headers := addHeadersToMap(headerData)

	var actualBody any
	switch bodyType.String() {
	case "main.S3ErrorTemplate":
		actualBody = &S3ErrorXML{}
	case "main.ListAnalyticsConfigurationsResultTemplate":
		actualBody = &ListAnalyticsConfigurationsResultXML{}
	default:
		return nil, fmt.Errorf("unhandled body type: %s", bodyType.String())
	}

	switch ty := actualBody.(type) {
	case *S3ErrorXML, *ListAnalyticsConfigurationsResultXML:
		if err = xml.Unmarshal(body, ty); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported actual body type: %T", actualBody)
	}

	return &Actual{Status: status, Headers: headers, Body: actualBody}, nil
}

func addHeadersToMap(headerData [][]byte) map[string][]string {
	headers := map[string][]string{}
	for _, header := range headerData {
		line := strings.TrimRight(string(header), "\r\n")
		if line == "" {
			break // end of headers
		}
		// Skip status line like: HTTP/1.1 501 Not Implemented
		if strings.HasPrefix(strings.ToUpper(line), "HTTP/") {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(k))
		val := strings.TrimSpace(v)
		headers[key] = append(headers[key], val)
	}
	return headers
}

func compare(expected *ExpectTemplate, expectedBody any, actual *Actual) error {
	if expected.Status != actual.Status {
		return fmt.Errorf("status: expected %d, got %d", expected.Status, actual.Status)
	}

	if err := headerCompare(expected.Headers, actual.Headers); err != nil {
		return err
	}

	if expectedError, ok := expectedBody.(S3ErrorTemplate); ok {
		actualError, ok := actual.Body.(*S3ErrorXML)
		if !ok {
			return fmt.Errorf("error casting actual response body to S3 error xml")
		}
		if actualError.Code != expectedError.Error.Code {
			return fmt.Errorf("expected error code of '%s', was '%s'", expectedError.Error.Code, actualError.Code)
		}
		if actualError.Message != expectedError.Error.Message {
			return fmt.Errorf("expected error message of '%s', was '%s'", expectedError.Error.Message, actualError.Message)
		}
		fmt.Println("comparison success")
	} else if expectedError, ok := expectedBody.(ListAnalyticsConfigurationsResultTemplate); ok {
		actualError, ok := actual.Body.(*ListAnalyticsConfigurationsResultXML)
		if !ok {
			return fmt.Errorf("error casting actual response body to list bucket analytics config xml")
		}
		if actualError.IsTruncated != expectedError.IsTruncated {
			return fmt.Errorf("expected IsTruncated value of '%t', was '%t'", expectedError.IsTruncated, actualError.IsTruncated)
		}
	} else {
		return fmt.Errorf("unrecognized type: %s", reflect.TypeOf(expectedBody).String())
	}
	return nil
}

func headerCompare(expectedHeaders map[string]string, actualHeaders map[string][]string) error {
	var problems []string
	for k, want := range expectedHeaders {
		key := strings.ToLower(k)
		gotVals := actualHeaders[key]
		got := ""
		if len(gotVals) > 0 {
			got = gotVals[0]
		}

		// missing header
		if got == "" {
			problems = append(problems, fmt.Sprintf("header %q missing (expected %q)", k, want))
			continue
		}

		// regex match
		if strings.HasPrefix(want, "re:") {
			pat := strings.TrimPrefix(want, "re:")
			re, err := regexp.Compile(pat)
			if err != nil {
				return fmt.Errorf("bad regex for header %q: %w", k, err)
			}
			if !re.MatchString(got) {
				problems = append(problems, fmt.Sprintf("header %q: expected /%s/, got %q", k, pat, got))
			}
			continue
		}

		// exact match
		if want != got {
			problems = append(problems, fmt.Sprintf("header %q: expected %q, got %q", k, want, got))
		}
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "\n"))
	}
	return nil
}
