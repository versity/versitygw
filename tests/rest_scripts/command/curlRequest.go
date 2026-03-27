package command

import (
	"fmt"
	"github.com/versity/versitygw/tests/rest_scripts/logger"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

type CurlCommand struct {
	*S3Request

	curlCommandString string
}

func (c *CurlCommand) PerformPayloadCalculations() error {
	return c.performBasePayloadCalculations()
}

func (c *CurlCommand) DeriveHeaderValues() error {
	c.deriveUniversalHeaderValues()
	if err := c.deriveConfigSpecificHeaderValues(); err != nil {
		return fmt.Errorf("error deriving config-specific header values: %w", err)
	}
	return nil
}

func (c *CurlCommand) Render() error {
	curlOpts := "-iks"
	if c.Config.Method == "HEAD" {
		curlOpts += "I"
	}
	curlCommand := []string{"curl", curlOpts}
	if c.Config.Method != "GET" {
		curlCommand = append(curlCommand, fmt.Sprintf("-X %s ", c.Config.Method))
	}
	fullPath := c.Config.Url + c.path
	awsUrl, err := url.Parse(fullPath)
	if err != nil {
		return fmt.Errorf("error parsing URL: %w", err)
	}
	if c.Config.Query != "" {
		canonicalQuery, err := canonicalizeQuery(c.Config.Query)
		if err != nil {
			return fmt.Errorf("error parsing query: %w", err)
		}
		awsUrl.RawQuery = canonicalQuery
	}

	enclosedPath := fmt.Sprintf("\"%s\"", awsUrl.String())
	curlCommand = append(curlCommand, enclosedPath)
	authorizationString := c.buildAuthorizationString()
	curlCommand = append(curlCommand, "-H", fmt.Sprintf("\"%s\"", authorizationString))
	for _, headerValue := range c.headerValues {
		headerString := fmt.Sprintf("\"%s: %s\"", headerValue.Key, headerValue.Value)
		curlCommand = append(curlCommand, "-H", headerString)
	}
	if c.Config.PayloadFile != "" {
		curlCommand = append(curlCommand, "-T", fmt.Sprintf("\"%s\"", c.Config.PayloadFile))
	} else if c.Config.Payload != "" {
		var err error
		curlCommand, err = c.appendCurlPayload(curlCommand)
		if err != nil {
			return err
		}
	}
	c.curlCommandString = strings.Join(curlCommand, " ")
	logger.PrintDebug("curl command: %s", c.curlCommandString)
	return nil
}

func (c *CurlCommand) String() string {
	return c.curlCommandString
}

func (c *CurlCommand) appendCurlPayload(curlCommand []string) ([]string, error) {
	if c.Config.WriteXMLPayloadToFile == "" {
		return nil, fmt.Errorf("curl XML payloads must be written to file with 'writeXMLPayloadToFile' param")
	}
	if err := os.MkdirAll(filepath.Dir(c.Config.WriteXMLPayloadToFile), 0o755); err != nil {
		return nil, fmt.Errorf("error creating payload folder: %w", err)
	}
	if err := os.WriteFile(c.Config.WriteXMLPayloadToFile, []byte(c.Config.Payload), 0o644); err != nil {
		return nil, fmt.Errorf("error writing payload to file '%s': %w", c.Config.WriteXMLPayloadToFile, err)
	}
	curlCommand = append(curlCommand, "-H", "\"Content-Type: application/xml\"", "--data-binary", fmt.Sprintf("\"@%s\"", c.Config.WriteXMLPayloadToFile))
	return curlCommand, nil
}
