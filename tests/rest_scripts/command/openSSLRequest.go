package command

import (
	"fmt"
	"github.com/versity/versitygw/tests/rest_scripts/logger"
	"os"
	"strings"
)

type OpenSSLCommand struct {
	*S3Request

	payloadManager OpenSSLPayloadManager
	contentLength  int64
}

func (o *OpenSSLCommand) PerformPayloadCalculations() error {
	if err := o.performBasePayloadCalculations(); err != nil {
		return fmt.Errorf("error performing base payload calculations: %w", err)
	}
	if err := o.initializePayloadAndGetContentLength(); err != nil {
		return fmt.Errorf("error initializing openssl-specific payload: %w", err)
	}
	return nil
}

func (o *OpenSSLCommand) DeriveHeaderValues() error {
	o.deriveUniversalHeaderValues()
	if !o.Config.OmitContentLength {
		o.headerValues = append(o.headerValues,
			&HeaderValue{"Content-Length", fmt.Sprintf("%d", o.contentLength), true})
	}
	if err := o.deriveConfigSpecificHeaderValues(); err != nil {
		return fmt.Errorf("error deriving config-specific header values: %w", err)
	}
	return nil
}

func (o *OpenSSLCommand) Render() error {
	if o.Config.Query != "" {
		o.path += "?" + o.Config.Query
	}
	openSSLCommand := []string{fmt.Sprintf("%s %s HTTP/1.1", o.Config.Method, o.path)}
	openSSLCommand = append(openSSLCommand, o.buildAuthorizationString())
	for _, headerValue := range o.headerValues {
		if headerValue.Key == "host" && o.Config.MissingHostParam {
			continue
		}
		openSSLCommand = append(openSSLCommand, fmt.Sprintf("%s:%s", headerValue.Key, headerValue.Value))
	}

	file, err := os.Create(o.Config.FilePath)
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
	if o.Config.PayloadFile != "" || o.Config.Payload != "" {
		if err = o.writePayload(file); err != nil {
			return fmt.Errorf("error writing openssl payload: %w", err)
		}
	}
	return nil
}

func (o *OpenSSLCommand) writePayload(file *os.File) error {
	if awsPayload, ok := o.payloadManager.(*PayloadStreamingAWS4HMACSHA256); ok {
		awsPayload.AddInitialSignatureAndSigningKey(o.signature, o.signingKey)
	}
	switch o.Config.PayloadType {
	case UnsignedPayload, "", StreamingUnsignedPayloadTrailer, StreamingAWS4HMACSHA256Payload, StreamingAWS4HMACSHA256PayloadTrailer:
		if err := o.payloadManager.WritePayload(o.Config.FilePath); err != nil {
			return fmt.Errorf("error writing payload to openssl file: %w", err)
		}
	default:
		return fmt.Errorf("unsupported payload type: %s", o.Config.PayloadType)
	}
	return nil
}

func (o *OpenSSLCommand) initializePayloadAndGetContentLength() error {
	switch o.Config.PayloadType {
	case StreamingAWS4HMACSHA256Payload, StreamingAWS4HMACSHA256PayloadTrailer:
		serviceString := fmt.Sprintf("%s/%s/%s/aws4_request", o.yearMonthDay, o.Config.AwsRegion, o.Config.ServiceName)
		o.payloadManager = NewPayloadStreamingAWS4HMACSHA256(o.dataSource, int64(o.Config.ChunkSize), PayloadType(o.Config.PayloadType), serviceString, o.currentDateTime, o.yearMonthDay, o.Config.ChecksumType)
	case StreamingUnsignedPayloadTrailer:
		streamingUnsignedPayloadTrailerImpl := NewStreamingUnsignedPayloadWithTrailer(o.dataSource, int64(o.Config.ChunkSize), o.Config.ChecksumType)
		streamingUnsignedPayloadTrailerImpl.OmitTrailerOrKey(o.Config.OmitPayloadTrailer, o.Config.OmitPayloadTrailerKey)
		o.payloadManager = streamingUnsignedPayloadTrailerImpl
	case UnsignedPayload, "":
		o.payloadManager = NewWholePayload(o.dataSource)
	default:
		return fmt.Errorf("unsupported OpenSSL payload type: '%s'", o.Config.PayloadType)
	}
	var err error
	o.contentLength, err = o.payloadManager.GetContentLength()
	if err != nil {
		return fmt.Errorf("error calculating Content-Length: %w", err)
	}
	logger.PrintDebug("Predicted payload size: %d", o.contentLength)
	return nil
}
