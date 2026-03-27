package command

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"strings"
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

type HeaderValue struct {
	Key    string
	Value  string
	Signed bool
}

type S3RequestConfigData struct {
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
	UnsignedParams               map[string]string
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
	OmitSHA256Hash               bool
	CustomSHA256Hash             string
	OmitDate                     bool
	CustomDate                   string
	WriteXMLPayloadToFile        string
}

type S3RequestBuilder struct {
	Config *S3RequestConfigData
}

func (s *S3RequestBuilder) OpenSSLCommand() error {
	openSSLCommand := &OpenSSLCommand{
		S3Request: &S3Request{
			Config: s.Config,
		},
	}
	if err := s.RenderCommand(openSSLCommand); err != nil {
		return fmt.Errorf("error rendering OpenSSL command: %w", err)
	}
	return nil
}

func (s *S3RequestBuilder) CurlShellCommand() (string, error) {
	curlCommand := &CurlCommand{
		S3Request: &S3Request{
			Config: s.Config,
		},
	}
	if err := s.RenderCommand(curlCommand); err != nil {
		return "", fmt.Errorf("error rendering curl command: %w", err)
	}
	return curlCommand.String(), nil
}

func (s *S3RequestBuilder) RenderCommand(renderer Renderer) error {
	renderer.CalculateDateTimeParams()
	if err := renderer.DeriveHost(); err != nil {
		return fmt.Errorf("error deriving host: %w", err)
	}
	renderer.DeriveBucketAndKeyPath()
	if err := renderer.PerformPayloadCalculations(); err != nil {
		return fmt.Errorf("error performing payload calculations: %w", err)
	}
	if err := renderer.DeriveHeaderValues(); err != nil {
		return fmt.Errorf("error deriving header values: %w", err)
	}
	if err := renderer.CalculateSignature(); err != nil {
		return fmt.Errorf("error calculating signature: %w", err)
	}
	if err := renderer.Render(); err != nil {
		return fmt.Errorf("error rendering command: %w", err)
	}
	return nil
}

func encodeS3Key(key string) string {
	parts := strings.Split(key, "/")
	for i, p := range parts {
		parts[i] = awsEscapePath(p)
	}
	return strings.Join(parts, "/")
}

func awsEscapePath(key string) string {
	var b strings.Builder
	b.Grow(len(key))
	for i := 0; i < len(key); i++ {
		c := key[i]
		if (c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' || c == '/' {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

func modifyHash(md5Hash []byte) {
	if md5Hash[0] == 'a' {
		md5Hash[0] = 'A'
	} else {
		md5Hash[0] = 'a'
	}
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}
