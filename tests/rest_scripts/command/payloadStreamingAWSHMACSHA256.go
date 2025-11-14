package command

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

type PayloadStreamingAWS4HMACSHA256 struct {
	*PayloadChunkedAWS
}

func NewPayloadStreamingAWS4HMACSHA256(source DataSource, chunkSize int64, serviceString, currentDateTime string) *PayloadStreamingAWS4HMACSHA256 {
	return &PayloadStreamingAWS4HMACSHA256{
		PayloadChunkedAWS: &PayloadChunkedAWS{
			PayloadChunked: &PayloadChunked{
				Payload: &Payload{
					dataSource:         source,
					payloadType:        StreamingAWS4HMACSHA256Payload,
					checksumType:       "",
					dataSizeCalculated: false,
					dataSize:           0,
				},
				chunkSize: chunkSize,
			},
			serviceString:      serviceString,
			currentDateTime:    currentDateTime,
			lastSignature:      "",
			emptyByteSignature: SHA256HashZeroBytes,
			signingKey:         nil,
		},
	}
}

func (s *PayloadStreamingAWS4HMACSHA256) AddInitialSignatureAndSigningKey(initialSignature string, signingKey []byte) {
	s.lastSignature = initialSignature
	s.signingKey = signingKey
}

func (s *PayloadStreamingAWS4HMACSHA256) GetContentLength() (int64, error) {
	return s.getChunkedPayloadContentLength(83, 85)
}

func (s *PayloadStreamingAWS4HMACSHA256) addSignature(chunk []byte, outFile *os.File) error {
	sha256sum := sha256.Sum256(chunk)
	sha256sumString := hex.EncodeToString(sha256sum[:])
	signature := s.getChunkedSTSSignature(sha256sumString)
	if _, err := outFile.Write([]byte(";chunk-signature=" + signature)); err != nil {
		return fmt.Errorf("error writing chunked signature: %w", err)
	}
	s.lastSignature = signature
	return nil
}

func (s *PayloadStreamingAWS4HMACSHA256) getReader() (io.Reader, error) {
	sourceFile, err := s.dataSource.GetReader()
	if err != nil {
		return nil, fmt.Errorf("error creating tee reader: %w", err)
	}
	return bufio.NewReader(sourceFile), nil
}

func (s *PayloadStreamingAWS4HMACSHA256) WritePayload(filePath string) error {
	s.addSignatureFunc = s.addSignature
	s.getReaderFunc = s.getReader
	s.addTrailerFunc = func(outFile *os.File) error {
		return nil
	}
	return s.writeChunkedPayload(filePath)
}
