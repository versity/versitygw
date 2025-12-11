package command

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
)

const (
	streamPayloadTrailerAlgo = "AWS4-HMAC-SHA256-TRAILER"
)

type PayloadStreamingAWS4HMACSHA256 struct {
	*PayloadChunkedAWS
	hasher hash.Hash
}

func NewPayloadStreamingAWS4HMACSHA256(source DataSource, chunkSize int64, payloadType PayloadType, serviceString string, currentDateTime, yyyymmdd, checksumType string) *PayloadStreamingAWS4HMACSHA256 {
	return &PayloadStreamingAWS4HMACSHA256{
		PayloadChunkedAWS: &PayloadChunkedAWS{
			PayloadChunked: &PayloadChunked{
				Payload: &Payload{
					dataSource:         source,
					payloadType:        payloadType,
					checksumType:       checksumType,
					dataSizeCalculated: false,
					dataSize:           0,
				},
				chunkSize: chunkSize,
			},
			serviceString:      serviceString,
			currentDateTime:    currentDateTime,
			yyyymmdd:           yyyymmdd,
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
	var trailerSize int64 = 85
	if s.payloadType == StreamingAWS4HMACSHA256PayloadTrailer {
		chLength, err := GetBase64ChecksumLength(s.checksumType)
		if err != nil {
			return 0, err
		}

		trailerSize += chLength + 92

		// sum the checksum length
		trailerSize += 16 + int64(len(s.checksumType))
	}
	return s.getChunkedPayloadContentLength(83, trailerSize)
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

func (s *PayloadStreamingAWS4HMACSHA256) addTrailer(outFile *os.File) error {
	checksum, err := s.getBase64Checksum(s.hasher)
	if err != nil {
		return fmt.Errorf("failed to calculated the trailing checksum: %w", err)
	}
	tr := fmt.Sprintf("x-amz-checksum-%s", s.checksumType)
	trailer := fmt.Sprintf("%s:%s", tr, checksum)

	finalSig := s.calculateTrailerSignature(trailer)

	trailerStr := fmt.Sprintf(
		"\r\n%s\r\nx-amz-trailer-signature:%s",
		trailer,
		finalSig,
	)

	if _, err := outFile.Write([]byte(trailerStr)); err != nil {
		return fmt.Errorf("error writing final chunk trailer: %w", err)
	}

	s.lastSignature = finalSig
	return nil
}

func (s *PayloadStreamingAWS4HMACSHA256) calculateTrailerSignature(trailer string) string {
	trailer += "\n"
	strToSign := s.getTrailerChunkStringToSign(trailer)
	return hex.EncodeToString(hmacSHA256(s.signingKey, strToSign))
}

func (s *PayloadStreamingAWS4HMACSHA256) getTrailerChunkStringToSign(trailer string) string {
	hsh := sha256.Sum256([]byte(trailer))
	sig := hex.EncodeToString(hsh[:])

	prefix := s.getStringToSignPrefix(streamPayloadTrailerAlgo)

	strToSign := fmt.Sprintf("%s\n%s\n%s",
		prefix,
		s.lastSignature,
		sig,
	)

	return strToSign
}

func (s PayloadStreamingAWS4HMACSHA256) getStringToSignPrefix(algo string) string {
	return fmt.Sprintf("%s\n%s\n%s",
		algo,
		s.currentDateTime,
		s.serviceString,
	)
}

func (s *PayloadStreamingAWS4HMACSHA256) getReader() (io.Reader, error) {
	sourceFile, err := s.dataSource.GetReader()
	if err != nil {
		return nil, fmt.Errorf("error creating reader: %w", err)
	}
	if s.payloadType == StreamingAWS4HMACSHA256PayloadTrailer && s.checksumType != "" {
		s.hasher = s.getChecksumHasher()
		sourceFile, err = s.dataSource.GetTeeReader(s.hasher)
		if err != nil {
			return nil, fmt.Errorf("error creating tee reader: %w", err)
		}
	}
	return bufio.NewReader(sourceFile), nil
}

func (s *PayloadStreamingAWS4HMACSHA256) WritePayload(filePath string) error {
	s.addSignatureFunc = s.addSignature
	s.getReaderFunc = s.getReader
	if s.payloadType == StreamingAWS4HMACSHA256PayloadTrailer {
		s.addTrailerFunc = s.addTrailer
	} else {
		s.addTrailerFunc = func(outFile *os.File) error {
			return nil
		}
	}
	return s.writeChunkedPayload(filePath)
}
