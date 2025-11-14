package command

import (
	"bufio"
	"fmt"
	"hash"
	"io"
	"os"
)

type StreamingUnsignedPayloadWithTrailer struct {
	*PayloadChunked
	hasher         hash.Hash
	checksumHeader string
	checksumValue  string
	omitTrailer    bool
	omitTrailerKey bool
}

func NewStreamingUnsignedPayloadWithTrailer(source DataSource, chunkSize int64, checksumType string) *StreamingUnsignedPayloadWithTrailer {
	return &StreamingUnsignedPayloadWithTrailer{
		PayloadChunked: &PayloadChunked{
			Payload: &Payload{
				dataSource:         source,
				payloadType:        StreamingUnsignedPayloadTrailer,
				checksumType:       checksumType,
				dataSizeCalculated: false,
				dataSize:           0,
			},
			chunkSize: chunkSize,
		},
		checksumHeader: "x-amz-checksum-" + checksumType,
		checksumValue:  "",
		omitTrailer:    false,
		omitTrailerKey: false,
	}
}

func (s *StreamingUnsignedPayloadWithTrailer) OmitTrailerOrKey(omitTrailer, omitTrailerKey bool) {
	s.omitTrailer = omitTrailer
	s.omitTrailerKey = omitTrailerKey
}

func (s *StreamingUnsignedPayloadWithTrailer) GetContentLength() (int64, error) {
	checksumValueLength, err := GetBase64ChecksumLength(s.checksumType)
	if err != nil {
		return 0, fmt.Errorf("error getting base64 checksum length: %w", err)
	}
	var trailerLength int64
	if s.omitTrailer {
		trailerLength = 4
	} else if s.omitTrailerKey {
		trailerLength = 1 + checksumValueLength + 4
	} else {
		trailerLength = 2 + int64(len(s.checksumHeader)) + 1 + checksumValueLength + 4
	}
	return s.getChunkedPayloadContentLength(2, trailerLength)
}

func (s *StreamingUnsignedPayloadWithTrailer) getReader() (io.Reader, error) {
	s.hasher = s.getChecksumHasher()
	teeReader, err := s.dataSource.GetTeeReader(s.hasher)
	if err != nil {
		return nil, fmt.Errorf("error creating tee reader: %w", err)
	}
	br := bufio.NewReader(teeReader)
	return br, nil
}

func (s *StreamingUnsignedPayloadWithTrailer) addTrailer(outFile *os.File) error {
	if s.omitTrailer {
		return nil
	}
	if _, err := outFile.Write([]byte{'\r', '\n'}); err != nil {
		return fmt.Errorf("error writing \\r\\n: %w", err)
	}
	checksum, err := s.getBase64Checksum(s.hasher)
	if err != nil {
		return fmt.Errorf("error getting checksum: %w", err)
	}
	if !s.omitTrailerKey {
		if _, err = outFile.Write([]byte(s.checksumHeader)); err != nil {
			return fmt.Errorf("error writing trailer key: %w", err)
		}
	}
	if _, err = outFile.Write([]byte(":" + checksum)); err != nil {
		return fmt.Errorf("error writing checksum: %w", err)
	}
	return nil
}

func (s *StreamingUnsignedPayloadWithTrailer) WritePayload(filePath string) error {
	s.addSignatureFunc = func(chunk []byte, file *os.File) error {
		return nil
	}
	s.getReaderFunc = s.getReader
	s.addTrailerFunc = s.addTrailer
	return s.writeChunkedPayload(filePath)
}
