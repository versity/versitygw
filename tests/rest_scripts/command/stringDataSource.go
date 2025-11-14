package command

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
)

type StringDataSource struct {
	dataString string
}

func NewStringDataSource(dataString string) *StringDataSource {
	return &StringDataSource{
		dataString: dataString,
	}
}

func (s *StringDataSource) SourceDataByteSize() (int64, error) {
	return int64(len(s.dataString)), nil
}

func (s *StringDataSource) CalculateSHA256HashString() (string, error) {
	hash := sha256.Sum256([]byte(s.dataString))
	return hex.EncodeToString(hash[:]), nil
}

func (s *StringDataSource) Close() error {
	return nil
}

func (s *StringDataSource) GetReader() (io.Reader, error) {
	stringReader := strings.NewReader(s.dataString)
	return stringReader, nil
}

func (s *StringDataSource) GetTeeReader(checksumWriter io.Writer) (io.Reader, error) {
	stringReader := strings.NewReader(s.dataString)
	r := io.TeeReader(stringReader, checksumWriter)
	return r, nil
}
