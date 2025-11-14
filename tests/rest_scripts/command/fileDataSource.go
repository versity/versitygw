package command

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

type FileDataSource struct {
	filePath string
	File     *os.File
}

func NewFileDataSource(filePath string) *FileDataSource {
	return &FileDataSource{
		filePath: filePath,
		File:     nil,
	}
}

func (f *FileDataSource) SourceDataByteSize() (int64, error) {
	fileInfo, err := os.Stat(f.filePath)
	if err != nil {
		return 0, fmt.Errorf("error getting file info: %w", err)
	}
	return fileInfo.Size(), nil
}

func (f *FileDataSource) CalculateSHA256HashString() (string, error) {
	file, err := os.Open(f.filePath)
	if err != nil {
		return "", fmt.Errorf("error opening payload file '%s': %w", f.filePath, err)
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err = io.Copy(hasher, file); err != nil {
		return "", fmt.Errorf("error copying file data of '%s' to hasher: %w", f.filePath, err)
	}

	hash := hasher.Sum(nil)
	return hex.EncodeToString(hash), nil
}

func (f *FileDataSource) Close() error {
	if f.File != nil {
		err := f.File.Close()
		f.File = nil
		return err
	}
	return nil
}

func (f *FileDataSource) openFile() error {
	var err error
	f.File, err = os.OpenFile(f.filePath, os.O_RDONLY, 0600)
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}
	return nil
}

func (f *FileDataSource) GetReader() (io.Reader, error) {
	if f.File == nil {
		if err := f.openFile(); err != nil {
			return nil, err
		}
	}
	return f.File, nil
}

func (f *FileDataSource) GetTeeReader(checksumWriter io.Writer) (io.Reader, error) {
	if f.File == nil {
		if err := f.openFile(); err != nil {
			return nil, err
		}
	}
	r := io.TeeReader(f.File, checksumWriter)
	return r, nil
}
