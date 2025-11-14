package command

import "io"

type DataSource interface {
	SourceDataByteSize() (int64, error)
	CalculateSHA256HashString() (string, error)
	Close() error
	GetReader() (io.Reader, error)
	GetTeeReader(io.Writer) (io.Reader, error)
}
