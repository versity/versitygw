package command

import (
	"fmt"
	"os"
)

type WholePayload struct {
	*Payload
}

func NewWholePayload(dataSource DataSource) *WholePayload {
	return &WholePayload{
		&Payload{
			dataSource:         dataSource,
			payloadType:        "",
			checksumType:       "",
			dataSizeCalculated: false,
			dataSize:           0,
		},
	}
}

func (w *WholePayload) CalculatePayloadSize() (int64, error) {
	return w.GetDataSize()
}

func (w *WholePayload) GetContentLength() (int64, error) {
	return w.GetDataSize()
}

func (w *WholePayload) WritePayload(filePath string) error {
	sourceFile, err := w.dataSource.GetReader()
	if err != nil {
		return fmt.Errorf("error creating tee reader: %w", err)
	}
	outFile, err := os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("error writing to file: %w", err)
	}
	buffer := make([]byte, 256)
	for {
		var bytesRead int
		bytesRead, err = sourceFile.Read(buffer)
		if err != nil {
			return fmt.Errorf("error reading data bytes: %w", err)
		}
		if bytesRead == 0 {
			break
		}
		if _, err = outFile.Write(buffer[:bytesRead]); err != nil {
			return fmt.Errorf("error writing bytes to file: %w", err)
		}
	}
	return nil
}
