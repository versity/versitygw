package command

import (
	"fmt"
	"io"
	"os"
)

type PayloadChunked struct {
	*Payload
	chunkSize        int64
	getReaderFunc    func() (io.Reader, error)
	addSignatureFunc func(chunk []byte, outFile *os.File) error
	addTrailerFunc   func(outFile *os.File) error
}

func (c *PayloadChunked) getChunkedPayloadContentLength(additionalChunkHeaderSize, additionalTrailerSize int64) (int64, error) {
	payloadSize, err := c.Payload.GetDataSize()
	if err != nil {
		return 0, fmt.Errorf("error getting payload data size: %w", err)
	}
	var sizeIdx int64
	var contentLength int64
	for sizeIdx = 0; sizeIdx < payloadSize; sizeIdx += c.chunkSize {
		var endIdx int64
		if sizeIdx+c.chunkSize < payloadSize {
			endIdx = sizeIdx + c.chunkSize
		} else {
			endIdx = payloadSize
		}
		hexSize := fmt.Sprintf("%x", endIdx-sizeIdx)
		contentLength += int64(len(hexSize)) + additionalChunkHeaderSize + (endIdx - sizeIdx) + 2
	}
	contentLength += 1 + additionalTrailerSize
	return contentLength, nil
}

func (c *PayloadChunked) writeChunkedPayload(filePath string) error {
	defer func() {
		c.dataSource.Close()
	}()
	outFile, err := os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("error writing to file: %w", err)
	}
	br, err := c.getReaderFunc()
	if err != nil {
		return fmt.Errorf("error getting data reader: %w", err)
	}
	payloadBuffer := make([]byte, c.chunkSize)
	for {
		var bytesRead int
		if bytesRead, err = c.addChunk(br, payloadBuffer, outFile); err != nil {
			return fmt.Errorf("error adding chunk: %w", err)
		}
		if bytesRead == 0 {
			break
		}
	}
	if _, err = outFile.Write([]byte{'0'}); err != nil {
		return fmt.Errorf("error writing \\r\\n: %w", err)
	}
	if err = c.addSignatureFunc(nil, outFile); err != nil {
		return fmt.Errorf("error adding signature: %w", err)
	}
	if err = c.addTrailerFunc(outFile); err != nil {
		return fmt.Errorf("error adding trailer: %w", err)
	}
	if _, err = outFile.Write([]byte{'\r', '\n', '\r', '\n'}); err != nil {
		return fmt.Errorf("error writing \\r\\n: %w", err)
	}
	return nil
}

func (c *PayloadChunked) addChunk(reader io.Reader, payloadBuffer []byte, outFile *os.File) (int, error) {
	var bytesRead int
	bytesRead, err := reader.Read(payloadBuffer)
	if err != nil && err != io.EOF {
		return 0, fmt.Errorf("error reading bytes: %w", err)
	}
	if bytesRead == 0 {
		return 0, nil
	}
	hexString := fmt.Sprintf("%x", bytesRead)
	if _, err = outFile.Write([]byte(hexString)); err != nil {
		return 0, fmt.Errorf("error writing hex string: %w", err)
	}
	if err = c.addSignatureFunc(payloadBuffer[:bytesRead], outFile); err != nil {
		return 0, fmt.Errorf("error adding signature: %w", err)
	}
	if _, err = outFile.Write([]byte{'\r', '\n'}); err != nil {
		return 0, fmt.Errorf("error writing \\r\\n: %w", err)
	}
	if _, err = outFile.Write(payloadBuffer[:bytesRead]); err != nil {
		return 0, fmt.Errorf("error writing bytes to file: %w", err)
	}
	if _, err = outFile.Write([]byte{'\r', '\n'}); err != nil {
		return 0, fmt.Errorf("error writing \\r\\n: %w", err)
	}
	return bytesRead, nil
}
