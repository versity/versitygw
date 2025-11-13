package command

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"reflect"

	"github.com/minio/crc64nvme"
)

type Payload struct {
	dataSource         DataSource
	payloadType        PayloadType
	checksumType       string
	dataSizeCalculated bool
	dataSize           int64
}

func GetBase64ChecksumLength(checksumType string) (int64, error) {
	switch checksumType {
	case ChecksumCRC32, ChecksumCRC32C:
		return 8, nil
	case ChecksumSHA256:
		return 44, nil
	case ChecksumSHA1:
		return 28, nil
	case ChecksumCRC64NVME:
		return 12, nil
	}
	return 0, errors.New("unrecognized checksum type: " + checksumType)
}

func (p *Payload) GetDataSize() (int64, error) {
	if !p.dataSizeCalculated {
		if p.dataSource != nil {
			dataSize, err := p.dataSource.SourceDataByteSize()
			if err != nil {
				return 0, fmt.Errorf("error getting payload data size: %w", err)
			}
			p.dataSize = dataSize
		} else {
			p.dataSize = 0
		}
		p.dataSizeCalculated = true
	}
	return p.dataSize, nil
}

func (p *Payload) getChecksumHasher() hash.Hash {
	switch p.checksumType {
	case ChecksumSHA256:
		return sha256.New()
	case ChecksumSHA1:
		return sha1.New()
	case ChecksumCRC32:
		return crc32.NewIEEE()
	case ChecksumCRC32C:
		return crc32.New(crc32.MakeTable(crc32.Castagnoli))
	case ChecksumCRC64NVME:
		return crc64nvme.New()
	}
	return nil
}

func (p *Payload) getBase64Checksum(hasher hash.Hash) (string, error) {
	switch p.checksumType {
	case ChecksumSHA256, ChecksumSHA1, ChecksumCRC32:
		return base64.StdEncoding.EncodeToString(hasher.Sum(nil)), nil
	case ChecksumCRC32C:
		var b [4]byte
		hasher32, ok := hasher.(hash.Hash32)
		if !ok {
			return "", fmt.Errorf("'%v' not a Hash32 interface", reflect.TypeOf(hasher).String())
		}
		sum := hasher32.Sum32()
		binary.BigEndian.PutUint32(b[:], sum)
		return base64.StdEncoding.EncodeToString(b[:]), nil
	case ChecksumCRC64NVME:
		var b [8]byte
		hasher64, ok := hasher.(hash.Hash64)
		if !ok {
			return "", fmt.Errorf("'%v' not a Hash64 interface", reflect.TypeOf(hasher).String())
		}
		sum := hasher64.Sum64()
		binary.BigEndian.PutUint64(b[:], sum)
		return base64.StdEncoding.EncodeToString(b[:]), nil
	}
	return "", fmt.Errorf("invalid checksum type specified: '%s'", p.checksumType)
}
