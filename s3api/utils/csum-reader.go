// Copyright 2023 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package utils

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"hash/crc64"
	"io"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
)

// HashType identifies the checksum algorithm to be used
type HashType string

const (
	// HashTypeMd5 generates MD5 checksum for the data stream
	HashTypeMd5 HashType = "md5"
	// HashTypeSha256 generates SHA256 Base64-Encoded checksum for the data stream
	HashTypeSha256 HashType = "sha256"
	// HashTypeSha256Hex generates SHA256 hex encoded checksum for the data stream
	HashTypeSha256Hex HashType = "sha256-hex"
	// HashTypeSha1 generates SHA1 Base64-Encoded checksum for the data stream
	HashTypeSha1 HashType = "sha1"
	// HashTypeCRC32 generates CRC32 Base64-Encoded checksum for the data stream
	HashTypeCRC32 HashType = "crc32"
	// HashTypeCRC32C generates CRC32C Base64-Encoded checksum for the data stream
	HashTypeCRC32C HashType = "crc32c"
	// HashTypeCRC64NVME generates CRC64NVME Base64-Encoded checksum for the data stream
	HashTypeCRC64NVME HashType = "crc64nvme"
	// HashTypeNone is a no-op checksum for the data stream
	HashTypeNone HashType = "none"
)

// HashReader is an io.Reader that calculates the checksum
// as the data is read
type HashReader struct {
	hashType HashType
	hash     hash.Hash
	r        io.Reader
	sum      string
}

var (
	errInvalidHashType = errors.New("unsupported or invalid checksum type")
)

// NewHashReader intializes an io.Reader from an underlying io.Reader that
// calculates the checksum while the reader is being read from. If the
// sum provided is not "", the reader will return an error when the underlying
// reader returns io.EOF if the checksum does not match the provided expected
// checksum.  If the provided sum is "", then the Sum() method can still
// be used to get the current checksum for the data read so far.
func NewHashReader(r io.Reader, expectedSum string, ht HashType) (*HashReader, error) {
	var hash hash.Hash
	switch ht {
	case HashTypeMd5:
		hash = md5.New()
	case HashTypeSha256Hex:
		hash = sha256.New()
	case HashTypeSha256:
		hash = sha256.New()
	case HashTypeSha1:
		hash = sha1.New()
	case HashTypeCRC32:
		hash = crc32.NewIEEE()
	case HashTypeCRC32C:
		hash = crc32.New(crc32.MakeTable(crc32.Castagnoli))
	case HashTypeCRC64NVME:
		hash = crc64.New(crc64NVMETable)
	case HashTypeNone:
		hash = noop{}
	default:
		return nil, errInvalidHashType
	}

	return &HashReader{
		hash:     hash,
		r:        r,
		sum:      expectedSum,
		hashType: ht,
	}, nil
}

// Read allows *HashReader to be used as an io.Reader
func (hr *HashReader) Read(p []byte) (int, error) {
	n, readerr := hr.r.Read(p)
	_, err := hr.hash.Write(p[:n])
	if err != nil {
		return n, err
	}
	if errors.Is(readerr, io.EOF) && hr.sum != "" {
		switch hr.hashType {
		case HashTypeMd5:
			sum := hr.Sum()
			if sum != hr.sum {
				return n, s3err.GetAPIError(s3err.ErrInvalidDigest)
			}
		case HashTypeSha256Hex:
			sum := hr.Sum()
			if sum != hr.sum {
				return n, s3err.GetAPIError(s3err.ErrContentSHA256Mismatch)
			}
		case HashTypeCRC32:
			sum := hr.Sum()
			if sum != hr.sum {
				return n, s3err.GetChecksumBadDigestErr(types.ChecksumAlgorithmCrc32)
			}
		case HashTypeCRC32C:
			sum := hr.Sum()
			if sum != hr.sum {
				return n, s3err.GetChecksumBadDigestErr(types.ChecksumAlgorithmCrc32c)
			}
		case HashTypeSha1:
			sum := hr.Sum()
			if sum != hr.sum {
				return n, s3err.GetChecksumBadDigestErr(types.ChecksumAlgorithmSha1)
			}
		case HashTypeSha256:
			sum := hr.Sum()
			if sum != hr.sum {
				return n, s3err.GetChecksumBadDigestErr(types.ChecksumAlgorithmSha256)
			}
		case HashTypeCRC64NVME:
			sum := hr.Sum()
			if sum != hr.sum {
				return n, s3err.GetChecksumBadDigestErr(types.ChecksumAlgorithmCrc64nvme)
			}
		default:
			return n, errInvalidHashType
		}
	}
	return n, readerr
}

func (hr *HashReader) SetReader(r io.Reader) {
	hr.r = r
}

// Sum returns the checksum hash of the data read so far
func (hr *HashReader) Sum() string {
	switch hr.hashType {
	case HashTypeMd5:
		return Base64SumString(hr.hash.Sum(nil))
	case HashTypeSha256Hex:
		return hex.EncodeToString(hr.hash.Sum(nil))
	case HashTypeCRC32:
		return Base64SumString(hr.hash.Sum(nil))
	case HashTypeCRC32C:
		return Base64SumString(hr.hash.Sum(nil))
	case HashTypeSha1:
		return Base64SumString(hr.hash.Sum(nil))
	case HashTypeSha256:
		return Base64SumString(hr.hash.Sum(nil))
	case HashTypeCRC64NVME:
		return Base64SumString(hr.hash.Sum(nil))
	default:
		return ""
	}
}

func (hr *HashReader) Type() HashType {
	return hr.hashType
}

// Base64SumString converts the hash bytes to the b64 encoded string checksum value
func Base64SumString(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

type noop struct{}

func (n noop) Write(p []byte) (int, error) { return 0, nil }
func (n noop) Sum(b []byte) []byte         { return []byte{} }
func (n noop) Reset()                      {}
func (n noop) Size() int                   { return 0 }
func (n noop) BlockSize() int              { return 1 }

// IsChecksumComposable tests if the final foll object crc can be calculated
// based on the part crc values.
func IsChecksumComposable(algo types.ChecksumAlgorithm) bool {
	switch algo {
	case types.ChecksumAlgorithmCrc32, types.ChecksumAlgorithmCrc32c, types.ChecksumAlgorithmCrc64nvme:
		return true
	default:
		return false
	}
}

// AddCRCChecksum calculates the composite CRC checksum after adding the part crc.
// Only CRC32, CRC32C, and CRC64NVME are supported. The input checksums must be base64-encoded strings.
func AddCRCChecksum(algo types.ChecksumAlgorithm, crc, partCrc string, partLen int64) (string, error) {
	switch algo {
	case types.ChecksumAlgorithmCrc32:
		data, err := base64.StdEncoding.DecodeString(partCrc)
		if err != nil {
			return "", fmt.Errorf("base64 decode partCrc: %w", err)
		}
		if len(data) != 4 {
			return "", fmt.Errorf("invalid crc32 part checksum length: %d", len(data))
		}
		currentCRC, err := base64.StdEncoding.DecodeString(crc)
		if err != nil {
			return "", fmt.Errorf("base64 decode crc: %w", err)
		}
		if len(currentCRC) != 4 {
			return "", fmt.Errorf("invalid crc32 checksum length: %d", len(currentCRC))
		}

		currentVal := uint32(currentCRC[0])<<24 | uint32(currentCRC[1])<<16 | uint32(currentCRC[2])<<8 | uint32(currentCRC[3])
		val := uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
		composite := crc32Combine(crc32.IEEE, currentVal, val, partLen)

		out := []byte{
			byte(composite >> 24),
			byte(composite >> 16),
			byte(composite >> 8),
			byte(composite),
		}
		return base64.StdEncoding.EncodeToString(out), nil
	case types.ChecksumAlgorithmCrc32c:
		data, err := base64.StdEncoding.DecodeString(partCrc)
		if err != nil {
			return "", fmt.Errorf("base64 decode partCrc: %w", err)
		}
		if len(data) != 4 {
			return "", fmt.Errorf("invalid crc32 part checksum length: %d", len(data))
		}
		currentCRC, err := base64.StdEncoding.DecodeString(crc)
		if err != nil {
			return "", fmt.Errorf("base64 decode crc: %w", err)
		}
		if len(currentCRC) != 4 {
			return "", fmt.Errorf("invalid crc32 checksum length: %d", len(currentCRC))
		}

		currentVal := uint32(currentCRC[0])<<24 | uint32(currentCRC[1])<<16 | uint32(currentCRC[2])<<8 | uint32(currentCRC[3])
		val := uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
		composite := crc32Combine(crc32.Castagnoli, currentVal, val, partLen)

		// Convert composite to big-endian bytes
		out := []byte{
			byte(composite >> 24),
			byte(composite >> 16),
			byte(composite >> 8),
			byte(composite),
		}
		return base64.StdEncoding.EncodeToString(out), nil
	case types.ChecksumAlgorithmCrc64nvme:
		data, err := base64.StdEncoding.DecodeString(partCrc)
		if err != nil {
			return "", fmt.Errorf("base64 decode partCrc: %w", err)
		}
		if len(data) != 8 {
			return "", fmt.Errorf("invalid crc64 part checksum length: %d", len(data))
		}
		currentCRC, err := base64.StdEncoding.DecodeString(crc)
		if err != nil {
			return "", fmt.Errorf("base64 decode crc: %w", err)
		}
		if len(currentCRC) != 8 {
			return "", fmt.Errorf("invalid crc64 checksum length: %d", len(currentCRC))
		}

		currentVal := uint64(currentCRC[0])<<56 | uint64(currentCRC[1])<<48 | uint64(currentCRC[2])<<40 | uint64(currentCRC[3])<<32 |
			uint64(currentCRC[4])<<24 | uint64(currentCRC[5])<<16 | uint64(currentCRC[6])<<8 | uint64(currentCRC[7])
		val := uint64(data[0])<<56 | uint64(data[1])<<48 | uint64(data[2])<<40 | uint64(data[3])<<32 |
			uint64(data[4])<<24 | uint64(data[5])<<16 | uint64(data[6])<<8 | uint64(data[7])
		composite := crc64Combine(crc64NVME, currentVal, val, partLen)

		out := []byte{
			byte(composite >> 56), byte(composite >> 48), byte(composite >> 40), byte(composite >> 32),
			byte(composite >> 24), byte(composite >> 16), byte(composite >> 8), byte(composite),
		}
		return base64.StdEncoding.EncodeToString(out), nil
	default:
		return "", fmt.Errorf("composite checksum not supported for algorithm: %v", algo)
	}
}

// NewCompositeChecksumReader initializes a composite checksum
// processor, which decodes and validates the provided
// checksums and returns the final checksum based on
// the previous processings.
//
// The supported checksum types are:
// - CRC32
// - CRC32C
// - SHA1
// - SHA256
func NewCompositeChecksumReader(ht HashType) (*CompositeChecksumReader, error) {
	var hasher hash.Hash
	switch ht {
	case HashTypeSha256:
		hasher = sha256.New()
	case HashTypeSha1:
		hasher = sha1.New()
	case HashTypeCRC32:
		hasher = crc32.NewIEEE()
	case HashTypeCRC32C:
		hasher = crc32.New(crc32.MakeTable(crc32.Castagnoli))
	case HashTypeNone:
		hasher = noop{}
	default:
		return nil, errInvalidHashType
	}

	return &CompositeChecksumReader{
		hasher: hasher,
	}, nil
}

type CompositeChecksumReader struct {
	hasher hash.Hash
}

// Decodes and writes the checksum in the hasher
func (ccr *CompositeChecksumReader) Process(checksum string) error {
	data, err := base64.StdEncoding.DecodeString(checksum)
	if err != nil {
		return fmt.Errorf("base64 decode: %w", err)
	}

	_, err = ccr.hasher.Write(data)
	if err != nil {
		return fmt.Errorf("hash write: %w", err)
	}

	return nil
}

// Returns the base64 encoded composite checksum
func (ccr *CompositeChecksumReader) Sum() string {
	return Base64SumString(ccr.hasher.Sum(nil))
}
