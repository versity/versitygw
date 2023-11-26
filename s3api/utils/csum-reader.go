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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
	"io"

	"github.com/versity/versitygw/s3err"
)

// HashType identifies the checksum algorithm to be used
type HashType string

const (
	// HashTypeMd5 generates MD5 checksum for the data stream
	HashTypeMd5 = "md5"
	// HashTypeSha256 generates SHA256 checksum for the data stream
	HashTypeSha256 = "sha256"
	// HashTypeNone is a no-op checksum for the data stream
	HashTypeNone = "none"
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
	case HashTypeSha256:
		hash = sha256.New()
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
			sum := base64.StdEncoding.EncodeToString(hr.hash.Sum(nil))
			if sum != hr.sum {
				return n, s3err.GetAPIError(s3err.ErrInvalidDigest)
			}
		case HashTypeSha256:
			sum := hex.EncodeToString(hr.hash.Sum(nil))
			if sum != hr.sum {
				return n, s3err.GetAPIError(s3err.ErrContentSHA256Mismatch)
			}
		default:
			return n, errInvalidHashType
		}
	}
	return n, readerr
}

// Sum returns the checksum hash of the data read so far
func (hr *HashReader) Sum() string {
	switch hr.hashType {
	case HashTypeMd5:
		return Md5SumString(hr.hash.Sum(nil))
	case HashTypeSha256:
		return hex.EncodeToString(hr.hash.Sum(nil))
	default:
		return ""
	}
}

// Md5SumString converts the hash bytes to the string checksum value
func Md5SumString(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

type noop struct{}

func (n noop) Write(p []byte) (int, error) { return 0, nil }
func (n noop) Sum(b []byte) []byte         { return []byte{} }
func (n noop) Reset()                      {}
func (n noop) Size() int                   { return 0 }
func (n noop) BlockSize() int              { return 1 }
