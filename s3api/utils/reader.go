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
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
	"io"

	"github.com/versity/versitygw/s3err"
)

type HashType string

const (
	HashTypeMd5    = "md5"
	HashTypeSha256 = "sha256"
)

type HashReader struct {
	hashType HashType
	hash     hash.Hash
	r        io.Reader
	sum      string
	err      error
}

func NewHashReader(r io.Reader, hash hash.Hash, sum string, ht HashType) *HashReader {
	return &HashReader{hash: hash, r: r, sum: sum, hashType: ht}
}

func (hr *HashReader) Read(p []byte) (int, error) {
	n, readerr := hr.r.Read(p)
	_, err := hr.hash.Write(p[:n])
	if err != nil {
		return n, err
	}
	if errors.Is(readerr, io.EOF) {
		if hr.hashType == HashTypeMd5 {
			sum := base64.StdEncoding.EncodeToString(hr.hash.Sum(nil))
			if sum != hr.sum {
				hr.err = s3err.GetAPIError(s3err.ErrInvalidDigest)
				return n, s3err.GetAPIError(s3err.ErrInvalidDigest)
			}
		} else if hr.hashType == HashTypeSha256 {
			sum := hex.EncodeToString(hr.hash.Sum(nil))
			if sum != hr.sum {
				hr.err = s3err.GetAPIError(s3err.ErrContentSHA256Mismatch)
				return n, s3err.GetAPIError(s3err.ErrContentSHA256Mismatch)
			}
		}
	}
	return n, readerr
}

func (hr *HashReader) Err() error {
	return hr.err
}
