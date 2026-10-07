// Copyright 2026 Versity Software
// Copyright 2026 Gluesys Inc. and Jihyeon Gim
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

package daos

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3api/middlewares"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

const (
	attrChecksums = "checksums"
	attrPartCRC64 = "part-crc64nvme"
)

func partCRCReader(body io.Reader) (io.Reader, func() string, error) {
	if body == nil {
		body = bytes.NewReader(nil)
	}
	hr, err := utils.NewHashReader(body, "", utils.HashTypeCRC64NVME)
	if err != nil {
		return nil, nil, err
	}
	return hr, hr.Sum, nil
}

func hashBytes(algo types.ChecksumAlgorithm, body []byte) (string, error) {
	return hashReader(algo, bytes.NewReader(body), "")
}

func hashReader(algo types.ChecksumAlgorithm, r io.Reader, expected string) (string, error) {
	hr, err := utils.NewHashReader(r, expected, utils.HashType(strings.ToLower(string(algo))))
	if err != nil {
		return "", s3err.GetAPIError(s3err.ErrInvalidChecksumAlgorithm)
	}
	if _, err := io.Copy(io.Discard, hr); err != nil {
		return "", err
	}
	return hr.Sum(), nil
}

func fullObjectChecksum(algo types.ChecksumAlgorithm, body []byte) (s3response.Checksum, error) {
	sum, err := hashBytes(algo, body)
	if err != nil {
		return s3response.Checksum{}, err
	}
	ch := s3response.Checksum{Algorithm: algo, Type: types.ChecksumTypeFullObject}
	ch.SetSum(algo, &sum)
	return ch, nil
}

func (d *Daos) storeChecksums(obj Object, ch s3response.Checksum) error {
	raw, err := json.Marshal(ch)
	if err != nil {
		return err
	}
	return mapFS(d.fs.SetXattr(obj, attrChecksums, raw))
}

func (d *Daos) loadChecksums(obj Object) (s3response.Checksum, error) {
	var ch s3response.Checksum
	raw, err := d.fs.GetXattr(obj, attrChecksums)
	if errors.Is(err, errNotExist) || len(raw) == 0 {
		return ch, nil
	}
	if err != nil {
		return ch, mapFS(err)
	}
	if err := json.Unmarshal(raw, &ch); err != nil {
		return ch, fmt.Errorf("parse checksum: %w", err)
	}
	return ch, nil
}

func (d *Daos) loadChecksumsAt(p string) (s3response.Checksum, error) {
	obj, err := d.fs.Open(p, openRead)
	if err != nil {
		return s3response.Checksum{}, mapFS(err)
	}
	defer d.fs.Release(obj)
	return d.loadChecksums(obj)
}

func fillPutChecksum(out *s3response.PutObjectOutput, ch s3response.Checksum) {
	out.ChecksumType = ch.Type
	out.ChecksumCRC32 = ch.CRC32
	out.ChecksumCRC32C = ch.CRC32C
	out.ChecksumSHA1 = ch.SHA1
	out.ChecksumSHA256 = ch.SHA256
	out.ChecksumCRC64NVME = ch.CRC64NVME
	out.ChecksumSHA512 = ch.SHA512
	out.ChecksumMD5 = ch.MD5
	out.ChecksumXXHASH64 = ch.XXHASH64
	out.ChecksumXXHASH3 = ch.XXHASH3
	out.ChecksumXXHASH128 = ch.XXHASH128
}

func fillGetChecksum(out *s3.GetObjectOutput, ch s3response.Checksum) {
	out.ChecksumType = ch.Type
	out.ChecksumCRC32 = ch.CRC32
	out.ChecksumCRC32C = ch.CRC32C
	out.ChecksumSHA1 = ch.SHA1
	out.ChecksumSHA256 = ch.SHA256
	out.ChecksumCRC64NVME = ch.CRC64NVME
	out.ChecksumSHA512 = ch.SHA512
	out.ChecksumMD5 = ch.MD5
	out.ChecksumXXHASH64 = ch.XXHASH64
	out.ChecksumXXHASH3 = ch.XXHASH3
	out.ChecksumXXHASH128 = ch.XXHASH128
}

func fillCompleteChecksum(out *s3response.CompleteMultipartUploadResult, ch s3response.Checksum) {
	kind := ch.Type
	out.ChecksumType = &kind
	out.ChecksumCRC32 = ch.CRC32
	out.ChecksumCRC32C = ch.CRC32C
	out.ChecksumSHA1 = ch.SHA1
	out.ChecksumSHA256 = ch.SHA256
	out.ChecksumCRC64NVME = ch.CRC64NVME
	out.ChecksumSHA512 = ch.SHA512
	out.ChecksumMD5 = ch.MD5
	out.ChecksumXXHASH64 = ch.XXHASH64
	out.ChecksumXXHASH3 = ch.XXHASH3
	out.ChecksumXXHASH128 = ch.XXHASH128
}

func fillHeadChecksum(out *s3.HeadObjectOutput, ch s3response.Checksum) {
	out.ChecksumType = ch.Type
	out.ChecksumCRC32 = ch.CRC32
	out.ChecksumCRC32C = ch.CRC32C
	out.ChecksumSHA1 = ch.SHA1
	out.ChecksumSHA256 = ch.SHA256
	out.ChecksumCRC64NVME = ch.CRC64NVME
	out.ChecksumSHA512 = ch.SHA512
	out.ChecksumMD5 = ch.MD5
	out.ChecksumXXHASH64 = ch.XXHASH64
	out.ChecksumXXHASH3 = ch.XXHASH3
	out.ChecksumXXHASH128 = ch.XXHASH128
}

type partHash struct {
	body    io.Reader
	user    *utils.HashReader
	crc64   *utils.HashReader
	trail   middlewares.ChecksumReader
	expose  bool
	userAlg utils.HashType
}

func (d *Daos) wrapPartBody(input *s3.UploadPartInput, stored s3response.Checksum) (partHash, error) {
	var out partHash
	chRdr, chunk := input.Body.(middlewares.ChecksumReader)
	trailing := chunk && chRdr.Algorithm() != ""
	inputAlg, inputSum := partHeaderChecksum(input)
	if !trailing && inputAlg == "" && stored.Type == types.ChecksumTypeComposite {
		return out, s3err.GetChecksumTypeMismatchErr(stored.Algorithm, "null")
	}
	if inputAlg != "" && stored.Type != "" {
		algo := types.ChecksumAlgorithm(strings.ToUpper(string(inputAlg)))
		if stored.Algorithm != algo {
			return out, s3err.GetChecksumTypeMismatchErr(stored.Algorithm, algo)
		}
	}
	tr := input.Body
	if tr == nil {
		tr = bytes.NewReader(nil)
	}
	if trailing {
		out.trail = chRdr
		out.userAlg = utils.HashType(chRdr.Algorithm())
		out.expose = true
	}
	calcAlg := inputAlg
	if calcAlg == "" {
		calcAlg = utils.HashTypeCRC64NVME
	}
	if stored.Type == "" {
		if calcAlg != utils.HashTypeCRC64NVME {
			crc, err := utils.NewHashReader(tr, "", utils.HashTypeCRC64NVME)
			if err != nil {
				return out, fmt.Errorf("initialize crc64nvme hash reader: %w", err)
			}
			tr = crc
			out.crc64 = crc
		}
		if !trailing {
			hr, err := utils.NewHashReader(tr, inputSum, calcAlg)
			if err != nil {
				return out, fmt.Errorf("initialize hash reader: %w", err)
			}
			tr = hr
			out.user = hr
			out.userAlg = calcAlg
			out.expose = inputAlg != ""
		}
	} else if !trailing {
		chAlg := utils.HashType(strings.ToLower(string(stored.Algorithm)))
		hr, err := utils.NewHashReader(tr, inputSum, chAlg)
		if err != nil {
			return out, fmt.Errorf("initialize hash reader: %w", err)
		}
		tr = hr
		out.user = hr
		out.userAlg = chAlg
		out.expose = true
		if stored.Algorithm != types.ChecksumAlgorithmCrc64nvme {
			crc, err := utils.NewHashReader(tr, "", utils.HashTypeCRC64NVME)
			if err != nil {
				return out, fmt.Errorf("initialize crc64nvme hash reader: %w", err)
			}
			tr = crc
			out.crc64 = crc
		}
	}
	out.body = tr
	return out, nil
}

func (h partHash) userSum() string {
	if h.trail != nil && h.trail.Algorithm() != "" {
		return h.trail.Checksum()
	}
	if h.user != nil {
		return h.user.Sum()
	}
	return ""
}

func (h partHash) crc64Sum() string {
	if h.userAlg == utils.HashTypeCRC64NVME {
		return h.userSum()
	}
	if h.crc64 != nil {
		return h.crc64.Sum()
	}
	return h.userSum()
}

func partHeaderChecksum(input *s3.UploadPartInput) (utils.HashType, string) {
	pairs := []struct {
		alg utils.HashType
		val *string
	}{
		{utils.HashTypeCRC32, input.ChecksumCRC32},
		{utils.HashTypeCRC32C, input.ChecksumCRC32C},
		{utils.HashTypeSha1, input.ChecksumSHA1},
		{utils.HashTypeSha256, input.ChecksumSHA256},
		{utils.HashTypeCRC64NVME, input.ChecksumCRC64NVME},
		{utils.HashTypeSha512, input.ChecksumSHA512},
		{utils.HashTypeMd5, input.ChecksumMD5},
		{utils.HashTypeXXHASH64, input.ChecksumXXHASH64},
		{utils.HashTypeXXHASH3, input.ChecksumXXHASH3},
		{utils.HashTypeXXHASH128, input.ChecksumXXHASH128},
	}
	for _, pair := range pairs {
		if pair.val != nil && *pair.val != "" {
			return pair.alg, *pair.val
		}
	}
	if input.ChecksumAlgorithm != "" {
		return utils.HashType(strings.ToLower(string(input.ChecksumAlgorithm))), ""
	}
	return "", ""
}

func setPartChecksum(res *s3.UploadPartOutput, alg utils.HashType, sum string) {
	if sum == "" {
		return
	}
	switch types.ChecksumAlgorithm(strings.ToUpper(string(alg))) {
	case types.ChecksumAlgorithmCrc32:
		res.ChecksumCRC32 = &sum
	case types.ChecksumAlgorithmCrc32c:
		res.ChecksumCRC32C = &sum
	case types.ChecksumAlgorithmSha1:
		res.ChecksumSHA1 = &sum
	case types.ChecksumAlgorithmSha256:
		res.ChecksumSHA256 = &sum
	case types.ChecksumAlgorithmCrc64nvme:
		res.ChecksumCRC64NVME = &sum
	case types.ChecksumAlgorithmSha512:
		res.ChecksumSHA512 = &sum
	case types.ChecksumAlgorithmMd5:
		res.ChecksumMD5 = &sum
	case types.ChecksumAlgorithmXxhash64:
		res.ChecksumXXHASH64 = &sum
	case types.ChecksumAlgorithmXxhash3:
		res.ChecksumXXHASH3 = &sum
	case types.ChecksumAlgorithmXxhash128:
		res.ChecksumXXHASH128 = &sum
	}
}

func (d *Daos) storePartSums(partPath string, stored s3response.Checksum, hashed partHash) error {
	obj, err := d.fs.Open(partPath, openRead)
	if err != nil {
		return mapFS(err)
	}
	defer d.fs.Release(obj)
	if stored.Type == "" {
		return nil
	}
	sum := hashed.userSum()
	ch := s3response.Checksum{Algorithm: stored.Algorithm}
	ch.SetSum(stored.Algorithm, &sum)
	return d.storeChecksums(obj, ch)
}

func (d *Daos) objectChecksumFromParts(uploadDir string, input *s3.CompleteMultipartUploadInput, parts []types.CompletedPart) (s3response.Checksum, error) {
	var none s3response.Checksum
	stored, err := d.loadChecksumsAt(uploadDir)
	if err != nil {
		return none, err
	}
	asked := stored.Type
	if input.ChecksumType != "" && stored.Type != input.ChecksumType {
		got := stored.Type
		if got == "" {
			got = types.ChecksumType("null")
		}
		return none, s3err.GetChecksumTypeMismatchOnMpErr(got)
	}
	algo := stored.Algorithm
	kind := stored.Type
	if kind == "" {
		kind = types.ChecksumTypeFullObject
		algo = types.ChecksumAlgorithmCrc64nvme
	}
	var composite *utils.CompositeChecksumReader
	if kind == types.ChecksumTypeComposite {
		composite, err = utils.NewCompositeChecksumReader(utils.HashType(strings.ToLower(string(algo))))
		if err != nil {
			return none, fmt.Errorf("initialize composite checksum reader: %w", err)
		}
	}
	var combined string
	for i, part := range parts {
		partPath := path.Join(uploadDir, itoa32(*part.PartNumber))
		info, err := d.fs.Stat(partPath)
		if err != nil {
			return none, mapFS(err)
		}
		partCh, err := d.loadChecksumsAt(partPath)
		if err != nil {
			return none, err
		}
		if err := validatePartChecksum(partCh, part, awsString(input.UploadId)); err != nil {
			return none, err
		}
		var piece string
		if asked != "" {
			piece = completedPartSum(algo, part)
		} else {
			raw, err := d.xattr(partPath, attrPartCRC64)
			if err != nil {
				return none, err
			}
			piece = string(raw)
		}
		switch kind {
		case types.ChecksumTypeFullObject:
			if i == 0 {
				combined = piece
			} else {
				combined, err = utils.AddCRCChecksum(algo, combined, piece, info.Size)
				if err != nil {
					return none, fmt.Errorf("add part checksum: %w", err)
				}
			}
		case types.ChecksumTypeComposite:
			if err := composite.Process(completedPartSum(algo, part)); err != nil {
				return none, fmt.Errorf("process part checksum: %w", err)
			}
		}
	}
	ch := s3response.Checksum{Algorithm: algo, Type: kind}
	value := combined
	if kind == types.ChecksumTypeComposite {
		value = fmt.Sprintf("%s-%d", composite.Sum(), len(parts))
	}
	ch.SetSum(algo, &value)
	if asked != "" {
		if err := checkCompleteDigest(input, algo, kind, value, len(parts)); err != nil {
			return none, err
		}
	}
	return ch, nil
}

func checkCompleteDigest(input *s3.CompleteMultipartUploadInput, algo types.ChecksumAlgorithm, kind types.ChecksumType, value string, n int) error {
	got := completeHeaderSum(input, algo)
	if got == nil {
		return nil
	}
	s := *got
	if kind == types.ChecksumTypeComposite && !strings.Contains(s, "-") {
		s = fmt.Sprintf("%s-%d", s, n)
	}
	if s != value {
		return s3err.GetChecksumBadDigestErr(algo)
	}
	return nil
}

func completeHeaderSum(input *s3.CompleteMultipartUploadInput, algo types.ChecksumAlgorithm) *string {
	switch algo {
	case types.ChecksumAlgorithmCrc32:
		return input.ChecksumCRC32
	case types.ChecksumAlgorithmCrc32c:
		return input.ChecksumCRC32C
	case types.ChecksumAlgorithmSha1:
		return input.ChecksumSHA1
	case types.ChecksumAlgorithmSha256:
		return input.ChecksumSHA256
	case types.ChecksumAlgorithmCrc64nvme:
		return input.ChecksumCRC64NVME
	case types.ChecksumAlgorithmSha512:
		return input.ChecksumSHA512
	case types.ChecksumAlgorithmMd5:
		return input.ChecksumMD5
	case types.ChecksumAlgorithmXxhash64:
		return input.ChecksumXXHASH64
	case types.ChecksumAlgorithmXxhash3:
		return input.ChecksumXXHASH3
	case types.ChecksumAlgorithmXxhash128:
		return input.ChecksumXXHASH128
	default:
		return nil
	}
}

func checksumForPut(po s3response.PutObjectInput, body []byte) (s3response.Checksum, bool, error) {
	algo := po.ChecksumAlgorithm
	expected := ""
	if algo == "" {
		algo, expected = putHeaderChecksum(po)
	} else {
		expected = putExpectedSum(po, algo)
	}
	if algo == "" {
		return s3response.Checksum{}, false, nil
	}
	ch, err := fullObjectChecksum(algo, body)
	if err != nil {
		return s3response.Checksum{}, false, err
	}
	if expected != "" && awsString(sumField(ch, algo)) != expected {
		return s3response.Checksum{}, false, s3err.GetChecksumBadDigestErr(algo)
	}
	return ch, true, nil
}

func putHeaderChecksum(po s3response.PutObjectInput) (types.ChecksumAlgorithm, string) {
	pairs := []struct {
		algo types.ChecksumAlgorithm
		val  *string
	}{
		{types.ChecksumAlgorithmCrc32, po.ChecksumCRC32},
		{types.ChecksumAlgorithmCrc32c, po.ChecksumCRC32C},
		{types.ChecksumAlgorithmSha1, po.ChecksumSHA1},
		{types.ChecksumAlgorithmSha256, po.ChecksumSHA256},
		{types.ChecksumAlgorithmCrc64nvme, po.ChecksumCRC64NVME},
		{types.ChecksumAlgorithmSha512, po.ChecksumSHA512},
		{types.ChecksumAlgorithmMd5, po.ChecksumMD5},
		{types.ChecksumAlgorithmXxhash64, po.ChecksumXXHASH64},
		{types.ChecksumAlgorithmXxhash3, po.ChecksumXXHASH3},
		{types.ChecksumAlgorithmXxhash128, po.ChecksumXXHASH128},
	}
	for _, pair := range pairs {
		if pair.val != nil && *pair.val != "" {
			return pair.algo, *pair.val
		}
	}
	return "", ""
}

func putExpectedSum(po s3response.PutObjectInput, algo types.ChecksumAlgorithm) string {
	got, value := putHeaderChecksum(po)
	if got == algo {
		return value
	}
	return ""
}

func sumField(ch s3response.Checksum, algo types.ChecksumAlgorithm) *string {
	switch algo {
	case types.ChecksumAlgorithmCrc32:
		return ch.CRC32
	case types.ChecksumAlgorithmCrc32c:
		return ch.CRC32C
	case types.ChecksumAlgorithmSha1:
		return ch.SHA1
	case types.ChecksumAlgorithmSha256:
		return ch.SHA256
	case types.ChecksumAlgorithmCrc64nvme:
		return ch.CRC64NVME
	case types.ChecksumAlgorithmSha512:
		return ch.SHA512
	case types.ChecksumAlgorithmMd5:
		return ch.MD5
	case types.ChecksumAlgorithmXxhash64:
		return ch.XXHASH64
	case types.ChecksumAlgorithmXxhash3:
		return ch.XXHASH3
	case types.ChecksumAlgorithmXxhash128:
		return ch.XXHASH128
	default:
		return nil
	}
}

func itoa32(n int32) string {
	return fmt.Sprintf("%d", n)
}

func completedPartSum(algo types.ChecksumAlgorithm, part types.CompletedPart) string {
	switch algo {
	case types.ChecksumAlgorithmCrc32:
		return awsString(part.ChecksumCRC32)
	case types.ChecksumAlgorithmCrc32c:
		return awsString(part.ChecksumCRC32C)
	case types.ChecksumAlgorithmSha1:
		return awsString(part.ChecksumSHA1)
	case types.ChecksumAlgorithmSha256:
		return awsString(part.ChecksumSHA256)
	case types.ChecksumAlgorithmCrc64nvme:
		return awsString(part.ChecksumCRC64NVME)
	case types.ChecksumAlgorithmSha512:
		return awsString(part.ChecksumSHA512)
	case types.ChecksumAlgorithmMd5:
		return awsString(part.ChecksumMD5)
	case types.ChecksumAlgorithmXxhash64:
		return awsString(part.ChecksumXXHASH64)
	case types.ChecksumAlgorithmXxhash3:
		return awsString(part.ChecksumXXHASH3)
	case types.ChecksumAlgorithmXxhash128:
		return awsString(part.ChecksumXXHASH128)
	default:
		return ""
	}
}

func validatePartChecksum(checksum s3response.Checksum, part types.CompletedPart, uploadID string) error {
	n, argValue := numberOfChecksums(part)
	if n > 1 {
		return s3err.GetInvalidArgumentErr(s3err.InvalidArgChecksumPart, argValue)
	}
	if checksum.Algorithm == "" {
		if n != 0 {
			return s3err.GetInvalidPartErr(uploadID, *part.PartNumber, awsString(part.ETag))
		}
		return nil
	}
	algo := checksum.Algorithm
	if n == 0 {
		return s3err.APIError{
			Code:           "InvalidRequest",
			Description:    fmt.Sprintf("The upload was created using a %v checksum. The complete request must include the checksum for each part. It was missing for part %v in the request.", strings.ToLower(string(algo)), *part.PartNumber),
			HTTPStatusCode: http.StatusBadRequest,
		}
	}
	for _, cs := range []struct {
		got  *string
		want string
		algo types.ChecksumAlgorithm
	}{
		{part.ChecksumCRC32, awsString(checksum.CRC32), types.ChecksumAlgorithmCrc32},
		{part.ChecksumCRC32C, awsString(checksum.CRC32C), types.ChecksumAlgorithmCrc32c},
		{part.ChecksumSHA1, awsString(checksum.SHA1), types.ChecksumAlgorithmSha1},
		{part.ChecksumSHA256, awsString(checksum.SHA256), types.ChecksumAlgorithmSha256},
		{part.ChecksumCRC64NVME, awsString(checksum.CRC64NVME), types.ChecksumAlgorithmCrc64nvme},
		{part.ChecksumSHA512, awsString(checksum.SHA512), types.ChecksumAlgorithmSha512},
		{part.ChecksumMD5, awsString(checksum.MD5), types.ChecksumAlgorithmMd5},
		{part.ChecksumXXHASH64, awsString(checksum.XXHASH64), types.ChecksumAlgorithmXxhash64},
		{part.ChecksumXXHASH3, awsString(checksum.XXHASH3), types.ChecksumAlgorithmXxhash3},
		{part.ChecksumXXHASH128, awsString(checksum.XXHASH128), types.ChecksumAlgorithmXxhash128},
	} {
		if cs.got == nil {
			continue
		}
		if !utils.IsValidChecksum(*cs.got, cs.algo) {
			return s3err.GetInvalidArgumentErr(s3err.InvalidArgChecksumPart, *cs.got)
		}
		if *cs.got != cs.want {
			if algo == cs.algo {
				return s3err.GetInvalidPartErr(uploadID, *part.PartNumber, awsString(part.ETag))
			}
			return s3err.APIError{
				Code:           "BadDigest",
				Description:    fmt.Sprintf("The %v you specified for part %v did not match what we received.", strings.ToLower(string(cs.algo)), *part.PartNumber),
				HTTPStatusCode: http.StatusBadRequest,
			}
		}
	}
	return nil
}

func numberOfChecksums(part types.CompletedPart) (int, string) {
	counter := 0
	builder := &strings.Builder{}
	for _, ch := range []struct {
		algo  types.ChecksumAlgorithm
		value *string
	}{
		{types.ChecksumAlgorithmCrc32, part.ChecksumCRC32},
		{types.ChecksumAlgorithmCrc32c, part.ChecksumCRC32C},
		{types.ChecksumAlgorithmCrc64nvme, part.ChecksumCRC64NVME},
		{types.ChecksumAlgorithmSha1, part.ChecksumSHA1},
		{types.ChecksumAlgorithmSha256, part.ChecksumSHA256},
	} {
		if awsString(ch.value) != "" {
			counter++
			fmt.Fprintf(builder, "%s:%s;", string(ch.algo), awsString(ch.value))
		}
	}
	for _, value := range []*string{part.ChecksumSHA512, part.ChecksumMD5, part.ChecksumXXHASH64, part.ChecksumXXHASH3, part.ChecksumXXHASH128} {
		if awsString(value) != "" {
			counter++
		}
	}
	return counter, builder.String()
}
