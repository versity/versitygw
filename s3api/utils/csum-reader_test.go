// Copyright 2025 Versity Software
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
	"hash/crc32"
	"hash/crc64"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func TestAddCRCChecksum_CRC32(t *testing.T) {
	data := []byte("this is a test buffer for crc32")
	mid := len(data) / 2
	part1 := data[:mid]
	part2 := data[mid:]

	crc1 := crc32.Checksum(part1, crc32.IEEETable)
	crc2 := crc32.Checksum(part2, crc32.IEEETable)
	crcFull := crc32.Checksum(data, crc32.IEEETable)

	crc1b := []byte{byte(crc1 >> 24), byte(crc1 >> 16), byte(crc1 >> 8), byte(crc1)}
	crc2b := []byte{byte(crc2 >> 24), byte(crc2 >> 16), byte(crc2 >> 8), byte(crc2)}
	crc1b64 := base64.StdEncoding.EncodeToString(crc1b)
	crc2b64 := base64.StdEncoding.EncodeToString(crc2b)

	combined, err := AddCRCChecksum(types.ChecksumAlgorithmCrc32, crc1b64, crc2b64, int64(len(part2)))
	if err != nil {
		t.Fatalf("AddCRCChecksum failed: %v", err)
	}
	combinedBytes, err := base64.StdEncoding.DecodeString(combined)
	if err != nil {
		t.Fatalf("base64 decode failed: %v", err)
	}
	combinedVal := uint32(combinedBytes[0])<<24 | uint32(combinedBytes[1])<<16 | uint32(combinedBytes[2])<<8 | uint32(combinedBytes[3])
	if combinedVal != crcFull {
		t.Errorf("CRC32 combine mismatch: got %x, want %x", combinedVal, crcFull)
	}
}

func TestAddCRCChecksum_CRC32c(t *testing.T) {
	data := []byte("this is a test buffer for crc32c")
	mid := len(data) / 2
	part1 := data[:mid]
	part2 := data[mid:]

	castagnoli := crc32.MakeTable(crc32.Castagnoli)
	crc1 := crc32.Checksum(part1, castagnoli)
	crc2 := crc32.Checksum(part2, castagnoli)
	crcFull := crc32.Checksum(data, castagnoli)

	crc1b := []byte{byte(crc1 >> 24), byte(crc1 >> 16), byte(crc1 >> 8), byte(crc1)}
	crc2b := []byte{byte(crc2 >> 24), byte(crc2 >> 16), byte(crc2 >> 8), byte(crc2)}
	crc1b64 := base64.StdEncoding.EncodeToString(crc1b)
	crc2b64 := base64.StdEncoding.EncodeToString(crc2b)

	combined, err := AddCRCChecksum(types.ChecksumAlgorithmCrc32c, crc1b64, crc2b64, int64(len(part2)))
	if err != nil {
		t.Fatalf("AddCRCChecksum failed: %v", err)
	}
	combinedBytes, err := base64.StdEncoding.DecodeString(combined)
	if err != nil {
		t.Fatalf("base64 decode failed: %v", err)
	}
	combinedVal := uint32(combinedBytes[0])<<24 | uint32(combinedBytes[1])<<16 | uint32(combinedBytes[2])<<8 | uint32(combinedBytes[3])
	if combinedVal != crcFull {
		t.Errorf("CRC32c combine mismatch: got %x, want %x", combinedVal, crcFull)
	}
}

func TestAddCRCChecksum_CRC64NVME(t *testing.T) {
	data := []byte("this is a test buffer for crc64nvme")
	mid := len(data) / 2
	part1 := data[:mid]
	part2 := data[mid:]

	table := crc64NVMETable
	crc1 := crc64.Checksum(part1, table)
	crc2 := crc64.Checksum(part2, table)
	crcFull := crc64.Checksum(data, table)

	crc1b := []byte{
		byte(crc1 >> 56), byte(crc1 >> 48), byte(crc1 >> 40), byte(crc1 >> 32),
		byte(crc1 >> 24), byte(crc1 >> 16), byte(crc1 >> 8), byte(crc1),
	}
	crc2b := []byte{
		byte(crc2 >> 56), byte(crc2 >> 48), byte(crc2 >> 40), byte(crc2 >> 32),
		byte(crc2 >> 24), byte(crc2 >> 16), byte(crc2 >> 8), byte(crc2),
	}
	crc1b64 := base64.StdEncoding.EncodeToString(crc1b)
	crc2b64 := base64.StdEncoding.EncodeToString(crc2b)

	combined, err := AddCRCChecksum(types.ChecksumAlgorithmCrc64nvme, crc1b64, crc2b64, int64(len(part2)))
	if err != nil {
		t.Fatalf("AddCRCChecksum failed: %v", err)
	}
	combinedBytes, err := base64.StdEncoding.DecodeString(combined)
	if err != nil {
		t.Fatalf("base64 decode failed: %v", err)
	}
	combinedVal := uint64(combinedBytes[0])<<56 | uint64(combinedBytes[1])<<48 | uint64(combinedBytes[2])<<40 | uint64(combinedBytes[3])<<32 |
		uint64(combinedBytes[4])<<24 | uint64(combinedBytes[5])<<16 | uint64(combinedBytes[6])<<8 | uint64(combinedBytes[7])
	if combinedVal != crcFull {
		t.Errorf("CRC64NVME combine mismatch: got %x, want %x", combinedVal, crcFull)
	}
}
