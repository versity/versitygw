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
	"hash/crc32"
	"hash/crc64"
	"testing"
)

func TestCRC32Combine(t *testing.T) {
	data := []byte("The quick brown fox jumps over the lazy dog")
	mid := len(data) / 2
	part1 := data[:mid]
	part2 := data[mid:]

	var poly uint32 = crc32.IEEE
	tab := crc32.MakeTable(poly)
	crc1 := crc32.Checksum(part1, tab)
	crc2 := crc32.Checksum(part2, tab)
	combined := crc32Combine(poly, crc1, crc2, int64(len(part2)))
	full := crc32.Checksum(data, tab)

	if combined != full {
		t.Errorf("crc32Combine failed: got %08x, want %08x", combined, full)
	}
}

func TestCRC64Combine(t *testing.T) {
	data := []byte("The quick brown fox jumps over the lazy dog")
	mid := len(data) / 2
	part1 := data[:mid]
	part2 := data[mid:]

	var poly uint64 = crc64NVME
	tab := crc64NVMETable
	crc1 := crc64.Checksum(part1, tab)
	crc2 := crc64.Checksum(part2, tab)
	combined := crc64Combine(poly, crc1, crc2, int64(len(part2)))
	full := crc64.Checksum(data, tab)

	if combined != full {
		t.Errorf("crc64Combine failed: got %016x, want %016x", combined, full)
	}
}
