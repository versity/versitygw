// Copyright (C) 1995-2017 Jean-loup Gailly and Mark Adler
//
// This software is provided 'as-is', without any express or implied
// warranty.  In no event will the authors be held liable for any damages
// arising from the use of this software.
//
// Permission is granted to anyone to use this software for any purpose,
// including commercial applications, and to alter it and redistribute it
// freely, subject to the following restrictions:
//
// 1. The origin of this software must not be misrepresented; you must not
//    claim that you wrote the original software. If you use this software
//    in a product, an acknowledgment in the product documentation would be
//    appreciated but is not required.
// 2. Altered source versions must be plainly marked as such, and must not be
//    misrepresented as being the original software.
// 3. This notice may not be removed or altered from any source distribution.
//
// Jean-loup Gailly        Mark Adler
// jloup@gzip.org          madler@alumni.caltech.edu

// Original implementation is from
// https://github.com/vimeo/go-util/blob/8cd4c737f091d9317f72b25df78ce6cf869f7d30/crc32combine/crc32combine.go
// extended for crc64 support.

// Following is ported from C to Go in 2016 by Justin Ruggles, with minimal alteration.
// Used uint for unsigned long. Used uint32 for input arguments in order to match
// the Go hash/crc32 package. zlib CRC32 combine (https://github.com/madler/zlib)

package utils

import (
	"hash/crc64"
)

const crc64NVME = 0x9a6c_9329_ac4b_c9b5

var crc64NVMETable = crc64.MakeTable(crc64NVME)

func gf2MatrixTimes(mat []uint64, vec uint64) uint64 {
	var sum uint64

	for vec != 0 {
		if vec&1 != 0 {
			sum ^= mat[0]
		}
		vec >>= 1
		mat = mat[1:]
	}
	return sum
}

func gf2MatrixSquare(square, mat []uint64) {
	if len(square) != len(mat) {
		panic("square matrix size mismatch")
	}
	for n := range mat {
		square[n] = gf2MatrixTimes(mat, mat[n])
	}
}

// crc32Combine returns the combined CRC-32 hash value of the two passed CRC-32
// hash values crc1 and crc2. poly represents the generator polynomial
// and len2 specifies the byte length that the crc2 hash covers.
func crc32Combine(poly uint32, crc1, crc2 uint32, len2 int64) uint32 {
	// degenerate case (also disallow negative lengths)
	if len2 <= 0 {
		return crc1
	}

	even := make([]uint64, 32) // even-power-of-two zeros operator
	odd := make([]uint64, 32)  // odd-power-of-two zeros operator

	// put operator for one zero bit in odd
	odd[0] = uint64(poly) // CRC-32 polynomial
	row := uint64(1)
	for n := 1; n < 32; n++ {
		odd[n] = row
		row <<= 1
	}

	// put operator for two zero bits in even
	gf2MatrixSquare(even, odd)

	// put operator for four zero bits in odd
	gf2MatrixSquare(odd, even)

	// apply len2 zeros to crc1 (first square will put the operator for one
	// zero byte, eight zero bits, in even)
	crc1n := uint64(crc1)
	for {
		// apply zeros operator for this bit of len2
		gf2MatrixSquare(even, odd)
		if len2&1 != 0 {
			crc1n = gf2MatrixTimes(even, crc1n)
		}
		len2 >>= 1

		// if no more bits set, then done
		if len2 == 0 {
			break
		}

		// another iteration of the loop with odd and even swapped
		gf2MatrixSquare(odd, even)
		if len2&1 != 0 {
			crc1n = gf2MatrixTimes(odd, crc1n)
		}
		len2 >>= 1

		// if no more bits set, then done
		if len2 == 0 {
			break
		}
	}

	// return combined crc
	crc1n ^= uint64(crc2)
	return uint32(crc1n)
}

// crc64Combine returns the combined CRC-64 hash value of the two passed CRC-64
// hash values crc1 and crc2. poly represents the generator polynomial
// and len2 specifies the byte length that the crc2 hash covers.
func crc64Combine(poly uint64, crc1, crc2 uint64, len2 int64) uint64 {
	// degenerate case (also disallow negative lengths)
	if len2 <= 0 {
		return crc1
	}

	even := make([]uint64, 64) // even-power-of-two zeros operator
	odd := make([]uint64, 64)  // odd-power-of-two zeros operator

	// put operator for one zero bit in odd
	odd[0] = poly // CRC-64 polynomial
	row := uint64(1)
	for n := 1; n < 64; n++ {
		odd[n] = row
		row <<= 1
	}

	// put operator for two zero bits in even
	gf2MatrixSquare(even, odd)

	// put operator for four zero bits in odd
	gf2MatrixSquare(odd, even)

	// apply len2 zeros to crc1 (first square will put the operator for one
	// zero byte, eight zero bits, in even)
	crc1n := crc1
	for {
		// apply zeros operator for this bit of len2
		gf2MatrixSquare(even, odd)
		if len2&1 != 0 {
			crc1n = gf2MatrixTimes(even, crc1n)
		}
		len2 >>= 1

		// if no more bits set, then done
		if len2 == 0 {
			break
		}

		// another iteration of the loop with odd and even swapped
		gf2MatrixSquare(odd, even)
		if len2&1 != 0 {
			crc1n = gf2MatrixTimes(odd, crc1n)
		}
		len2 >>= 1

		// if no more bits set, then done
		if len2 == 0 {
			break
		}
	}

	// return combined crc
	crc1n ^= crc2
	return crc1n
}
