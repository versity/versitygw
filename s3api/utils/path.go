// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// code modified from golang std library src/internal/filepathlite/path.go
// to support path separator '/' for all platforms.
package utils

import (
	"strings"
)

const separator = '/'

// isObjectLocal checks if the given path would result in an object
// that is local to the bucket.
func isObjectLocal(path string) bool {
	if path == "" || path == "." {
		return true
	}

	path = strings.Join([]string{".", path}, string(separator))

	hasDots := false
	for p := path; p != ""; {
		var part string
		part, p, _ = strings.Cut(p, "/")
		if part == "." || part == ".." {
			hasDots = true
			break
		}
	}
	if hasDots {
		path = clean(path)
	}
	if path == ".." || strings.HasPrefix(path, "../") {
		return false
	}
	return true
}

func clean(path string) string {
	originalPath := path
	if path == "" {
		return originalPath + "."
	}
	rooted := isPathSeparator(path[0])

	// Invariants:
	//	reading from path; r is index of next byte to process.
	//	writing to buf; w is index of next byte to write.
	//	dotdot is index in buf where .. must stop, either because
	//		it is the leading slash or it is a leading ../../.. prefix.
	n := len(path)
	out := lazybuf{path: path, volAndPath: originalPath, volLen: 0}
	r, dotdot := 0, 0
	if rooted {
		out.append(separator)
		r, dotdot = 1, 1
	}

	for r < n {
		switch {
		case isPathSeparator(path[r]):
			// empty path element
			r++
		case path[r] == '.' && (r+1 == n || isPathSeparator(path[r+1])):
			// . element
			r++
		case path[r] == '.' && path[r+1] == '.' && (r+2 == n || isPathSeparator(path[r+2])):
			// .. element: remove to last separator
			r += 2
			switch {
			case out.w > dotdot:
				// can backtrack
				out.w--
				for out.w > dotdot && !isPathSeparator(out.index(out.w)) {
					out.w--
				}
			case !rooted:
				// cannot backtrack, but not rooted, so append .. element.
				if out.w > 0 {
					out.append(separator)
				}
				out.append('.')
				out.append('.')
				dotdot = out.w
			}
		default:
			// real path element.
			// add slash if needed
			if rooted && out.w != 1 || !rooted && out.w != 0 {
				out.append(separator)
			}
			// copy element
			for ; r < n && !isPathSeparator(path[r]); r++ {
				out.append(path[r])
			}
		}
	}

	// Turn empty string into "."
	if out.w == 0 {
		out.append('.')
	}

	return FromSlash(out.string())
}

func isPathSeparator(c uint8) bool {
	return c == '/'
}

func FromSlash(path string) string {
	if separator == '/' {
		return path
	}
	return replaceStringByte(path, '/', separator)
}

func replaceStringByte(s string, old, new byte) string {
	if strings.IndexByte(s, old) == -1 {
		return s
	}
	n := []byte(s)
	for i := range n {
		if n[i] == old {
			n[i] = new
		}
	}
	return string(n)
}

// A lazybuf is a lazily constructed path buffer.
// It supports append, reading previously appended bytes,
// and retrieving the final string. It does not allocate a buffer
// to hold the output until that output diverges from s.
type lazybuf struct {
	path       string
	buf        []byte
	w          int
	volAndPath string
	volLen     int
}

func (b *lazybuf) index(i int) byte {
	if b.buf != nil {
		return b.buf[i]
	}
	return b.path[i]
}

func (b *lazybuf) append(c byte) {
	if b.buf == nil {
		if b.w < len(b.path) && b.path[b.w] == c {
			b.w++
			return
		}
		b.buf = make([]byte, len(b.path))
		copy(b.buf, b.path[:b.w])
	}
	b.buf[b.w] = c
	b.w++
}

func (b *lazybuf) string() string {
	if b.buf == nil {
		return b.volAndPath[:b.volLen+b.w]
	}
	return b.volAndPath[:b.volLen] + string(b.buf[:b.w])
}
