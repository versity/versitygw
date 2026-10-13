// Copyright 2026 Versity Software
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

package posix

import (
	"io/fs"
	"os"
	"slices"
	"strings"
	"unicode/utf8"
)

// An object is stored at the path of its key relative to the bucket
// directory, one path element per "/" separated key segment. Windows can't
// name a file after every key segment: the characters " * : < > ? \ | and
// the control characters U+0001-U+001F are invalid, a trailing dot or space
// is stripped, and a device name such as CON or NUL opens the device. With
// encodeKeys, the characters that make a segment such a name are stored as
// the private use character U+F000 plus the character code, the convention
// Cygwin and WSL use for the invalid characters: every invalid character,
// the trailing dot or space, and the first letter of a device name. A private
// use character U+F000-U+F07F of the key is stored after U+F000, so that a
// stored name is the name of one key only.
const (
	// nameEscape is stored before a key character in the range of the
	// characters that stand for other characters.
	nameEscape = '\uf000'
	// nameLast is the last character that stands for another character.
	nameLast = '\uf07f'
)

// encodeKey returns the path, relative to the bucket directory, that the
// object key is stored at.
func (p *Posix) encodeKey(key string) string {
	if !p.encodeKeys {
		return key
	}
	return encodeWindowsName(key, isReservedName)
}

// decodeKey returns the object key stored at name, a path relative to the
// bucket directory.
func (p *Posix) decodeKey(name string) string {
	if !p.encodeKeys {
		return name
	}
	return decodeWindowsName(name)
}

// bucketFS returns the file system of the bucket directory with the entries
// named after the keys they store.
func (p *Posix) bucketFS(bucket string) fs.FS {
	fsys := os.DirFS(p.BucketPath(bucket))
	if !p.encodeKeys {
		return fsys
	}
	return windowsNameFS{fsys: fsys, isReserved: isReservedName}
}

// encodeWindowsName returns the name key is stored under on Windows.
// isReserved reports whether a path element is a device name.
func encodeWindowsName(key string, isReserved func(string) bool) string {
	segs := strings.Split(key, "/")
	changed := false
	for i, seg := range segs {
		if enc := encodeWindowsSegment(seg, isReserved); enc != seg {
			segs[i] = enc
			changed = true
		}
	}
	if !changed {
		return key
	}
	return strings.Join(segs, "/")
}

func encodeWindowsSegment(seg string, isReserved func(string) bool) string {
	// these path elements are resolved like on any other platform
	if seg == "" || seg == "." || seg == ".." {
		return seg
	}

	b := make([]byte, 0, len(seg))
	for i := 0; i < len(seg); {
		r, size := utf8.DecodeRuneInString(seg[i:])
		switch {
		case isInvalidWindowsChar(r):
			b = utf8.AppendRune(b, nameEscape+r)
		case nameEscape <= r && r <= nameLast:
			b = utf8.AppendRune(b, nameEscape)
			b = append(b, seg[i:i+size]...)
		default:
			b = append(b, seg[i:i+size]...)
		}
		i += size
	}

	if c := b[len(b)-1]; c == '.' || c == ' ' {
		b = utf8.AppendRune(b[:len(b)-1], nameEscape+rune(c))
	}

	name := string(b)
	// device names start with an ASCII letter
	if name[0] < utf8.RuneSelf && isReserved(name) {
		name = string(nameEscape+rune(name[0])) + name[1:]
	}
	return name
}

func isInvalidWindowsChar(r rune) bool {
	switch r {
	case '"', '*', ':', '<', '>', '?', '\\', '|':
		return true
	}
	return 0 < r && r < ' '
}

// isDOSDeviceName reports whether the path element name, which has no path
// separator or colon, is a device name on Windows 10: a device name followed
// by nothing, by spaces or by an extension. Windows 11 no longer treats a
// device name with an extension as a device.
func isDOSDeviceName(name string) bool {
	base, _, _ := strings.Cut(name, ".")
	base = strings.TrimRight(base, " ")
	switch strings.ToUpper(base) {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return true
	}
	if len(base) < 4 {
		return false
	}
	switch strings.ToUpper(base[:3]) {
	case "COM", "LPT":
		switch base[3:] {
		case "1", "2", "3", "4", "5", "6", "7", "8", "9", "\u00b9", "\u00b2", "\u00b3":
			return true
		}
	}
	return false
}

// decodeWindowsName returns the key stored under name on Windows.
func decodeWindowsName(name string) string {
	var b []byte
	for i := 0; i < len(name); {
		r, size := utf8.DecodeRuneInString(name[i:])
		if r < nameEscape || r > nameLast {
			if b != nil {
				b = append(b, name[i:i+size]...)
			}
			i += size
			continue
		}
		if b == nil {
			b = append(make([]byte, 0, len(name)), name[:i]...)
		}
		if r == nameEscape && i+size < len(name) {
			_, next := utf8.DecodeRuneInString(name[i+size:])
			b = append(b, name[i+size:i+size+next]...)
			i += size + next
			continue
		}
		if r == nameEscape {
			b = append(b, name[i:i+size]...)
		} else {
			b = append(b, byte(r-nameEscape))
		}
		i += size
	}
	if b == nil {
		return name
	}
	return string(b)
}

// windowsNameFS presents the files of fsys, a bucket directory, under the
// keys they're stored at by encodeWindowsName, in the byte order of the keys.
// Entries whose names no key is stored under are left out: the files a key
// can't be read from aren't listed.
type windowsNameFS struct {
	fsys       fs.FS
	isReserved func(string) bool
}

func (w windowsNameFS) Open(name string) (fs.File, error) {
	return w.fsys.Open(encodeWindowsName(name, w.isReserved))
}

func (w windowsNameFS) Stat(name string) (fs.FileInfo, error) {
	return fs.Stat(w.fsys, encodeWindowsName(name, w.isReserved))
}

func (w windowsNameFS) ReadDir(name string) ([]fs.DirEntry, error) {
	ents, err := fs.ReadDir(w.fsys, encodeWindowsName(name, w.isReserved))
	keyEnts := make([]fs.DirEntry, 0, len(ents))
	for _, ent := range ents {
		key := decodeWindowsName(ent.Name())
		if encodeWindowsName(key, w.isReserved) != ent.Name() {
			continue
		}
		keyEnts = append(keyEnts, keyDirEntry{DirEntry: ent, key: key})
	}
	slices.SortFunc(keyEnts, func(a, b fs.DirEntry) int {
		return strings.Compare(a.Name(), b.Name())
	})
	return keyEnts, err
}

// keyDirEntry is a directory entry named after the key segment it stores.
type keyDirEntry struct {
	fs.DirEntry
	key string
}

func (e keyDirEntry) Name() string { return e.key }
