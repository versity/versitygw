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

//go:build windows

package posix

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestReservedNameWithoutExtension checks that a device name without an
// extension is reserved on every version of Windows.
func TestReservedNameWithoutExtension(t *testing.T) {
	for _, name := range []string{"CON", "con", "nul ", "AUX", "PRN", "COM1", "lpt9", "COM\u00b9", "CONIN$", "conout$"} {
		if !isReservedName(name) {
			t.Errorf("%+q isn't reserved", name)
		}
	}
	for _, name := range []string{"CONSOLE", "COM0", "LPT", "a", "con\uf020"} {
		if isReservedName(name) {
			t.Errorf("%+q is reserved", name)
		}
	}
}

// TestEncodedNamesAreFiles checks that Windows stores a file under the name
// of every key, apart from the keys it would otherwise store it as.
func TestEncodedNamesAreFiles(t *testing.T) {
	dir := t.TempDir()
	keys := []string{
		"question?", "question", "a:b", "a", `back\slash`, "pipe|<>\"*", "tab\tchar",
		"trailingdot.", "trailingdot", "trailingspace ", "trailingspace",
		"CON", "nul.txt", "COM1", "LPT\u00b9", "CONIN$", "pua\uf03f", "pua?",
	}
	for _, key := range keys {
		name := filepath.Join(dir, encodeWindowsName(key, isReservedName))
		if err := os.WriteFile(name, []byte(key), 0644); err != nil {
			t.Fatalf("write %+q: %v", key, err)
		}
	}
	for _, key := range keys {
		data, err := os.ReadFile(filepath.Join(dir, encodeWindowsName(key, isReservedName)))
		if err != nil || string(data) != key {
			t.Errorf("read %+q: got %+q, %v", key, data, err)
		}
	}

	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, ent := range ents {
		got = append(got, decodeWindowsName(ent.Name()))
	}
	slices.Sort(got)
	slices.Sort(keys)
	if !slices.Equal(got, keys) {
		t.Errorf("read dir: got %+q, want %+q", got, keys)
	}
}
