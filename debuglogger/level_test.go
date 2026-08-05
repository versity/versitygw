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

package debuglogger

import "testing"

func TestParseLevel(t *testing.T) {
	tests := []struct {
		in      string
		want    Level
		wantErr bool
	}{
		{"silent", LevelSilent, false},
		{"", LevelSilent, false},
		{"SILENT", LevelSilent, false},
		{"debug", LevelDebug, false},
		{" Debug ", LevelDebug, false},
		{"unsafe", LevelUnsafe, false},
		{"UNSAFE", LevelUnsafe, false},
		{"verbose", LevelSilent, true},
		{"true", LevelSilent, true},
	}
	for _, tt := range tests {
		got, err := ParseLevel(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseLevel(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if err == nil && got != tt.want {
			t.Errorf("ParseLevel(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestLevelGatesDebugAndUnsafe(t *testing.T) {
	defer SetLevel(LevelSilent)

	SetLevel(LevelSilent)
	if IsDebugEnabled() {
		t.Error("IsDebugEnabled() at LevelSilent = true, want false")
	}
	if IsUnsafeEnabled() {
		t.Error("IsUnsafeEnabled() at LevelSilent = true, want false")
	}

	SetLevel(LevelDebug)
	if !IsDebugEnabled() {
		t.Error("IsDebugEnabled() at LevelDebug = false, want true")
	}
	if IsUnsafeEnabled() {
		t.Error("IsUnsafeEnabled() at LevelDebug = true, want false")
	}

	SetLevel(LevelUnsafe)
	if !IsDebugEnabled() {
		t.Error("IsDebugEnabled() at LevelUnsafe = false, want true")
	}
	if !IsUnsafeEnabled() {
		t.Error("IsUnsafeEnabled() at LevelUnsafe = false, want true")
	}
}

func TestIsIAMDebugEnabledRequiresBothLevelAndIAMFlag(t *testing.T) {
	defer func() {
		SetLevel(LevelSilent)
		debugIAMEnabled.Store(false)
	}()

	SetLevel(LevelSilent)
	debugIAMEnabled.Store(true)
	if IsIAMDebugEnabled() {
		t.Error("IsIAMDebugEnabled() with iam-debug set but level silent = true, want false")
	}

	SetLevel(LevelDebug)
	debugIAMEnabled.Store(false)
	if IsIAMDebugEnabled() {
		t.Error("IsIAMDebugEnabled() with level debug but iam-debug unset = true, want false")
	}

	debugIAMEnabled.Store(true)
	if !IsIAMDebugEnabled() {
		t.Error("IsIAMDebugEnabled() with level debug and iam-debug set = false, want true")
	}
}
