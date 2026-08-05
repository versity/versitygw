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

import (
	"fmt"
	"strings"
	"sync/atomic"
)

// Level controls both whether the debug logger produces any output and,
// when it does, whether secrets and tokens embedded in that output are
// masked.
type Level int32

const (
	// LevelSilent prints no debug logs. This is the default.
	LevelSilent Level = iota
	// LevelDebug prints full request/response logs with secrets and
	// tokens (access keys, session tokens, signatures, ...) masked.
	LevelDebug
	// LevelUnsafe prints full request/response logs with secrets and
	// tokens shown in the clear. Anyone with access to this output can
	// read and replay credentials directly; never use in production.
	LevelUnsafe
)

func (l Level) String() string {
	switch l {
	case LevelSilent:
		return "silent"
	case LevelDebug:
		return "debug"
	case LevelUnsafe:
		return "unsafe"
	default:
		return "unknown"
	}
}

// ParseLevel parses "silent", "debug", or "unsafe" (case-insensitive) into
// a Level. An empty string parses as LevelSilent.
func ParseLevel(s string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "silent":
		return LevelSilent, nil
	case "debug":
		return LevelDebug, nil
	case "unsafe":
		return LevelUnsafe, nil
	default:
		return LevelSilent, fmt.Errorf("invalid log level %q: must be one of 'silent', 'debug', 'unsafe'", s)
	}
}

var currentLevel atomic.Int32

// SetLevel sets the active debug log level.
func SetLevel(l Level) {
	currentLevel.Store(int32(l))
}

// CurrentLevel returns the active debug log level.
func CurrentLevel() Level {
	return Level(currentLevel.Load())
}

// IsDebugEnabled returns true when the debug logger produces output, at
// either LevelDebug or LevelUnsafe.
func IsDebugEnabled() bool {
	return CurrentLevel() != LevelSilent
}

// IsUnsafeEnabled returns true when the debug logger is configured to print
// secrets and tokens without masking.
func IsUnsafeEnabled() bool {
	return CurrentLevel() == LevelUnsafe
}
