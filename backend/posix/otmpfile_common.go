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
	"fmt"
	"math/rand"
	"os"
	"time"
)

func (tmp *tmpfile) Write(b []byte) (int, error) {
	if int64(len(b)) > tmp.size {
		return 0, fmt.Errorf("write exceeds content length %v", tmp.size)
	}

	n, err := tmp.f.Write(b)
	tmp.size -= int64(n)
	return n, err
}

func (tmp *tmpfile) File() *os.File {
	return tmp.f
}

func sleepWithJitter(backoffMs int) {
	if backoffMs <= 1 {
		time.Sleep(1 * time.Millisecond)
		return
	}

	maxJitter := max(1, backoffMs/4)
	jitter := rand.Intn((maxJitter*2)+1) - maxJitter
	sleepMs := max(backoffMs+jitter, 1)
	time.Sleep(time.Duration(sleepMs) * time.Millisecond)
}
