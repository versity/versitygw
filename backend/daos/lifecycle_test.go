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

package daos

import (
	"errors"
	"testing"
)

func TestInitRefPairsEachAttempt(t *testing.T) {
	var inits, finis, disconnects int
	a, err := acquireInit(func() error { inits++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	b, err := acquireInit(func() error { inits++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := a.release(func() error { disconnects++; return nil }, func() error { finis++; return nil }); err != nil {
		t.Fatal(err)
	}
	if inits != 2 || finis != 1 || disconnects != 1 || !b.held {
		t.Fatalf("inits %d finis %d disconnects %d held %v", inits, finis, disconnects, b.held)
	}
	if err := a.release(func() error { disconnects++; return nil }, func() error { finis++; return nil }); err != nil {
		t.Fatal(err)
	}
	if disconnects != 1 || finis != 1 {
		t.Fatalf("repeat disconnects %d finis %d", disconnects, finis)
	}
	if _, err := acquireInit(func() error { return errors.New("init") }); err == nil {
		t.Fatal("failed init owned a reference")
	}
	failed, err := acquireInit(func() error { inits++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	disconnectErr := errors.New("disconnect")
	finiErr := errors.New("fini")
	rel := failed.release(func() error { return disconnectErr }, func() error { finis++; return finiErr })
	if !errors.Is(rel, disconnectErr) || !errors.Is(rel, finiErr) {
		t.Fatal(rel)
	}
	if !b.held || finis != 2 {
		t.Fatalf("other held %v finis %d", b.held, finis)
	}
}
