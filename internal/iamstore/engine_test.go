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

package iamstore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type testConfig struct {
	Users map[string]string `json:"users"`
}

func TestEngineInitializesReadsParsesAndStoresJSON(t *testing.T) {
	dir := t.TempDir()

	engine, err := New(dir, "users.json", "users.json.backup", testConfig{Users: map[string]string{}}, func(conf *testConfig) {
		if conf.Users == nil {
			conf.Users = map[string]string{}
		}
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	conf, err := engine.GetIAM()
	if err != nil {
		t.Fatalf("GetIAM: %v", err)
	}
	if conf.Users == nil {
		t.Fatal("GetIAM returned nil Users map")
	}

	err = engine.StoreIAM(func(data []byte) ([]byte, error) {
		conf, err := engine.ParseIAM(data)
		if err != nil {
			return nil, err
		}
		conf.Users["alice"] = "created"
		return json.Marshal(conf)
	})
	if err != nil {
		t.Fatalf("StoreIAM: %v", err)
	}

	conf, err = engine.GetIAM()
	if err != nil {
		t.Fatalf("GetIAM after store: %v", err)
	}
	if conf.Users["alice"] != "created" {
		t.Fatalf("stored user = %q, want created", conf.Users["alice"])
	}

	if _, err := os.Stat(filepath.Join(dir, "users.json.backup")); err != nil {
		t.Fatalf("stat backup file: %v", err)
	}
}
