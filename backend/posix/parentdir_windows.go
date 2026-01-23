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
	"syscall"

	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

func handleParentDirError(name string) (s3response.PutObjectOutput, error) {
	dir := filepath.Dir(name)
	d, statErr := os.Stat(dir)
	if statErr == nil && !d.IsDir() {
		return s3response.PutObjectOutput{}, s3err.GetAPIError(s3err.ErrObjectParentIsFile)
	}
	// Parent doesn't exist or is a directory, treat as ENOENT
	return s3response.PutObjectOutput{}, syscall.ENOENT
}
