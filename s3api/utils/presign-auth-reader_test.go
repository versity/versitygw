// Copyright 2023 Versity Software
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

package utils

import (
	"testing"
	"time"

	"github.com/versity/versitygw/s3err"
)

func Test_validateExpiration(t *testing.T) {
	type args struct {
		str  string
		date time.Time
	}
	tests := []struct {
		name string
		args args
		err  error
	}{
		{
			name: "empty-expiration",
			args: args{
				str:  "",
				date: time.Now(),
			},
			err: s3err.GetAPIError(s3err.ErrInvalidQueryParams),
		},
		{
			name: "invalid-expiration",
			args: args{
				str:  "invalid_expiration",
				date: time.Now(),
			},
			err: s3err.GetAPIError(s3err.ErrMalformedExpires),
		},
		{
			name: "negative-expiration",
			args: args{
				str:  "-320",
				date: time.Now(),
			},
			err: s3err.GetAPIError(s3err.ErrNegativeExpires),
		},
		{
			name: "exceeding-expiration",
			args: args{
				str:  "6048000",
				date: time.Now(),
			},
			err: s3err.GetAPIError(s3err.ErrMaximumExpires),
		},
		{
			name: "expired value",
			args: args{
				str:  "200",
				date: time.Now().AddDate(0, 0, -1),
			},
			err: s3err.GetAPIError(s3err.ErrExpiredPresignRequest),
		},
		{
			name: "valid expiration",
			args: args{
				str:  "300",
				date: time.Now(),
			},
			err: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateExpiration(tt.args.str, tt.args.date)
			// Check for nil case
			if tt.err == nil && err != nil {
				t.Errorf("Expected nil error, got: %v", err)
				return
			} else if tt.err == nil && err == nil {
				// Both are nil, no need for further comparison
				return
			}

			if err.Error() != tt.err.Error() {
				t.Errorf("Expected error: %v, got: %v", tt.err, err)
			}
		})
	}
}
