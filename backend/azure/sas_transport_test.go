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

package azure

import (
	"context"
	"net"
	"strings"
	"testing"
)

// TestPerClientTransportErrorsOmitSAS reproduces a transport failure of the
// per-container and per-blob clients built with a SAS token. The error must
// keep the request path and drop the query, which holds the token.
func TestPerClientTransportErrorsOmitSAS(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "http://" + l.Addr().String() + "/acct"
	l.Close()

	const sig = "SECRETSIGNATURE"
	az, err := newAzure("", "", endpoint, "sv=2024-01-01&sig="+sig, 0, "")
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	checks := []struct {
		name string
		call func() error
	}{
		{
			name: "container",
			call: func() error {
				c, err := az.getContainerClient("testbucket")
				if err != nil {
					return err
				}
				_, err = c.GetProperties(ctx, nil)
				return err
			},
		},
		{
			name: "blob",
			call: func() error {
				c, err := az.getBlobClient("testbucket", "k")
				if err != nil {
					return err
				}
				_, err = c.GetProperties(ctx, nil)
				return err
			},
		},
		{
			name: "blockblob",
			call: func() error {
				c, err := az.getBlockBlobClient("testbucket", "k")
				if err != nil {
					return err
				}
				_, err = c.GetProperties(ctx, nil)
				return err
			},
		},
	}

	for _, tt := range checks {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.call()
			if err == nil {
				t.Fatal("expected a transport error")
			}
			msg := err.Error()
			if strings.Contains(msg, sig) || strings.Contains(msg, "sig=") {
				t.Fatalf("SAS query leaked in transport error: %s", msg)
			}
			if !strings.Contains(msg, "/acct/testbucket") {
				t.Fatalf("transport error lost the request path: %s", msg)
			}
		})
	}
}
