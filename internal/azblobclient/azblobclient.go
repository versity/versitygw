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

// Package azblobclient creates Azure Blob Storage clients from the
// account, key, SAS token and endpoint options shared by the azure
// backend and the azure IAM service.
package azblobclient

import (
	"fmt"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
)

// Credentials describes how a client returned by New authenticates.
// Exactly one of SASToken, SharedKey and Default is set.
type Credentials struct {
	// ServiceURL is the blob service endpoint, defaulting to
	// https://<account>.blob.core.windows.net/ when none was provided.
	ServiceURL string
	SASToken   string
	SharedKey  *azblob.SharedKeyCredential
	Default    *azidentity.DefaultAzureCredential
}

// New returns a client for the blob service. A SAS token takes
// precedence, then an account name and key; with neither, the
// DefaultAzureCredential chain (environment, workload identity,
// managed identity, Azure CLI, ...) is used.
func New(accountName, accountKey, serviceURL, sasToken string) (*azblob.Client, Credentials, error) {
	url := serviceURL
	if serviceURL == "" && accountName != "" {
		// if not otherwise specified, use the typical form:
		// http(s)://<account>.blob.core.windows.net/
		url = fmt.Sprintf("https://%s.blob.core.windows.net/", accountName)
	}

	if sasToken != "" {
		client, err := azblob.NewClientWithNoCredential(url+"?"+sasToken, nil)
		if err != nil {
			return nil, Credentials{}, fmt.Errorf("init client: %w", err)
		}
		return client, Credentials{ServiceURL: url, SASToken: sasToken}, nil
	}

	if accountName == "" {
		// if account name not provided, try to get from env var
		// NOTE: AZURE_CLIENT_ID holds the client ID of an Entra ID
		// identity, not a storage account name. It is read by
		// DefaultAzureCredential on its own, and pairing it with an
		// account key below cannot produce a valid shared key.
		// Kept as is to preserve the azure backend behavior.
		accountName = os.Getenv("AZURE_CLIENT_ID")
	}

	if accountName == "" || accountKey == "" {
		cred, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return nil, Credentials{}, fmt.Errorf("init default credentials: %w", err)
		}
		client, err := azblob.NewClient(url, cred, nil)
		if err != nil {
			return nil, Credentials{}, fmt.Errorf("init client: %w", err)
		}
		return client, Credentials{ServiceURL: url, Default: cred}, nil
	}

	cred, err := azblob.NewSharedKeyCredential(accountName, accountKey)
	if err != nil {
		return nil, Credentials{}, fmt.Errorf("init credentials: %w", err)
	}

	client, err := azblob.NewClientWithSharedKeyCredential(url, cred, nil)
	if err != nil {
		return nil, Credentials{}, fmt.Errorf("init client: %w", err)
	}

	return client, Credentials{ServiceURL: url, SharedKey: cred}, nil
}
