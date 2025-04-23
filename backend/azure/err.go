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

package azure

import (
	"errors"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/versity/versitygw/s3err"
)

// Parses azure ResponseError into AWS APIError
func azureErrToS3Err(apiErr error) error {
	var azErr *azcore.ResponseError
	if !errors.As(apiErr, &azErr) {
		return apiErr
	}

	return azErrToS3err(azErr)
}

func azErrToS3err(azErr *azcore.ResponseError) s3err.APIError {
	switch azErr.ErrorCode {
	case "ContainerAlreadyExists":
		return s3err.GetAPIError(s3err.ErrBucketAlreadyExists)
	case "InvalidResourceName", "ContainerNotFound":
		return s3err.GetAPIError(s3err.ErrNoSuchBucket)
	case "BlobNotFound":
		return s3err.GetAPIError(s3err.ErrNoSuchKey)
	case "TagsTooLarge":
		return s3err.GetAPIError(s3err.ErrInvalidTagValue)
	case "Requested Range Not Satisfiable":
		return s3err.GetAPIError(s3err.ErrInvalidRange)
	}
	return s3err.APIError{
		Code:           azErr.ErrorCode,
		Description:    azErr.RawResponse.Status,
		HTTPStatusCode: azErr.StatusCode,
	}
}

func parseMpError(mpErr error) error {
	err := azureErrToS3Err(mpErr)

	serr, ok := err.(s3err.APIError)
	if !ok || serr.Code != "NoSuchKey" {
		return mpErr
	}

	return s3err.GetAPIError(s3err.ErrNoSuchUpload)
}
