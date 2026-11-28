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

// AWS SDK clients signed as the root account, for setting up and checking
// state behind the WebUI's back.

import { IAMClient } from '@aws-sdk/client-iam';
import { S3Client } from '@aws-sdk/client-s3';
import { region, rootCredentials } from '../config';

export function rootIamClient(endpoint: string): IAMClient {
  return new IAMClient({ endpoint, region, credentials: rootCredentials });
}

export function rootS3Client(endpoint: string): S3Client {
  return new S3Client({ endpoint, region, credentials: rootCredentials, forcePathStyle: true });
}
