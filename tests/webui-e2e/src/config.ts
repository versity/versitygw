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

// Settings shared by the test environment and the tests.

import path from 'node:path';

/** The tests/webui-e2e directory. */
export const suiteDir = path.resolve(__dirname, '..');

/** The repository root, where the versitygw sources are. */
export const repoDir = path.resolve(suiteDir, '../..');

/** Where each versitygw process writes its log, one file per process. */
export const logDir = path.join(suiteDir, 'logs');

/**
 * The address every process listens on and every URL names: an IPv4
 * literal, not "localhost", so that the browser, the IAM service and the
 * tests reach the same address however the machine resolves names.
 */
export const host = '127.0.0.1';

export function localUrl(port: number, path = ''): string {
  return `http://${host}:${port}${path}`;
}

/** The root account of the IAM service and of every gateway. */
export const rootCredentials = {
  accessKeyId: 'admin',
  secretAccessKey: 'adminsecret',
} as const;

/** The account every IAM service resource lives in. */
export const accountId = '000000000000';

export const region = 'us-east-1';

/** The path every versitygw process answers health checks on. */
export const healthPath = '/healthz';
