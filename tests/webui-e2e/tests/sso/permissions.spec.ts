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

// A single sign-on session can do what its role allows, and no more.

import { helloObject, seedBucket } from '../../src/data/buckets';
import { users } from '../../src/data/users';
import { expect, test } from '../../src/fixtures/sso';
import type { UploadFile } from '../../src/pages/explorer-page';

const file: UploadFile = { name: 'notes.txt', mimeType: 'text/plain', buffer: Buffer.from('uploaded with SSO\n') };

test('the admin role uploads', async ({ signInWithSSO, explorer, app, keyPrefix }) => {
  await signInWithSSO(users.alice);
  await explorer.openBucket(seedBucket.name, keyPrefix);
  await explorer.upload([file]);

  await expect(app.toasts).toContainText('Uploaded 1 file');
  await expect(explorer.objectRow(file.name)).toBeVisible();
});

test('the read-only role lists but cannot upload', async ({ signInWithSSO, explorer, app, keyPrefix }) => {
  await signInWithSSO(users.bob);
  await explorer.openBucket(seedBucket.name);
  await expect(explorer.objectRow(helloObject.key)).toBeVisible();

  await explorer.openBucket(seedBucket.name, keyPrefix);
  await explorer.upload([file]);

  await expect(app.toasts).toContainText(`Failed to upload ${file.name}`);
  await expect(explorer.objectRow(file.name)).toHaveCount(0);
});
