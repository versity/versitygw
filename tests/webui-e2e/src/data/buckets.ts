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

// Buckets the environment creates on every gateway before the tests run.
// Tests may add objects to them under keys of their own; they must not
// change or delete what is listed here.

export interface SeedObject {
  readonly key: string;
  readonly body: string;
}

export interface SeedBucket {
  readonly name: string;
  readonly objects: readonly SeedObject[];
}

export const helloObject = {
  key: 'hello.txt',
  body: 'hello from versitygw\n',
} as const satisfies SeedObject;

export const seedBucket = {
  name: 'webui-e2e',
  objects: [helloObject],
} as const satisfies SeedBucket;
