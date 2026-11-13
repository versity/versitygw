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

import type { Locator, Page } from '@playwright/test';

export interface UploadFile {
  name: string;
  mimeType: string;
  buffer: Buffer;
}

/** The object browser (explorer.html). */
export class ExplorerPage {
  readonly uploadButton: Locator;
  /** The listed objects of the open bucket and prefix; folders aside. */
  readonly objectRows: Locator;

  constructor(
    private readonly page: Page,
    private readonly webuiUrl: string,
  ) {
    this.uploadButton = page.locator('#upload-btn');
    this.objectRows = page.locator('#objects-table tr.file-row');
  }

  /** Opens a bucket, at a prefix ending in "/" if given. */
  async openBucket(bucket: string, prefix = ''): Promise<void> {
    await this.page.goto(this.url(bucket, prefix));
  }

  /** The address openBucket opens. */
  url(bucket: string, prefix = ''): string {
    return new URL(`explorer.html#${bucket}/${prefix}`, this.webuiUrl).href;
  }

  /** The row of an object in the listing, by its name under the prefix. */
  objectRow(name: string): Locator {
    return this.objectRows.filter({ has: this.page.getByText(name, { exact: true }) });
  }

  /** Uploads files to the open bucket and prefix through the file chooser. */
  async upload(files: UploadFile[]): Promise<void> {
    const fileChooser = this.page.waitForEvent('filechooser');
    await this.uploadButton.click();
    await (await fileChooser).setFiles(files);
  }
}
