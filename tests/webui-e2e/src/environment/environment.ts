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

// Brings up the system under test: the versitygw processes of the
// topology, provisioned with what the tests expect. The identity providers
// run separately, in Docker.

import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { healthPath, logDir } from '../config';
import { discoveryUrl, type IdentityProvider } from '../idp/identity-provider';
import { allGateways, allIdentityProviders, iamService } from '../topology';
import { ServiceGroup } from './process';
import { provision } from './provision';
import { gatewayArgs, iamServiceArgs, versitygwBinary } from './versitygw';
import { respondsOk } from './wait';

/** Stops what startEnvironment started and deletes its data. */
export type StopEnvironment = () => Promise<void>;

export async function startEnvironment(): Promise<StopEnvironment> {
  await checkIdentityProviders(allIdentityProviders);
  await rm(logDir, { recursive: true, force: true });
  await mkdir(logDir, { recursive: true });
  // Short, because a unix socket path may not be longer than about 100 bytes.
  const workDir = await mkdtemp(path.join(os.tmpdir(), 'vgw-e2e-'));

  const services = new ServiceGroup();
  const stop: StopEnvironment = async () => {
    await services.stopAll();
    await rm(workDir, { recursive: true, force: true });
  };

  try {
    const binary = await versitygwBinary(workDir);
    const iamPrivateSocket = path.join(workDir, 'iam.sock');

    await services.start({
      name: 'IAM service',
      command: binary,
      args: iamServiceArgs({
        service: iamService,
        dataDir: await makeDir(workDir, 'iam'),
        privateSocket: iamPrivateSocket,
      }),
      logFile: path.join(logDir, 'iam.log'),
      readyUrls: [healthUrl(iamService.url)],
    });

    for (const gateway of allGateways) {
      await services.start({
        name: `${gateway.name} gateway`,
        command: binary,
        args: gatewayArgs({
          gateway,
          iamService,
          iamPrivateSocket,
          dataDir: await makeDir(workDir, `${gateway.name}/data`),
          versioningDir: await makeDir(workDir, `${gateway.name}/versions`),
        }),
        logFile: path.join(logDir, `gateway-${gateway.name}.log`),
        readyUrls: [healthUrl(gateway.s3Url), gateway.webuiUrl],
      });
    }

    await provision({ iamService, gateways: allGateways, identityProviders: allIdentityProviders });
  } catch (error) {
    await stop();
    throw error;
  }
  return stop;
}

/** Fails fast, saying what to do, when a provider is not up. */
async function checkIdentityProviders(idps: readonly IdentityProvider[]): Promise<void> {
  const down: string[] = [];
  for (const idp of idps) {
    if (!(await respondsOk(discoveryUrl(idp)))) down.push(`${idp.name} (${discoveryUrl(idp)})`);
  }
  if (down.length > 0) {
    throw new Error(
      `These identity providers are not serving their discovery documents: ${down.join(', ')}.\n` +
        'Start them first, from tests/webui-e2e: npm run idp:up',
    );
  }
}

async function makeDir(parent: string, name: string): Promise<string> {
  const dir = path.join(parent, name);
  await mkdir(dir, { recursive: true });
  return dir;
}

function healthUrl(baseUrl: string): string {
  return new URL(healthPath, baseUrl).href;
}
