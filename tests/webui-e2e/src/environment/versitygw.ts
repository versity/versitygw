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

// The versitygw binary and its command lines for the topology's processes.

import path from 'node:path';
import { healthPath, repoDir, rootCredentials } from '../config';
import { type IdentityProvider, roleClaim, webuiClientId } from '../idp/identity-provider';
import type { Gateway, IamService } from '../topology';
import { runCommand } from './process';

/** $VERSITYGW_BINARY, or else a binary built from this checkout into dir. */
export async function versitygwBinary(dir: string): Promise<string> {
  const prebuilt = process.env.VERSITYGW_BINARY;
  if (prebuilt) return path.resolve(prebuilt);

  const binary = path.join(dir, 'versitygw');
  await runCommand('go', ['build', '-o', binary, './cmd/versitygw'], repoDir);
  return binary;
}

export interface IamServiceArgs {
  service: IamService;
  dataDir: string;
  /** The unix socket of the private API the gateways use. */
  privateSocket: string;
}

export function iamServiceArgs({ service, dataDir, privateSocket }: IamServiceArgs): string[] {
  return [
    ...globalArgs(service.url),
    // The WebUIs call it from origins of their own.
    '--cors-allow-origin', '*',
    'iam',
    '--dir', dataDir,
    '--private-ports', privateSocket,
    // The identity providers are plain http on loopback.
    '--oidc-allow-private-endpoints',
    '--oidc-allow-insecure-transport',
  ];
}

export interface GatewayArgs {
  gateway: Gateway;
  iamService: IamService;
  /** The IAM service's private API socket. */
  iamPrivateSocket: string;
  dataDir: string;
  versioningDir: string;
}

export function gatewayArgs({ gateway, iamService, iamPrivateSocket, dataDir, versioningDir }: GatewayArgs): string[] {
  return [
    ...globalArgs(gateway.s3Url),
    '--cors-allow-origin', new URL(gateway.webuiUrl).origin,
    '--iam-standalone-endpoint', iamPrivateSocket,
    '--webui', new URL(gateway.webuiUrl).host,
    '--webui-gateways', gateway.s3Url,
    '--webui-iam-gateways', iamService.url,
    ...(gateway.sso ? webuiSsoArgs(gateway.sso) : []),
    'posix',
    '--versioning-dir', versioningDir,
    dataDir,
  ];
}

/** The options every process takes before its subcommand. */
function globalArgs(url: string): string[] {
  return [
    '--port', new URL(url).host,
    '--access', rootCredentials.accessKeyId,
    '--secret', rootCredentials.secretAccessKey,
    '--health', healthPath,
    // Every request and response, with secrets masked.
    '--log-level', 'debug',
  ];
}

function webuiSsoArgs(idp: IdentityProvider): string[] {
  return [
    '--webui-oidc-issuer', idp.issuer,
    '--webui-oidc-client-id', webuiClientId,
    '--webui-oidc-role-claim', roleClaim,
    '--webui-oidc-label', idp.signInLabel,
    ...(idp.scopes ? ['--webui-oidc-scopes', idp.scopes] : []),
    // The identity providers are plain http on loopback.
    '--webui-oidc-allow-http',
  ];
}
