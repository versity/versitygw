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

// What the tests expect to exist before they start: the identity providers
// registered on the IAM service, the roles their users assume, and the seed
// bucket on every gateway.

import {
  CreateOpenIDConnectProviderCommand,
  CreateRoleCommand,
  type IAMClient,
  PutRolePolicyCommand,
} from '@aws-sdk/client-iam';
import { CreateBucketCommand, PutObjectCommand, type S3Client } from '@aws-sdk/client-s3';
import { rootIamClient, rootS3Client } from '../aws/clients';
import { allowPolicy, webIdentityTrustPolicy } from '../aws/policies';
import { type SeedBucket, seedBucket } from '../data/buckets';
import { roles, type TestRole } from '../data/roles';
import { groupsClaim, type IdentityProvider, webuiClientId } from '../idp/identity-provider';
import type { Gateway, IamService } from '../topology';

interface RegisteredProvider {
  idp: IdentityProvider;
  arn: string;
}

export interface ProvisionTargets {
  iamService: IamService;
  gateways: readonly Gateway[];
  identityProviders: readonly IdentityProvider[];
}

export async function provision({ iamService, gateways, identityProviders }: ProvisionTargets): Promise<void> {
  const iam = rootIamClient(iamService.url);
  const providers: RegisteredProvider[] = [];
  for (const idp of identityProviders) {
    providers.push({ idp, arn: await registerIdentityProvider(iam, idp) });
  }
  for (const role of Object.values(roles)) {
    await createRole(iam, role, providers);
  }
  for (const gateway of gateways) {
    await createSeedBucket(rootS3Client(gateway.s3Url), seedBucket);
  }
}

async function registerIdentityProvider(iam: IAMClient, idp: IdentityProvider): Promise<string> {
  const { OpenIDConnectProviderArn } = await iam.send(
    new CreateOpenIDConnectProviderCommand({ Url: idp.issuer, ClientIDList: [webuiClientId] }),
  );
  if (!OpenIDConnectProviderArn) throw new Error(`registering ${idp.issuer} returned no ARN`);
  return OpenIDConnectProviderArn;
}

/** Creates the role, trusted by every provider for members of its group. */
async function createRole(iam: IAMClient, role: TestRole, providers: readonly RegisteredProvider[]): Promise<void> {
  const trustPolicy = webIdentityTrustPolicy(
    providers.map(({ idp, arn }) => ({
      providerArn: arn,
      issuer: idp.issuer,
      audience: webuiClientId,
      groupsClaim,
      group: role.trustedGroup,
    })),
  );
  await iam.send(new CreateRoleCommand({ RoleName: role.name, AssumeRolePolicyDocument: JSON.stringify(trustPolicy) }));
  await iam.send(
    new PutRolePolicyCommand({
      RoleName: role.name,
      PolicyName: 'permissions',
      PolicyDocument: JSON.stringify(allowPolicy(role.actions)),
    }),
  );
}

async function createSeedBucket(s3: S3Client, bucket: SeedBucket): Promise<void> {
  await s3.send(new CreateBucketCommand({ Bucket: bucket.name }));
  for (const object of bucket.objects) {
    await s3.send(new PutObjectCommand({ Bucket: bucket.name, Key: object.key, Body: object.body }));
  }
}
