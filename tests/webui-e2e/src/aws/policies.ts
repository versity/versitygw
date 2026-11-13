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

// IAM policy documents.

export interface PolicyDocument {
  Version: '2012-10-17';
  Statement: PolicyStatement[];
}

interface PolicyStatement {
  Effect: 'Allow' | 'Deny';
  Action: string | string[];
  Resource?: string;
  Principal?: { Federated: string };
  Condition?: Record<string, Record<string, string | string[]>>;
}

/** Allows the actions on every resource. */
export function allowPolicy(actions: readonly string[]): PolicyDocument {
  return {
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: [...actions], Resource: '*' }],
  };
}

export interface WebIdentityTrust {
  /** The registered OIDC provider's ARN. */
  providerArn: string;
  /** The provider's issuer, which prefixes its condition keys. */
  issuer: string;
  /** The client ID the token must be issued to. */
  audience: string;
  /** The claim that lists the user's groups. */
  groupsClaim: string;
  /** A group the user must be in. */
  group: string;
}

/**
 * A trust policy that lets members of a group at any of the providers
 * assume the role with AssumeRoleWithWebIdentity.
 */
export function webIdentityTrustPolicy(trusts: readonly WebIdentityTrust[]): PolicyDocument {
  return {
    Version: '2012-10-17',
    Statement: trusts.map((trust) => ({
      Effect: 'Allow',
      Principal: { Federated: trust.providerArn },
      Action: 'sts:AssumeRoleWithWebIdentity',
      Condition: {
        StringEquals: { [`${trust.issuer}:aud`]: trust.audience },
        'ForAnyValue:StringEquals': { [`${trust.issuer}:${trust.groupsClaim}`]: trust.group },
      },
    })),
  };
}
