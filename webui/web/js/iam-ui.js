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

/**
 * VersityGW IAM - shared UI helpers for the IAM pages
 *
 * Loaded by iam.html, iam-users.html, iam-roles.html and iam-oidc.html after
 * js/app.js. Holds the parts the three IAM pages would otherwise duplicate:
 * the policy editor (identity and trust variants), repeatable form rows, the
 * per-section access-denied state, and the shared quota numbers.
 */

// ============================================
// Server-side quotas (surfaced as helper text and disabled states)
// ============================================

const IAM_LIMITS = {
  accessKeysPerUser: 2,
  userPolicyBytes: 2048,
  rolePolicyBytes: 10240,
  trustPolicyBytes: 2048,
  policyDocumentBytes: 131072,
  roleDescriptionChars: 1000,
  namePattern: /^[A-Za-z0-9+=,.@_-]+$/,
  nameChars: 64,
  pathChars: 512,
  tagsPerResource: 50,
  tagKeyChars: 128,
  tagValueChars: 256,
  tagKeyPattern: /^[\p{L}\p{Z}\p{N}_.:/=+\-@]+$/u,
  tagValuePattern: /^[\p{L}\p{Z}\p{N}_.:/=+\-@]*$/u,
  minSessionDuration: 3600,
  maxSessionDuration: 43200,
  oidcClientIds: 100,
  oidcClientIdChars: 255,
  oidcThumbprints: 5,
  oidcThumbprintChars: 40,
  oidcUrlChars: 255,
  listPageSize: 100
};

const IAM_ACCOUNT_ID = '000000000000';

// ============================================
// Formatting & small utilities
// ============================================

function iamFormatDate(value) {
  if (!value) return '-';
  const date = new Date(value);
  if (isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function iamByteLength(text) {
  return new TextEncoder().encode(text || '').length;
}

/**
 * Copy machine-issued strings (ARNs, key IDs, thumbprints) to the clipboard
 */
async function iamCopy(text, label = 'Value') {
  try {
    await navigator.clipboard.writeText(text);
    showToast(label + ' copied to clipboard', 'success');
  } catch (e) {
    showToast('Unable to copy to clipboard', 'error');
  }
}

/**
 * ARNs are long. Render them monospace, truncated, with a copy button.
 */
function iamArnCell(arn) {
  if (!arn) return '<span class="text-charcoal-300">-</span>';
  const safe = escapeHtml(arn);
  return `<div class="flex items-center gap-2 min-w-0">
    <span class="font-mono text-xs text-charcoal truncate max-w-[22rem]" title="${safe}">${safe}</span>
    <button onclick="iamCopy('${safe}', 'ARN')" class="p-1 text-charcoal-300 hover:text-accent hover:bg-accent-50 rounded transition-colors flex-shrink-0" title="Copy ARN">
      <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>
    </button>
  </div>`;
}

function iamStatusBadge(status) {
  const active = status === 'Active';
  const cls = active ? 'bg-green-50 text-green-700' : 'bg-yellow-50 text-yellow-700';
  return `<span class="px-2 py-0.5 ${cls} text-xs font-medium rounded">${escapeHtml(status || '-')}</span>`;
}

/**
 * Per-section denial state. Partial access is the common case for non-root
 * callers, so a denied List* call reports itself in place instead of failing
 * the whole page.
 */
function iamShowAccessDenied(tableBodyId, columns, message) {
  const tbody = document.getElementById(tableBodyId);
  if (!tbody) return;
  tbody.innerHTML = `<tr><td colspan="${columns}" class="py-12 px-6 text-center">
    <svg class="w-12 h-12 text-gray-300 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
    <p class="text-gray-500">${escapeHtml(message)}</p>
  </td></tr>`;
}

/**
 * Turn an IAM error into product copy. Deletion preconditions are the one case
 * where the server's own message is less useful than a prescriptive one.
 */
function iamErrorText(error, context) {
  const raw = (error && error.message) || 'Unknown error';
  if (raw.startsWith('DeleteConflictPolicies') || raw.startsWith('DeleteConflict')) {
    return raw.includes('Role') || context === 'role'
      ? 'This role still has inline policies. Remove them before deleting it.'
      : 'This user still has access keys or inline policies. Remove them before deleting it.';
  }
  if (raw.startsWith('AccessKeysLimitExceeded')) {
    return `This user already has ${IAM_LIMITS.accessKeysPerUser} access keys. Delete one before creating another.`;
  }
  if (raw.startsWith('InlinePolicyQuotaExceeded')) {
    return 'Saving this policy would exceed the aggregate inline-policy size for this identity.';
  }
  return context ? `Error ${context}: ${raw}` : raw;
}

function iamIsAccessDenied(error) {
  const raw = (error && error.message) || '';
  return raw.startsWith('AccessDenied') || raw.startsWith('AuthorizationError');
}

/**
 * Terse form of an error, for places with no room for a paragraph
 * (stat-card notes, table cells)
 */
function iamShortError(error) {
  const raw = (error && error.message) || 'Unknown error';
  if (raw.startsWith('Network error:')) return 'IAM service unreachable';
  return raw.length > 90 ? raw.slice(0, 90) + '\u2026' : raw;
}

// ============================================
// Name / path validation (client side, matching server rules)
// ============================================

function iamValidateName(name, label = 'Name') {
  if (!name) return `${label} is required.`;
  if (name.length > IAM_LIMITS.nameChars) return `${label} must be ${IAM_LIMITS.nameChars} characters or fewer.`;
  if (!IAM_LIMITS.namePattern.test(name)) return `${label} may contain letters, numbers and + = , . @ _ - only.`;
  return null;
}

function iamValidatePath(path) {
  if (!path) return null;
  if (path.length > IAM_LIMITS.pathChars) return `Path must be ${IAM_LIMITS.pathChars} characters or fewer.`;
  if (!path.startsWith('/') || !path.endsWith('/')) return 'Path must start and end with /.';
  return null;
}

/**
 * Validate a collected tag list against the same rules the server applies,
 * so an obvious mistake is caught before a round trip. Returns an error
 * string, or null when the list is acceptable.
 */
function iamValidateTags(tags) {
  if (tags.length > IAM_LIMITS.tagsPerResource) {
    return `A single resource can carry ${IAM_LIMITS.tagsPerResource} tags at most.`;
  }

  const seen = new Set();
  for (const tag of tags) {
    if (!tag.Key) return 'Every tag needs a key.';
    if (tag.Key.length > IAM_LIMITS.tagKeyChars) {
      return `Tag key "${tag.Key}" must be ${IAM_LIMITS.tagKeyChars} characters or fewer.`;
    }
    if (!IAM_LIMITS.tagKeyPattern.test(tag.Key)) {
      return `Tag key "${tag.Key}" may contain letters, numbers, spaces and _ . : / = + - @ only.`;
    }
    if ((tag.Value || '').length > IAM_LIMITS.tagValueChars) {
      return `Tag value for "${tag.Key}" must be ${IAM_LIMITS.tagValueChars} characters or fewer.`;
    }
    if (!IAM_LIMITS.tagValuePattern.test(tag.Value || '')) {
      return `Tag value for "${tag.Key}" may contain letters, numbers, spaces and _ . : / = + - @ only.`;
    }
    // Tag keys are compared case-insensitively, so "env" and "ENV" are the
    // same key twice — which the service rejects outright.
    const folded = tag.Key.toLowerCase();
    if (seen.has(folded)) return `Tag key "${tag.Key}" is listed twice. Keys are case insensitive.`;
    seen.add(folded);
  }

  return null;
}

/**
 * Render a tag list as read-only two-tone chips, key alongside value.
 */
function iamTagChips(tags) {
  if (!tags.length) return '<span class="text-sm text-charcoal-300">No tags</span>';
  return tags.map(tag => {
    const value = tag.Value
      ? `<span class="px-2 py-1 bg-white border-l border-gray-200 text-charcoal-400">${escapeHtml(tag.Value)}</span>`
      : '<span class="px-2 py-1 bg-white border-l border-gray-200 text-charcoal-300 italic">empty</span>';
    return `<span class="inline-flex items-center overflow-hidden rounded-md border border-gray-200 bg-gray-50 text-xs font-mono">
      <span class="px-2 py-1 font-medium text-charcoal">${escapeHtml(tag.Key)}</span>${value}
    </span>`;
  }).join('');
}

// ============================================
// Repeatable form rows (tags, client IDs, thumbprints)
// ============================================

function iamRemoveRow(button) {
  const row = button.closest('[data-iam-row]');
  if (row) row.remove();
}

function iamAddTagRow(containerId, key = '', value = '') {
  const container = document.getElementById(containerId);
  if (!container) return;
  if (container.querySelectorAll('[data-iam-row]').length >= IAM_LIMITS.tagsPerResource) {
    showToast(`A resource can carry ${IAM_LIMITS.tagsPerResource} tags at most`, 'warning');
    return;
  }
  const row = document.createElement('div');
  row.className = 'flex items-center gap-2';
  row.setAttribute('data-iam-row', 'tag');
  row.innerHTML = `<input type="text" data-tag-key value="${escapeHtml(key)}" maxlength="${IAM_LIMITS.tagKeyChars}" placeholder="Key" class="flex-1 px-3 py-2 border border-gray-200 rounded-lg text-sm text-charcoal placeholder:text-charcoal-300 focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/20 transition-all">
    <input type="text" data-tag-value value="${escapeHtml(value)}" maxlength="${IAM_LIMITS.tagValueChars}" placeholder="Value" class="flex-1 px-3 py-2 border border-gray-200 rounded-lg text-sm text-charcoal placeholder:text-charcoal-300 focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/20 transition-all">
    <button type="button" onclick="iamRemoveRow(this)" class="p-2 text-charcoal-300 hover:text-red-600 hover:bg-red-50 rounded-lg transition-colors" title="Remove">
      <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
    </button>`;
  container.appendChild(row);
}

function iamCollectTags(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return [];
  return Array.from(container.querySelectorAll('[data-iam-row="tag"]'))
    .map(row => ({
      Key: row.querySelector('[data-tag-key]').value.trim(),
      Value: row.querySelector('[data-tag-value]').value.trim()
    }))
    .filter(tag => tag.Key);
}

function iamAddTextRow(containerId, value = '', placeholder = '', maxlength = 255) {
  const container = document.getElementById(containerId);
  if (!container) return;
  const row = document.createElement('div');
  row.className = 'flex items-center gap-2';
  row.setAttribute('data-iam-row', 'text');
  row.innerHTML = `<input type="text" data-row-value value="${escapeHtml(value)}" maxlength="${maxlength}" placeholder="${escapeHtml(placeholder)}" class="flex-1 px-3 py-2 border border-gray-200 rounded-lg text-sm font-mono text-charcoal placeholder:font-sans placeholder:text-charcoal-300 focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/20 transition-all">
    <button type="button" onclick="iamRemoveRow(this)" class="p-2 text-charcoal-300 hover:text-red-600 hover:bg-red-50 rounded-lg transition-colors" title="Remove">
      <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
    </button>`;
  container.appendChild(row);
}

function iamCollectTextRows(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return [];
  return Array.from(container.querySelectorAll('[data-iam-row="text"] [data-row-value]'))
    .map(input => input.value.trim())
    .filter(Boolean);
}

// ============================================
// Policy editor (identity and trust variants)
// ============================================

const IAM_POLICY_VARIANTS = {
  identity: {
    infoTitle: 'About Inline Identity Policies',
    infoBody: 'An inline policy grants the identity it is attached to permission to call specific actions on specific resources. The principal is implicit, so an identity policy must not contain a <strong>Principal</strong> field.',
    reference: `<div>
        <p class="font-medium text-charcoal mb-1">Common Actions:</p>
        <ul class="space-y-0.5 text-charcoal-400">
          <li>&bull; <code class="bg-white px-1 py-0.5 rounded">iam:GetUser</code> - Read own or another user</li>
          <li>&bull; <code class="bg-white px-1 py-0.5 rounded">iam:ListAccessKeys</code> - List a user's keys</li>
          <li>&bull; <code class="bg-white px-1 py-0.5 rounded">iam:CreateAccessKey</code> - Rotate credentials</li>
          <li>&bull; <code class="bg-white px-1 py-0.5 rounded">s3:GetObject</code> - Read objects</li>
        </ul>
      </div>
      <div>
        <p class="font-medium text-charcoal mb-1">Resource Format:</p>
        <ul class="space-y-0.5 text-charcoal-400">
          <li>&bull; User: <code class="bg-white px-1 py-0.5 rounded text-[10px]">arn:aws:iam::${IAM_ACCOUNT_ID}:user/alice</code></li>
          <li>&bull; Role: <code class="bg-white px-1 py-0.5 rounded text-[10px]">arn:aws:iam::${IAM_ACCOUNT_ID}:role/reader</code></li>
          <li>&bull; Objects: <code class="bg-white px-1 py-0.5 rounded text-[10px]">arn:aws:s3:::bucket/*</code></li>
        </ul>
      </div>`,
    help: `<div>
        <p class="font-medium mb-1">Required Fields:</p>
        <ul class="list-disc list-inside space-y-1 text-charcoal-400 ml-2">
          <li><strong>Version:</strong> Always "2012-10-17"</li>
          <li><strong>Statement:</strong> Array of policy statements</li>
        </ul>
      </div>
      <div>
        <p class="font-medium mb-1">Statement Fields:</p>
        <ul class="list-disc list-inside space-y-1 text-charcoal-400 ml-2">
          <li><strong>Sid:</strong> Statement identifier (optional, but recommended)</li>
          <li><strong>Effect:</strong> "Allow" or "Deny"</li>
          <li><strong>Action:</strong> Array of actions (e.g., ["iam:GetUser"])</li>
          <li><strong>Resource:</strong> Array of ARNs the actions apply to</li>
          <li><strong>Principal:</strong> Not allowed in an identity policy</li>
        </ul>
      </div>
      <div>
        <p class="font-medium mb-1">Authorization Model:</p>
        <p class="text-charcoal-400 ml-2">Each action is resolved as <code class="bg-white px-1 py-0.5 rounded">iam:&lt;ActionName&gt;</code> against the concrete target ARN. There is no implicit self-access: a user with no inline policy cannot call GetUser even on itself.</p>
      </div>`,
    example: {
      Version: '2012-10-17',
      Statement: [
        {
          Sid: 'ReadOwnIdentity',
          Effect: 'Allow',
          Action: ['iam:GetUser', 'iam:ListAccessKeys'],
          Resource: [`arn:aws:iam::${IAM_ACCOUNT_ID}:user/alice`]
        },
        {
          Sid: 'ReadObjects',
          Effect: 'Allow',
          Action: ['s3:GetObject'],
          Resource: ['arn:aws:s3:::example-bucket/*']
        }
      ]
    }
  },
  trust: {
    infoTitle: 'About Trust Policies',
    infoBody: 'A trust policy states who may assume this role. <strong>Principal</strong> is required, <strong>Resource</strong> is not allowed, and every action must be <code>sts:</code>-prefixed. Shared identity providers are additionally tenancy-scoped by the server; it will describe the rule if the document violates it.',
    reference: `<div>
        <p class="font-medium text-charcoal mb-1">Actions:</p>
        <ul class="space-y-0.5 text-charcoal-400">
          <li>&bull; <code class="bg-white px-1 py-0.5 rounded">sts:AssumeRole</code></li>
          <li>&bull; <code class="bg-white px-1 py-0.5 rounded">sts:AssumeRoleWithWebIdentity</code></li>
        </ul>
      </div>
      <div>
        <p class="font-medium text-charcoal mb-1">Principal Keys:</p>
        <ul class="space-y-0.5 text-charcoal-400">
          <li>&bull; <code class="bg-white px-1 py-0.5 rounded">AWS</code> - a user ARN in this account</li>
          <li>&bull; <code class="bg-white px-1 py-0.5 rounded">Federated</code> - an OIDC provider ARN</li>
          <li>&bull; <code class="bg-white px-1 py-0.5 rounded">Service</code> - a service principal</li>
        </ul>
      </div>`,
    help: `<div>
        <p class="font-medium mb-1">Required Fields:</p>
        <ul class="list-disc list-inside space-y-1 text-charcoal-400 ml-2">
          <li><strong>Version:</strong> Always "2012-10-17"</li>
          <li><strong>Statement:</strong> Array of trust statements</li>
          <li><strong>Principal:</strong> Object with AWS, Service or Federated keys only</li>
          <li><strong>Action:</strong> sts: actions only</li>
        </ul>
      </div>
      <div>
        <p class="font-medium mb-1">Not Allowed:</p>
        <ul class="list-disc list-inside space-y-1 text-charcoal-400 ml-2">
          <li><strong>Resource</strong> and <strong>NotResource</strong> - the role itself is the resource</li>
          <li>Non-sts actions</li>
        </ul>
      </div>
      <div>
        <p class="font-medium mb-1">Federated Providers:</p>
        <p class="text-charcoal-400 ml-2">Trust statements naming a shared provider (GitHub Actions, GitLab and similar) must scope the condition to your own tenancy. The server validates this and returns a descriptive error when the scoping is missing.</p>
      </div>`,
    example: {
      Version: '2012-10-17',
      Statement: [
        {
          Sid: 'AllowUserToAssume',
          Effect: 'Allow',
          Principal: { AWS: `arn:aws:iam::${IAM_ACCOUNT_ID}:user/example` },
          Action: ['sts:AssumeRole']
        }
      ]
    }
  }
};

const iamPolicyEditor = {
  _state: null,

  _ensureModal() {
    if (document.getElementById('iam-policy-modal')) return;
    const wrapper = document.createElement('div');
    wrapper.id = 'iam-policy-modal';
    wrapper.className = 'modal hidden fixed inset-0 z-50';
    wrapper.innerHTML = `<div class="modal-backdrop absolute inset-0" onclick="iamPolicyEditor.close()"></div>
      <div class="absolute inset-0 flex items-center justify-center p-4">
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-5xl relative max-h-[90vh] flex flex-col">
          <div class="flex items-center justify-between p-6 border-b border-gray-100 flex-shrink-0">
            <div>
              <h2 id="iam-policy-title" class="text-xl font-semibold text-charcoal">Inline Policy</h2>
              <p id="iam-policy-subtitle" class="text-sm text-charcoal-300 mt-1"></p>
            </div>
            <button onclick="iamPolicyEditor.close()" class="p-2 text-charcoal-300 hover:text-charcoal hover:bg-gray-100 rounded-lg transition-colors">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
            </button>
          </div>
          <div class="flex-1 overflow-auto">
            <div class="p-6 space-y-6">
              <div class="bg-blue-50 border border-blue-200 rounded-lg p-4">
                <div class="flex items-start gap-3">
                  <svg class="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                  <div class="text-sm text-blue-800">
                    <p id="iam-policy-info-title" class="font-medium"></p>
                    <p id="iam-policy-info-body" class="mt-1"></p>
                  </div>
                </div>
              </div>
              <div id="iam-policy-name-row" class="hidden">
                <label class="block text-sm font-medium text-charcoal mb-2">Policy Name <span class="text-red-500">*</span></label>
                <input type="text" id="iam-policy-name" maxlength="64" placeholder="e.g., read-own-keys" class="w-full px-4 py-2.5 border-2 border-gray-200 rounded-lg text-charcoal font-mono text-sm placeholder:font-sans placeholder:text-charcoal-300 focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/20 transition-all">
                <p class="mt-2 text-xs text-charcoal-300">Up to 64 characters. Letters, numbers and + = , . @ _ - only. The name cannot be changed after saving.</p>
              </div>
              <div class="bg-gray-50 border border-gray-200 rounded-lg p-4">
                <h3 class="text-sm font-semibold text-charcoal mb-3 flex items-center gap-2">
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
                  Quick Reference
                </h3>
                <div id="iam-policy-reference" class="grid grid-cols-2 gap-4 text-xs"></div>
              </div>
              <div>
                <div class="flex items-center justify-between mb-3">
                  <label class="text-sm font-medium text-charcoal">Policy Document</label>
                  <div class="flex gap-2">
                    <button onclick="iamPolicyEditor.toggleHelp()" class="inline-flex items-center gap-1 px-3 py-1.5 text-xs border border-gray-200 hover:bg-gray-50 text-charcoal rounded-lg transition-colors">
                      <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                      Help
                    </button>
                    <button onclick="iamPolicyEditor.loadExample()" class="inline-flex items-center gap-1 px-3 py-1.5 text-xs border border-gray-200 hover:bg-gray-50 text-charcoal rounded-lg transition-colors">
                      <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
                      Load Example
                    </button>
                    <button onclick="iamPolicyEditor.validate(true)" class="inline-flex items-center gap-1 px-3 py-1.5 text-xs border border-accent text-accent hover:bg-accent-50 rounded-lg transition-colors">
                      <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                      Validate
                    </button>
                  </div>
                </div>
                <div id="iam-policy-status" class="mb-3 hidden"></div>
                <textarea id="iam-policy-editor-json" rows="16" oninput="iamPolicyEditor.updateCounter()" placeholder="No policy defined. Click 'Load Example' to get started." class="w-full px-4 py-3 border-2 border-gray-200 rounded-lg text-sm font-mono focus:outline-none focus:border-accent resize-none"></textarea>
                <p id="iam-policy-counter" class="mt-2 text-xs text-charcoal-300"></p>
              </div>
              <div id="iam-policy-help" class="hidden bg-gray-50 border border-gray-200 rounded-lg p-4">
                <div class="flex items-start justify-between mb-3">
                  <h3 class="text-sm font-semibold text-charcoal flex items-center gap-2">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253"/></svg>
                    Policy Structure Guide
                  </h3>
                  <button onclick="iamPolicyEditor.toggleHelp()" class="text-charcoal-300 hover:text-charcoal">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
                  </button>
                </div>
                <div id="iam-policy-help-body" class="space-y-3 text-sm text-charcoal"></div>
              </div>
            </div>
          </div>
          <div class="flex items-center justify-between p-6 border-t border-gray-100 flex-shrink-0">
            <button id="iam-policy-delete-btn" onclick="iamPolicyEditor.remove()" class="hidden px-4 py-2.5 border border-red-200 text-red-600 hover:bg-red-50 font-medium rounded-lg transition-colors">Delete Policy</button>
            <div class="flex gap-3 ml-auto">
              <button onclick="iamPolicyEditor.close()" class="px-4 py-2.5 border border-gray-200 rounded-lg text-charcoal font-medium hover:bg-gray-50 transition-colors">Cancel</button>
              <button id="iam-policy-save-btn" onclick="iamPolicyEditor.save()" class="px-4 py-2.5 bg-accent hover:bg-accent-600 text-white font-medium rounded-lg transition-colors">Save Policy</button>
            </div>
          </div>
        </div>
      </div>`;
    document.body.appendChild(wrapper);
  },

  /**
   * @param {Object} opts
   *   variant     'identity' | 'trust'
   *   title       modal heading
   *   subtitle    the identity this document belongs to
   *   policyName  existing name ('' for a new policy)
   *   nameEditable show and require the policy-name field
   *   document    initial JSON text
   *   quota       { otherBytes, max } for the aggregate inline-policy counter
   *   maxBytes    hard limit for this single document
   *   showDelete  render the Delete Policy button
   *   saveLabel   label for the save button (default 'Save Policy')
   *   onSave      async ({ policyName, document }) => void
   *   onDelete    async () => void
   */
  open(opts) {
    this._ensureModal();
    const variant = IAM_POLICY_VARIANTS[opts.variant] || IAM_POLICY_VARIANTS.identity;
    this._state = Object.assign({ variant: 'identity' }, opts);

    document.getElementById('iam-policy-title').textContent = opts.title || 'Policy';
    document.getElementById('iam-policy-subtitle').textContent = opts.subtitle || '';
    document.getElementById('iam-policy-info-title').textContent = variant.infoTitle;
    document.getElementById('iam-policy-info-body').innerHTML = variant.infoBody;
    document.getElementById('iam-policy-reference').innerHTML = variant.reference;
    document.getElementById('iam-policy-help-body').innerHTML = variant.help;
    document.getElementById('iam-policy-help').classList.add('hidden');

    const nameRow = document.getElementById('iam-policy-name-row');
    const nameInput = document.getElementById('iam-policy-name');
    nameRow.classList.toggle('hidden', !opts.nameEditable);
    nameInput.value = opts.policyName || '';

    const editor = document.getElementById('iam-policy-editor-json');
    editor.value = opts.document || '';

    document.getElementById('iam-policy-delete-btn').classList.toggle('hidden', !opts.showDelete);
    document.getElementById('iam-policy-save-btn').textContent = opts.saveLabel || 'Save Policy';
    this._setStatus(null);
    this.updateCounter();
    openModal('iam-policy-modal');
  },

  close() {
    this._state = null;
    closeModal('iam-policy-modal');
  },

  toggleHelp() {
    document.getElementById('iam-policy-help').classList.toggle('hidden');
  },

  loadExample() {
    const variant = IAM_POLICY_VARIANTS[this._state?.variant] || IAM_POLICY_VARIANTS.identity;
    document.getElementById('iam-policy-editor-json').value = JSON.stringify(variant.example, null, 2);
    this._setStatus(null);
    this.updateCounter();
  },

  updateCounter() {
    const state = this._state;
    if (!state) return;
    const bytes = iamByteLength(document.getElementById('iam-policy-editor-json').value);
    const counter = document.getElementById('iam-policy-counter');
    const quota = state.quota;
    if (quota) {
      const total = (quota.otherBytes || 0) + bytes;
      const over = total > quota.max;
      counter.className = 'mt-2 text-xs ' + (over ? 'text-red-600 font-medium' : 'text-charcoal-300');
      counter.textContent = `${total} / ${quota.max} bytes used across this identity's inline policies (this document: ${bytes} bytes)`;
    } else {
      const max = state.maxBytes || IAM_LIMITS.policyDocumentBytes;
      const over = bytes > max;
      counter.className = 'mt-2 text-xs ' + (over ? 'text-red-600 font-medium' : 'text-charcoal-300');
      counter.textContent = `${bytes} / ${max} bytes`;
    }
  },

  _setStatus(message, type = 'error') {
    const el = document.getElementById('iam-policy-status');
    if (!message) {
      el.classList.add('hidden');
      el.innerHTML = '';
      return;
    }
    const styles = {
      error: 'bg-red-50 border-red-200 text-red-800',
      success: 'bg-green-50 border-green-200 text-green-800',
      warning: 'bg-yellow-50 border-yellow-200 text-yellow-800'
    };
    el.className = `mb-3 border rounded-lg px-4 py-3 text-sm ${styles[type]}`;
    el.textContent = message;
    el.classList.remove('hidden');
  },

  /**
   * Client-side grammar check. Deliberately shallow: it catches the two
   * grammars' hard rules and leaves everything else to the server's own
   * descriptive errors.
   */
  validate(announce = false) {
    const state = this._state;
    if (!state) return null;
    const text = document.getElementById('iam-policy-editor-json').value.trim();
    if (!text) {
      this._setStatus('Policy document is empty.');
      return null;
    }

    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch (e) {
      this._setStatus('Invalid JSON: ' + e.message);
      return null;
    }

    const errors = [];
    if (!parsed.Version) errors.push('Missing "Version" (use "2012-10-17").');
    const statements = Array.isArray(parsed.Statement) ? parsed.Statement : (parsed.Statement ? [parsed.Statement] : []);
    if (statements.length === 0) errors.push('"Statement" must be a non-empty array.');

    statements.forEach((st, i) => {
      const at = `Statement ${i + 1}`;
      if (!st || typeof st !== 'object') { errors.push(`${at} must be an object.`); return; }
      if (st.Effect !== 'Allow' && st.Effect !== 'Deny') errors.push(`${at}: "Effect" must be "Allow" or "Deny".`);
      const actions = [].concat(st.Action || st.NotAction || []);
      if (actions.length === 0) errors.push(`${at}: "Action" is required.`);

      if (state.variant === 'trust') {
        if (!st.Principal || typeof st.Principal !== 'object' || Array.isArray(st.Principal)) {
          errors.push(`${at}: "Principal" is required and must be an object with AWS, Service or Federated keys.`);
        } else {
          const allowed = ['AWS', 'Service', 'Federated'];
          Object.keys(st.Principal).forEach(key => {
            if (!allowed.includes(key)) errors.push(`${at}: "Principal.${key}" is not allowed. Use AWS, Service or Federated.`);
          });
        }
        if ('Resource' in st || 'NotResource' in st) errors.push(`${at}: "Resource" is not allowed in a trust policy.`);
        actions.forEach(action => {
          if (typeof action === 'string' && !action.startsWith('sts:')) errors.push(`${at}: "${action}" is not an sts: action.`);
        });
      } else {
        if ('Principal' in st || 'NotPrincipal' in st) errors.push(`${at}: "Principal" is not allowed in an identity policy - the identity it is attached to is the principal.`);
        const resources = [].concat(st.Resource || st.NotResource || []);
        if (resources.length === 0) errors.push(`${at}: "Resource" is required.`);
      }
    });

    const bytes = iamByteLength(text);
    const maxBytes = state.maxBytes || IAM_LIMITS.policyDocumentBytes;
    if (bytes > maxBytes) errors.push(`Document is ${bytes} bytes, over the ${maxBytes}-byte limit.`);
    if (state.quota && (state.quota.otherBytes || 0) + bytes > state.quota.max) {
      errors.push(`This identity's inline policies would total ${(state.quota.otherBytes || 0) + bytes} bytes, over the ${state.quota.max}-byte aggregate limit.`);
    }

    if (errors.length > 0) {
      this._setStatus(errors.join(' '));
      return null;
    }

    if (announce) this._setStatus('Policy document is valid.', 'success');
    else this._setStatus(null);
    return JSON.stringify(parsed);
  },

  async save() {
    const state = this._state;
    if (!state) return;

    let policyName = state.policyName || '';
    if (state.nameEditable) {
      policyName = document.getElementById('iam-policy-name').value.trim();
      const nameError = iamValidateName(policyName, 'Policy name');
      if (nameError) { this._setStatus(nameError); return; }
    }

    const document_ = this.validate();
    if (!document_) return;

    const btn = document.getElementById('iam-policy-save-btn');
    setLoading(btn, true);
    try {
      await state.onSave({ policyName, document: document_ });
      this.close();
    } catch (error) {
      console.error('Error saving policy:', error);
      this._setStatus(iamErrorText(error));
    } finally {
      setLoading(btn, false);
    }
  },

  async remove() {
    const state = this._state;
    if (!state || !state.onDelete) return;
    const btn = document.getElementById('iam-policy-delete-btn');
    setLoading(btn, true);
    try {
      await state.onDelete();
      this.close();
    } catch (error) {
      console.error('Error deleting policy:', error);
      this._setStatus(iamErrorText(error));
    } finally {
      setLoading(btn, false);
    }
  }
};

// ============================================
// Tag editor
// ============================================

/**
 * Edit an identity's whole tag set at once, then apply it as the minimal
 * pair of API calls: one untag for the keys that disappeared, one tag for
 * the ones added or changed. Editing the set as a whole — rather than a
 * tag at a time — is what lets a rename, a couple of additions and a couple
 * of removals be one reviewable Save.
 */
const iamTagEditor = {
  _state: null,

  _ensureModal() {
    if (document.getElementById('iam-tag-modal')) return;
    const wrapper = document.createElement('div');
    wrapper.id = 'iam-tag-modal';
    wrapper.className = 'modal hidden fixed inset-0 z-50';
    wrapper.innerHTML = `<div class="modal-backdrop absolute inset-0" onclick="iamTagEditor.close()"></div>
      <div class="absolute inset-0 flex items-center justify-center p-4">
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-2xl relative max-h-[90vh] flex flex-col">
          <div class="flex items-center justify-between p-6 border-b border-gray-100 flex-shrink-0">
            <div>
              <h2 id="iam-tag-title" class="text-xl font-semibold text-charcoal">Tags</h2>
              <p id="iam-tag-subtitle" class="text-sm text-charcoal-300 mt-1"></p>
            </div>
            <button onclick="iamTagEditor.close()" class="p-2 text-charcoal-300 hover:text-charcoal hover:bg-gray-100 rounded-lg transition-colors">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
            </button>
          </div>
          <div class="flex-1 overflow-auto">
            <div class="p-6 space-y-5">
              <div class="bg-blue-50 border border-blue-200 rounded-lg p-4">
                <div class="flex items-start gap-3">
                  <svg class="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                  <div class="text-sm text-blue-800">
                    <p class="font-medium">About Tags</p>
                    <p class="mt-1">Key/value labels for grouping and search. They are also readable from policy conditions as <code class="font-mono">aws:PrincipalTag/&lt;key&gt;</code> for the tagged identity and <code class="font-mono">aws:ResourceTag/&lt;key&gt;</code> for the identity being acted on. Keys are case insensitive; values may be empty.</p>
                  </div>
                </div>
              </div>
              <div id="iam-tag-status" class="hidden"></div>
              <div>
                <div class="flex items-center justify-between mb-2">
                  <label class="block text-sm font-medium text-charcoal">Tags</label>
                  <button type="button" onclick="iamTagEditor.addRow()" class="px-3 py-1.5 text-xs border border-gray-200 hover:bg-gray-50 text-charcoal rounded-lg transition-colors">Add Tag</button>
                </div>
                <div id="iam-tag-rows" class="space-y-2"></div>
                <p id="iam-tag-empty" class="hidden py-6 text-center text-sm text-charcoal-300">No tags yet. Use <span class="font-medium">Add Tag</span> to create one.</p>
                <p id="iam-tag-counter" class="mt-3 text-xs text-charcoal-300"></p>
              </div>
            </div>
          </div>
          <div class="flex items-center justify-end gap-3 p-6 border-t border-gray-100 flex-shrink-0">
            <button onclick="iamTagEditor.close()" class="px-4 py-2.5 border border-gray-200 rounded-lg text-charcoal font-medium hover:bg-gray-50 transition-colors">Cancel</button>
            <button id="iam-tag-save-btn" onclick="iamTagEditor.save()" class="px-4 py-2.5 bg-accent hover:bg-accent-600 text-white font-medium rounded-lg transition-colors">Save Tags</button>
          </div>
        </div>
      </div>`;
    document.body.appendChild(wrapper);

    // iamAddTagRow and iamRemoveRow are shared with the create forms and
    // report nothing back, so watch the container instead of hooking them.
    new MutationObserver(() => this.updateCounter())
      .observe(document.getElementById('iam-tag-rows'), { childList: true });
  },

  /**
   * @param {Object} opts
   *   title     modal heading
   *   subtitle  the identity these tags belong to
   *   tags      current tags, as [{Key, Value}]
   *   onSave    async ({ set, remove }) => void, where set holds the tags to
   *             add or overwrite and remove holds the keys to drop
   */
  open(opts) {
    this._ensureModal();
    this._state = Object.assign({}, opts);

    document.getElementById('iam-tag-title').textContent = opts.title || 'Tags';
    document.getElementById('iam-tag-subtitle').textContent = opts.subtitle || '';

    const rows = document.getElementById('iam-tag-rows');
    rows.innerHTML = '';
    (opts.tags || []).forEach(tag => iamAddTagRow('iam-tag-rows', tag.Key, tag.Value || ''));

    this._setStatus(null);
    this.updateCounter();
    openModal('iam-tag-modal');
  },

  close() {
    this._state = null;
    closeModal('iam-tag-modal');
  },

  addRow() {
    iamAddTagRow('iam-tag-rows');
    const rows = document.querySelectorAll('#iam-tag-rows [data-iam-row="tag"]');
    const last = rows[rows.length - 1];
    if (last) last.querySelector('[data-tag-key]').focus();
  },

  updateCounter() {
    const rows = document.querySelectorAll('#iam-tag-rows [data-iam-row="tag"]').length;
    document.getElementById('iam-tag-empty').classList.toggle('hidden', rows > 0);

    const counter = document.getElementById('iam-tag-counter');
    const over = rows > IAM_LIMITS.tagsPerResource;
    counter.className = 'mt-3 text-xs ' + (over ? 'text-red-600 font-medium' : 'text-charcoal-300');
    counter.textContent = `${rows} / ${IAM_LIMITS.tagsPerResource} tags`;
  },

  _setStatus(message) {
    const el = document.getElementById('iam-tag-status');
    if (!message) {
      el.classList.add('hidden');
      el.textContent = '';
      return;
    }
    el.className = 'border rounded-lg px-4 py-3 text-sm bg-red-50 border-red-200 text-red-800';
    el.textContent = message;
    el.classList.remove('hidden');
  },

  /**
   * Diff the edited rows against the tags the modal opened with. A key whose
   * only change is its casing still lands in set: the tag action overwrites
   * the stored tag in place, taking the new casing with it.
   */
  _diff(current) {
    const original = this._state.tags || [];
    const originalByKey = new Map(original.map(tag => [tag.Key.toLowerCase(), tag]));
    const currentKeys = new Set(current.map(tag => tag.Key.toLowerCase()));

    const set = current.filter(tag => {
      const before = originalByKey.get(tag.Key.toLowerCase());
      return !before || before.Key !== tag.Key || (before.Value || '') !== (tag.Value || '');
    });
    const remove = original
      .filter(tag => !currentKeys.has(tag.Key.toLowerCase()))
      .map(tag => tag.Key);

    return { set, remove };
  },

  async save() {
    const state = this._state;
    if (!state) return;

    // iamCollectTags drops keyless rows, so a value typed without a key
    // would silently vanish. Catch that before it does.
    const orphanValue = Array.from(document.querySelectorAll('#iam-tag-rows [data-iam-row="tag"]'))
      .some(row => !row.querySelector('[data-tag-key]').value.trim() &&
        row.querySelector('[data-tag-value]').value.trim());
    if (orphanValue) { this._setStatus('Every tag needs a key.'); return; }

    const current = iamCollectTags('iam-tag-rows');
    const error = iamValidateTags(current);
    if (error) { this._setStatus(error); return; }

    const { set, remove } = this._diff(current);
    if (!set.length && !remove.length) {
      showToast('No tag changes to save', 'info');
      this.close();
      return;
    }

    const btn = document.getElementById('iam-tag-save-btn');
    setLoading(btn, true);
    try {
      await state.onSave({ set, remove });
      this.close();
    } catch (err) {
      console.error('Error saving tags:', err);
      this._setStatus(iamErrorText(err));
    } finally {
      setLoading(btn, false);
    }
  }
};
