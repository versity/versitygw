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
 * VersityGW Admin - Application Utilities
 */

// ============================================
// Navigation & Auth Guards
// ============================================

/**
 * Check if user is authenticated, redirect to login if not
 * Also loads user context (user type and accessible gateways)
 */
function requireAuth() {
  if (!api.loadCredentials()) {
    window.location.href = 'index.html';
    return false;
  }
  api.loadUserContext();
  return true;
}

/**
 * Require admin role, redirect non-admins to explorer
 * Call this on admin-only pages (dashboard, users, buckets, settings)
 * Also loads user context (user type and accessible gateways)
 */
function requireAdmin() {
  if (!api.loadCredentials()) {
    window.location.href = 'index.html';
    return false;
  }
  api.loadUserContext();
  if (!api.isAdmin()) {
    window.location.href = 'explorer.html';
    return false;
  }
  return true;
}

/**
 * Redirect to appropriate page if already authenticated
 * Admin users go to dashboard, regular users go to explorer
 */
function redirectIfAuthenticated() {
  if (api.loadCredentials()) {
    if (api.isAdmin()) {
      window.location.href = 'dashboard.html';
    } else {
      window.location.href = 'explorer.html';
    }
    return true;
  }
  return false;
}

// ============================================
// Toast Notifications
// ============================================

let toastContainer = null;

function initToasts() {
  if (!toastContainer) {
    toastContainer = document.createElement('div');
    toastContainer.id = 'toast-container';
    toastContainer.className = 'fixed top-4 right-4 z-50 flex flex-col gap-2';
    document.body.appendChild(toastContainer);
  }
}

function showToast(message, type = 'info') {
  initToasts();

  const toast = document.createElement('div');
  const bgColors = {
    success: 'bg-green-50 border-green-500 text-green-800',
    error: 'bg-red-50 border-red-500 text-red-800',
    warning: 'bg-yellow-50 border-yellow-500 text-yellow-800',
    info: 'bg-blue-50 border-blue-500 text-blue-800'
  };

  const icons = {
    success: `<svg class="w-5 h-5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>`,
    error: `<svg class="w-5 h-5 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>`,
    warning: `<svg class="w-5 h-5 text-yellow-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>`,
    info: `<svg class="w-5 h-5 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>`
  };

  toast.className = `flex items-center gap-3 px-4 py-3 rounded-lg border-l-4 shadow-lg max-w-sm animate-slide-in ${bgColors[type]}`;
  toast.innerHTML = `
    ${icons[type]}
    <p class="text-sm font-medium flex-1">${escapeHtml(message)}</p>
    <button onclick="this.parentElement.remove()" class="text-gray-400 hover:text-gray-600">
      <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
    </button>
  `;

  toastContainer.appendChild(toast);

  // Auto-remove after 5 seconds
  setTimeout(() => {
    toast.classList.add('animate-fade-out');
    setTimeout(() => toast.remove(), 300);
  }, 5000);
}

// ============================================
// Modal Utilities
// ============================================

function openModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.remove('hidden');
    // Focus first input
    const firstInput = modal.querySelector('input:not([readonly]), select');
    if (firstInput) setTimeout(() => firstInput.focus(), 100);
  }
}

function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.add('hidden');
  }
}

function closeAllModals() {
  document.querySelectorAll('[id$="-modal"]').forEach(modal => {
    modal.classList.add('hidden');
  });
}

// Close modals on Escape key
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeAllModals();
});

// ============================================
// Loading States
// ============================================

function setLoading(element, loading) {
  if (loading) {
    element.disabled = true;
    element.dataset.originalText = element.innerHTML;
    element.innerHTML = `
      <svg class="animate-spin h-5 w-5 mx-auto" fill="none" viewBox="0 0 24 24">
        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
      </svg>
    `;
  } else {
    element.disabled = false;
    if (element.dataset.originalText) {
      element.innerHTML = element.dataset.originalText;
    }
  }
}

function showTableLoading(tableBodyId, columns) {
  const tbody = document.getElementById(tableBodyId);
  if (!tbody) return;

  tbody.innerHTML = '';
  for (let i = 0; i < 5; i++) {
    const row = document.createElement('tr');
    row.className = 'border-b border-gray-50';
    for (let j = 0; j < columns; j++) {
      row.innerHTML += `
        <td class="py-4 px-6">
          <div class="h-4 bg-gray-200 rounded animate-pulse" style="width: ${60 + Math.random() * 40}%"></div>
        </td>
      `;
    }
    tbody.appendChild(row);
  }
}

function showEmptyState(tableBodyId, columns, message = 'No data found') {
  const tbody = document.getElementById(tableBodyId);
  if (!tbody) return;

  tbody.innerHTML = `
    <tr>
      <td colspan="${columns}" class="py-12 px-6 text-center">
        <svg class="w-12 h-12 text-gray-300 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4"/>
        </svg>
        <p class="text-gray-500">${escapeHtml(message)}</p>
      </td>
    </tr>
  `;
}

// ============================================
// Utility Functions
// ============================================

function escapeHtml(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function formatRole(role) {
  const roleConfig = {
    admin: { label: 'Admin', class: 'bg-primary-50 text-primary' },
    user: { label: 'User', class: 'bg-gray-100 text-charcoal' },
    userplus: { label: 'User+', class: 'bg-accent-50 text-accent' }
  };
  const config = roleConfig[role] || roleConfig.user;
  return `<span class="px-2.5 py-1 ${config.class} text-xs font-medium rounded-md">${config.label}</span>`;
}

function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

// ============================================
// Sidebar Active State
// ============================================

function initSidebar() {
  const currentPage = window.location.pathname.split('/').pop() || 'index.html';
  document.querySelectorAll('.nav-item').forEach(item => {
    const href = item.getAttribute('href');
    if (href === currentPage) {
      item.classList.add('active');
      item.classList.remove('text-white/70');
      item.classList.add('text-white');
    } else {
      item.classList.remove('active');
    }
  });
}

// ============================================
// Update User Info in Sidebar
// ============================================

function updateUserInfo() {
  const info = api.getCredentialsInfo();
  if (!info) return;

  const accessKeyShort = info.accessKey.length > 12
    ? info.accessKey.substring(0, 12) + '...'
    : info.accessKey;

  const roleLabel = info.isAdmin ? 'Admin' : 'User';

  const userInfoEl = document.getElementById('user-info');
  if (userInfoEl) {
    userInfoEl.innerHTML = `
      <div class="flex-1 min-w-0">
        <p class="text-white text-sm font-medium truncate">${escapeHtml(accessKeyShort)}</p>
        <p class="text-white/50 text-xs">${roleLabel}</p>
      </div>
    `;
  }
}

/**
 * Initialize sidebar with role-based navigation
 * Hides admin-only nav items for non-admin users
 */
function initSidebarWithRole() {
  initSidebar();

  // Hide admin-only nav items for non-admin users
  if (!api.isAdmin()) {
    document.querySelectorAll('[data-admin-only]').forEach(item => {
      item.style.display = 'none';
    });
  }
}

// ============================================
// Confirm Dialog
// ============================================

function confirm(message, onConfirm, onCancel) {
  const modal = document.createElement('div');
  modal.className = 'fixed inset-0 z-50';
  modal.innerHTML = `
    <div class="modal-backdrop absolute inset-0" style="background: rgba(0,0,0,0.5); backdrop-filter: blur(4px);"></div>
    <div class="absolute inset-0 flex items-center justify-center p-4">
      <div class="bg-white rounded-xl shadow-2xl w-full max-w-md relative">
        <div class="p-6">
          <div class="w-12 h-12 bg-yellow-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <svg class="w-6 h-6 text-yellow-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
            </svg>
          </div>
          <h3 class="text-lg font-semibold text-charcoal text-center mb-2">Confirm Action</h3>
          <p class="text-charcoal-300 text-center mb-6">${escapeHtml(message)}</p>
          <div class="flex items-center justify-center gap-3">
            <button id="confirm-cancel" class="px-4 py-2.5 border border-gray-200 rounded-lg text-charcoal font-medium hover:bg-gray-50 transition-colors">
              Cancel
            </button>
            <button id="confirm-ok" class="px-4 py-2.5 bg-primary hover:bg-primary-600 text-white font-medium rounded-lg transition-colors">
              Confirm
            </button>
          </div>
        </div>
      </div>
    </div>
  `;

  document.body.appendChild(modal);

  modal.querySelector('#confirm-cancel').addEventListener('click', () => {
    modal.remove();
    if (onCancel) onCancel();
  });

  modal.querySelector('#confirm-ok').addEventListener('click', () => {
    modal.remove();
    if (onConfirm) onConfirm();
  });

  modal.querySelector('.modal-backdrop').addEventListener('click', () => {
    modal.remove();
    if (onCancel) onCancel();
  });
}


// ============================================
// CSS Animations (inject once)
// ============================================

const styleEl = document.createElement('style');
styleEl.textContent = `
  @keyframes slide-in {
    from { transform: translateX(100%); opacity: 0; }
    to { transform: translateX(0); opacity: 1; }
  }
  @keyframes fade-out {
    from { opacity: 1; }
    to { opacity: 0; }
  }
  .animate-slide-in { animation: slide-in 0.3s ease-out; }
  .animate-fade-out { animation: fade-out 0.3s ease-out; }
`;
document.head.appendChild(styleEl);
