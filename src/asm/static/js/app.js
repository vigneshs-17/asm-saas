/* ASM SaaS Dashboard - Client Application Logic
   Uses Supabase JS (UMD) and HTMX.
   Strict Security Constraints:
   - Zero DOM property mutations with raw untrusted data (textContent only)
   - htmx.config.allowEval = false
   - htmx.config.allowScriptTags = false
   - Tokens in module memory, backed by sessionStorage
*/

(function () {
  'use strict';

  // Configure HTMX security settings immediately
  if (window.htmx) {
    window.htmx.config.allowEval = false;
    window.htmx.config.allowScriptTags = false;
  }

  // Module variable holding current JWT access token
  let currentAccessToken = null;
  let isAuthenticated = false;
  let isRefreshing = false;
  let supabaseClient = null;

  // Retrieve configuration from data attributes on document body
  const bodyEl = document.body;
  const supabaseUrl = bodyEl.getAttribute('data-supabase-url') || '';
  const supabaseKey = bodyEl.getAttribute('data-supabase-key') || '';

  if (window.supabase && supabaseUrl && supabaseKey) {
    supabaseClient = window.supabase.createClient(supabaseUrl, supabaseKey, {
      auth: {
        persistSession: true,
        storage: window.sessionStorage,
        autoRefreshToken: true,
        detectSessionInUrl: false,
      },
    });

    supabaseClient.auth.onAuthStateChange(function (event, session) {
      if (session && session.access_token) {
        currentAccessToken = session.access_token;
        if (event === 'TOKEN_REFRESHED') {
          return;
        }
        if ((event === 'SIGNED_IN' || event === 'INITIAL_SESSION') && !isAuthenticated) {
          isAuthenticated = true;
          onUserAuthenticated(session.user);
        }
      } else if (event === 'SIGNED_OUT' || !session) {
        currentAccessToken = null;
        isAuthenticated = false;
        onUserSignedOut();
      }
    });
  }

  // Inject Authorization Bearer token into all HTMX requests synchronously
  document.body.addEventListener('htmx:configRequest', function (evt) {
    if (currentAccessToken) {
      evt.detail.headers['Authorization'] = 'Bearer ' + currentAccessToken;
    }
  });

  // Handle HTMX response errors (e.g. 401 token expiration)
  document.body.addEventListener('htmx:responseError', async function (evt) {
    const xhr = evt.detail.xhr;
    if (xhr && xhr.status === 401 && !isRefreshing && supabaseClient) {
      isRefreshing = true;
      try {
        const { data, error } = await supabaseClient.auth.refreshSession();
        if (error || !data || !data.session) {
          throw error || new Error('Session refresh failed');
        }
        currentAccessToken = data.session.access_token;
        isRefreshing = false;
        // Retry the failed HTMX request once, keeping the original element's swap style.
        // The scan detail poller uses hx-target="this" + hx-swap="outerHTML"; retrying with
        // htmx's default swap (replace the target's children) would nest a second polling
        // <section> inside the first.
        if (evt.detail.requestConfig) {
          const cfg = evt.detail.requestConfig;
          const sourceElt = evt.detail.elt;
          const swapStyle = sourceElt && sourceElt.getAttribute
            ? sourceElt.getAttribute('hx-swap')
            : null;
          const retryContext = {
            target: evt.detail.target,
            headers: Object.assign({}, cfg.headers, {
              Authorization: 'Bearer ' + currentAccessToken,
            }),
          };
          if (swapStyle) {
            retryContext.swap = swapStyle;
          }
          window.htmx.ajax(cfg.verb.toUpperCase(), cfg.path, retryContext);
        }
      } catch (err) {
        isRefreshing = false;
        currentAccessToken = null;
        await supabaseClient.auth.signOut();
        onUserSignedOut();
      }
    }
  });

  // UI state toggles
  function onUserAuthenticated(user) {
    const authContainer = document.getElementById('auth-section');
    const appShell = document.getElementById('app-shell');
    const userDisplay = document.getElementById('user-email-display');

    if (authContainer) authContainer.classList.add('hidden');
    if (appShell) appShell.classList.remove('hidden');
    if (userDisplay && user && user.email) {
      userDisplay.textContent = user.email;
    }

    // Load user organizations
    loadOrgSwitcher();
  }

  function onUserSignedOut() {
    isAuthenticated = false;
    currentAccessToken = null;
    const authContainer = document.getElementById('auth-section');
    const appShell = document.getElementById('app-shell');
    const contentArea = document.getElementById('main-content-area');
    const orgSelector = document.getElementById('org-switcher-select');

    if (authContainer) authContainer.classList.remove('hidden');
    if (appShell) appShell.classList.add('hidden');
    if (contentArea) {
      while (contentArea.firstChild) {
        contentArea.removeChild(contentArea.firstChild);
      }
    }
    if (orgSelector) {
      while (orgSelector.firstChild) {
        orgSelector.removeChild(orgSelector.firstChild);
      }
    }
  }

  // Load organizations list for current user
  async function loadOrgSwitcher() {
    if (!currentAccessToken) return;
    try {
      const resp = await authenticatedFetch('/orgs');
      if (resp.status === 401) return;
      if (!resp.ok) {
        throw new Error('Failed to fetch organizations');
      }
      const orgs = await resp.json();
      const orgSelect = document.getElementById('org-switcher-select');
      if (!orgSelect) return;

      while (orgSelect.firstChild) {
        orgSelect.removeChild(orgSelect.firstChild);
      }

      if (!orgs || orgs.length === 0) {
        // User has no organizations; render empty org creation screen
        loadEmptyOrgView();
        return;
      }

      orgs.forEach(function (org) {
        const opt = document.createElement('option');
        opt.value = String(org.id);
        opt.textContent = org.name + ' (' + org.role + ')';
        orgSelect.appendChild(opt);
      });

      // Default to first organization
      const selectedOrgId = orgs[0].id;
      loadDomainsList(selectedOrgId);
    } catch (err) {
      showError('Failed to load organizations: ' + err.message);
    }
  }

  function loadEmptyOrgView() {
    return window.htmx.ajax('GET', '/ui/empty-org', {
      target: '#main-content-area',
    });
  }

  function loadDomainsList(orgId) {
    if (!orgId) return Promise.resolve();
    return window.htmx.ajax('GET', '/ui/orgs/' + orgId + '/domains', {
      target: '#main-content-area',
    });
  }

  function loadDomainDetail(orgId, domainId) {
    if (!orgId || !domainId) return Promise.resolve();
    return window.htmx.ajax('GET', '/ui/orgs/' + orgId + '/domains/' + domainId, {
      target: '#main-content-area',
    });
  }

  function loadScansList(orgId, domainId) {
    if (!orgId || !domainId) return Promise.resolve();
    return window.htmx.ajax('GET', '/ui/orgs/' + orgId + '/domains/' + domainId + '/scans', {
      target: '#main-content-area',
    });
  }

  function loadScanDetail(orgId, scanId) {
    if (!orgId || !scanId) return Promise.resolve();
    return window.htmx.ajax('GET', '/ui/orgs/' + orgId + '/scans/' + scanId, {
      target: '#main-content-area',
    });
  }

  // Authenticated fetch wrapper
  async function authenticatedFetch(url, options) {
    const opts = options || {};
    opts.headers = opts.headers || {};
    if (currentAccessToken) {
      opts.headers['Authorization'] = 'Bearer ' + currentAccessToken;
    }
    let resp = await fetch(url, opts);
    if (resp.status === 401 && supabaseClient && !isRefreshing) {
      isRefreshing = true;
      try {
        const { data, error } = await supabaseClient.auth.refreshSession();
        if (error || !data || !data.session) {
          throw error || new Error('Refresh failed');
        }
        currentAccessToken = data.session.access_token;
        isRefreshing = false;
        opts.headers['Authorization'] = 'Bearer ' + currentAccessToken;
        resp = await fetch(url, opts);
      } catch (err) {
        isRefreshing = false;
        currentAccessToken = null;
        isAuthenticated = false;
        await supabaseClient.auth.signOut();
        onUserSignedOut();
      }
    }
    return resp;
  }

  function formatErrorMessage(detailOrMsg, fallback) {
    if (!detailOrMsg) return fallback || 'An unexpected error occurred.';
    if (Array.isArray(detailOrMsg)) {
      // FastAPI 422 validation errors: array of objects with 'msg'
      const messages = detailOrMsg.map(function (item) {
        return item && item.msg ? item.msg : String(item);
      });
      return messages.join('; ');
    }
    if (typeof detailOrMsg === 'object') {
      if (detailOrMsg.detail) {
        return formatErrorMessage(detailOrMsg.detail, fallback);
      }
      if (detailOrMsg.message) {
        return String(detailOrMsg.message);
      }
      return JSON.stringify(detailOrMsg);
    }
    return String(detailOrMsg);
  }

  function showError(detailOrMsg, fallback) {
    const errBox = document.getElementById('global-error-box');
    if (errBox) {
      errBox.textContent = formatErrorMessage(detailOrMsg, fallback);
      errBox.classList.remove('hidden');
    }
  }

  function clearError() {
    const errBox = document.getElementById('global-error-box');
    if (errBox) {
      errBox.textContent = '';
      errBox.classList.add('hidden');
    }
  }

  // Global Event Delegation (Form submissions, Actions, Copy buttons)
  document.addEventListener('submit', async function (evt) {
    const form = evt.target;

    // 1. Sign-in Form
    if (form && form.id === 'signin-form') {
      evt.preventDefault();
      clearError();
      const emailInput = form.querySelector('input[name="email"]');
      const passInput = form.querySelector('input[name="password"]');
      const email = emailInput ? emailInput.value.trim() : '';
      const password = passInput ? passInput.value : '';

      if (!email || !password) {
        showError('Email and password are required.');
        return;
      }

      if (!supabaseClient) {
        showError('Authentication client is not configured.');
        return;
      }

      const { data, error } = await supabaseClient.auth.signInWithPassword({
        email: email,
        password: password,
      });

      if (error) {
        showError(error.message);
      }
      // On success, onAuthStateChange fires SIGNED_IN and calls onUserAuthenticated once.
      return;
    }

    // 2. Create Organization Form (POST /orgs)
    if (form && form.id === 'create-org-form') {
      evt.preventDefault();
      clearError();
      const nameInput = form.querySelector('input[name="name"]');
      const name = nameInput ? nameInput.value.trim() : '';
      if (!name) {
        showError('Organization name is required.');
        return;
      }

      try {
        const resp = await authenticatedFetch('/orgs', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: name }),
        });

        if (!resp.ok) {
          const errData = await resp.json().catch(function () { return {}; });
          showError(errData.detail || 'Failed to create organization.');
          return;
        }

        const newOrg = await resp.json();
        await loadOrgSwitcher();
      } catch (err) {
        showError('Error creating organization: ' + err.message);
      }
      return;
    }

    // 3. Add Domain Form (POST /orgs/{org_id}/domains)
    if (form && form.id === 'add-domain-form') {
      evt.preventDefault();
      clearError();
      const orgId = form.getAttribute('data-org-id');
      const nameInput = form.querySelector('input[name="name"]');
      const name = nameInput ? nameInput.value.trim() : '';

      if (!name) {
        showError('Domain name is required.');
        return;
      }

      try {
        const resp = await authenticatedFetch('/orgs/' + orgId + '/domains', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: name }),
        });

        if (!resp.ok) {
          const errData = await resp.json().catch(function () { return {}; });
          showError(errData.detail || 'Failed to add domain.');
          return;
        }

        loadDomainsList(orgId);
      } catch (err) {
        showError('Error adding domain: ' + err.message);
      }
      return;
    }
  });

  // Click handler delegation
  document.addEventListener('click', async function (evt) {
    const target = evt.target;
    if (!target) return;

    // Sign out button
    if (target.id === 'signout-button') {
      evt.preventDefault();
      if (supabaseClient) {
        await supabaseClient.auth.signOut();
      }
      currentAccessToken = null;
      onUserSignedOut();
      return;
    }

    // Copy to clipboard
    if (target.classList.contains('btn-copy')) {
      evt.preventDefault();
      const copyValue = target.getAttribute('data-copy-value') || '';
      if (copyValue) {
        navigator.clipboard.writeText(copyValue).then(function () {
          const origText = target.textContent;
          target.textContent = 'Copied!';
          setTimeout(function () {
            target.textContent = origText;
          }, 2000);
        });
      }
      return;
    }

    // Navigation: View domain details
    if (target.classList.contains('btn-view-domain')) {
      evt.preventDefault();
      const orgId = target.getAttribute('data-org-id');
      const domainId = target.getAttribute('data-domain-id');
      loadDomainDetail(orgId, domainId);
      return;
    }

    // Navigation: Back to domains list
    if (target.id === 'btn-back-domains') {
      evt.preventDefault();
      const orgId = target.getAttribute('data-org-id');
      loadDomainsList(orgId);
      return;
    }

    // Action: Check Verification Now (POST /orgs/{org_id}/domains/{domain_id}/verification/check)
    if (target.id === 'btn-check-verification') {
      evt.preventDefault();
      clearError();
      const orgId = target.getAttribute('data-org-id');
      const domainId = target.getAttribute('data-domain-id');

      target.disabled = true;
      const originalBtnText = target.textContent;
      target.textContent = 'Checking...';

      try {
        const resp = await authenticatedFetch(
          '/orgs/' + orgId + '/domains/' + domainId + '/verification/check',
          { method: 'POST' }
        );

        target.disabled = false;
        target.textContent = originalBtnText;

        if (resp.status === 429) {
          const errData = await resp.json().catch(function () { return {}; });
          showError(errData.detail || 'Verification check is on cooldown.');
          return;
        }

        if (!resp.ok) {
          const errData = await resp.json().catch(function () { return {}; });
          showError(errData.detail || 'Verification check failed.');
          return;
        }

        const data = await resp.json();

        // Refresh domain detail FIRST, then render check_outcome/check_detail into #verification-check-result AFTER swap finishes
        loadDomainDetail(orgId, domainId).then(function () {
          const freshResultContainer = document.getElementById('verification-check-result');
          if (freshResultContainer) {
            while (freshResultContainer.firstChild) {
              freshResultContainer.removeChild(freshResultContainer.firstChild);
            }

            const box = document.createElement('div');
            box.className = 'alert-box alert-info';

            const title = document.createElement('strong');
            title.textContent = 'Check outcome: ' + (data.check_outcome || 'unknown');
            box.appendChild(title);

            if (data.check_detail) {
              const detailPara = document.createElement('p');
              detailPara.className = 'text-muted';
              detailPara.textContent = data.check_detail;
              box.appendChild(detailPara);
            }

            freshResultContainer.appendChild(box);
          }
        });
      } catch (err) {
        target.disabled = false;
        target.textContent = originalBtnText;
        showError('Verification check error: ' + err.message);
      }
      return;
    }

    // Action: Rotate Verification Token (POST /orgs/{org_id}/domains/{domain_id}/verification/rotate)
    if (target.id === 'btn-rotate-token') {
      evt.preventDefault();
      clearError();
      const orgId = target.getAttribute('data-org-id');
      const domainId = target.getAttribute('data-domain-id');

      if (!window.confirm('Rotating the token will invalidate the current DNS verification record. Continue?')) {
        return;
      }

      try {
        const resp = await authenticatedFetch(
          '/orgs/' + orgId + '/domains/' + domainId + '/verification/rotate',
          { method: 'POST' }
        );

        if (!resp.ok) {
          const errData = await resp.json().catch(function () { return {}; });
          showError(errData.detail || 'Token rotation failed.');
          return;
        }

        // Refresh domain detail
        loadDomainDetail(orgId, domainId);
      } catch (err) {
        showError('Token rotation error: ' + err.message);
      }
      return;
    }

    // Navigation: View domain scans list
    if (target.classList.contains('btn-view-scans')) {
      evt.preventDefault();
      clearError();
      const orgId = target.getAttribute('data-org-id');
      const domainId = target.getAttribute('data-domain-id');
      loadScansList(orgId, domainId);
      return;
    }

    // Navigation: View scan detail
    if (target.classList.contains('btn-view-scan')) {
      evt.preventDefault();
      clearError();
      const orgId = target.getAttribute('data-org-id');
      const scanId = target.getAttribute('data-scan-id');
      loadScanDetail(orgId, scanId);
      return;
    }

    // Navigation: Back to domain detail
    if (target.id === 'btn-back-domain-detail') {
      evt.preventDefault();
      clearError();
      const orgId = target.getAttribute('data-org-id');
      const domainId = target.getAttribute('data-domain-id');
      loadDomainDetail(orgId, domainId);
      return;
    }

    // Action: Manually refresh a scan whose automatic polling stopped (15-minute cap)
    if (target.id === 'btn-refresh-scan') {
      evt.preventDefault();
      clearError();
      const orgId = target.getAttribute('data-org-id');
      const scanId = target.getAttribute('data-scan-id');
      loadScanDetail(orgId, scanId);
      return;
    }

    // Navigation: Back to scans list
    if (target.id === 'btn-back-scans') {
      evt.preventDefault();
      clearError();
      const orgId = target.getAttribute('data-org-id');
      const domainId = target.getAttribute('data-domain-id');
      loadScansList(orgId, domainId);
      return;
    }

    // Action: Run Scan (POST /orgs/{org_id}/domains/{domain_id}/scans)
    if (target.id === 'btn-run-scan') {
      evt.preventDefault();
      clearError();
      const orgId = target.getAttribute('data-org-id');
      const domainId = target.getAttribute('data-domain-id');

      target.disabled = true;
      const originalBtnText = target.textContent;
      target.textContent = 'Starting scan...';

      const idempotencyKey = (window.crypto && window.crypto.randomUUID)
        ? window.crypto.randomUUID()
        : String(Date.now());

      try {
        const resp = await authenticatedFetch(
          '/orgs/' + orgId + '/domains/' + domainId + '/scans',
          {
            method: 'POST',
            headers: {
              'Idempotency-Key': idempotencyKey,
            },
          }
        );

        target.disabled = false;
        target.textContent = originalBtnText;

        if (resp.status === 409) {
          const errData = await resp.json().catch(function () { return {}; });
          showError(errData.detail || 'A scan is already active for this domain.');
          return;
        }

        if (resp.status === 422) {
          const errData = await resp.json().catch(function () { return {}; });
          showError(errData.detail || 'Domain ownership verification required before scanning.');
          return;
        }

        if (!resp.ok) {
          const errData = await resp.json().catch(function () { return {}; });
          showError(errData.detail || 'Failed to start scan.');
          return;
        }

        const scanData = await resp.json();
        loadScanDetail(orgId, scanData.id);
      } catch (err) {
        target.disabled = false;
        target.textContent = originalBtnText;
        showError('Run scan error: ' + err.message);
      }
      return;
    }
  });

  // Org switcher change handler
  document.addEventListener('change', function (evt) {
    if (evt.target && evt.target.id === 'org-switcher-select') {
      const orgId = evt.target.value;
      clearError();
      loadDomainsList(orgId);
    }
  });
})();
