// Authenticated transport for the Apiary cockpit. This module owns browser and
// desktop session renewal so rendering code never assembles auth headers or
// persists session credentials itself.
'use strict';

function bytesBase64(bytes) {
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

async function sha256Hex(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return [...digest].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

export function createApiaryClient(token) {
  let sessionCsrf = sessionStorage.getItem('apiary.csrf');
  let sessionNpub = sessionStorage.getItem('apiary.npub');
  let browserConnecting = null;
  let desktopConnecting = null;
  let desktop = null;
  try {
    const encoded = new URLSearchParams(location.hash.slice(1)).get('desktop');
    if (encoded) desktop = JSON.parse(encoded);
  } catch {
    desktop = null;
  }
  let desktopAccess = sessionStorage.getItem('apiary.desktop_access');
  if (desktop && desktop.access_token) {
    desktopAccess = desktop.access_token;
    sessionStorage.setItem('apiary.desktop_access', desktopAccess);
  }

  function headers(extra) {
    const result = Object.assign({}, extra);
    if (token) result['x-apiary-token'] = token;
    if (sessionCsrf) result['x-apiary-csrf'] = sessionCsrf;
    return result;
  }

  async function nip98Authorization(url, opts) {
    if (!window.nostr || typeof window.nostr.signEvent !== 'function') {
      throw new Error('This Apiary host requires a Nostr signer. Enable a NIP-07 browser signer, then reload.');
    }
    const method = String((opts && opts.method) || 'GET').toUpperCase();
    const target = new URL(url, location.href);
    const tags = [['u', target.href], ['method', method]];
    if (opts && opts.body !== undefined && opts.body !== null) {
      tags.push(['payload', await sha256Hex(String(opts.body))]);
    }
    const signed = await window.nostr.signEvent({
      kind: 27235,
      created_at: Math.floor(Date.now() / 1000),
      tags,
      content: '',
    });
    return 'Nostr ' + bytesBase64(new TextEncoder().encode(JSON.stringify(signed)));
  }

  function rememberSession(result) {
    sessionCsrf = result.csrf;
    sessionNpub = result.npub;
    sessionStorage.setItem('apiary.csrf', result.csrf);
    sessionStorage.setItem('apiary.npub', result.npub);
    return result;
  }

  async function establishBrowserSession() {
    if (browserConnecting) return browserConnecting;
    browserConnecting = (async () => {
      const opts = { method: 'POST' };
      const authorization = await nip98Authorization('/api/session', opts);
      const response = await fetch('/api/session', {
        method: 'POST',
        credentials: 'same-origin',
        headers: headers({ authorization }),
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok || !result.ok) {
        throw new Error(result.error || `Nostr sign-in was refused (${response.status}).`);
      }
      return rememberSession(result);
    })();
    try {
      return await browserConnecting;
    } finally {
      browserConnecting = null;
    }
  }

  async function establishDesktopSession(manager) {
    if (!desktopAccess) throw new Error('The SSH desktop credential is unavailable. Reconnect this workspace.');
    if (desktopConnecting) return desktopConnecting;
    desktopConnecting = (async () => {
      let choice = manager || null;
      // Two passes at most: the first may learn WHICH identity to renew as.
      for (let attempt = 0; attempt < 2; attempt++) {
        const response = await fetch('/api/desktop/session', {
          method: 'POST',
          credentials: 'same-origin',
          headers: {
            authorization: 'Bearer ' + desktopAccess,
            'content-type': 'application/json',
          },
          body: JSON.stringify(choice ? { manager: choice } : {}),
        });
        const result = await response.json().catch(() => ({}));
        if (response.status === 409 && Array.isArray(result.managers)) {
          // The host refuses to guess between approved managers. That is
          // right for a NEW sign-in and wrong for a RENEWAL: this session
          // already had an identity, and the daemon restarting is not a
          // reason to ask again. Come back as whoever we already were;
          // only a genuinely unknown identity is worth a question.
          const known = sessionNpub
            && result.managers.some(entry => entry.npub === sessionNpub);
          if (!choice && known) { choice = sessionNpub; continue; }
          const error = new Error(result.error || 'Choose an approved manager for this desktop session.');
          error.desktopManagers = result.managers;
          throw error;
        }
        if (!response.ok || !result.ok) {
          throw new Error(result.error || `Desktop authentication was refused (${response.status}).`);
        }
        return rememberSession(result);
      }
      throw new Error('This workspace could not renew its desktop session.');
    })();
    try {
      return await desktopConnecting;
    } finally {
      desktopConnecting = null;
    }
  }

  async function authenticatedFetch(url, opts, retried) {
    const request = Object.assign({}, opts || {});
    request.credentials = 'same-origin';
    request.headers = headers(request.headers);
    const response = await fetch(url, request);
    if (response.status === 401 && !retried && !token) {
      if (desktopAccess) await establishDesktopSession();
      else if (sessionStorage.getItem('apiary.nip46') === 'connected') {
        sessionStorage.removeItem('apiary.nip46');
        sessionStorage.removeItem('apiary.csrf');
        sessionStorage.removeItem('apiary.npub');
        throw new Error('Your remote-signer session expired. Sign in with the NIP-46 signer again.');
      } else await establishBrowserSession();
      return authenticatedFetch(url, opts, true);
    }
    return response;
  }

  async function json(url, opts) {
    const response = await authenticatedFetch(url, opts);
    return response.json();
  }

  async function signOut() {
    const response = await fetch('/api/session', {
      method: 'DELETE',
      credentials: 'same-origin',
      headers: headers(),
    });
    if (!response.ok && response.status !== 401) {
      const result = await response.json().catch(() => ({}));
      throw new Error(result.error || `Sign out failed (${response.status}).`);
    }
    sessionCsrf = null;
    sessionNpub = null;
    sessionStorage.removeItem('apiary.csrf');
    sessionStorage.removeItem('apiary.npub');
    sessionStorage.removeItem('apiary.nip46');
    sessionStorage.removeItem('apiary.desktop_access');
    location.replace('/');
  }

  return {
    fetch: authenticatedFetch,
    json,
    signOut,
    establishBrowserSession,
    establishDesktopSession,
    get desktop() { return desktop; },
    get sessionNpub() { return sessionNpub; },
    get hasDesktopAccess() { return Boolean(desktopAccess); },
  };
}
