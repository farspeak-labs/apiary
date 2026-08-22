// Apiary cockpit. All dynamic strings render through textContent — agent
// names, log fields, model output, tool args, and errors are DATA, and the
// governance origin never interprets data as markup. (CSP backs this up:
// no inline script, no external sources.)
import { createApiaryClient } from '/cockpit-api.js';
import {
  inferenceDefaultBaseURL,
  inferenceEndpoint,
  inferenceModels,
  inferenceProviderLabel,
  inferenceProviders,
  inferenceRoleForName,
  inferenceRoleLabel,
} from '/cockpit-inference.js';

let sel = null, tab = 'overview', agents = [], owners = [], managers = [], hostStatus = {};
let hostView = null; // null | 'library' | 'managers' | 'audit' | 'found' | 'import'
let listenerPoll = null;
let manifestRequest = null;
let browserApprovalWatch = null;

// Desktop mode hands the per-launch token in the boot URL; every API call
// echoes it back in a header. Without a token this is a no-op.
const TOKEN = new URLSearchParams(location.search).get('token');
const REMOTE = new URLSearchParams(location.search).get('remote');
const INITIAL_AGENT = new URLSearchParams(location.search).get('agent');
const INITIAL_TAB = new URLSearchParams(location.search).get('tab');
const client = createApiaryClient(TOKEN);
const DESKTOP = client.desktop;
const apiaryFetch = client.fetch;
const j = client.json;
const signOut = client.signOut;
const establishBrowserSession = client.establishBrowserSession;
const establishDesktopSession = client.establishDesktopSession;

// el('div', 'cls', 'text') — safe node construction.
function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}
function shortNostrId(value, leading = 12, trailing = 8) {
  const text = String(value || '');
  if (text.length <= leading + trailing + 1) return text;
  return `${text.slice(0, leading)}…${text.slice(-trailing)}`;
}
function nostrId(value, tag = 'span', cls = null) {
  const node = el(tag, cls, shortNostrId(value));
  node.title = String(value || '');
  node.setAttribute('aria-label', String(value || ''));
  return node;
}
async function copyText(value) {
  const text = String(value || '');
  if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
    await navigator.clipboard.writeText(text);
    return;
  }
  const fallback = el('textarea');
  fallback.value = text;
  fallback.setAttribute('readonly', '');
  fallback.style.cssText = 'position:fixed;left:-9999px;top:0;';
  document.body.append(fallback);
  fallback.select();
  const copied = document.execCommand('copy');
  fallback.remove();
  if (!copied) throw new Error('Clipboard access is unavailable.');
}
function copyableNostrId(value) {
  const full = String(value || '');
  const row = el('div', 'agent-public-id');
  const label = el('span', 'agent-public-id-label', 'Nostr ID');
  const id = el('code', 'agent-public-id-value', full);
  id.title = 'Agent public identity';
  const copy = el('button', 'btn agent-public-id-copy', 'Copy Nostr ID');
  copy.type = 'button';
  const status = el('span', 'agent-public-id-status');
  status.setAttribute('role', 'status');
  status.setAttribute('aria-live', 'polite');
  copy.onclick = async () => {
    try {
      await copyText(full);
      status.textContent = 'Copied';
      copy.textContent = 'Copied';
      setTimeout(() => { copy.textContent = 'Copy Nostr ID'; status.textContent = ''; }, 1800);
    } catch (error) {
      status.textContent = error && error.message ? error.message : 'Could not copy';
    }
  };
  row.append(label, id, copy, status);
  return row;
}
function help(text) { return el('div', 'help', text); }
function kv(k, v) {
  const row = el('div', 'kv');
  row.append(el('span', 'k', k), el('span', 'v', v === undefined || v === null ? '—' : String(v)));
  return row;
}
function section(title, helpText) {
  const s = el('div', 'section');
  s.append(el('h3', null, title));
  if (helpText) s.append(help(helpText));
  return s;
}
function api(path) { return `/api/agents/${encodeURIComponent(sel)}${path}`; }
function currentManifest() {
  if (!manifestRequest) manifestRequest = j(api('/manifest'));
  return manifestRequest;
}

function approvalBrowserUrl() {
  const base = new URL(hostStatus.origin || location.origin);
  base.searchParams.set('agent', sel);
  base.searchParams.set('tab', 'overview');
  return base.href;
}

async function approveWithNostr(governor, status, button) {
  if (!window.nostr || typeof window.nostr.signEvent !== 'function') {
    status.textContent = 'Enable a NIP-07 Nostr signer in this browser, then try again.';
    return false;
  }
  button.disabled = true;
  status.textContent = 'Preparing the approval for your Nostr signer…';
  try {
    const exported = await j(api('/ratify/export'), {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ as: governor }),
    });
    if (!exported.ok) throw new Error(exported.error || 'Apiary could not prepare the approval.');
    status.textContent = 'Confirm the approval in your Nostr signer…';
    const event = await window.nostr.signEvent(exported.unsigned_event);
    const imported = await j(api('/ratify/import'), {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ event }),
    });
    if (!imported.ok) throw new Error(imported.error || 'Apiary could not verify the signed approval.');
    status.textContent = imported.snapshot_warning
      ? 'Approved. Apiary could not save the optional review snapshot: ' + imported.snapshot_warning
      : 'Approved. Opening the agent overview…';
    await loadRoster();
    openTab('overview');
    return true;
  } catch (error) {
    status.textContent = 'Could not approve: ' + (error && error.message ? error.message : String(error));
    return false;
  } finally {
    button.disabled = false;
  }
}

async function connectRemoteSigner(status, button, bunkerUri) {
  const bunker = String(bunkerUri || '').trim();
  if (!bunker.startsWith('bunker://')) {
    status.textContent = 'Paste a bunker:// connection string from your remote signer.';
    return false;
  }
  button.disabled = true;
  status.textContent = 'Connecting to the remote signer…';
  try {
    let response = await fetch('/api/nip46/connect', {
      method: 'POST', credentials: 'same-origin', headers: {'content-type': 'application/json'},
      body: JSON.stringify({bunker_uri: bunker.trim()}),
    });
    let result = await response.json().catch(() => ({}));
    const opened = new Set();
    for (let attempt = 0; attempt < 60; attempt += 1) {
      if (!response.ok) throw new Error(result.error || `Remote signer connection failed (${response.status}).`);
      if (result.ok) {
        sessionStorage.setItem('apiary.csrf', result.csrf);
        sessionStorage.setItem('apiary.npub', result.npub);
        sessionStorage.setItem('apiary.nip46', 'connected');
        status.textContent = 'Remote signer connected. Reloading the approval…';
        location.reload();
        return true;
      }
      if (!result.pending || !result.connection) throw new Error(result.error || 'The remote signer did not complete the connection.');
      if (result.auth_url && !opened.has(result.auth_url)) {
        opened.add(result.auth_url);
        showRemoteSignerAuthorization(status, result.auth_url, 'Approve Apiary in the remote signer, then return here.');
      } else if (!result.auth_url) {
        status.textContent = 'Waiting for the remote signer…';
      }
      await new Promise(resolve => setTimeout(resolve, 1500));
      response = await fetch('/api/nip46/connect/continue', {
        method: 'POST', credentials: 'same-origin', headers: {'content-type': 'application/json'},
        body: JSON.stringify({connection: result.connection}),
      });
      result = await response.json().catch(() => ({}));
    }
    throw new Error('The remote signer did not answer. Check its relay connection and try again.');
  } catch (error) {
    status.textContent = 'Could not connect remote signer: ' + (error && error.message ? error.message : String(error));
    return false;
  } finally {
    button.disabled = false;
  }
}

async function approveWithNip46(governor, status, button) {
  button.disabled = true;
  status.textContent = 'Preparing the approval for your remote signer…';
  try {
    const exported = await j(api('/ratify/export'), {
      method: 'POST', headers: {'content-type': 'application/json'},
      body: JSON.stringify({as: governor}),
    });
    if (!exported.ok) throw new Error(exported.error || 'Apiary could not prepare the approval.');
    let signed;
    const opened = new Set();
    for (let attempt = 0; attempt < 60; attempt += 1) {
      const result = await j('/api/nip46/sign', {
        method: 'POST', headers: {'content-type': 'application/json'},
        body: JSON.stringify({unsigned_event: exported.unsigned_event}),
      });
      if (result.ok) { signed = result.event; break; }
      if (result.code === 'nip46_auth_required' && result.auth_url) {
        if (!opened.has(result.auth_url)) {
          opened.add(result.auth_url);
          showRemoteSignerAuthorization(status, result.auth_url, 'Approve this event in the remote signer, then return here.');
        }
      } else if (result.pending) {
        status.textContent = 'Waiting for the remote signer to sign…';
      } else {
        throw new Error(result.error || 'The remote signer could not sign this approval.');
      }
      await new Promise(resolve => setTimeout(resolve, 1500));
    }
    if (!signed) throw new Error('The remote signer did not answer.');
    const imported = await j(api('/ratify/import'), {
      method: 'POST', headers: {'content-type': 'application/json'},
      body: JSON.stringify({event: signed}),
    });
    if (!imported.ok) throw new Error(imported.error || 'Apiary could not verify the signed approval.');
    status.textContent = 'Approved. Opening the agent overview…';
    await loadRoster();
    openTab('overview');
    return true;
  } catch (error) {
    status.textContent = 'Could not approve: ' + (error && error.message ? error.message : String(error));
    return false;
  } finally {
    button.disabled = false;
  }
}

function ownerHolders(keys) {
  const byNpub = new Map();
  for (const identity of [...owners, ...agents]) byNpub.set(identity.npub, identity);
  return [...byNpub.values()].filter(identity => keys.some(k => k === identity.npub));
}

function approvalPeople() {
  const byNpub = new Map();
  for (const identity of [...managers, ...owners]) byNpub.set(identity.npub, identity);
  return [...byNpub.values()].sort((a, b) => (a.name || a.npub).localeCompare(b.name || b.npub));
}

function agentManagerCandidates(target) {
  const byNpub = new Map();
  for (const identity of approvalPeople()) byNpub.set(identity.npub, {...identity, identityKind: 'person'});
  for (const agent of agents) {
    if (agent.npub !== target) byNpub.set(agent.npub, {...agent, identityKind: 'agent'});
  }
  return [...byNpub.values()].sort((a, b) => (a.name || a.npub).localeCompare(b.name || b.npub));
}

function field(labelText, control, hint) {
  const label = el('label', 'field');
  label.append(el('span', null, labelText), control);
  if (hint) label.append(el('small', null, hint));
  return label;
}

// Technical values must survive the OS/browser text stack byte-for-byte.
// In particular, macOS autocapitalization turns `wss://` into `Wss://`, and
// writing assistants can replace punctuation inside URLs, keys, and tokens.
function technicalInput(control) {
  control.autocomplete = 'off';
  control.spellcheck = false;
  control.setAttribute('autocapitalize', 'none');
  control.setAttribute('autocorrect', 'off');
  control.setAttribute('data-gramm', 'false');
  control.setAttribute('data-gramm_editor', 'false');
  control.setAttribute('data-enable-grammarly', 'false');
  return control;
}

const connectorKindLabel = {
  obsidian: 'Obsidian vault',
  'markdown-vault': 'Markdown folder',
  'web-search': 'Full web search & research',
  'web-fetch': 'Web page reader',
  files: 'Files and documents',
  git: 'Git repositories',
  mcp: 'MCP server',
  'nostr-publish': 'Nostr publish',
  'mock-echo': 'Test connector',
};

function connectorSupportsReadWrite(kind, caps) {
  if (kind === 'obsidian' || kind === 'markdown-vault') return true;
  if (kind === 'mcp') return !/\/readonly(?:\/|$)/.test((caps && caps.url) || '');
  return false;
}

function connectorAccessMode(kind, caps) {
  if (kind === 'obsidian' || kind === 'markdown-vault') return caps && caps.write ? 'read-write' : 'read-only';
  if (kind === 'mcp') {
    if (caps && caps.access) return caps.access;
    return /\/readonly(?:\/|$)/.test((caps && caps.url) || '') ? 'read-only' : 'read-write';
  }
  return 'read-only';
}

function setConnectorAccess(kind, caps, mode) {
  if (kind === 'obsidian' || kind === 'markdown-vault') caps.write = mode === 'read-write';
  else if (kind === 'mcp') caps.access = mode;
}

function accessSelect(mode = 'read-only') {
  const select = el('select');
  for (const [value, label] of [['read-only', 'Read only'], ['read-write', 'Read + write']]) {
    const option = el('option', null, label); option.value = value; select.append(option);
  }
  select.value = mode;
  select.setAttribute('aria-label', 'Connector access');
  return select;
}

const mcpActionWords = new Set([
  'get', 'list', 'find', 'search', 'lookup', 'check', 'view', 'read',
  'create', 'add', 'update', 'set', 'delete', 'remove', 'submit', 'send',
]);

function singularToolWord(word) {
  if (word.endsWith('ies') && word.length > 3) return word.slice(0, -3) + 'y';
  if (/(ches|shes|xes|zes)$/.test(word)) return word.slice(0, -2);
  if (word.endsWith('s') && !word.endsWith('ss')) return word.slice(0, -1);
  return word;
}

function mcpToolCategory(name) {
  const source = String(name || 'Other');
  const snake = source.split(/[_./:-]+/).filter(Boolean);
  if (snake.length > 1 && !mcpActionWords.has(snake[0].toLowerCase())) {
    const count = snake[0].toLowerCase() === 'platform' && snake.length > 2 ? 2 : 1;
    return snake.slice(0, count).map(word => word[0].toUpperCase() + word.slice(1)).join(' ');
  }
  let words = source
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map(word => word.toLowerCase());
  if (words.length > 1 && mcpActionWords.has(words[0])) words = words.slice(1);
  if (!words.length) return 'Other';
  words = words.slice(0, Math.min(2, words.length));
  words[words.length - 1] = singularToolWord(words[words.length - 1]);
  return words.map(word => word[0].toUpperCase() + word.slice(1)).join(' ');
}

function mcpToolPolicies(tools, caps) {
  const policies = new Map();
  const explicit = caps && caps.tool_access && typeof caps.tool_access === 'object'
    ? caps.tool_access : null;
  if (explicit) {
    for (const tool of tools) {
      const mode = explicit[tool.name];
      if (mode === 'read-write') policies.set(tool.name, tool.read_only ? 'read-only' : 'read-write');
      else if (mode === 'read-only' && tool.read_only) policies.set(tool.name, mode);
    }
    return policies;
  }
  const allowed = new Set((caps && caps.allowed_tools) || []);
  const wildcard = allowed.has('*');
  const mode = connectorAccessMode('mcp', caps || {}) === 'read-only' ? 'read-only' : 'read-write';
  for (const tool of tools) {
    if ((wildcard || allowed.has(tool.name)) && (mode === 'read-write' || tool.read_only)) {
      policies.set(tool.name, tool.read_only ? 'read-only' : mode);
    }
  }
  return policies;
}

function mcpToolPolicyObject(policies) {
  return Object.fromEntries([...policies.entries()].sort(([a], [b]) => a.localeCompare(b)));
}

function renderMcpToolPolicyPicker(root, tools, policies) {
  root.replaceChildren();
  const groups = new Map();
  for (const tool of tools) {
    const category = mcpToolCategory(tool.name);
    if (!groups.has(category)) groups.set(category, []);
    groups.get(category).push(tool);
  }
  const intro = help('Choose a category policy, then refine individual tools. “Read only” is available only when the MCP server explicitly marks that tool readOnlyHint=true; unmarked tools remain blocked unless you grant Read + write.');
  const allRow = el('div', 'row');
  const allPolicy = el('select');
  for (const [value, label] of [['', 'Select across all tools…'], ['blocked', 'Block all'], ['read-only', 'Allow all declared read-only tools'], ['read-write', 'Allow all tools (Read + write where needed)']]) {
    const option = el('option', null, label); option.value = value; allPolicy.append(option);
  }
  allPolicy.onchange = () => {
    if (!allPolicy.value) return;
    for (const tool of tools) {
      let mode = allPolicy.value;
      if (mode === 'read-only' && !tool.read_only) mode = 'blocked';
      if (mode === 'read-write' && tool.read_only) mode = 'read-only';
      if (mode === 'blocked') policies.delete(tool.name);
      else policies.set(tool.name, mode);
    }
    renderMcpToolPolicyPicker(root, tools, policies);
  };
  allRow.append(allPolicy, el('span', 'meta', 'Bulk selection is expanded into explicit named-tool permissions.'));
  root.append(intro, allRow);
  for (const [category, categoryTools] of [...groups.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    const details = el('details', 'mcp-tool-group');
    const selectedCount = () => categoryTools.filter(tool => policies.has(tool.name)).length;
    const summary = el('summary', null, `${category} · ${selectedCount()}/${categoryTools.length} allowed`);
    const categoryRow = el('div', 'row');
    const categoryPolicy = el('select');
    for (const [value, label] of [['', 'Set category…'], ['blocked', 'Block category'], ['read-only', 'Allow declared read-only tools'], ['read-write', 'Allow category (R/W where needed)']]) {
      const option = el('option', null, label); option.value = value; categoryPolicy.append(option);
    }
    categoryRow.append(categoryPolicy, el('span', 'meta', 'Applies to every tool in this category; you can override below.'));
    details.append(summary, categoryRow);
    const selects = [];
    for (const tool of categoryTools.sort((a, b) => a.name.localeCompare(b.name))) {
      const row = el('div', 'mcp-tool-policy');
      const select = el('select');
      const choices = tool.read_only
        ? [['blocked', 'Blocked'], ['read-only', 'Read only']]
        : [['blocked', 'Blocked'], ['read-write', 'Read + write']];
      for (const [value, label] of choices) {
        const option = el('option', null, label); option.value = value; select.append(option);
      }
      select.value = policies.get(tool.name) || 'blocked';
      const description = el('span', 'mcp-tool-description');
      description.append(el('b', null, tool.name), el('span', 'meta', ` · ${tool.read_only ? 'server-marked read only' : 'write-capable or unmarked'}`));
      if (tool.description) description.append(document.createTextNode(' — ' + tool.description));
      select.onchange = () => {
        if (select.value === 'blocked') policies.delete(tool.name);
        else policies.set(tool.name, select.value);
        summary.textContent = `${category} · ${selectedCount()}/${categoryTools.length} allowed`;
        categoryPolicy.value = '';
      };
      selects.push([tool, select]);
      row.append(select, description); details.append(row);
    }
    categoryPolicy.onchange = () => {
      if (!categoryPolicy.value) return;
      for (const [tool, select] of selects) {
        let mode = categoryPolicy.value;
        if (mode === 'read-only' && !tool.read_only) mode = 'blocked';
        if (mode === 'read-write' && tool.read_only) mode = 'read-only';
        select.value = mode;
        if (mode === 'blocked') policies.delete(tool.name);
        else policies.set(tool.name, mode);
      }
      summary.textContent = `${category} · ${selectedCount()}/${categoryTools.length} allowed`;
    };
    root.append(details);
  }
}

function desktopAction(action, params) {
  const target = new URL(`apiary-desktop://${action}`);
  for (const [key, value] of Object.entries(params || {})) {
    if (value !== undefined && value !== null && String(value).trim() !== '') {
      target.searchParams.set(key, String(value).trim());
    }
  }
  location.assign(target.href);
}

function openExternalUrl(url) {
  if (DESKTOP) {
    desktopAction('open-external', { url });
    return;
  }
  const opened = window.open(url, '_blank', 'noopener,noreferrer');
  if (!opened) throw new Error('The browser blocked the signer authorization window. Allow pop-ups for this Apiary host and try again.');
}

function stopBrowserApprovalWatch(watch = browserApprovalWatch) {
  if (!watch) return;
  if (watch.interval) clearInterval(watch.interval);
  if (watch.timeout) clearTimeout(watch.timeout);
  window.removeEventListener('focus', watch.check);
  document.removeEventListener('visibilitychange', watch.onVisibility);
  if (browserApprovalWatch === watch) browserApprovalWatch = null;
}

function watchForBrowserApproval(targetNpub, status, button, { restart = false, announce = false } = {}) {
  if (!DESKTOP || !targetNpub) return null;
  if (browserApprovalWatch?.targetNpub === targetNpub && !restart) {
    browserApprovalWatch.status = status;
    browserApprovalWatch.button = button;
    return browserApprovalWatch;
  }

  stopBrowserApprovalWatch();
  const watch = {
    targetNpub,
    status,
    button,
    checking: false,
    interval: null,
    timeout: null,
    announced: announce,
  };
  watch.onVisibility = () => {
    if (!document.hidden) watch.check();
  };
  watch.check = async () => {
    if (watch.checking || browserApprovalWatch !== watch) return;
    watch.checking = true;
    try {
      const data = await j('/api/agents');
      const updated = data.agents || [];
      const target = updated.find(agent => agent.npub === targetNpub);
      if (!target?.ratified) return;

      agents = updated;
      manifestRequest = null;
      if (watch.status?.isConnected) {
        watch.status.textContent = 'Approval received. Refreshing the agent…';
      }
      stopBrowserApprovalWatch(watch);
      await loadRoster();
      if (sel === targetNpub) {
        tab = 'overview';
        await render();
      }
    } catch (_) {
      // Browser approval may still be in progress; keep polling until timeout.
    } finally {
      watch.checking = false;
    }
  };

  browserApprovalWatch = watch;
  window.addEventListener('focus', watch.check);
  document.addEventListener('visibilitychange', watch.onVisibility);
  watch.interval = setInterval(watch.check, 1500);
  watch.timeout = setTimeout(() => {
    if (browserApprovalWatch !== watch) return;
    stopBrowserApprovalWatch(watch);
    if (watch.button?.isConnected) watch.button.disabled = false;
    if (watch.announced && watch.status?.isConnected) {
      watch.status.textContent = 'Approval has not appeared yet. Complete it in the browser, then try again.';
    }
  }, 300000);
  if (announce) {
    if (button?.isConnected) button.disabled = true;
    if (status?.isConnected) status.textContent = 'Browser opened. Waiting for signed approval…';
  }
  watch.check();
  return watch;
}

function browserApprovalControl(label, url, targetNpub, status) {
  const button = el('button', 'btn', label);
  button.type = 'button';
  watchForBrowserApproval(targetNpub, status, button);
  button.onclick = () => {
    watchForBrowserApproval(targetNpub, status, button, { restart: true, announce: true });
    openExternalUrl(url);
  };
  return button;
}

function showRemoteSignerAuthorization(status, url, message) {
  status.replaceChildren(document.createTextNode(`${message} `));
  status.append(oauthAuthorizeControl('Open signer approval', url));
  if (DESKTOP) openExternalUrl(url);
}

function oauthAuthorizeControl(label, url) {
  if (!DESKTOP) {
    const link = el('a', null, label);
    link.href = url;
    link.target = '_blank';
    link.rel = 'noopener';
    link.style.color = 'var(--amber)';
    return link;
  }
  const button = el('button', 'btn', label);
  button.type = 'button';
  button.onclick = () => desktopAction('open-external', { url });
  return button;
}

function remoteSignerControl(status, label = 'Connect remote signer') {
  const trigger = el('button', 'btn solid', label);
  trigger.type = 'button';

  const panel = section('Connect a NIP-46 remote signer', 'In your signer, create a connection for Apiary and copy its bunker:// connection string. Apiary keeps only a temporary client connection; your private key stays in the signer.');
  panel.hidden = true;
  const uriLabel = el('label', null, 'Bunker connection string');
  const uri = document.createElement('input');
  uri.type = 'text';
  uri.placeholder = 'bunker://…';
  technicalInput(uri);
  uri.setAttribute('aria-label', 'NIP-46 bunker connection string');
  uriLabel.append(uri);
  const connect = el('button', 'btn solid', 'Connect signer');
  connect.type = 'button';
  const cancel = el('button', 'btn', 'Cancel');
  cancel.type = 'button';
  const actions = el('div', 'row');
  actions.append(connect, cancel);
  panel.append(uriLabel, actions);

  trigger.onclick = () => {
    panel.hidden = false;
    trigger.setAttribute('aria-expanded', 'true');
    uri.focus();
  };
  cancel.onclick = () => {
    panel.hidden = true;
    trigger.setAttribute('aria-expanded', 'false');
    status.textContent = '';
  };
  connect.onclick = () => connectRemoteSigner(status, connect, uri.value);
  uri.addEventListener('keydown', event => {
    if (event.key === 'Enter') {
      event.preventDefault();
      connect.click();
    }
  });

  return { trigger, panel };
}

function hostDisplayName() {
  if (DESKTOP) {
    if (DESKTOP.mode !== 'remote') return 'This Mac';
    const profiles = Array.isArray(DESKTOP.remotes) ? DESKTOP.remotes : [];
    const active = profiles.find(profile => profile.id === DESKTOP.active_remote);
    if (active && active.name) return active.name;
  }
  if (REMOTE) return REMOTE;
  if (location.hostname === 'localhost' || location.hostname === '127.0.0.1' || location.hostname === '::1') {
    return 'This Mac';
  }
  return location.hostname || 'Apiary host';
}

function setHostHealth(state, detail) {
  const name = hostDisplayName();
  const label = state === 'online' ? `${name} · Online`
    : state === 'offline' ? `${name} · Unreachable`
      : `${name} · Checking`;
  const toggle = document.getElementById('host-status-toggle');
  const statusLabel = document.getElementById('host-status-label');
  const health = document.getElementById('c-health');
  statusLabel.textContent = label;
  toggle.classList.toggle('is-online', state === 'online');
  toggle.classList.toggle('is-offline', state === 'offline');
  toggle.title = detail || label;
  health.textContent = label;
  health.className = 'chip' + (state === 'online' ? ' ok' : state === 'offline' ? ' bad' : '');
  health.title = detail || label;
}

function renderBackendSwitcher() {
  if (!DESKTOP) return;
  const root = document.getElementById('desktop-backend');
  root.hidden = false;
  root.className = 'backend-control';
  root.replaceChildren();

  const profiles = Array.isArray(DESKTOP.remotes) ? DESKTOP.remotes : [];
  const activeId = DESKTOP.mode === 'remote' ? DESKTOP.active_remote : 'local';
  const active = profiles.find(profile => profile.id === activeId);
  const heading = el('div', 'backend-heading');
  const current = el('span', 'backend-current');
  current.textContent = DESKTOP.mode === 'remote' && active
    ? `${active.name}\n${active.ssh_target}`
    : 'This Mac\nlocal agents and settings';
  current.style.whiteSpace = 'pre-line';
  heading.append(el('strong', null, 'Backend'), current);
  root.append(heading);

  if (DESKTOP.environment_override) {
    root.append(el('div', 'backend-managed', 'This connection is controlled by the APIARY_REMOTE_SSH environment setting. Remove the setting to switch backends here.'));
    return;
  }

  const select = el('select');
  select.setAttribute('aria-label', 'Apiary backend');
  const local = el('option', null, 'This Mac (local)');
  local.value = 'local';
  select.append(local);
  for (const profile of profiles) {
    const option = el('option', null, `${profile.name} (${profile.ssh_target})`);
    option.value = profile.id;
    select.append(option);
  }
  select.value = activeId || 'local';
  const switchButton = el('button', 'btn solid', 'Switch');
  switchButton.type = 'button';
  switchButton.disabled = select.value === activeId;
  switchButton.onclick = () => {
    message.textContent = 'Confirm the backend change in the Apiary dialog.';
    desktopAction('switch', { profile: select.value });
  };
  const primary = el('div', 'backend-actions');
  primary.append(select, switchButton);
  root.append(primary);

  const secondary = el('div', 'backend-secondary');
  const reconnect = el('button', 'btn', 'Reconnect');
  reconnect.type = 'button';
  reconnect.onclick = () => {
    message.textContent = 'Confirm the restart in the Apiary dialog.';
    desktopAction('reconnect');
  };
  const editButton = el('button', 'btn', 'Edit selected server');
  editButton.type = 'button';
  editButton.disabled = select.value === 'local';
  const remove = el('button', 'btn danger', 'Remove saved server');
  remove.type = 'button';
  remove.disabled = select.value === 'local';
  remove.onclick = () => {
    message.textContent = 'Confirm removal in the Apiary dialog.';
    desktopAction('remove', { profile: select.value });
  };
  secondary.append(reconnect, editButton, remove);
  root.append(secondary);

  const message = el('div', 'backend-message');
  message.setAttribute('role', 'status');
  message.setAttribute('aria-live', 'polite');
  root.append(message);

  const input = (label, name, placeholder, options) => {
    const control = el('input');
    control.name = name;
    control.placeholder = placeholder;
    for (const [key, value] of Object.entries(options || {})) {
      if (value === true) control.setAttribute(key, '');
      else control.setAttribute(key, value);
    }
    if (name !== 'name') technicalInput(control);
    return field(label, control);
  };
  const remoteForm = submitLabel => {
    const form = el('form', 'backend-form');
    const name = input('Name', 'name', 'Home server', { required: true, maxlength: '80' });
    name.classList.add('wide');
    const target = input('SSH destination', 'ssh_target', 'user@server', { required: true, maxlength: '255', pattern: '[^\\s]+' });
    target.classList.add('wide');
    const remotePort = input('Apiary port', 'remote_port', '7777', { type: 'number', min: '1', max: '65535', value: '7777' });
    const localPort = input('Preferred local tunnel port', 'local_port', '7777', { type: 'number', min: '1', max: '65535', value: '7777' });
    const sshPort = input('SSH port (optional)', 'ssh_port', '22', { type: 'number', min: '1', max: '65535' });
    const identity = input('SSH key path (optional)', 'identity_file', '/Users/you/.ssh/apiary', { maxlength: '1024' });
    identity.classList.add('wide');
    const submit = el('button', 'btn solid', submitLabel);
    submit.type = 'submit';
    submit.classList.add('wide');
    form.append(name, target, remotePort, localPort, sshPort, identity, submit);
    return form;
  };

  const edit = document.createElement('details');
  edit.className = 'backend-add';
  edit.append(el('summary', null, 'Edit selected server'));
  const editForm = remoteForm('Save changes');
  const fillEditForm = () => {
    const profile = profiles.find(candidate => candidate.id === select.value);
    if (!profile) return;
    editForm.elements.name.value = profile.name || '';
    editForm.elements.ssh_target.value = profile.ssh_target || '';
    editForm.elements.remote_port.value = profile.remote_port || 7777;
    editForm.elements.local_port.value = profile.local_port || 7777;
    editForm.elements.ssh_port.value = profile.ssh_port || '';
    editForm.elements.identity_file.value = profile.identity_file || '';
  };
  editButton.onclick = () => {
    fillEditForm();
    edit.open = true;
    editForm.elements.name.focus();
  };
  editForm.onsubmit = event => {
    event.preventDefault();
    if (!editForm.reportValidity()) return;
    const data = Object.fromEntries(new FormData(editForm).entries());
    data.profile = select.value;
    message.textContent = 'Confirm the server changes in the Apiary dialog.';
    desktopAction('edit', data);
  };
  edit.append(editForm);
  root.append(edit);

  const add = document.createElement('details');
  add.className = 'backend-add';
  add.append(el('summary', null, 'Add a server'));
  const addForm = remoteForm('Save and connect');
  addForm.onsubmit = event => {
    event.preventDefault();
    if (!addForm.reportValidity()) return;
    const data = Object.fromEntries(new FormData(addForm).entries());
    message.textContent = 'Confirm the new server in the Apiary dialog.';
    desktopAction('add', data);
  };
  add.append(addForm);
  root.append(add);

  const syncSelectedServer = () => {
    const localSelected = select.value === 'local';
    switchButton.disabled = select.value === activeId;
    editButton.disabled = localSelected;
    remove.disabled = localSelected;
    edit.hidden = localSelected;
    if (!localSelected && edit.open) fillEditForm();
  };
  select.onchange = syncSelectedServer;
  syncSelectedServer();
}

renderBackendSwitcher();

// ------------------------------------------------------------ host status

async function loadStatus() {
  try {
    hostStatus = await j('/api/status');
    if (!hostStatus.ok) throw new Error(hostStatus.error || 'Could not load this Apiary host.');
  } catch (error) {
    const message = error && error.message ? error.message : 'Could not reach this Apiary host.';
    setHostHealth('offline', message);
    throw error;
  }
  setHostHealth('online', `${hostDisplayName()} is connected and responding.`);
  const set = (id, text, cls) => {
    const n = document.getElementById(id);
    n.textContent = text;
    if (cls !== undefined) n.className = cls;
  };
  set('c-ver', 'Apiary v' + (hostStatus.version || '?'));
  document.getElementById('c-home').title = 'state directory: ' + (hostStatus.home || '?');
  set('c-home', 'State · ' + ((hostStatus.home || '?').split('/').filter(Boolean).pop() || '/'));
  set('c-auth', 'Authentication · ' + (hostStatus.auth || '?')
      + (hostStatus.token_gated ? ' + token' : '')
      + (REMOTE ? ' · SSH → ' + REMOTE : ''));
  document.getElementById('signout').hidden = hostStatus.auth !== 'nip98' || !!TOKEN;
  set('c-model', hostStatus.anthropic_key_present ? 'Drafting model ready' : 'Drafting model unavailable',
      'chip ' + (hostStatus.anthropic_key_present ? 'ok' : ''));
  document.getElementById('c-model').title = hostStatus.anthropic_key_present
    ? 'The host can use ANTHROPIC_API_KEY to draft new agent configurations'
    : 'No host ANTHROPIC_API_KEY. Agent-owned inference credentials may still be configured and ready.';
  set('c-lock', hostStatus.unlocked ? 'Workspace unlocked' : 'Workspace locked · Unlock',
      'chip click ' + (hostStatus.unlocked ? 'ok' : 'bad'));
  // Once unlocked, never ask again: the passphrase prompt disappears and
  // the bar only offers LOCK.
  const unlocked = !!hostStatus.unlocked;
  document.getElementById('u-pass').style.display = unlocked ? 'none' : '';
  document.getElementById('u-go').style.display = unlocked ? 'none' : '';
  document.getElementById('u-remember-row').style.display = !unlocked && hostStatus.can_remember_unlock ? '' : 'none';
  document.getElementById('u-forget').style.display = hostStatus.automatic_unlock && hostStatus.can_forget_unlock ? '' : 'none';
  document.getElementById('u-help').textContent = unlocked
    ? (hostStatus.automatic_unlock
      ? 'keystore unlocked · automatic launch unlock is protected by macOS Keychain'
      : 'keystore unlocked for this session — LOCK to forget the passphrase')
    : 'Workspace locked. Unlock to run agents, approve changes, and use protected credentials.';
}

document.getElementById('signout').onclick = async event => {
  const button = event.currentTarget;
  button.disabled = true;
  try { await signOut(); }
  catch (error) {
    button.disabled = false;
    alert(error && error.message ? error.message : 'Could not sign out.');
  }
};

async function loadOwners() {
  try {
    const d = await j('/api/owners');
    owners = d.ok ? (d.owners || []) : [];
  } catch {
    owners = [];
  }
}

async function loadManagers() {
  try {
    const d = await j('/api/managers');
    managers = d.ok ? (d.managers || []) : [];
  } catch {
    managers = [];
  }
}

document.getElementById('c-lock').onclick = () => {
  const b = document.getElementById('unlockbar');
  b.style.display = b.style.display === 'flex' ? 'none' : 'flex';
};
document.getElementById('c-keytool').onclick = () => {
  const b = document.getElementById('keybar');
  b.style.display = b.style.display === 'flex' ? 'none' : 'flex';
};
async function requestUnlock(passphrase, remember) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 60000);
  try {
    return await j('/api/unlock', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ passphrase, remember: !!remember }),
      signal: controller.signal,
    });
  } catch (error) {
    if (error && error.name === 'AbortError') {
      throw new Error('Unlock timed out after 60 seconds. Check the host connection and try again.');
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}
document.getElementById('u-go').onclick = async () => {
  const button = document.getElementById('u-go');
  const st = document.getElementById('u-status');
  const pass = document.getElementById('u-pass');
  if (!pass.value) { st.textContent = 'Enter the workspace passphrase.'; pass.focus(); return; }
  button.disabled = true;
  const originalLabel = button.textContent;
  button.textContent = 'Unlocking…';
  st.textContent = 'Deriving the workspace key. This normally takes a few seconds.';
  try {
    const r = await requestUnlock(pass.value, document.getElementById('u-remember').checked);
    st.textContent = r.ok
      ? ((r.verified_against_key ? 'Workspace unlocked.' : 'Workspace unlocked (empty keystore).')
        + (r.automatic_unlock ? ' Saved in macOS Keychain.' : '')
        + (r.remember_warning ? ' Could not remember it: ' + r.remember_warning : ''))
      : 'Could not unlock: ' + (r.error || 'The host refused the passphrase.');
    if (!r.ok) return;
    pass.value = '';
    await Promise.all([loadOwners(), loadStatus()]);
    render();
    setTimeout(() => { document.getElementById('unlockbar').style.display = 'none'; }, 1200);
  } catch (error) {
    st.textContent = 'Could not unlock: ' + (error && error.message ? error.message : String(error));
  } finally {
    button.disabled = false;
    button.textContent = originalLabel;
  }
};
document.getElementById('u-lock').onclick = async () => {
  await j('/api/lock', { method: 'POST' });
  document.getElementById('u-status').textContent = hostStatus.automatic_unlock
    ? 'locked for this session · automatic unlock remains saved'
    : 'locked — passphrase forgotten';
  loadStatus();
};
document.getElementById('u-forget').onclick = async () => {
  const r = await j('/api/unlock/forget', { method: 'POST' });
  document.getElementById('u-status').textContent = r.ok
    ? 'automatic unlock removed from macOS Keychain'
    : 'could not remove automatic unlock: ' + r.error;
  await loadStatus();
};
document.getElementById('k-go').onclick = async () => {
  const r = await j('/api/key?key=' + encodeURIComponent(document.getElementById('k-in').value.trim()));
  document.getElementById('k-out').textContent = r.ok ? `${r.npub} · ${r.hex}` : 'invalid: ' + r.error;
};

// ------------------------------------------------------------ roster

async function loadRoster() {
  const d = await j('/api/agents');
  agents = d.agents || [];
  const root = document.getElementById('roster');
  root.replaceChildren();
  const running = new Set((hostStatus.listeners || []).filter(l => l.running).map(l => l.npub));
  const makeCard = a => {
    const card = el('button', 'agent' + (sel === a.npub ? ' sel' : ''));
    card.type = 'button';
    card.setAttribute('aria-pressed', sel === a.npub ? 'true' : 'false');
    const nm = el('div', 'nm', a.name || '(unnamed)');
    nm.append(el('span', 'badge ' + (a.ratified ? 'rat' : 'unrat'), a.ratified ? 'ratified' : 'unratified'));
    nm.append(el('span', 'badge ' + (a.archived ? 'unrat' : a.active ? 'live' : 'unrat'), a.archived ? 'archived' : a.active ? 'active' : 'inactive'));
    if (running.has(a.npub)) nm.append(el('span', 'badge live', 'listening'));
    card.append(nm, nostrId(a.npub, 'div', 'np'), el('div', 'np', a.log_entries + ' signed events'));
    card.onclick = () => { hostView = null; sel = a.npub; render(); loadRoster(); };
    return card;
  };
  const current = agents.filter(a => !a.archived);
  const archived = agents.filter(a => a.archived);
  if (!current.length) root.append(el('div', 'empty', agents.length ? 'No current agents.' : 'Your first agent will appear here.'));
  for (const a of current) root.append(makeCard(a));
  if (archived.length) {
    const group = el('details', 'archived-agents');
    group.open = archived.some(a => a.npub === sel);
    group.append(el('summary', null, `Archived (${archived.length})`));
    for (const a of archived) group.append(makeCard(a));
    root.append(group);
  }
}

document.querySelectorAll('nav button').forEach(b => b.onclick = () => {
  hostView = null;
  tab = b.dataset.tab;
  document.querySelectorAll('nav button').forEach(x => x.classList.toggle('sel', x === b));
  document.querySelectorAll('nav button').forEach(x => x.setAttribute('aria-current', x === b ? 'page' : 'false'));
  render();
});

function openTab(next) {
  hostView = null; tab = next;
  document.querySelectorAll('nav button').forEach(x => {
    const current = x.dataset.tab === next;
    x.classList.toggle('sel', current);
    x.setAttribute('aria-current', current ? 'page' : 'false');
  });
  render();
}

function entryLine(bold, rest, metaLines) {
  const div = el('div', 'entry');
  div.append(el('b', null, bold));
  if (rest) div.append(document.createTextNode(' ' + rest));
  for (const m of metaLines || []) div.append(el('div', 'meta', m));
  return div;
}

// ------------------------------------------------------------ tabs

async function render() {
  if (listenerPoll) { clearInterval(listenerPoll); listenerPoll = null; }
  if (browserApprovalWatch && (browserApprovalWatch.targetNpub !== sel || hostView)) {
    stopBrowserApprovalWatch();
  }
  manifestRequest = null;
  syncSidebarSelection();
  // Agent tabs only make sense when looking at an agent.
  document.querySelector('nav').style.display = (hostView || !sel) ? 'none' : 'flex';
  const c = document.getElementById('content');
  c.replaceChildren();
  if (!hostStatus.unlocked && agents.length) {
    const notice = el('div', 'attention');
    notice.append(el('h2', null, 'Workspace locked'));
    notice.append(help('You can inspect agents while locked. Unlock the workspace to run agents, approve changes, or use protected credentials.'));
    const unlock = el('button', 'btn solid', 'Unlock workspace');
    unlock.onclick = () => {
      document.getElementById('unlockbar').style.display = 'flex';
      document.getElementById('u-pass').focus();
    };
    notice.append(unlock);
    c.append(notice);
  }
  if (hostView === 'library') return renderLibrary(c);
  if (hostView === 'managers') return renderManagers(c);
  if (hostView === 'audit') return renderControlAudit(c);
  if (hostView === 'found') return renderFound(c);
  if (hostView === 'import') return renderImport(c);
  if (!sel && !agents.length) return renderWelcome(c);
  if (!sel) { c.append(el('div', 'empty', 'Choose an agent from the sidebar.')); return; }
  const selectedAgent = agents.find(agent => agent.npub === sel);
  if (selectedAgent && selectedAgent.archived && tab !== 'overview') {
    tab = 'overview';
    document.querySelectorAll('nav button').forEach(button => {
      const current = button.dataset.tab === 'overview';
      button.classList.toggle('sel', current);
      button.setAttribute('aria-current', current ? 'page' : 'false');
    });
  }
  if (!selectedAgent || !selectedAgent.archived) await ratifyBanner(c);
  if (tab === 'overview') return renderOverview(c);
  if (tab === 'run') return renderRun(c);
  if (tab === 'log') return renderLog(c);
  if (tab === 'inference') return renderInference(c);
  if (tab === 'manifest') return renderManifest(c);
  if (tab === 'buzz') return renderBuzz(c);
  if (tab === 'connectors') return renderConnectors(c);
  if (tab === 'skills') return renderSkills(c);
  if (tab === 'routines') return renderRoutines(c);
  if (tab === 'creds') return renderCreds(c);
}

// ------------------------------------------------------------ first run

function setupProgress(current) {
  const steps = el('div', 'setup-steps');
  for (let i = 1; i <= 3; i++) steps.append(el('span', 'setup-step' + (i < current ? ' done' : i === current ? ' current' : '')));
  return steps;
}

function renderWelcome(c) {
  const wrap = el('section', 'setup');
  const card = el('div', 'setup-card');
  wrap.append(card); c.append(wrap);
  const eyebrow = el('div', 'eyebrow', 'Set up Apiary');
  const status = el('div', 'meta');
  status.setAttribute('role', 'status');
  status.setAttribute('aria-live', 'polite');

  if (!hostStatus.unlocked) {
    card.append(eyebrow, el('h2', null, 'Protect your agent workspace'),
      help('Create the passphrase that encrypts identities and credentials on this device. Apiary keeps it in memory only while unlocked.'),
      setupProgress(1));
    const pass = el('input'); pass.type = 'password'; pass.autocomplete = 'new-password';
    const confirm = el('input'); confirm.type = 'password'; confirm.autocomplete = 'new-password';
    const go = el('button', 'btn solid', 'Continue');
    card.append(field('Workspace passphrase', pass, 'Use at least 10 characters and store it somewhere safe.'),
      field('Confirm passphrase', confirm), el('div', 'row'), status);
    card.querySelector('.row').append(go);
    go.onclick = async () => {
      if (pass.value.length < 10) { status.textContent = 'Use at least 10 characters.'; pass.focus(); return; }
      if (pass.value !== confirm.value) { status.textContent = 'The passphrases do not match.'; confirm.focus(); return; }
      go.disabled = true; status.textContent = 'Creating your encrypted workspace…';
      try {
        const r = await requestUnlock(pass.value, false);
        if (!r.ok) { status.textContent = 'Could not unlock: ' + (r.error || 'The host refused the passphrase.'); return; }
        pass.value = ''; confirm.value = '';
        await Promise.all([loadStatus(), loadOwners()]); render();
      } catch (error) {
        status.textContent = 'Could not unlock: ' + (error && error.message ? error.message : String(error));
      } finally {
        go.disabled = false;
      }
    };
    return;
  }

  if (!approvalPeople().length) {
    card.append(eyebrow, el('h2', null, 'Create your approval identity'),
      help('This is your human authority in Apiary. It approves agent configurations and can stop an agent. It is separate from every agent identity.'),
      setupProgress(2));
    const name = el('input'); name.placeholder = 'e.g. Ryan'; name.autocomplete = 'name';
    const go = el('button', 'btn solid', 'Create approval identity');
    const note = el('div', 'attention');
    note.append(el('b', null, 'Why this is separate'), help('An agent can never approve its own permissions. Your approval key is encrypted with the workspace passphrase and never appears as a runnable agent.'));
    const row = el('div', 'row'); row.append(go);
    card.append(field('Your name', name, 'Used only as a local label.'), note, row, status);
    go.onclick = async () => {
      if (!name.value.trim()) { status.textContent = 'Enter a name for your approval identity.'; name.focus(); return; }
      go.disabled = true; status.textContent = 'Creating and encrypting your approval identity…';
      const r = await j('/api/owners', { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({name:name.value.trim()}) });
      go.disabled = false;
      if (!r.ok) { status.textContent = 'Could not create the identity: ' + r.error; return; }
      await Promise.all([loadOwners(), loadStatus()]); render();
    };
    return;
  }

  card.append(eyebrow, el('h2', null, 'Create your first agent'),
    help('Start with a clear job. Apiary creates a conservative configuration for you to review before the agent can run.'),
    setupProgress(3));
  const name = el('input'); name.placeholder = 'e.g. Morning brief';
  const purpose = el('textarea'); purpose.rows = 4; purpose.placeholder = 'What should this agent reliably help you do?';
  const owner = el('select'); owner.multiple = true; owner.size = Math.min(5, Math.max(2, approvalPeople().length));
  approvalPeople().forEach((identity, index) => {
    const option = el('option', null, identity.name || shortNostrId(identity.npub));
    option.value = identity.npub; option.selected = index === 0; owner.append(option);
  });
  const draft = el('input'); draft.type = 'checkbox'; draft.checked = !!hostStatus.anthropic_key_present; draft.disabled = !hostStatus.anthropic_key_present;
  const draftLabel = el('label', 'field'); const draftLine = el('span'); draftLine.append(draft, document.createTextNode(' Tailor the configuration with the connected model'));
  draftLabel.append(draftLine, el('small', null, hostStatus.anthropic_key_present ? 'You will review everything before approval.' : 'No host model credential is configured, so Apiary will use its conservative template.'));
  const go = el('button', 'btn solid', 'Create draft');
  const row = el('div', 'row'); row.append(go);
  card.append(field('Agent name', name), field('Purpose', purpose),
    field('Managed by', owner, 'Choose one or more people. Each selected person can independently approve or stop this agent.'),
    draftLabel, row, status);
  go.onclick = async () => {
    if (!name.value.trim()) { status.textContent = 'Give the agent a name.'; name.focus(); return; }
    if (!purpose.value.trim()) { status.textContent = 'Describe what the agent should do.'; purpose.focus(); return; }
    const selectedManagers = [...owner.selectedOptions].map(option => option.value);
    if (!selectedManagers.length) { status.textContent = 'Choose at least one manager.'; owner.focus(); return; }
    go.disabled = true; status.textContent = 'Creating the identity and draft configuration…';
    const r = await j('/api/agents/found', { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({
      name:name.value.trim(), purpose:purpose.value.trim(), suspend_keys:selectedManagers, draft_with:draft.checked ? 'anthropic' : null,
    }) });
    go.disabled = false;
    if (!r.ok) { status.textContent = 'Could not create the agent: ' + r.error; return; }
    sel = r.npub; tab = 'manifest'; hostView = null;
    document.querySelectorAll('nav button').forEach(x => x.classList.toggle('sel', x.dataset.tab === 'manifest'));
    await Promise.all([loadRoster(), loadStatus()]); render();
  };
}

// ------------------------------------------------------------ overview

// ------------------------------------------------------- ratify banner

/// Amendments (grants, routines, caps, proposals) leave the manifest
/// UNRATIFIED — nothing runs until a governor countersigns. Say so on
/// every tab, with the button right there.
async function ratifyBanner(c) {
  const a = agents.find(x => x.npub === sel);
  if (!a || a.ratified) {
    if (a?.ratified && browserApprovalWatch?.targetNpub === a.npub) {
      stopBrowserApprovalWatch();
    }
    return;
  }
  const box = el('section', 'attention');
  box.append(el('h2', null, 'Review changes before this agent can run'),
    help(`${a.name || 'This agent'} is paused because its configuration has not been approved. Apiary will show you the effective setup and the exact file changes before signing.`));
  const d = await currentManifest();
  const governance = (d.ok && d.manifest && d.manifest.governance) || {};
  const keys = [
    ...(governance.suspend_keys || []),
    ...(governance.managers || []).filter(manager => manager.role === 'governor').map(manager => manager.npub),
  ];
  const holders = ownerHolders(keys);
  const localApprovers = hostStatus.auth === 'open'
    ? holders
    : holders.filter(identity => identity.npub === client.sessionNpub);
  const sessionIsGovernor = !!client.sessionNpub && keys.includes(client.sessionNpub);
  const st = el('div', 'meta');
  st.setAttribute('role', 'status');
  st.setAttribute('aria-live', 'polite');
  c.append(box);
  if (!d.ok) { st.textContent = 'Could not load the configuration: ' + d.error; box.append(st); return; }
  const m = d.manifest || {};
  const inf = (m.inference || [])[0];
  const summary = el('div', 'section');
  summary.append(el('h3', null, 'Effective setup'),
    kv('Model', inf ? `${inf.provider} / ${inf.model}` : 'No model configured'),
    kv('Daily token limit', ((m.governance || {}).budgets || {}).tokens_per_day || 'No limit set'),
    kv('Capabilities', `${(m.connectors || []).length} granted`),
    kv('Always-on channels', Object.keys(m.presence || {}).length),
    kv('Automations', (m.routines || []).length));
  const technical = el('details', 'technical');
  technical.append(el('summary', null, d.approved_yaml ? 'Technical diff' : 'Full configuration for first approval'));
  technical.append(d.approved_yaml ? lineDiff(d.approved_yaml, d.yaml || '') : (() => {
    const pre = el('pre'); pre.textContent = d.yaml || ''; return pre;
  })());
  summary.append(technical); box.append(summary);

  if (localApprovers.length) {
    const who = el('select');
    for (const h of localApprovers) { const o = el('option', null, h.name || shortNostrId(h.npub)); o.value = h.npub; who.append(o); }
    const rat = el('button', 'btn solid', 'Approve configuration');
    const approveRow = el('div', 'row');
    approveRow.append(el('span', 'meta', 'Approve as'), who, rat); box.append(approveRow, st);
    rat.onclick = async () => {
      rat.disabled = true; st.textContent = 'Signing with the agent and your approval identity…';
      const r = await j(api('/ratify'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ as: who.value }) });
      st.textContent = r.ok
        ? (r.snapshot_warning ? 'Approved, but Apiary could not save the review snapshot: ' + r.snapshot_warning : 'Approved. The configuration is now in force.')
        : 'Could not approve: ' + r.error;
      rat.disabled = false;
      if (r.ok) { await loadRoster(); openTab('overview'); }
    };
    return;
  }

  if (sessionIsGovernor && window.nostr && typeof window.nostr.signEvent === 'function') {
    const rat = el('button', 'btn solid', 'Approve with Nostr');
    const approveRow = el('div', 'row');
    approveRow.append(rat); box.append(approveRow, st);
    rat.onclick = () => approveWithNostr(client.sessionNpub, st, rat);
    return;
  }

  if (sessionIsGovernor && sessionStorage.getItem('apiary.nip46') === 'connected') {
    const rat = el('button', 'btn solid', 'Approve with remote signer');
    const reconnect = remoteSignerControl(st, 'Change remote signer');
    const approveRow = el('div', 'row');
    approveRow.append(rat, reconnect.trigger); box.append(approveRow, reconnect.panel, st);
    rat.onclick = () => approveWithNip46(client.sessionNpub, st, rat);
    return;
  }

  if (sessionIsGovernor) {
    const remote = remoteSignerControl(st);
    const row = el('div', 'row');
    row.append(remote.trigger);
    if (!DESKTOP) {
      box.append(row, remote.panel, help('Use a NIP-46 bunker to approve without putting your Nostr private key in Apiary.'), st);
      return;
    }
    const approve = browserApprovalControl(
      'Open secure browser approval',
      approvalBrowserUrl(),
      a.npub,
      st,
    );
    row.append(approve);
    box.append(row, remote.panel, help('Connect a NIP-46 remote signer here, or open a browser that already has a NIP-07 signer. Your private key stays in the signer.'), st);
    return;
  }

  st.textContent = sessionIsGovernor
    ? 'This session is authorized, but no signing key is available. Open Apiary in a browser with your Nostr signer, or use the external signing tools in Configuration.'
    : 'A listed agent governor must approve these changes. Sign in as a governor or ask one to review this agent.';
  const row = el('div', 'row');
  if (tab !== 'manifest') {
    const open = el('button', 'btn', 'Open advanced approval tools');
    open.onclick = () => openTab('manifest');
    row.append(open);
  }
  box.append(row, st);
}

// ------------------------------------------------------ proposal banner

function lineDiff(a, b) {
  const A = a.split('\n'), B = b.split('\n');
  const setA = new Set(A), setB = new Set(B);
  const out = el('pre', 'diff');
  out.style.cssText = 'white-space:pre-wrap;font-size:11px;max-height:280px;overflow:auto;margin:6px 0;';
  // Simple: lines only in B are additions, only in A are removals; common lines shown dim.
  const seenB = new Set();
  for (const line of B) {
    const d = el('div', null, (setA.has(line) ? '  ' : '+ ') + line);
    if (!setA.has(line)) d.style.color = '#7ec87e';
    else d.style.opacity = '0.45';
    out.append(d);
    seenB.add(line);
  }
  for (const line of A) if (!setB.has(line)) { const d = el('div', null, '- ' + line); d.style.color = '#e07070'; out.append(d); }
  return out;
}

async function proposalBanner(c) {
  const p = await j(api('/proposal'));
  if (!p.ok || !p.pending) return;
  const box = el('div', 'ev');
  box.style.borderColor = 'var(--amber)';
  const who = (agents.find(a => a.npub === sel) || {}).name || 'the agent';
  box.append(el('b', null, `${who} proposes an amendment — waiting for you`));
  box.append(kv('summary', p.summary));
  if (p.reason) box.append(kv('its reason', p.reason));
  box.append(kv('proposed', p.at ? new Date(p.at).toLocaleString() : '—'));
  const details = el('details');
  details.append(el('summary', null, 'what would change'));
  details.append(lineDiff(p.current_yaml || '', p.proposed_yaml || ''));
  box.append(details);
  const row = el('div', 'row');
  const acc = el('button', 'btn solid', 'Accept draft');
  const rej = el('button', 'btn danger', 'Reject');
  const st = el('span', 'meta', '');
  row.append(acc, rej, st);
  box.append(row, help('Accepting moves the draft into the configuration review above. It does not approve or run the changes. The agent can propose; only you can enact.'));
  c.append(box);
  acc.onclick = async () => {
    const r = await j(api('/proposal/accept'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    st.textContent = r.ok ? 'Accepted. Review and approve the configuration above.' : 'Failed: ' + r.error;
    if (r.ok) { loadRoster(); setTimeout(render, 800); }
  };
  rej.onclick = async () => {
    const r = await j(api('/proposal/reject'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    st.textContent = r.ok ? 'rejected' : 'failed: ' + r.error;
    if (r.ok) setTimeout(render, 500);
  };
}

// Set when a founding request is approved; renderFound reads it once.
let foundingPrefill = null;

async function foundingBanner(c) {
  const p = await j(api('/founding-proposal'));
  if (!p.ok || !p.pending) return;
  const q = p.request || {};
  const box = el('div', 'ev');
  box.style.borderColor = 'var(--amber)';
  const who = (agents.find(a => a.npub === sel) || {}).name || 'the agent';
  box.append(el('b', null, `${who} requests a new agent: “${q.name}” — waiting for you`));
  box.append(kv('purpose', q.purpose || '—'));
  if (q.reason) box.append(kv('its reason', q.reason));
  if (q.role) box.append(kv('role sketch', q.role));
  if ((q.skills || []).length) box.append(kv('skills', q.skills.join(' · ')));
  if ((q.connectors || []).length) box.append(kv('would need', q.connectors.join(' · ')));
  if (q.tokens_per_day) box.append(kv('proposed spend', q.tokens_per_day + ' tokens/day'));
  box.append(kv('requested', q.at ? new Date(q.at).toLocaleString() : '—'));
  const row = el('div', 'row');
  const acc = el('button', 'btn solid', 'Approve — open founding');
  const rej = el('button', 'btn danger', 'Reject');
  const why = el('input'); why.placeholder = 'why not? (recorded for the agent)'; why.className = 'grow';
  const st = el('span', 'meta', '');
  row.append(acc, rej, why, st);
  box.append(row, help('Approving only opens the founding flow, prefilled from this request. The new agent still gets your review and ratification before anything runs. The decision is recorded where the requesting agent can read it.'));
  c.append(box);
  acc.onclick = async () => {
    const r = await j(api('/founding-proposal/accept'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    if (!r.ok) { st.textContent = 'Failed: ' + r.error; return; }
    foundingPrefill = r.request;
    hostView = 'found';
    document.querySelectorAll('nav button').forEach(x => x.classList.remove('sel'));
    render();
  };
  rej.onclick = async () => {
    const r = await j(api('/founding-proposal/reject'), {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ reason: why.value.trim() }),
    });
    st.textContent = r.ok ? 'rejected and recorded' : 'failed: ' + r.error;
    if (r.ok) setTimeout(render, 500);
  };
}

function metric(label, value) {
  const node = el('div', 'metric');
  node.append(el('span', 'label', label), el('span', 'value', value));
  return node;
}

function quick(title, description, target) {
  const button = el('button', 'quick'); button.type = 'button';
  button.append(el('b', null, title), el('span', null, description));
  button.onclick = () => openTab(target);
  return button;
}

function quickAction(title, description, action) {
  const button = el('button', 'quick'); button.type = 'button';
  button.append(el('b', null, title), el('span', null, description));
  button.onclick = action;
  return button;
}

function agentLifecycleSection(roster) {
  const archived = !!roster.archived;
  const lifecycle = section('Agent lifecycle', archived
    ? 'This agent is archived. It cannot accept new work or be changed, and its standing presence is stopped.'
    : 'Archiving safely removes this agent from everyday use without destroying its portable identity, configuration, or history.');
  const status = el('span', 'meta', '');
  if (!archived) {
    const archive = el('button', 'btn danger', 'Archive agent');
    archive.onclick = async () => {
      if (!confirm(`Archive ${roster.name || 'this agent'}? It will stop running and move out of the normal agent list.`)) return;
      archive.disabled = true; status.textContent = 'Stopping and archiving…';
      const result = await j(api('/archive'), {
        method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify({archived: true}),
      });
      archive.disabled = false;
      if (!result.ok) { status.textContent = 'Could not archive: ' + result.error; return; }
      status.textContent = 'Archived.';
      await loadRoster(); render();
    };
    const row = el('div', 'row'); row.append(archive, status); lifecycle.append(row);
    lifecycle.append(help('An already-running one-time request may finish; archiving prevents all new runs and scheduled work.'));
    return lifecycle;
  }

  const restore = el('button', 'btn solid', 'Restore agent');
  restore.onclick = async () => {
    restore.disabled = true; status.textContent = 'Restoring…';
    const result = await j(api('/archive'), {
      method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify({archived: false}),
    });
    restore.disabled = false;
    if (!result.ok) { status.textContent = 'Could not restore: ' + result.error; return; }
    status.textContent = 'Restored. The agent remains inactive until you explicitly activate it.';
    await loadRoster(); render();
  };
  const restoreRow = el('div', 'row'); restoreRow.append(restore, status); lifecycle.append(restoreRow);

  const permanent = el('details', 'technical');
  permanent.append(el('summary', null, 'Permanently delete this agent'));
  const warning = el('div', 'attention');
  warning.append(el('b', null, 'This cannot be undone'),
    help('Apiary will permanently remove the local private identity, credentials, configuration, signed history, and issued control tokens. Export the agent first if it may be needed again.'));
  const expected = roster.name || sel;
  const confirmation = el('input'); confirmation.placeholder = `Type ${expected} to confirm`;
  confirmation.autocomplete = 'off';
  const remove = el('button', 'btn danger', 'Permanently delete agent'); remove.disabled = true;
  const deleteStatus = el('span', 'meta', '');
  confirmation.oninput = () => { remove.disabled = confirmation.value !== expected; };
  remove.onclick = async () => {
    if (confirmation.value !== expected) return;
    if (!confirm(`Permanently delete ${expected}? There is no recovery without an export.`)) return;
    remove.disabled = true; deleteStatus.textContent = 'Permanently deleting local agent data…';
    const result = await j(`/api/agents/${encodeURIComponent(sel)}`, {
      method: 'DELETE', headers: {'content-type': 'application/json'}, body: JSON.stringify({confirmation: sel}),
    });
    if (!result.ok) { remove.disabled = false; deleteStatus.textContent = 'Could not delete: ' + result.error; return; }
    sel = null; tab = 'overview'; hostView = null;
    await loadRoster(); render();
  };
  const deleteRow = el('div', 'row'); deleteRow.append(remove, deleteStatus);
  permanent.append(warning, field('Confirmation', confirmation), deleteRow);
  lifecycle.append(permanent);
  return lifecycle;
}

async function renderOverview(c) {
  const roster = agents.find(a => a.npub === sel) || {};
  const proposal = roster.archived
    ? Promise.resolve()
    : proposalBanner(c).then(() => foundingBanner(c));
  const [d, spend, listener, controlTokens] = await Promise.all([
    currentManifest(), j(api('/spend')), j(api('/listener')), j(api('/control-tokens')),
  ]);
  await proposal;
  if (!d.ok) { c.append(el('div', 'ev err', 'Could not load this agent: ' + d.error)); return; }
  const m = d.manifest || {};
  const models = m.inference || [];
  const taskModels = models.filter(x => inferenceRoleForName(x.name) === 'language');
  const supportingModels = models.filter(x => inferenceRoleForName(x.name) !== 'language');
  const connectors = m.connectors || [];
  const declared = listener.ok ? (listener.declared || []) : [];
  const routines = m.routines || [];

  const head = el('div', 'page-head');
  head.append(el('div', 'eyebrow', roster.active ? 'Active on this host' : 'Agent overview'),
    el('h2', 'page-title', roster.name || 'Unnamed agent'),
    copyableNostrId(sel),
    el('p', 'page-lede', roster.archived
      ? 'Archived and safely stopped. Restore it to make changes or run it again.'
      : d.ratified
      ? 'Ready for governed tasks. Review its limits, connections, and always-on presence at a glance.'
      : 'Its draft configuration is waiting for your review and approval.'));
  c.append(head);

  const stats = el('div', 'metrics');
  const remaining = spend.ok && spend.remaining !== null && spend.remaining !== undefined
    ? Number(spend.remaining).toLocaleString() : 'Not limited';
  stats.append(metric('Approval', d.ratified ? 'Approved' : 'Needs review'),
    metric('Daily tokens left', remaining),
    metric('Capabilities', String(connectors.length)),
    metric('Always-on channels', String(declared.length)));
  c.append(stats);

  if (roster.archived) {
    c.append(agentLifecycleSection(roster));
    const archivedSetup = section('Archived agent details', 'Archived agents remain inspectable but are read-only until restored.');
    const publicIdentity = kv('Public identity', shortNostrId(sel));
    publicIdentity.querySelector('.v').title = sel;
    archivedSetup.append(publicIdentity, kv('Configuration hash', d.manifest_sha256),
      kv('Signed events', String(roster.log_entries || 0)),
      help('Restore this agent before editing its configuration, granting capabilities, approving changes, or starting work.'));
    c.append(archivedSetup);
    return;
  }

  const shortcuts = el('div', 'quick-grid');
  shortcuts.append(quick('Start a task', 'Give this agent a one-time job.', 'run'),
    quick('Manage capabilities', 'Choose what it can read or change.', 'connectors'),
    quick('Manage skills', 'Add approved workflows and expertise.', 'skills'),
    quickAction('Export or transfer', 'Create a portable agent bundle.', () => {
      const portability = document.getElementById('agent-portability');
      if (!portability) return;
      portability.open = true;
      portability.scrollIntoView({behavior: 'smooth', block: 'start'});
      setTimeout(() => portability.querySelector('input')?.focus(), 320);
    }));
  c.append(shortcuts);

  const constitution = m.constitution || {};
  const character = section('Role and personality',
    'This is the agent’s durable, approved operating character. It guides every response but cannot grant capabilities or override limits.');
  const purpose = el('textarea'); purpose.rows = 4; purpose.value = constitution.purpose || '';
  purpose.placeholder = 'What should this agent reliably help people accomplish?';
  const role = el('input'); role.value = constitution.role || ''; role.placeholder = 'e.g. Research analyst';
  const voice = el('textarea'); voice.rows = 2; voice.value = constitution.voice || '';
  voice.placeholder = 'e.g. Clear, curious, candid, and concise';
  const principles = el('textarea', 'address-list'); principles.rows = 4;
  principles.value = (constitution.principles || []).join('\n');
  principles.placeholder = 'One operating principle per line';
  const boundaries = el('textarea', 'address-list'); boundaries.rows = 4;
  boundaries.value = (constitution.boundaries || []).join('\n');
  boundaries.placeholder = 'One behavioral boundary per line';
  const saveCharacter = el('button', 'btn', 'Save role and personality');
  const characterStatus = el('span', 'meta', '');
  const characterRow = el('div', 'row'); characterRow.append(saveCharacter, characterStatus);
  character.append(field('Purpose', purpose), field('Role', role), field('Voice', voice),
    field('Operating principles', principles, 'One per line. These tell the agent how to approach its work.'),
    field('Boundaries', boundaries, 'One per line. Technical permissions are still enforced separately under Capabilities.'),
    help('Saving is a constitutional amendment: the agent pauses until a manager reviews and approves it.'),
    characterRow);
  saveCharacter.onclick = async () => {
    saveCharacter.disabled = true; characterStatus.textContent = 'Saving amendment…';
    const lines = value => value.split('\n').map(item => item.trim()).filter(Boolean);
    const result = await j(api('/constitution'), {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({
        purpose: purpose.value.trim(), role: role.value.trim(), voice: voice.value.trim(),
        principles: lines(principles.value), boundaries: lines(boundaries.value),
      }),
    });
    saveCharacter.disabled = false;
    if (!result.ok) { characterStatus.textContent = 'Could not save: ' + result.error; return; }
    characterStatus.textContent = 'Saved. Review and approve the amendment before this agent can run.';
    await loadRoster(); render();
  };
  c.append(character);

  const governanceConfig = m.governance || {};
  const roleByKey = new Map();
  for (const key of (governanceConfig.suspend_keys || [])) roleByKey.set(key, 'governor');
  for (const manager of (governanceConfig.managers || [])) roleByKey.set(manager.npub, manager.role);
  const people = agentManagerCandidates(sel);
  const knownKeys = new Set(people.map(person => person.npub));
  const governance = section('Agent managers',
    'Authority belongs to this agent, not the whole host. Viewers inspect, operators can run it, editors can propose amendments, and governors manage credentials and approve constitutional changes.');
  const roleChoices = [
    ['none', 'No access'], ['viewer', 'Viewer'], ['operator', 'Operator'],
    ['editor', 'Editor'], ['governor', 'Governor'],
  ];
  const roleControls = [];
  for (const person of people) {
    const select = el('select'); select.setAttribute('aria-label', `Role for ${person.name || person.npub}`);
    for (const [value, label] of roleChoices) {
      const option = el('option', null, label); option.value = value; select.append(option);
    }
    select.value = roleByKey.get(person.npub) || 'none';
    const label = el('label', 'row');
    label.append(select, el('span', null, person.name || shortNostrId(person.npub)),
      nostrId(person.npub, 'code'),
      el('span', 'meta', person.identityKind === 'agent' ? 'Apiary agent' :
        managers.some(manager => manager.npub === person.npub) ? 'host manager' : 'person'));
    governance.append(label); roleControls.push([select, person.npub]);
  }
  const other = el('textarea', 'address-list'); other.rows = 3;
  other.placeholder = 'npub1… viewer|operator|editor|governor';
  other.value = [...roleByKey.entries()]
    .filter(([key]) => !knownKeys.has(key))
    .map(([key, role]) => `${key} ${role}`)
    .join('\n');
  const saveManagers = el('button', 'btn', 'Save agent managers');
  const managerStatus = el('span', 'meta', '');
  const managerRow = el('div', 'row'); managerRow.append(saveManagers, managerStatus);
  governance.append(field('Other Nostr IDs', other, 'One per line as “npub role”. A missing role defaults to governor for compatibility.'),
    help('Changing this list is a constitutional amendment: Apiary pauses the agent until one of the newly listed managers approves it.'),
    managerRow);
  saveManagers.onclick = async () => {
    const selected = roleControls
      .filter(([select]) => select.value !== 'none')
      .map(([select, npub]) => ({npub, role: select.value}));
    const additional = [];
    for (const line of other.value.split('\n').map(value => value.trim()).filter(Boolean)) {
      const parts = line.split(/\s+/); const npub = parts[0];
      const role = roleChoices.some(([value]) => value === parts[1] && value !== 'none') ? parts[1] : 'governor';
      additional.push({npub, role});
    }
    const roleManagers = [...selected, ...additional];
    if (!roleManagers.some(manager => manager.role === 'governor')) {
      managerStatus.textContent = 'At least one governor is required.'; return;
    }
    if (new Set(roleManagers.map(manager => manager.npub)).size !== roleManagers.length) {
      managerStatus.textContent = 'Each identity may appear only once.'; return;
    }
    saveManagers.disabled = true; managerStatus.textContent = 'Saving amendment…';
    const result = await j(api('/governors'), {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({managers: roleManagers}),
    });
    saveManagers.disabled = false;
    if (!result.ok) { managerStatus.textContent = 'Could not update managers: ' + result.error; return; }
    managerStatus.textContent = 'Saved. Review and approve the amendment before this agent can run.';
    await loadRoster(); render();
  };
  c.append(governance);

  const harnessSection = section('Harnesses and native tools',
    'A harness is a complete external agent loop such as Goose or Claude Code. Each grant independently controls native tools, profile inheritance, OS restrictions, and accounting.');
  const harnessList = el('div');
  for (const harness of (m.harnesses || [])) {
    const card = el('div', 'item');
    card.append(el('b', null, harness.name),
      kv('adapter', `${harness.kind || 'acp'} · ${harness.command}`),
      kv('native tools', harness.access || 'inference-only'),
      kv('host profile', harness.profile || 'isolated'),
      kv('OS sandbox', harness.sandbox || 'none'),
      kv('accounting', harness.metering || 'strict'),
      harness.allowed_tools && harness.allowed_tools.length ? kv('allowed tools', harness.allowed_tools.join(', ')) : el('span'));
    const remove = el('button', 'btn danger', 'Remove');
    remove.onclick = async () => {
      if (!confirm(`Remove harness ${harness.name} from this agent?`)) return;
      const result = await j(api('/harnesses/' + encodeURIComponent(harness.name)), {method: 'DELETE'});
      if (!result.ok) { alert('Could not remove harness: ' + result.error); return; }
      await loadRoster(); render();
    };
    card.append(remove); harnessList.append(card);
  }
  if (!(m.harnesses || []).length) harnessList.append(el('div', 'none', 'No foreign harnesses granted · native Apiary loop only'));
  const harnessForm = el('details');
  harnessForm.append(el('summary', null, 'Add a harness'));
  const hName = el('input'); hName.placeholder = 'e.g. goose-workspace';
  const hCommand = el('input'); hCommand.placeholder = 'e.g. goose';
  const hArgs = el('textarea', 'address-list'); hArgs.rows = 3; hArgs.placeholder = 'One argument per line';
  const hWorkdir = el('input'); hWorkdir.placeholder = 'Optional working directory';
  const hAccess = el('select');
  for (const [value, label] of [['inference-only', 'Inference only · deny ACP tool requests'], ['curated', 'Curated native tools · approve selected requests'], ['full', 'Full harness · approve native tools']]) {
    const option = el('option', null, label); option.value = value; hAccess.append(option);
  }
  const hProfile = el('select');
  for (const [value, label] of [['isolated', 'Isolated profile · clean HOME'], ['curated', 'Curated profile · selected environment'], ['inherit', 'Full host profile · global agents, skills and credentials']]) {
    const option = el('option', null, label); option.value = value; hProfile.append(option);
  }
  const hSandbox = el('select');
  for (const [value, label] of [
    ['read-only', 'Read only · deny filesystem writes'],
    ['read-only-no-network', 'Read only + offline · deny writes and network'],
    ['no-network', 'Offline · deny network access'],
    ['none', 'Unrestricted OS access · no process sandbox'],
  ]) {
    const option = el('option', null, label); option.value = value; hSandbox.append(option);
  }
  const hTools = el('textarea', 'address-list'); hTools.rows = 3; hTools.placeholder = 'ACP permission title, one per line (curated tools only)';
  const hEnv = el('textarea', 'address-list'); hEnv.rows = 2; hEnv.placeholder = 'Environment variable names, one per line (curated profile only)';
  const hMetering = el('select');
  for (const [value, label] of [['strict', 'Strict · refuse unknown usage'], ['estimated', 'Estimated · charge a fixed amount'], ['unmetered', 'Unmetered · daily token limit does not apply']]) {
    const option = el('option', null, label); option.value = value; hMetering.append(option);
  }
  const hEstimate = el('input'); hEstimate.type = 'number'; hEstimate.min = '1'; hEstimate.max = '64000'; hEstimate.value = '8192';
  const hDiscover = el('button', 'btn', 'Find installed harnesses');
  const harnessSave = el('button', 'btn', 'Add harness');
  const harnessStatus = el('span', 'meta', '');
  const hDiscoverRow = el('div', 'row'); hDiscoverRow.append(hDiscover);
  const hRow = el('div', 'row'); hRow.append(harnessSave, harnessStatus);
  harnessForm.append(hDiscoverRow,
    help('Discovery checks known local executables only. It does not launch them, copy credentials, add a grant, or approve an amendment.'),
    field('Name', hName), field('Command', hCommand),
    field('Arguments', hArgs, 'One per line; arguments are exact and ratified.'),
    field('Working directory', hWorkdir, 'Optional. This selects cwd but does not confine the process.'),
    field('Native tool access', hAccess), field('Host profile', hProfile),
    field('OS sandbox', hSandbox, 'macOS enforcement applies to the complete harness process tree. A requested sandbox fails closed on unsupported hosts.'),
    field('Allowed tool titles', hTools), field('Inherited environment', hEnv),
    field('Token accounting', hMetering), field('Estimated tokens per run', hEstimate),
    help('Full host profile deliberately inherits the harness user’s global agents, skills, extensions, credentials, and environment. Isolated creates a clean per-agent HOME. Read-only blocks writes but not reads; no-network blocks outbound and inbound network access. Goose mode is pinned to chat, approve, or auto from the selected access. Other harnesses must honor ACP permission requests.'), hRow);
  hDiscover.onclick = async () => {
    hDiscover.disabled = true; harnessStatus.textContent = 'Checking this host…';
    const result = await j(api('/harnesses/discover'));
    hDiscover.disabled = false;
    if (!result.ok) { harnessStatus.textContent = 'Could not discover harnesses: ' + result.error; return; }
    const candidates = result.harnesses || [];
    if (!candidates.length) { harnessStatus.textContent = 'No supported ACP harness was found on this host.'; return; }
    const candidate = candidates.find(item => item.id === 'berd-goose') || candidates[0];
    hName.value = candidate.id;
    hCommand.value = candidate.command;
    hArgs.value = (candidate.args || []).join('\n');
    hAccess.value = 'inference-only';
    hProfile.value = 'isolated';
    hSandbox.value = 'none';
    hMetering.value = 'estimated';
    hEstimate.value = '8192';
    harnessStatus.textContent = `${candidate.name} found. Review these defaults, then add and approve the amendment.`;
  };
  harnessSave.onclick = async () => {
    const lines = value => value.split('\n').map(item => item.trim()).filter(Boolean);
    const harness = {
      name: hName.value.trim(), kind: 'acp', command: hCommand.value.trim(), args: lines(hArgs.value),
      access: hAccess.value, profile: hProfile.value, sandbox: hSandbox.value, allowed_tools: lines(hTools.value),
      inherit_env: lines(hEnv.value), metering: hMetering.value,
    };
    if (hWorkdir.value.trim()) harness.workdir = hWorkdir.value.trim();
    if (hMetering.value === 'estimated') harness.estimated_tokens_per_run = Number(hEstimate.value);
    harnessSave.disabled = true; harnessStatus.textContent = 'Saving amendment…';
    const result = await j(api('/harnesses'), {method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify({harness})});
    harnessSave.disabled = false;
    if (!result.ok) { harnessStatus.textContent = 'Could not save: ' + result.error; return; }
    harnessStatus.textContent = 'Saved. Approve the amendment before use.';
    await loadRoster(); render();
  };
  harnessSection.append(harnessList, harnessForm);
  c.append(harnessSection);

  const control = section('Agent access and integrations',
    'Create a time-bounded credential signed by this agent. It can connect an AG-UI surface such as OpenBot or let this agent use Apiary’s control MCP server. It never inherits a human manager’s authority.');
  const ttl = el('select');
  for (const [seconds, label] of [[3600, '1 hour'], [86400, '24 hours'], [604800, '7 days'], [2592000, '30 days'], [7776000, '90 days']]) {
    const option = el('option', null, label); option.value = String(seconds); if (seconds === 86400) option.selected = true; ttl.append(option);
  }
  const tokenLabel = el('input'); tokenLabel.placeholder = 'e.g. Scout manager loop'; tokenLabel.maxLength = 80;
  const createToken = el('button', 'btn', 'Create agent access token');
  const tokenStatus = el('span', 'meta', '');
  const tokenOutput = el('textarea', 'address-list'); tokenOutput.rows = 4; tokenOutput.readOnly = true;
  tokenOutput.placeholder = 'The token is shown here once created.';
  const tokenUrl = el('input'); tokenUrl.readOnly = true; tokenUrl.placeholder = 'MCP URL';
  const openBotUrl = el('input'); openBotUrl.readOnly = true;
  openBotUrl.value = `${location.origin}${api('/ag-ui')}`;
  const tokenList = el('div');
  const drawTokens = tokens => {
    tokenList.replaceChildren();
    if (!tokens.length) { tokenList.append(el('div', 'none', 'No recorded management tokens')); return; }
    for (const token of tokens) {
      const card = el('div', 'item');
      const state = token.active ? 'active' : token.revoked_at ? 'revoked' : 'expired';
      card.append(el('b', null, token.label || 'Unlabeled token'),
        kv('state', state), kv('ID', token.id.slice(0, 16) + '…'),
        kv('created', new Date(token.created_at * 1000).toLocaleString()),
        kv('expires', new Date(token.expires_at * 1000).toLocaleString()));
      if (token.active) {
        const revoke = el('button', 'btn danger', 'Revoke');
        revoke.onclick = async () => {
          if (!confirm(`Revoke ${token.label || token.id.slice(0, 12)} now?`)) return;
          revoke.disabled = true;
          const result = await j(api('/control-tokens/' + encodeURIComponent(token.id)), {method: 'DELETE'});
          if (!result.ok) { revoke.disabled = false; tokenStatus.textContent = 'Could not revoke: ' + result.error; return; }
          tokenStatus.textContent = 'Token revoked immediately.';
          const refreshed = await j(api('/control-tokens'));
          drawTokens(refreshed.ok ? (refreshed.tokens || []) : []);
        };
        card.append(revoke);
      }
      tokenList.append(card);
    }
  };
  drawTokens(controlTokens.ok ? (controlTokens.tokens || []) : []);
  createToken.onclick = async () => {
    createToken.disabled = true; tokenStatus.textContent = 'Signing token…';
    const result = await j(api('/control-token'), {
      method: 'POST', headers: {'content-type': 'application/json'},
      body: JSON.stringify({expires_in_seconds: Number(ttl.value), label: tokenLabel.value.trim()}),
    });
    createToken.disabled = false;
    if (!result.ok) { tokenStatus.textContent = 'Could not create token: ' + result.error; return; }
    tokenOutput.value = result.token; tokenUrl.value = result.mcp_url;
    tokenStatus.textContent = 'Created. Copy it now; OpenBot stores it as the coworker’s write-only Authorization header.';
    const refreshed = await j(api('/control-tokens'));
    drawTokens(refreshed.ok ? (refreshed.tokens || []) : []);
  };
  const tokenRow = el('div', 'row'); tokenRow.append(ttl, createToken, tokenStatus);
  control.append(field('Label', tokenLabel), tokenRow,
    field('OpenBot AG-UI endpoint', openBotUrl, 'In OpenBot, create a coworker with this endpoint and Authorization: Bearer <credential>.'),
    field('Apiary control MCP URL', tokenUrl), field('Bearer credential', tokenOutput),
    help('OpenBot may provide tools in an AG-UI run, but Apiary does not inherit them. This agent can use only its separately approved Apiary connectors, skills, and harness policy. The bearer is shown only when created and can be revoked below before expiry.'),
    el('h4', null, 'Token history'), tokenList);
  c.append(control);

  const active = section('Always-on presence', declared.length
    ? 'Activation keeps declared channels available on this host. One-time tasks work while inactive.'
    : 'No always-on channel is configured. One-time tasks are still available.');
  const channelBox = el('div');
  const drawChannels = l => {
    channelBox.replaceChildren();
    const kinds = l.ok ? (l.declared || []) : [];
    const supervisorNote = l.supervisor_note === 'manifest is not ratified — nothing runs'
      ? 'Waiting for approval'
      : l.supervisor_note;
    if (!kinds.length) channelBox.append(el('div', 'none', 'No channels declared'));
    for (const kind of kinds) {
      const ch = (l.channels || {})[kind] || {};
      const status = ch.running
        ? 'Running'
        : (ch.note || supervisorNote || (roster.active ? 'Starting' : 'Inactive'));
      channelBox.append(kv(kind, status));
    }
  };
  drawChannels(listener);
  const actRow = el('div', 'row');
  const actBtn = el('button', 'btn' + (roster.active ? ' danger' : ' solid'), roster.active ? 'Deactivate' : 'Activate');
  const actSt = el('span', 'meta', '');
  actRow.append(actBtn, actSt);
  active.append(channelBox, actRow);
  actBtn.onclick = async () => {
    actBtn.disabled = true;
    const r = await j(api('/active'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ active: !roster.active }) });
    actSt.textContent = r.ok ? r.note : 'Could not change activation: ' + r.error;
    await loadRoster(); render();
  };

  const setup = el('details', 'technical');
  setup.append(el('summary', null, 'Add or inspect channels'));
  const dKind = el('select');
  for (const kind of ['telegram', 'slack', 'buzz']) { const option = el('option', null, kind); option.value = kind; dKind.append(option); }
  const dCred = el('input'); dCred.type = 'password'; dCred.placeholder = 'Channel secret, if required';
  const dConf = el('textarea'); dConf.rows = 3; dConf.placeholder = 'Advanced channel settings as JSON';
  const dGo = el('button', 'btn', 'Add channel');
  const dSt = el('span', 'meta', '');
  const dRow = el('div', 'row'); dRow.append(dGo, dSt);
  setup.append(field('Channel type', dKind), field('Secret', dCred), field('Settings', dConf), dRow,
    help('Telegram and Slack require platform credentials. Buzz can be configured more easily from Workspace. Adding a channel creates a change for you to review.'));
  dGo.onclick = async () => {
    let config = {};
    try { if (dConf.value.trim()) config = JSON.parse(dConf.value); }
    catch { dSt.textContent = 'Settings must be valid JSON.'; dConf.focus(); return; }
    dGo.disabled = true; dSt.textContent = 'Encrypting and adding…';
    const r = await j(api('/presence'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ kind: dKind.value, credential: dCred.value || null, config }) });
    dGo.disabled = false; dCred.value = '';
    dSt.textContent = r.ok ? 'Added. Review and approve the change above.' : 'Could not add channel: ' + r.error;
    if (r.ok) { await loadRoster(); render(); }
  };
  active.append(setup); c.append(active);
  listenerPoll = setInterval(async () => drawChannels(await j(api('/listener'))), 4000);

  const current = section('Current setup');
  current.append(kv('Task models', taskModels.length ? taskModels.map(x => `${x.name}: ${x.provider} / ${x.model}`).join(', ') : 'None configured'),
    kv('Default route', (m.routing || {}).default || 'Not set'),
    kv('Memory & voice', supportingModels.length ? supportingModels.map(x => `${inferenceRoleLabel[inferenceRoleForName(x.name)]}: ${x.provider}${x.model ? ' / ' + x.model : ''}`).join(', ') : 'None configured'),
    kv('Capabilities', connectors.length ? connectors.map(x => x.name || x.type).join(', ') : 'None granted'),
    kv('Skills', (m.skills || []).length ? (m.skills || []).map(x => x.name).join(', ') : 'None installed'),
    kv('Automations', routines.length ? `${routines.length} configured` : 'None'),
    kv('Memory', `${(m.memory || {}).log || 'local'} log · ${(m.memory || {}).index || 'no index'}`));
  if (spend.ok && spend.budget_tokens_per_day) {
    const bar = el('div', 'bar'); const fill = el('div');
    const used = spend.used + spend.reserved;
    fill.style.width = (Math.min(1, used / spend.budget_tokens_per_day) * 100).toFixed(1) + '%';
    if (used / spend.budget_tokens_per_day > .85) fill.className = 'hot';
    bar.append(fill); current.append(bar, help(`${Number(used).toLocaleString()} of ${Number(spend.budget_tokens_per_day).toLocaleString()} daily tokens used or reserved.`));
  }
  c.append(current);

  const advanced = el('details', 'section technical');
  advanced.id = 'agent-portability';
  advanced.append(el('summary', null, 'Export, identity, and host coordination'));
  const body = el('div');
  const publicIdentity = kv('Public identity', shortNostrId(sel));
  publicIdentity.querySelector('.v').title = sel;
  publicIdentity.querySelector('.v').setAttribute('aria-label', sel);
  body.append(publicIdentity, kv('Configuration hash', d.manifest_sha256));
  const rnIn = el('input'); rnIn.value = roster.name || '';
  const rnGo = el('button', 'btn', 'Rename'); const rnSt = el('span', 'meta', '');
  const rnRow = el('div', 'row'); rnRow.append(rnGo, rnSt);
  body.append(field('Local display name', rnIn), rnRow);
  rnGo.onclick = async () => {
    const r = await j(api('/name'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name: rnIn.value.trim() }) });
    rnSt.textContent = r.ok ? 'Renamed.' : 'Could not rename: ' + r.error;
    if (r.ok) await loadRoster();
  };
  const exPass = el('input'); exPass.type = 'password'; exPass.placeholder = 'Optional handoff passphrase';
  const exTo = technicalInput(el('input')); exTo.placeholder = 'Or recipient npub';
  const exBtn = el('button', 'btn', 'Export agent'); const exSt = el('span', 'meta', '');
  const exRow = el('div', 'row'); exRow.append(exBtn, exSt);
  body.append(field('One-time transfer passphrase', exPass), field('Seal export to', exTo), exRow,
    help('The agent does not have a passphrase. For another host, create a disposable transfer passphrase or seal to its recipient identity. If both are blank, this is a same-workspace backup and its key remains protected by the source workspace passphrase.'));
  exBtn.onclick = async () => {
    if (exPass.value && exTo.value) { exSt.textContent = 'Choose a passphrase or recipient, not both.'; return; }
    exBtn.disabled = true; exSt.textContent = 'Creating verified bundle…';
    const r = await j(api('/export'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ export_passphrase: exPass.value || null, to_npub: exTo.value.trim() || null }) });
    exBtn.disabled = false; exPass.value = ''; exTo.value = '';
    exSt.textContent = r.ok ? `${r.note} Saved to ${r.path}` : 'Could not export: ' + r.error;
  };
  const leaseLine = kv('Host lease', 'Checking…'); body.append(leaseLine);
  j(api('/lease')).then(lz => {
    let value = lz.ok ? (lz.note || 'No live lease') : 'Unavailable: ' + lz.error;
    if (lz.ok && lz.lease) value = lz.lease.ours ? 'Held by this host' : (lz.lease.expired ? 'Previous lease expired' : `Held by another host: ${lz.lease.holder}`);
    leaseLine.replaceChildren(el('span', 'k', 'Host lease'), el('span', 'v', value));
    if (lz.ok && lz.lease && !lz.lease.ours && !lz.lease.expired) {
      const take = el('button', 'btn danger', 'Take over on this host');
      take.onclick = async () => {
        take.disabled = true;
        const r = await j(api('/lease/takeover'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
        take.textContent = r.ok ? 'Takeover requested' : 'Takeover failed';
      };
      body.append(take);
    }
  });
  advanced.append(body); c.append(advanced, agentLifecycleSection(roster));
}

// ------------------------------------------------------ inference setup

function inferenceForm(slot, afterSave) {
  const form = el('div', 'connection-form');
  const role = el('select');
  for (const value of ['language', 'embedding', 'transcription', 'speech']) {
    const option = el('option', null, inferenceRoleLabel[value]); option.value = value; role.append(option);
  }
  role.value = slot ? slot.role : 'language';
  if (slot) role.disabled = true;

  const name = el('input'); name.value = slot ? slot.name : '';
  name.placeholder = 'e.g. workhorse or fast';
  const provider = el('select');
  const legacyClaude = !!(slot && slot.provider === 'anthropic' && (slot.requires || {}).auth === 'oauth');
  const initialProvider = legacyClaude ? 'claude-code' : (slot && slot.provider);
  const model = el('select');
  const customModel = technicalInput(el('input')); customModel.placeholder = 'Custom model identifier'; customModel.style.display = 'none';
  const modelControls = el('div'); modelControls.style.display = 'grid'; modelControls.style.gap = '6px'; modelControls.append(model, customModel);
  const endpoint = technicalInput(el('input')); endpoint.value = (slot && slot.requires && slot.requires.base_url) || '';
  endpoint.placeholder = 'Provider API base URL';
  endpoint.dataset.auto = endpoint.value ? '0' : '1';
  endpoint.oninput = () => { endpoint.dataset.auto = '0'; };
  const auth = el('select');
  for (const [value, label] of [['api-key', 'API key']]) {
    const option = el('option', null, label); option.value = value; auth.append(option);
  }
  auth.value = 'api-key';
  const credential = technicalInput(el('input')); credential.type = 'password';
  credential.placeholder = slot && slot.credential_source && slot.credential_source.startsWith('sealed') ? 'Leave blank to keep current credential' : 'API key, if required';
  const voice = el('input'); voice.value = (slot && slot.requires && slot.requires.voice) || '';
  voice.placeholder = 'Voice, e.g. af_heart or alloy';
  const locale = technicalInput(el('input')); locale.value = (slot && slot.requires && slot.requires.locale) || '';
  locale.placeholder = 'Locale, e.g. en_US';
  const makeDefault = el('input'); makeDefault.type = 'checkbox';
  const makeDefaultLabel = el('label'); makeDefaultLabel.append(makeDefault, document.createTextNode(' Use as the default task model'));
  const clear = el('input'); clear.type = 'checkbox';
  const clearLabel = el('label'); clearLabel.append(clear, document.createTextNode(' Remove the stored credential'));

  let modelInitialized = false;
  const refreshModelChoices = () => {
    const choices = ((inferenceModels[role.value] || {})[provider.value] || []);
    const initial = !modelInitialized && slot && initialProvider === provider.value ? (slot.model || '') : '';
    model.replaceChildren();
    for (const [value, label] of choices) { const option = el('option', null, label); option.value = value; model.append(option); }
    const custom = el('option', null, 'Custom model…'); custom.value = '__custom__'; model.append(custom);
    if (initial && choices.some(([value]) => value === initial)) model.value = initial;
    else if (initial) { model.value = '__custom__'; customModel.value = initial; }
    else if (choices.length) model.value = choices[0][0];
    else model.value = '__custom__';
    customModel.style.display = model.value === '__custom__' ? '' : 'none';
    const needsModel = role.value === 'language' || choices.length > 0;
    model.closest('.field').style.display = needsModel ? '' : 'none';
    if (!needsModel) customModel.style.display = 'none';
    modelInitialized = true;
  };
  model.onchange = () => { customModel.style.display = model.value === '__custom__' ? '' : 'none'; if (model.value === '__custom__') customModel.focus(); };

  const refreshEndpoint = () => {
    const defaultURL = inferenceDefaultBaseURL(role.value, provider.value);
    if (endpoint.dataset.auto === '1' || !endpoint.value.trim()) { endpoint.value = defaultURL; endpoint.dataset.auto = '1'; }
    endpoint.closest('.field').style.display = defaultURL ? '' : 'none';
    endpoint.readOnly = provider.value !== 'openai' && !(role.value === 'embedding' && provider.value === 'ollama');
    endpoint.title = endpoint.readOnly ? 'This provider uses its standard endpoint.' : 'Change this for an OpenAI-compatible or local server.';
  };

  const refreshAuth = () => {
    const anthropic = role.value === 'language' && provider.value === 'anthropic';
    auth.closest('.field').style.display = anthropic ? '' : 'none';
    const subscription = role.value === 'language' && ['claude-code', 'codex'].includes(provider.value);
    credential.closest('.field').style.display = subscription ? 'none' : '';
    credential.placeholder = slot && slot.credential_source === 'sealed API key'
      ? 'Leave blank to keep current API key'
      : 'API key, if required';
  };

  const refreshProviderChoices = () => {
    const current = provider.value || initialProvider;
    provider.replaceChildren();
    for (const [value, label] of inferenceProviders[role.value]) {
      const option = el('option', null, label); option.value = value; provider.append(option);
    }
    if ([...provider.options].some(o => o.value === current)) provider.value = current;
    const fixedName = { embedding: 'embed', transcription: 'transcribe', speech: 'speak' }[role.value];
    if (fixedName) { name.value = fixedName; name.readOnly = true; }
    else { if (!slot && ['embed', 'transcribe', 'speak'].includes(name.value)) name.value = ''; name.readOnly = false; }
    voice.closest('.field').style.display = role.value === 'speech' ? '' : 'none';
    locale.closest('.field').style.display = role.value === 'transcription' ? '' : 'none';
    makeDefaultLabel.style.display = role.value === 'language' ? '' : 'none';
    modelInitialized = false;
    refreshModelChoices();
    refreshEndpoint();
    refreshAuth();
  };

  form.append(field('Role', role), field('Connection name', name, 'Routing refers to this stable name.'),
    field('Provider', provider), field('Model', modelControls),
    field('Base URL', endpoint, 'Provider defaults are prefilled. OpenAI-compatible and local endpoints remain editable.'),
    field('Authentication', auth, 'Subscription routes use the account already signed in to the official Claude Code or Codex CLI on this host. API connections use agent-sealed keys.'),
    field('Credential', credential, 'API keys are encrypted to this agent before they are written.'),
    field('Voice', voice), field('Locale', locale));
  const flags = el('div', 'wide row'); flags.append(makeDefaultLabel);
  if (slot && slot.credential_source && slot.credential_source.startsWith('sealed')) flags.append(clearLabel);
  form.append(flags);
  const actions = el('div', 'connection-actions');
  const save = el('button', 'btn solid', slot ? 'Save connection' : 'Add connection');
  const status = el('span', 'meta', legacyClaude ? 'Ready to migrate to this Mac’s Claude Code sign-in.' : ''); actions.append(save, status);
  if (slot) {
    const remove = el('button', 'btn danger', 'Remove'); let armed = false;
    remove.onclick = async () => {
      if (!armed) { armed = true; remove.textContent = 'Remove connection'; status.textContent = 'This change will require approval.'; return; }
      remove.disabled = true;
      const r = await j(api('/inference/' + encodeURIComponent(slot.name)), { method: 'DELETE' });
      status.textContent = r.ok ? 'Removed. Review and approve the change.' : 'Could not remove: ' + r.error;
      if (r.ok) { await loadRoster(); afterSave(); }
      else remove.disabled = false;
    };
    actions.append(remove);
  }
  form.append(actions);
  role.onchange = () => { endpoint.dataset.auto = '1'; refreshProviderChoices(); };
  provider.onchange = () => { endpoint.dataset.auto = '1'; refreshProviderChoices(); };
  auth.onchange = refreshAuth;
  provider.value = initialProvider || inferenceProviders[role.value][0][0];
  refreshProviderChoices();

  const persist = async () => {
    const connectionName = name.value.trim().replace(/\s+/g, '-');
    if (!connectionName) { status.textContent = 'Give this connection a name.'; name.focus(); return; }
    if (!/^[A-Za-z0-9_-]{1,40}$/.test(connectionName)) { status.textContent = 'Use only letters, numbers, dashes, or underscores in the connection name.'; name.focus(); return; }
    name.value = connectionName;
    const chosenModel = model.value === '__custom__' ? customModel.value.trim() : model.value;
    if (role.value === 'language' && !chosenModel) { status.textContent = 'Choose a model or enter a custom model identifier.'; customModel.focus(); return; }
    const requires = Object.assign({}, (slot && slot.requires) || {});
    if (endpoint.value.trim()) requires.base_url = endpoint.value.trim(); else delete requires.base_url;
    if (provider.value === 'anthropic') {
      requires.auth = 'api-key';
      delete requires.oauth_profile;
    } else { delete requires.auth; delete requires.oauth_profile; }
    if (['claude-code', 'codex'].includes(provider.value)) delete requires.base_url;
    if (voice.value.trim()) requires.voice = voice.value.trim(); else delete requires.voice;
    if (locale.value.trim()) requires.locale = locale.value.trim(); else delete requires.locale;
    save.disabled = true;
    status.textContent = credential.value ? 'Encrypting credential…' : 'Saving…';
    const r = await j(api('/inference'), {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        original_name: slot ? slot.name : null,
        name: connectionName, provider: provider.value, model: chosenModel || null,
        credential: credential.value || null, clear_credential: clear.checked || legacyClaude,
        requires, set_default: makeDefault.checked,
      }),
    });
    credential.value = ''; save.disabled = false;
    status.textContent = r.ok ? 'Saved. Review and approve the change.' : 'Could not save: ' + r.error;
    if (r.ok) { await loadRoster(); afterSave(); }
  };
  save.onclick = persist;
  return form;
}

function inferenceSource(slot, routing, rerender, ratified) {
  const item = el('article', 'source-item');
  const head = el('div', 'source-head');
  const identity = el('div');
  identity.append(el('div', 'source-name', slot.name), el('div', 'source-role', inferenceRoleLabel[slot.role] || slot.role));
  const detail = el('div', 'source-detail');
  detail.append(el('div', null, `${inferenceProviderLabel(slot.provider)}${slot.model ? ' · ' + slot.model : ''}`),
    el('div', null, `${inferenceEndpoint(slot)} · credential: ${slot.credential_source}`));
  if (routing.default === slot.name) detail.append(el('div', 'risk', 'Default route for tasks'));
  const state = el('div', 'source-state');
  const stateName = (slot.status && slot.status.state) || 'unavailable';
  state.append(el('span', 'state ' + stateName, stateName === 'ready' ? 'Verified locally' : stateName));
  state.append(el('div', 'source-detail', (slot.status && slot.status.detail) || 'No diagnostic available'));
  head.append(identity, detail, state); item.append(head);
  if (slot.role === 'language') {
    const actions = el('div', 'connection-actions');
    const test = el('button', 'btn', 'Test connection');
    const testStatus = el('span', 'meta', ratified ? '' : 'Approve the configuration before testing.');
    test.disabled = !ratified;
    test.onclick = async () => {
      test.disabled = true; testStatus.textContent = 'Running a small governed test…';
      const result = await j(api('/inference/' + encodeURIComponent(slot.name) + '/test'), { method: 'POST' });
      test.disabled = !ratified;
      testStatus.textContent = result.ok
        ? `Passed · ${Math.round(result.elapsed_ms)}ms · ${result.input_tokens}in/${result.output_tokens}out`
        : 'Failed · ' + result.error;
    };
    actions.append(test, testStatus); item.append(actions);
  }
  const edit = el('details'); edit.append(el('summary', null, 'Edit route'), inferenceForm(slot, rerender));
  item.append(edit);
  return item;
}

async function renderInference(c) {
  const d = await j(api('/inference'));
  const head = el('div', 'page-head');
  head.append(el('div', 'eyebrow', 'Model routing'),
    el('h2', 'page-title', 'Inference'),
    el('p', 'page-lede', 'Choose which models this agent uses to think, remember, hear, and speak. Subscription routes share the official CLI account signed in on this host; API providers keep agent-sealed credentials.'));
  c.append(head);
  if (!d.ok) { c.append(el('div', 'ev err', 'Could not load inference setup: ' + d.error)); return; }
  const slots = d.slots || [], routing = d.routing || {};
  const language = slots.filter(s => s.role === 'language');
  const support = slots.filter(s => s.role !== 'language');
  const verified = slots.filter(s => s.status && s.status.state === 'ready').length;
  c.append((() => { const m = el('div', 'metrics'); m.append(metric('Task models', language.length), metric('Supporting engines', support.length), metric('Verified locally', verified), metric('Default route', routing.default || 'Not set')); return m; })());

  const claudeRoutes = language.filter(s => s.provider === 'claude-code');
  if (claudeRoutes.length) {
    const account = section('Claude Code on this Mac', 'One host account serves every Claude Code route. Each route only chooses a model and routing name.');
    const status = claudeRoutes.find(s => s.status && s.status.state === 'ready') || claudeRoutes[0];
    account.append(kv('Account', (status.status && status.status.detail) || 'Claude Code sign-in is unavailable'),
      kv('Used by', claudeRoutes.map(s => s.name).join(', ')));
    c.append(account);
  }
  const codexRoutes = language.filter(s => s.provider === 'codex');
  if (codexRoutes.length) {
    const account = section('ChatGPT subscription on this host', 'One official Codex sign-in serves every ChatGPT subscription route. Apiary never copies the OAuth credential into an agent.');
    const status = codexRoutes.find(s => s.status && s.status.state === 'ready') || codexRoutes[0];
    account.append(kv('Account', (status.status && status.status.detail) || 'Codex ChatGPT sign-in is unavailable'),
      kv('Used by', codexRoutes.map(s => s.name).join(', ')));
    c.append(account);
  }

  const rerender = () => setTimeout(render, 350);
  const task = section('Task models', 'Language models receive prompts and may call granted capabilities. “Configured” means a credential is present; Apiary avoids a billable probe.');
  const taskList = el('div', 'source-list');
  for (const slot of language) taskList.append(inferenceSource(slot, routing, rerender, d.ratified));
  if (!language.length) taskList.append(el('div', 'none', 'No task model is configured.'));
  task.append(taskList);
  if (language.length) {
    const select = el('select');
    for (const slot of language) { const option = el('option', null, slot.name); option.value = slot.name; select.append(option); }
    select.value = routing.default || '';
    const save = el('button', 'btn', 'Set default'); const status = el('span', 'meta', '');
    const line = el('div', 'route-line'); line.append(select, save, status); task.append(line);
    save.onclick = async () => {
      save.disabled = true;
      const r = await j(api('/inference/default'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name: select.value }) });
      save.disabled = false; status.textContent = r.ok ? 'Saved. Approval required.' : 'Could not save: ' + r.error;
      if (r.ok) { await loadRoster(); rerender(); }
    };
  }
  const add = el('details', 'technical'); add.append(el('summary', null, 'Add a model route'), inferenceForm(null, rerender));
  task.append(add); c.append(task);

  const equipment = section('Memory and voice', 'Supporting engines have reserved roles: embed builds semantic memory, transcribe hears audio, and speak renders voice replies.');
  const supportList = el('div', 'source-list');
  for (const slot of support) supportList.append(inferenceSource(slot, routing, rerender, d.ratified));
  if (!support.length) supportList.append(el('div', 'none', 'No supporting engines are configured.'));
  equipment.append(supportList); c.append(equipment);

  const policy = section('Routing policy', 'Routing is decided before inference. Human-approved floors win, then task rules, then the default model.');
  if (!(routing.floors || []).length && !(routing.rules || []).length) policy.append(el('div', 'none', 'No conditional routes. Every task uses the default model.'));
  for (const rule of routing.floors || []) policy.append(kv('Required floor', `${rule.when} → ${rule.to}`));
  for (const rule of routing.rules || []) policy.append(kv('Task rule', `${rule.when} → ${rule.to}`));
  if (language.length > 1 && routing.default) {
    const fallback = el('select');
    const none = el('option', null, 'No automatic fallback'); none.value = ''; fallback.append(none);
    for (const slot of language.filter(slot => slot.name !== routing.default)) {
      const option = el('option', null, slot.name); option.value = slot.name; fallback.append(option);
    }
    fallback.value = (((routing.fallbacks || {})[routing.default] || [])[0]) || '';
    const saveFallback = el('button', 'btn', 'Save fallback');
    const fallbackStatus = el('span', 'meta', 'Only used before text or a tool action begins.');
    const fallbackLine = el('div', 'route-line'); fallbackLine.append(fallback, saveFallback, fallbackStatus);
    saveFallback.onclick = async () => {
      saveFallback.disabled = true;
      const result = await j(api('/inference/fallback'), {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ primary: routing.default, fallback: fallback.value || null }),
      });
      saveFallback.disabled = false;
      fallbackStatus.textContent = result.ok ? 'Saved. Approval required.' : 'Could not save: ' + result.error;
      if (result.ok) { await loadRoster(); rerender(); }
    };
    policy.append(field(`Fallback when ${routing.default} is unavailable`, fallbackLine,
      'Fallback routes are part of the approved policy. Apiary never retries after emitting text or starting a tool call.'));
  }
  const advanced = el('button', 'btn', 'Edit advanced routing'); advanced.onclick = () => openTab('manifest');
  policy.append(advanced); c.append(policy);
}

// ------------------------------------------------------------ run

async function renderRun(c) {
  const manifestResult = await currentManifest();
  const harnesses = manifestResult.ok ? ((manifestResult.manifest || {}).harnesses || []) : [];
  c.append(help('One governed task. The stream below is AG-UI presence (steps, tool calls, text); the signed log is truth — every model call lands as a signed checkpoint entry. Budget reservations are taken before the call and settled after.'));
  const box = el('div'); box.id = 'runbox';
  const ta = el('textarea'); ta.id = 'task'; ta.placeholder = 'task for this agent…';
  ta.setAttribute('aria-label', 'Task');
  const go = el('button', null, 'Run task'); go.id = 'go';
  box.append(ta, go);
  const row = el('div', 'row');
  const cls = el('input'); cls.placeholder = 'class (optional, e.g. reasoning)';
  const dcls = el('input'); dcls.placeholder = 'data class (optional, e.g. sensitive)';
  const harness = el('select');
  const native = el('option', null, 'Native Apiary loop'); native.value = 'native'; harness.append(native);
  for (const grant of harnesses) { const option = el('option', null, `${grant.name} · ${grant.access || 'inference-only'} · ${grant.profile || 'isolated'}`); option.value = grant.name; harness.append(option); }
  cls.setAttribute('aria-label', 'Routing class');
  dcls.setAttribute('aria-label', 'Data class');
  row.append(cls, dcls, harness);
  c.append(box, row,
    help('class picks a routing rule from the manifest (which model slot handles this kind of task). data class engages routing floors — e.g. a "sensitive" floor can pin such tasks to a local model regardless of what routing would prefer.'));
  const events = el('div'); events.id = 'events';
  c.append(events);
  go.onclick = () => runTask(ta, go, events, cls.value.trim() || null, dcls.value.trim() || null, harness.value);
}

function ev(events, cls, text) {
  const node = el('div', 'ev ' + cls, text);
  events.append(node);
  node.scrollIntoView({ block: 'nearest' });
  return node;
}

async function runTask(ta, go, events, cls, dcls, harness) {
  const task = ta.value.trim();
  if (!task) return;
  go.disabled = true;
  events.replaceChildren();
  try {
    const resp = await apiaryFetch(api('/run'), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ task, class: cls, data_class: dcls, harness }),
    });
    if (!resp.ok) {
      let msg = String(resp.status);
      try { msg = (await resp.json()).error || msg; } catch {}
      ev(events, 'err', 'refused: ' + msg);
      go.disabled = false;
      return;
    }
    const reader = resp.body.getReader();
    const dec = new TextDecoder();
    let buf = '';
    let responseNode = null;
    let responseText = null;
    let pendingText = '';
    let paint = null;
    let lastScroll = 0;
    const flushText = () => {
      paint = null;
      if (!pendingText || !responseText) return;
      responseText.appendData(pendingText);
      pendingText = '';
      const now = performance.now();
      if (now - lastScroll > 100) {
        responseNode.scrollIntoView({ block: 'nearest' });
        lastScroll = now;
      }
    };
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let i;
      while ((i = buf.indexOf('\n\n')) >= 0) {
        const frame = buf.slice(0, i); buf = buf.slice(i + 2);
        const line = frame.split('\n').find(l => l.startsWith('data:'));
        if (!line) continue;
        let e; try { e = JSON.parse(line.slice(5)); } catch { continue; }
        switch (e.type) {
          case 'RUN_STARTED': ev(events, 'meta', 'run started · ' + e.runId); break;
          case 'STEP_STARTED': ev(events, 'step', '⚙ ' + e.stepName); break;
          case 'TOOL_CALL_START': ev(events, 'tool', '⚒ tool: ' + e.toolCallName); break;
          case 'TOOL_CALL_ARGS': ev(events, 'meta', 'args ' + e.delta); break;
          case 'TOOL_CALL_END': ev(events, e.ok ? 'tool' : 'err', `⚒ ${e.toolCallId} ${e.ok ? 'ok' : 'FAILED'} — ${e.detail}`); break;
          case 'TEXT_MESSAGE_CONTENT':
            if (!responseNode) {
              responseNode = ev(events, 'text', '');
              responseText = document.createTextNode('');
              responseNode.append(responseText);
            }
            pendingText += e.delta;
            if (!paint) paint = requestAnimationFrame(flushText);
            break;
          case 'CUSTOM':
            if (e.name === 'apiary.checkpoint') {
              const v = e.value;
              const timing = v.timings_ms || {};
              const prep = ['admission_ms', 'budget_ms', 'route_ms', 'memory_ms', 'connectors_ms']
                .reduce((sum, key) => sum + (Number(timing[key]) || 0), 0);
              const providerSetup = Number(timing.provider_bind_ms) || 0;
              const speed = timing.first_token_ms == null ? ''
                : ` · first text ${Math.round(timing.first_token_ms)}ms · Apiary prep ${prep.toFixed(1)}ms`
                  + (providerSetup > 0 ? ` · provider setup ${providerSetup.toFixed(1)}ms` : '');
              const model = v.model ? ` · ${v.model}` : '';
              const tokens = v.input_tokens == null ? '' : ` · ${v.input_tokens}in/${v.output_tokens}out`;
              ev(events, 'meta', `✓ signed checkpoint ${v.log_event}${model}${tokens}${speed}`);
            } else if (e.name === 'apiary.inference_attempt_failed') {
              const v = e.value || {};
              ev(events, v.fallback ? 'step' : 'err', v.fallback
                ? `inference ${v.slot} unavailable · falling back to ${v.fallback}`
                : `inference ${v.slot} failed · ${v.detail || 'unknown error'}`);
            }
            break;
          case 'RUN_FINISHED': ev(events, 'meta', 'run finished'); loadRoster(); break;
          case 'RUN_ERROR': ev(events, 'err', e.message); break;
        }
      }
    }
    if (paint) cancelAnimationFrame(paint);
    flushText();
  } catch (err) { ev(events, 'err', String(err)); }
  go.disabled = false;
}

// ------------------------------------------------------------ log

async function renderLog(c) {
  const [d, initialListener] = await Promise.all([j(api('/log?tail=100')), j(api('/listener'))]);
  if (!d.ok) { c.append(el('div', 'ev err', 'error: ' + d.error)); return; }
  const live = section('Live message lifecycle', 'Fast, host-local presence status. Durable received, run, and reply checkpoints remain in the signed log below.');
  const liveBody = el('div'); live.append(liveBody); c.append(live);
  const drawLive = listener => {
    liveBody.replaceChildren();
    if (!listener.ok) { liveBody.append(el('div', 'none', 'Live presence is unavailable: ' + listener.error)); return; }
    let count = 0;
    for (const [kind, channel] of Object.entries(listener.channels || {})) {
      for (const line of (channel.lines || []).slice(-12).reverse()) {
        if (!/(received|inference|reply)/i.test(line)) continue;
        liveBody.append(entryLine(kind, line)); count += 1;
      }
    }
    if (!count) liveBody.append(el('div', 'none', 'No recent message lifecycle events.'));
  };
  drawLive(initialListener);
  listenerPoll = setInterval(async () => drawLive(await j(api('/listener'))), 3000);
  const chain = d.chain.valid ? `chain valid · ${d.chain.entries} entries` : `CHAIN BROKEN: ${d.chain.error}`;
  c.append(entryLine('signed log', chain));
  c.append(help('Every entry is a signed nostr event chained to the previous one — the agent’s tamper-evident memory and audit trail in one. "chain valid" means every signature verifies and no entry was removed or reordered.'));

  const row = el('div', 'row');
  const pub = el('button', 'btn', 'PUBLISH TO RELAYS');
  const rem = el('button', 'btn', 'FETCH REMOTE COPY');
  const st = el('span', 'meta', '');
  row.append(pub, rem, st);
  c.append(row, help('Publish pushes the log to the manifest’s memory.log_relays, tier-enforced: public entries go as-is, self-tier entries go NIP-44-encrypted to the agent’s own key (anyone can store them, only the agent can read them), local-tier entries never leave. Fetch pulls the published copy back, verifies signatures, and decrypts the agent’s own wrapped entries — proof the memory is truly portable.'));

  const out = el('div');
  c.append(out);
  pub.onclick = async () => {
    st.textContent = 'publishing…';
    const r = await j(api('/log/publish'), { method: 'POST' });
    st.textContent = r.ok
      ? `published: ${r.published_public} public, ${r.published_wrapped} wrapped · ${r.skipped_local} local kept back · ${r.already_published} already up`
      : 'failed: ' + r.error;
  };
  rem.onclick = async () => {
    st.textContent = 'fetching…';
    out.replaceChildren();
    const r = await j(api('/log/remote'));
    st.textContent = r.ok ? 'fetched' : 'failed: ' + r.error;
    if (!r.ok) return;
    for (const relay of (r.relays || [])) {
      out.append(entryLine(relay.relay, relay.ok ? `${(relay.events || []).length} events` : 'unreachable: ' + relay.error));
      for (const e of (relay.events || []).slice(0, 30)) {
        const b = e.body || {};
        out.append(entryLine(b.action || (e.wrapped ? '(wrapped)' : '?'), '→ ' + (b.outcome || ''), [
          new Date(e.at * 1000).toLocaleString() + (e.wrapped ? ' · self-tier (decrypted locally)' : ' · public'),
          e.id,
        ]));
      }
    }
  };

  for (const e of (d.entries || []).slice().reverse()) {
    const b = e.body || {};
    const meta = [
      new Date(e.at * 1000).toLocaleString()
        + (b.model ? ' · ' + b.model : '')
        + (b.harness ? ' · ' + b.harness : '')
        + (b.cost ? ` · ${b.cost.input_tokens}in/${b.cost.output_tokens}out` : '')
        + (b.detail?.timings_ms?.first_token_ms == null ? ''
          : ` · first text ${Math.round(b.detail.timings_ms.first_token_ms)}ms`),
      e.id,
    ];
    c.append(entryLine(b.action || '?', '→ ' + (b.outcome || '?'), meta));
  }
}

// ------------------------------------------------------------ manifest

async function renderManifest(c) {
  const d = await currentManifest();
  if (!d.ok) { c.append(el('div', 'ev err', 'Could not load configuration: ' + d.error)); return; }
  const head = el('div', 'page-head');
  head.append(el('div', 'eyebrow', d.ratified ? 'Approved configuration' : 'Draft configuration'),
    el('h2', 'page-title', 'Configuration'),
    el('p', 'page-lede', 'Advanced editing for models, routing, memory, limits, governance, and host coordination. Saving creates a draft for separate review and approval.'));
  c.append(head);

  const guide = el('details');
  guide.append(el('summary', null, 'Configuration field guide'));
  const g = el('div');
  const rows = [
    ['identity.npub', 'the agent’s public key — immutable; the host refuses an amendment that changes it'],
    ['constitution', 'the agent’s durable purpose, role, voice, operating principles, and behavioral boundaries. These are authoritative instructions, but never grant capabilities or override enforced limits.'],
    ['skills[]', 'approved procedural knowledge imported from SKILL.md. Each entry stores name, trigger description, instructions, and optional connector requirements. Requirements never grant connectors.'],
    ['inference[]', 'agent-owned inference connections. Task-model names are routing targets; reserved names embed, transcribe, and speak provide semantic memory and voice equipment. Manage ordinary changes from Inference. Per-slot credentials are NIP-44-sealed.'],
    ['routing.default', 'slot used when no rule matches'],
    ['routing.rules[]', 'conditional slot choices, e.g. {when: task.class == "reasoning", to: workhorse}'],
    ['routing.floors[]', 'human-owned clamps, e.g. {when: data.class == "sensitive", to: local} — routing may be stricter than a floor, never looser'],
    ['connectors[]', 'what the agent may touch, default-deny. Each entry: {type, caps, credential?}. Managed from Capabilities: host library holds configurations, grants are per-agent amendments with credentials sealed to this agent alone.'],
    ['memory.log', 'default tier for new log entries: public | self | local'],
    ['memory.index', 'semantic index location (local)'],
    ['memory.log_relays[]', 'nostr relays the log publishes to (tier-enforced)'],
    ['presence.buzz', 'standing workspace membership: {relay, trigger?}. Constitutional — where the agent lives is ratified. While the agent is ACTIVE (Overview), the host supervises its mention listener.'],
    ['governance.suspend_keys[]', 'legacy/full governor npubs — ratifiers; at least one governor is required'],
    ['governance.managers[]', 'scoped viewer, operator, editor, or governor identities'],
    ['governance.budgets.tokens_per_day', 'hard daily token ceiling, enforced by atomic reservations'],
    ['lease', 'which host runs the agent: relay-event heartbeats, takeover policy (contested-human = a person resolves disputes), timings'],
  ];
  for (const [k, v] of rows) g.append(kv(k, v));
  guide.append(g);
  c.append(guide);

  const ed = el('textarea'); ed.id = 'med'; ed.spellcheck = false; ed.value = d.yaml;
  ed.setAttribute('aria-label', 'Manifest YAML');
  const row = el('div', 'row');
  const save = el('button', 'btn solid', 'Save changes for review');
  const status2 = el('span', 'meta', '');
  row.append(save, status2);
  c.append(ed, row);
  c.append(help('Saving pauses the agent until these changes pass the review-and-approve step.'));
  save.onclick = async () => {
    save.disabled = true; status2.textContent = 'Validating…';
    const r = await j(api('/manifest'), {
      method: 'PUT', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ yaml: ed.value }),
    });
    save.disabled = false;
    status2.textContent = r.ok ? 'Saved. Review the changes above.' : `Could not save: ${r.error}`;
    if (r.ok) { await loadRoster(); render(); }
  };

  const ext = el('details', 'technical');
  ext.append(el('summary', null, 'Approve with an external signing key'));
  const extBody = el('div');
  extBody.append(help('For governors who keep their master nostr key outside this host: export the unsigned ratification event, sign it with your own tooling (nak, a NIP-07 extension, a signer app), and import the signed event. The keystore never sees the key.'));
  const exRow = el('div', 'row');
  const exKey = technicalInput(el('input', 'grow')); exKey.placeholder = 'external governor key (npub or hex, must have governor role)';
  const exGo = el('button', 'btn', 'EXPORT UNSIGNED EVENT');
  exRow.append(exKey, exGo);
  const exOut = el('pre'); exOut.style.display = 'none';
  const imRow = el('div', 'row');
  const imIn = el('textarea'); imIn.rows = 4; imIn.placeholder = 'paste the signed event JSON here';
  const imGo = el('button', 'btn', 'IMPORT SIGNED EVENT');
  const exSt = el('span', 'meta', '');
  imRow.append(imGo, exSt);
  extBody.append(exRow, exOut, imIn, imRow);
  ext.append(extBody);
  c.append(ext);
  exGo.onclick = async () => {
    const r = await j(api('/ratify/export'), {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ as: exKey.value.trim() }),
    });
    exOut.style.display = 'block';
    exOut.textContent = r.ok ? JSON.stringify(r.unsigned_event, null, 2) : 'refused: ' + r.error;
  };
  imGo.onclick = async () => {
    let evj;
    try { evj = JSON.parse(imIn.value); } catch { exSt.textContent = 'not valid JSON'; return; }
    exSt.textContent = 'importing…';
    const r = await j(api('/ratify/import'), {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ event: evj }),
    });
    exSt.textContent = r.ok
      ? (r.snapshot_warning ? 'Approved, but the review snapshot could not be saved: ' + r.snapshot_warning : 'Approved by ' + r.ratified_by.slice(0, 12) + '…')
      : 'Could not import approval: ' + r.error;
    loadRoster(); if (r.ok) render();
  };
}

// ------------------------------------------------------------ buzz

function workspaceDraftScope() {
  const host = hostDisplayName() || location.origin || 'apiary';
  return `${host}::${sel || ''}`;
}

function workspaceDraftKey(field) {
  return `apiary.workspace.${encodeURIComponent(workspaceDraftScope())}.${field}`;
}

function workspaceDraft(field, fallback = '') {
  const saved = localStorage.getItem(workspaceDraftKey(field));
  return saved === null ? String(fallback || '') : saved;
}

function saveWorkspaceDraft(field, value) {
  localStorage.setItem(workspaceDraftKey(field), String(value || ''));
}

function configuredBuzz(manifestResult) {
  const manifest = manifestResult && manifestResult.manifest ? manifestResult.manifest : {};
  const buzz = manifest.presence && manifest.presence.buzz;
  return buzz && typeof buzz === 'object' ? buzz : {};
}

function relayInput(configuredRelay = '') {
  const inp = technicalInput(el('input', 'relay-address'));
  inp.placeholder = 'wss://your-buzz-relay';
  const scopedRelay = localStorage.getItem(workspaceDraftKey('relay'));
  const fallbackRelay = configuredRelay || localStorage.getItem('apiary.relay') || '';
  inp.value = scopedRelay === null ? fallbackRelay : scopedRelay;
  if (scopedRelay === null && fallbackRelay) saveWorkspaceDraft('relay', fallbackRelay);
  inp.oninput = () => saveWorkspaceDraft('relay', inp.value);
  inp.onchange = () => {
    inp.value = inp.value.trim();
    saveWorkspaceDraft('relay', inp.value);
  };
  return inp;
}

async function renderBuzz(c) {
  const roster = agents.find(a => a.npub === sel) || {};
  const manifestResult = await currentManifest();
  const buzz = configuredBuzz(manifestResult);
  const configuredRelay = typeof buzz.relay === 'string'
    ? buzz.relay
    : (typeof buzz.url === 'string' ? buzz.url : '');
  c.append(help('Buzz is a nostr-native agent workspace — and structurally just a relay, so the agent joins with its own key (NIP-42 auth), not a bot token. Everything here acts AS the selected agent and logs to its signed history.'));

  const relaySec = section('Workspace relay', 'The Buzz relay URL. Membership is admitted relay-side (buzz-admin); until admitted, operations will be refused politely.');
  const relay = relayInput(configuredRelay);
  relaySec.append(relay);
  c.append(relaySec);
  const rv = () => relay.value.trim();

  const profSec = section('Profile',
    'Publishes a kind-0 profile so the workspace shows a name instead of a hex key. Also lands in the public log.');
  const pName = el('input');
  pName.placeholder = 'display name';
  pName.value = workspaceDraft('profile.name', roster.name || '');
  pName.oninput = () => saveWorkspaceDraft('profile.name', pName.value);
  const pAbout = el('input', 'grow');
  pAbout.placeholder = 'about (optional)';
  pAbout.value = workspaceDraft('profile.about');
  pAbout.oninput = () => saveWorkspaceDraft('profile.about', pAbout.value);
  const pGo = el('button', 'btn', 'PUBLISH PROFILE');
  const pSt = el('span', 'meta', '');
  const pRow = el('div', 'row'); pRow.append(pName, pAbout, pGo, pSt);
  profSec.append(pRow);
  c.append(profSec);
  pGo.onclick = async () => {
    pSt.textContent = 'publishing…';
    const r = await j(api('/buzz/profile'), {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ relay: rv(), name: pName.value.trim(), about: pAbout.value.trim() || null }),
    });
    if (r.ok) {
      pName.value = pName.value.trim();
      pAbout.value = pAbout.value.trim();
      saveWorkspaceDraft('profile.name', pName.value);
      saveWorkspaceDraft('profile.about', pAbout.value);
    }
    pSt.textContent = r.ok ? 'published ✓' : 'failed: ' + r.error;
  };

  const chanSec = section('Channels', 'Click a channel to read it; use the box to post as this agent.');
  const chList = el('div');
  const chSt = el('span', 'meta', '');
  const chGo = el('button', 'btn', 'LIST CHANNELS');
  const chRow = el('div', 'row'); chRow.append(chGo, chSt);
  const joinIn = el('input', 'grow'); joinIn.placeholder = 'channel id to join (NIP-29 join request)';
  const joinGo = el('button', 'btn', 'REQUEST JOIN');
  const joinRow = el('div', 'row'); joinRow.append(joinIn, joinGo);
  const msgs = el('div');
  const postIn = el('input', 'grow'); postIn.placeholder = 'message…';
  const postGo = el('button', 'btn solid', 'POST');
  const postRow = el('div', 'row'); postRow.append(postIn, postGo);
  postRow.style.display = 'none';
  let curChan = workspaceDraft('channel.id') || null;
  let curChanName = workspaceDraft('channel.name') || null;
  chanSec.append(chRow, chList, joinRow, msgs, postRow);
  c.append(chanSec);

  const readChan = async (id, name) => {
    const displayName = name || curChanName || id;
    curChan = id;
    curChanName = displayName;
    saveWorkspaceDraft('channel.id', id);
    saveWorkspaceDraft('channel.name', displayName);
    msgs.replaceChildren(el('div', 'meta', 'reading #' + displayName + '…'));
    const r = await j(api('/buzz/read') + `?relay=${encodeURIComponent(rv())}&channel=${encodeURIComponent(id)}&limit=30`);
    msgs.replaceChildren();
    postRow.style.display = 'flex';
    if (!r.ok) { msgs.append(el('div', 'ev err', r.error)); return; }
    const keyRow = await j('/api/key?key=' + encodeURIComponent(sel));
    for (const msg of (r.messages || [])) {
      const line = el('div', 'msg' + (keyRow.ok && msg.author === keyRow.hex ? ' mine' : ''));
      line.append(el('span', 'who', msg.author.slice(0, 8) + '… '), document.createTextNode(msg.content));
      line.append(el('div', 'meta', new Date(msg.at * 1000).toLocaleString()));
      msgs.append(line);
    }
  };
  chGo.onclick = async () => {
    chSt.textContent = 'authenticating + listing…';
    const r = await j(api('/buzz/channels') + '?relay=' + encodeURIComponent(rv()));
    chSt.textContent = r.ok ? (r.channels.length + ' channels') : 'failed: ' + r.error;
    chList.replaceChildren();
    if (!r.ok) return;
    for (const ch of (r.channels || [])) {
      const n = el('div', 'chan', '#' + (ch.name || '(unnamed)') + ' · ' + ch.id);
      n.onclick = () => readChan(ch.id, ch.name);
      chList.append(n);
    }
    const remembered = (r.channels || []).find(ch => ch.id === curChan);
    if (remembered) await readChan(remembered.id, remembered.name);
  };
  joinGo.onclick = async () => {
    chSt.textContent = 'requesting…';
    const r = await j(api('/buzz/join'), {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ relay: rv(), channel: joinIn.value.trim() }),
    });
    chSt.textContent = r.ok ? r.note : 'failed: ' + r.error;
  };
  postGo.onclick = async () => {
    if (!curChan || !postIn.value.trim()) return;
    const r = await j(api('/buzz/post'), {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ relay: rv(), channel: curChan, message: postIn.value }),
    });
    if (r.ok) { postIn.value = ''; readChan(curChan, curChanName); }
    else msgs.append(el('div', 'ev err', 'post failed: ' + r.error));
  };

  const lisSec = section('Mention listener',
    `Keep ${roster.name || 'this agent'} listening for mentions in this Buzz workspace. Apiary will save the listener as a reviewable change before it can run.`);
  const supNote = el('div', 'kv');
  lisSec.append(supNote);
  const listenerDetail = el('p', 'muted');
  lisSec.append(listenerDetail);
  const listenerActions = el('div', 'row');
  const listenerAction = el('button', 'btn', 'Checking listener…');
  listenerAction.disabled = true;
  const listenerStatus = el('span', 'muted');
  listenerActions.append(listenerAction, listenerStatus);
  lisSec.append(listenerActions);
  const lLines = el('pre'); lLines.style.display = 'none';
  lisSec.append(lLines);
  c.append(lisSec);
  const listenerConfig = async () => {
    const result = await currentManifest();
    const active = Boolean((agents.find(a => a.npub === sel) || {}).active);
    if (!result.ok) {
      return {
        ok: false,
        error: result.error || 'Could not load the agent configuration.',
        declared: false,
        ratified: false,
        active,
      };
    }
    const manifest = result.manifest || {};
    return {
      ok: true,
      declared: Boolean(manifest && manifest.presence && manifest.presence.buzz),
      ratified: Boolean(result.ratified),
      active,
    };
  };
  const setListenerAction = (label, run, primary = false) => {
    listenerAction.textContent = label;
    listenerAction.className = primary ? 'btn solid' : 'btn';
    listenerAction.disabled = false;
    listenerAction.onclick = async () => {
      listenerAction.disabled = true;
      listenerStatus.textContent = '';
      try { await run(); }
      catch (e) {
        listenerStatus.textContent = e.message || String(e);
        listenerAction.disabled = false;
      }
    };
  };
  let listenerPolling = false;
  const pollListener = async () => {
    if (listenerPolling) return;
    listenerPolling = true;
    try {
      manifestRequest = null;
      const [state, runtime] = await Promise.all([listenerConfig(), j(api('/listener'))]);
      const ch = runtime.ok ? (runtime.channels || {}).buzz : null;
      const trigger = `@${roster.name || 'agent'}`;

      if (!state.ok) {
        supNote.replaceChildren(el('span', 'k', 'buzz channel'), el('span', 'v', 'configuration unavailable'));
        listenerDetail.textContent = state.error;
        setListenerAction('Retry', pollListener);
        return;
      }

      const status = !state.declared ? 'not set up'
        : !state.ratified ? 'waiting for approval'
        : !state.active ? 'approved, inactive'
        : !runtime.ok ? 'live status unavailable'
        : ch && ch.running ? 'listening'
        : (ch && ch.note) || 'starting';
      supNote.replaceChildren(el('span', 'k', 'buzz channel'), el('span', 'v', status));

      if (!state.declared) {
        listenerDetail.textContent = `Not configured. Set up a listener for ${trigger} on ${rv() || 'the Buzz relay'}, then review and approve the change.`;
        setListenerAction('Set up mention listener', async () => {
          const relayUrl = rv();
          if (!/^wss?:\/\//i.test(relayUrl)) throw new Error('Enter the Buzz relay address first (wss://…).');
          listenerStatus.textContent = 'Creating a reviewable change…';
          const saved = await j(api('/presence'), {
            method: 'POST', headers: {'content-type': 'application/json'},
            body: JSON.stringify({kind: 'buzz', credential: null, config: {relay: relayUrl, trigger}}),
          });
          if (!saved.ok) throw new Error(saved.error || 'Could not set up the mention listener.');
          manifestRequest = null;
          await loadRoster();
          openTab('overview');
        }, true);
      } else if (!state.ratified) {
        listenerDetail.textContent = `The ${trigger} listener is saved but waiting for review and approval.`;
        setListenerAction('Review & approve', async () => openTab('overview'), true);
      } else if (!state.active) {
        listenerDetail.textContent = `The ${trigger} listener is approved. Activate ${roster.name || 'the agent'} to start listening.`;
        setListenerAction(`Activate ${roster.name || 'agent'}`, async () => {
          listenerStatus.textContent = 'Activating…';
          const activated = await j(api('/active'), {
            method: 'POST', headers: {'content-type': 'application/json'},
            body: JSON.stringify({active: true}),
          });
          if (!activated.ok) throw new Error(activated.error || 'Could not activate the agent.');
          await loadRoster();
          listenerStatus.textContent = 'Activated. Starting listener…';
          setTimeout(pollListener, 250);
        }, true);
      } else if (runtime.ok && ch && ch.running) {
        listenerDetail.textContent = `Listening for ${trigger} on ${rv() || 'the configured Buzz relay'}.`;
        listenerAction.textContent = 'Listening';
        listenerAction.className = 'btn';
        listenerAction.disabled = true;
        listenerAction.onclick = null;
        listenerStatus.textContent = '';
      } else if (!runtime.ok) {
        listenerDetail.textContent = `The ${trigger} listener is approved and active, but Apiary could not read its live status: ${runtime.error || 'unknown error'}`;
        setListenerAction('Retry live status', pollListener);
      } else {
        listenerDetail.textContent = `The ${trigger} listener is approved and the agent is active, but the listener has not started. Open the presence controls for its live status and logs.`;
        setListenerAction('Open presence controls', async () => openTab('overview'));
      }
      if (ch && (ch.lines || []).length) {
        lLines.style.display = 'block'; lLines.textContent = ch.lines.join('\n');
      } else {
        lLines.style.display = 'none'; lLines.textContent = '';
      }
    } finally {
      listenerPolling = false;
    }
  };
  pollListener();
  listenerPoll = setInterval(pollListener, 3000);
}

// --------------------------------------------------------------- skills

async function renderSkills(c) {
  const d = await j(api('/skills'));
  if (!d.ok) { c.append(el('div', 'ev err', 'Could not load skills: ' + d.error)); return; }
  const skills = d.skills || [];
  const head = el('div', 'page-head');
  head.append(el('div', 'eyebrow', 'Approved know-how'),
    el('h2', 'page-title', 'Skills'),
    el('p', 'page-lede', 'Skills are reusable workflows and domain expertise. Apiary imports the standard SKILL.md shape, selects relevant skills for each task, and loads only those instructions.'));
  c.append(head);

  const installed = section('Installed skills', skills.length
    ? 'A skill is available only when every connector it requires is separately granted. Skills never add permissions or credentials.'
    : 'No skills are installed. Add a concise SKILL.md below.');
  const list = el('div', 'catalog-list');
  installed.append(list);
  c.append(installed);

  const editor = el('details', 'section'); editor.open = skills.length === 0;
  editor.append(el('summary', null, skills.length ? 'Add or edit a skill' : 'Add a skill'));
  const editorBody = el('div');
  const markdown = el('textarea'); markdown.rows = 18; markdown.spellcheck = false;
  markdown.placeholder = `---
name: web-research
description: Research current topics with public web sources. Use for briefs, comparisons, and fact checking.
---

# Workflow

Search broadly, prefer primary sources, distinguish facts from inference, and cite important claims.`;
  const requirements = el('input');
  requirements.placeholder = 'web-search, web-fetch';
  let originalName = null;
  const save = el('button', 'btn solid', 'Save skill for review');
  const clear = el('button', 'btn', 'New skill');
  const status = el('span', 'meta', '');
  const row = el('div', 'row'); row.append(save, clear, status);
  editorBody.append(
    field('SKILL.md', markdown, 'Frontmatter accepts only name and description. Keep the Markdown body concise and procedural.'),
    field('Required connectors', requirements, 'Optional connector kinds, comma-separated. This checks availability; it does not grant anything.'),
    help('Saving embeds the exact instructions in the portable manifest and pauses the agent until a manager approves the amendment.'),
    row);
  editor.append(editorBody); c.append(editor);

  const resetEditor = () => {
    originalName = null; markdown.value = ''; requirements.value = '';
    save.textContent = 'Save skill for review'; status.textContent = '';
  };
  clear.onclick = () => { resetEditor(); editor.open = true; markdown.focus(); };
  save.onclick = async () => {
    if (!markdown.value.trim()) { status.textContent = 'Paste or write a SKILL.md first.'; markdown.focus(); return; }
    const required = requirements.value.split(/[\n,]+/).map(value => value.trim()).filter(Boolean);
    save.disabled = true; status.textContent = 'Validating and saving amendment…';
    const result = await j(api('/skills'), {
      method: 'POST', headers: {'content-type':'application/json'}, body: JSON.stringify({
        markdown: markdown.value, requires_connectors: required, original_name: originalName,
      }),
    });
    save.disabled = false;
    if (!result.ok) { status.textContent = 'Could not save: ' + result.error; return; }
    status.textContent = 'Saved. Review and approve the amendment before the agent can run.';
    await loadRoster(); render();
  };

  for (const skill of skills) {
    const item = el('div', 'catalog-item');
    item.append(el('h4', null, skill.name), el('p', null, skill.description));
    const meta = el('div', 'catalog-meta');
    meta.append(el('span', skill.available ? 'state ready' : 'state unavailable', skill.available ? 'Available' : 'Missing capabilities'));
    if ((skill.requires_connectors || []).length) {
      meta.append(el('span', null, 'Requires: ' + skill.requires_connectors.join(', ')));
    } else {
      meta.append(el('span', null, 'No connector requirements'));
    }
    item.append(meta);
    if ((skill.missing_connectors || []).length) {
      item.append(help('Grant separately before use: ' + skill.missing_connectors.join(', ')));
    }
    const actions = el('div', 'row');
    const edit = el('button', 'btn', 'Edit');
    const remove = el('button', 'btn danger', 'Remove');
    const itemStatus = el('span', 'meta', '');
    actions.append(edit, remove, itemStatus); item.append(actions); list.append(item);
    edit.onclick = () => {
      originalName = skill.name; markdown.value = skill.markdown;
      requirements.value = (skill.requires_connectors || []).join(', ');
      save.textContent = 'Save skill changes for review'; status.textContent = '';
      editor.open = true; editor.scrollIntoView({behavior:'smooth', block:'start'}); markdown.focus();
    };
    remove.onclick = async () => {
      if (!confirm(`Remove the ${skill.name} skill? The agent will pause until this amendment is approved.`)) return;
      remove.disabled = true; itemStatus.textContent = 'Removing…';
      const result = await j(api('/skills/' + encodeURIComponent(skill.name)), {method:'DELETE'});
      if (!result.ok) { remove.disabled = false; itemStatus.textContent = 'Could not remove: ' + result.error; return; }
      await loadRoster(); render();
    };
  }
}

// ------------------------------------------------------------ connectors

// ------------------------------------------------------------ routines

function whenText(r) {
  if (r.every) return `every ${r.every}`;
  if (r.at) return `once at ${r.at} (${r.tz})`;
  return `${r.when} (${r.tz})`;
}
function tsText(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  const diff = (d - Date.now()) / 1000;
  const abs = Math.abs(diff);
  const rel = abs < 90 ? `${Math.round(abs)}s` : abs < 5400 ? `${Math.round(abs / 60)}m` : abs < 172800 ? `${Math.round(abs / 3600)}h` : `${Math.round(abs / 86400)}d`;
  return `${d.toLocaleString()} (${diff >= 0 ? 'in ' + rel : rel + ' ago'})`;
}

async function renderRoutines(c) {
  await proposalBanner(c);
  await foundingBanner(c);
  const d = await j(api('/routines'));
  if (!d.ok) { c.append(el('div', 'ev err', 'error: ' + d.error)); return; }
  const sec = section('Routines',
    'Standing instructions the governor ratified once; the host replays them on schedule. Time is the only door with no human on the other side, so a routine’s authority comes from ratification — a chat message can never plant one. Each fire is an ordinary governed run (same floors, budget, signed log), on exactly one host (the lease), never overlapping. Keep them small and bounded.');
  if (!d.coordinated) sec.append(help('This agent declares no memory.log_relays — routines run without cross-host coordination (fine for one host; add relays before running the agent on two).'));
  if (!(d.routines || []).length) sec.append(kv('routines', 'none yet — add one below, then ratify in Configuration'));
  for (const r of d.routines) {
    const box = el('div', 'ev');
    const head = el('div', 'row');
    const flag = !r.enabled ? ' · disabled' : r.paused ? ' · PAUSED on this host' : r.spent ? ' · spent (one-shot fired)' : r.running ? ' · running now' : '';
    head.append(el('b', null, r.name), el('span', 'meta', whenText(r) + flag));
    box.append(head);
    box.append(kv('task', r.task));
    box.append(kv('deliver', (r.deliver || []).length ? r.deliver.map(x => x.telegram ? `telegram ${x.telegram}${x.as_voice ? ' (voice)' : ''}` : x.buzz ? `buzz #${x.buzz}` : x.nostr ? 'nostr publish' : x.companion ? `companion${x.as_voice ? ' (voice)' : ''}` : '?').join(', ') : 'log only'));
    box.append(kv('next fire', r.schedule_error ? 'schedule error: ' + r.schedule_error : tsText(r.next_fire)));
    if (r.preview && r.preview.length) box.append(kv('then', r.preview.slice(1).map(p => new Date(p).toLocaleString()).join(' · ')));
    box.append(kv('last', r.last_fired ? `${tsText(r.last_fired)} → ${r.last_outcome || '?'}` : 'never'));
    if (r.last_delivery && r.last_delivery.length) box.append(kv('delivered', JSON.stringify(r.last_delivery)));
    box.append(kv('fires · budget', `${r.fires} · ${r.budget && r.budget.tokens_per_run ? r.budget.tokens_per_run + ' tokens/run' : 'default reservation'} · catch_up ${r.catch_up}`));
    if (r.note) box.append(kv('supervisor', r.note));
    const acts = el('div', 'row');
    const run = el('button', 'btn solid', 'RUN NOW');
    const pause = el('button', 'btn', r.paused ? 'RESUME' : 'PAUSE');
    const st = el('span', 'meta', '');
    acts.append(run, pause, st);
    box.append(acts);
    sec.append(box);
    run.onclick = async () => {
      st.textContent = 'firing… (governed run + delivery)';
      run.disabled = true;
      const res = await j(api('/routines/' + encodeURIComponent(r.name) + '/run'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
      st.textContent = res.ok ? `→ ${res.outcome}; delivered ${JSON.stringify(res.delivered)}` : 'failed: ' + res.error;
      run.disabled = false;
      setTimeout(render, 1500);
    };
    pause.onclick = async () => {
      const res = await j(api('/routines/' + encodeURIComponent(r.name) + '/' + (r.paused ? 'resume' : 'pause')), { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
      st.textContent = res.ok ? (res.paused ? 'paused on this host (schedule stays in the manifest)' : 'resumed') : 'failed: ' + res.error;
      render();
    };
  }
  c.append(sec);

  // ---- add form → appends to manifest YAML, PUTs it; ratify afterward
  const add = section('Add a routine',
    'Writes an amendment to the manifest — re-ratify in Configuration afterward. Times are in the zone you pick; cron is standard 5-field (min hour day month weekday, Sunday = 0).');
  const fName = el('input'); fName.placeholder = 'name (e.g. morning-brief)';
  const fKind = el('select');
  for (const [v, t] of [['when', 'cron'], ['every', 'every (15m, 2h, 1d)'], ['at', 'once at (YYYY-MM-DDTHH:MM)']]) { const o = el('option', null, t); o.value = v; fKind.append(o); }
  const fWhen = el('input', 'grow'); fWhen.placeholder = '0 8 * * 1-5';
  const fTz = el('input'); fTz.placeholder = 'tz (America/Chicago)'; fTz.value = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
  const fTask = el('textarea'); fTask.rows = 3; fTask.placeholder = 'the standing instruction — what should the agent do each time?';
  const fDeliverKind = el('select');
  for (const [v, t] of [['', 'log only (no delivery)'], ['telegram', 'telegram chat id'], ['buzz', 'buzz channel'], ['nostr', 'nostr publish'], ['companion', 'companion (spoken by apiary-voice)']]) { const o = el('option', null, t); o.value = v; fDeliverKind.append(o); }
  const fDeliverTo = el('input', 'grow'); fDeliverTo.placeholder = 'chat id / channel';
  const fVoice = el('input'); fVoice.type = 'checkbox'; fVoice.style.width = 'auto';
  const voiceLabel = el('label', null, ' as voice'); voiceLabel.prepend(fVoice);
  const fBudget = el('input'); fBudget.placeholder = 'tokens/run (e.g. 8000)'; fBudget.value = '8000';
  const go = el('button', 'btn solid', 'ADD (AMEND MANIFEST)');
  const st = el('span', 'meta', '');
  const r1 = el('div', 'row'); r1.append(fName, fKind, fWhen, fTz);
  const r2 = el('div', 'row'); r2.append(fDeliverKind, fDeliverTo, voiceLabel, fBudget);
  const r3 = el('div', 'row'); r3.append(go, st);
  add.append(r1, help('cron: standard 5 fields (Sunday = 0). every: 15m/2h/1d, minimum 1m, no tz needed. at: one-shot, disables itself after firing.'), fTask, r2, r3);
  c.append(add);
  fKind.onchange = () => { fWhen.placeholder = fKind.value === 'when' ? '0 8 * * 1-5' : fKind.value === 'every' ? '30m' : '2026-08-17T15:00'; };
  go.onclick = async () => {
    const name = fName.value.trim().replace(/[^A-Za-z0-9_-]/g, '-');
    if (!name || !fWhen.value.trim() || !fTask.value.trim()) { st.textContent = 'name, schedule, and task are required'; return; }
    const m = await j(api('/manifest'));
    if (!m.ok) { st.textContent = 'failed: ' + m.error; return; }
    let yaml = m.yaml.replace(/\s+$/, '');
    const q = s => JSON.stringify(String(s));
    let entry = `- name: ${name}\n`;
    entry += `  ${fKind.value}: ${q(fWhen.value.trim())}\n`;
    if (fKind.value !== 'every') entry += `  tz: ${q(fTz.value.trim() || 'UTC')}\n`;
    entry += `  task: |\n` + fTask.value.trim().split('\n').map(l => '    ' + l).join('\n') + '\n';
    if (fDeliverKind.value) {
      entry += `  deliver:\n`;
      if (fDeliverKind.value === 'companion') entry += `  - companion: true\n`;
      else if (fDeliverKind.value === 'nostr') entry += `  - nostr: publish\n`;
      else entry += `  - ${fDeliverKind.value}: ${q(fDeliverTo.value.trim())}\n`;
      if (fVoice.checked) entry += `    as_voice: true\n`;
    }
    if (fBudget.value.trim()) entry += `  budget:\n    tokens_per_run: ${parseInt(fBudget.value, 10) || 8000}\n`;
    if (/^routines:\s*$/m.test(yaml)) yaml += '\n' + entry;
    else if (/^routines:/m.test(yaml)) yaml += '\n' + entry;
    else yaml += '\nroutines:\n' + entry;
    const r = await j(api('/manifest'), { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ yaml }) });
    st.textContent = r.ok ? `added ${name} — now ratify in Configuration` : 'failed: ' + r.error;
    if (r.ok) { loadRoster(); setTimeout(render, 800); }
  };
}

async function renderConnectors(c) {
  const lib = await j('/api/connectors');
  if (!lib.ok) { c.append(el('div', 'ev err', 'error: ' + lib.error)); return; }
  const d = await j(api('/manifest'));
  if (!d.ok) { c.append(el('div', 'ev err', 'error: ' + d.error)); return; }

  // ---- this agent's grants
  const gSec = section('Grants',
    'A grant copies a host-library entry into this agent’s manifest, sealing any secret to this agent alone. Every grant or revoke is an amendment — re-ratify in Configuration afterward.');
  const grants = (d.manifest.connectors || []);
  if (!grants.length) gSec.append(kv('grants', 'none — the agent can think and speak, not act'));
  for (const g of grants) {
    const box = el('div', 'ev');
    const row = el('div', 'row');
    const title = (g.caps && g.caps.library_name) || (g.caps && g.caps.vaults && g.caps.vaults[0] && g.caps.vaults[0].name) || g.type;
    row.append(el('b', null, title), el('span', 'meta', connectorKindLabel[g.type] || g.type), el('span', 'meta', g.credential ? 'credential sealed to this agent' : 'no credential'));
    row.append(el('span', 'grow', ''));
    const rv = el('button', 'btn danger', 'REVOKE');
    row.append(rv);
    box.append(row);
    connectorDetails(box, g.type, g.caps || {}, async (mode, select) => {
      const previous = connectorAccessMode(g.type, g.caps || {});
      const caps = {}; setConnectorAccess(g.type, caps, mode);
      select.disabled = true;
      const r = await j(api('/connectors/' + encodeURIComponent(g.type) + '/caps'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ caps }) });
      select.disabled = false;
      if (!r.ok) select.value = previous;
      else {
        g.caps = Object.assign({}, g.caps || {}, r.caps || {});
        const persisted = connectorAccessMode(g.type, g.caps);
        select.value = persisted;
      }
      const persisted = connectorAccessMode(g.type, g.caps || {});
      gStatus.textContent = r.ok ? `${persisted === 'read-write' ? 'read + write enabled' : 'read-only'} — re-ratify in Configuration` : 'failed: ' + r.error;
      if (r.ok) loadRoster();
    });
    rv.onclick = async () => {
      const r = await j(api('/connectors/' + encodeURIComponent(g.type)), { method: 'DELETE' });
      gStatus.textContent = r.ok ? `revoked ${g.type} — re-ratify in Configuration` : 'failed: ' + r.error;
      loadRoster(); render();
    };
    if (g.type === 'mcp') {
      // Discover with THIS agent's sealed credential (post-OAuth), tick, apply.
      // OAuth-backed servers must never offer a knowingly unauthenticated
      // probe: authenticate first, then enumerate the agent's actual tools.
      const oauthPending = !!(g.caps && (g.caps.oauth || g.caps.oauth_client_id) && !g.credential);
      const dRow = el('div', 'row');
      const disc = el('button', 'btn', 'DISCOVER TOOLS');
      const dSt = el('span', 'meta', '');
      dRow.append(disc, dSt);
      const toolsBox = el('div');
      if (oauthPending) {
        dSt.textContent = 'Connect with OAuth below before discovering tools.';
        box.append(dSt);
      } else {
        box.append(dRow, toolsBox);
      }
      disc.onclick = async () => {
        dSt.textContent = 'probing with this agent’s credential…';
        const key = (g.caps && (g.caps.library_name || g.caps.url || g.caps.command)) || 'mcp';
        const r = await j(api('/connectors/' + encodeURIComponent(key) + '/discover'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
        if (!r.ok) { dSt.textContent = 'failed: ' + r.error; return; }
        const policies = mcpToolPolicies(r.tools, g.caps || {});
        toolsBox.replaceChildren();
        dSt.textContent = `${r.tools.length} tools — choose category or per-tool access`;
        renderMcpToolPolicyPicker(toolsBox, r.tools, policies);
        const apply = el('button', 'btn solid', 'APPLY ALLOWLIST (AMEND)');
        const aSt = el('span', 'meta', '');
        const aRow = el('div', 'row'); aRow.append(apply, aSt);
        toolsBox.append(aRow);
        apply.onclick = async () => {
          const toolAccess = mcpToolPolicyObject(policies);
          const rr = await j(api('/connectors/mcp/allowed_tools'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ tools: Object.keys(toolAccess), tool_access: toolAccess }) });
          aSt.textContent = rr.ok ? 'Applied. Opening review and approval…' : 'failed: ' + rr.error;
          if (rr.ok) {
            g.caps = Object.assign({}, g.caps || {}, { allowed_tools: rr.allowed_tools, tool_access: rr.tool_access || toolAccess, access: rr.access || 'mixed' });
            await loadRoster(); openTab('overview');
          }
        };
      };
      const autoKey = (g.caps && (g.caps.library_name || g.caps.url || g.caps.command)) || 'mcp';
      if (window.__autoDiscoverMcp === autoKey) {
        window.__autoDiscoverMcp = null;
        setTimeout(() => disc.click(), 0);
      }
    }
    gSec.append(box);
  }
  const gRow = el('div', 'row');
  const gSel = el('select');
  for (const e of (lib.library || [])) {
    const o = el('option', null, `${e.name} (${e.kind})`);
    o.value = e.name; gSel.append(o);
  }
  if (!(lib.library || []).length) gSel.append(el('option', null, 'library is empty — open it above to add entries'));
  const gCred = el('input', 'grow'); gCred.type = 'password';
  gCred.placeholder = 'secret to seal to this agent (optional)';
  const gGo = el('button', 'btn solid', 'GRANT');
  const gStatus = el('span', 'meta', '');
  gRow.append(gSel, gCred, gGo, gStatus);
  gSec.append(gRow,
    help('The secret (if any) is sealed with NIP-44 to this agent’s key at grant time and lands in the manifest as a blob — never stored anywhere else, unreadable by other agents or hosts.'));
  c.append(gSec);
  const updateGrantHint = () => {
    const entry = (lib.library || []).find(e => e.name === gSel.value);
    const catalog = (lib.catalog || []).find(item => entry && entry.caps && entry.caps.catalog_id === item.id);
    const wantsOauth = !!(entry && entry.caps && (entry.caps.oauth || entry.caps.oauth_client_id));
    gCred.placeholder = catalog && catalog.credential_label
      ? catalog.credential_label + ' — encrypted for this agent'
      : 'secret to seal to this agent (optional)';
    gCred.disabled = wantsOauth;
    gGo.textContent = wantsOauth ? 'CONNECT WITH OAUTH' : 'GRANT';
  };
  gSel.onchange = updateGrantHint; updateGrantHint();
  gGo.onclick = async () => {
    if (!gSel.value) return;
    const entry = (lib.library || []).find(e => e.name === gSel.value);
    const catalog = (lib.catalog || []).find(item => entry && entry.caps && entry.caps.catalog_id === item.id);
    const needsCredential = catalog && catalog.setup === 'credential';
    if (needsCredential && !gCred.value) {
      gStatus.textContent = `${catalog.credential_label || 'credential'} required`;
      gCred.focus();
      return;
    }
    const wantsOauth = entry && entry.caps && (entry.caps.oauth || entry.caps.oauth_client_id) && !gCred.value;
    if (wantsOauth) {
      gStatus.textContent = 'starting OAuth…';
      const r = await j(api('/connectors/oauth'), {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ name: gSel.value }),
      });
      if (!r.ok) { gStatus.textContent = 'failed: ' + r.error; return; }
      gStatus.replaceChildren();
      const a = oauthAuthorizeControl('AUTHORIZE IN BROWSER →', r.auth_url);
      gStatus.append(a, el('span', 'meta', ' waiting for the callback…'));
      const poll = setInterval(async () => {
        const d2 = await j(api('/manifest'));
        const connected = d2.ok && (d2.manifest.connectors || []).some(connector =>
          connector.type === 'mcp' && connector.credential && connector.caps && connector.caps.library_name === gSel.value);
        if (connected) {
          clearInterval(poll);
          window.__autoDiscoverMcp = gSel.value;
          gStatus.textContent = 'OAuth complete — discovering tools…';
          loadRoster(); render();
        }
      }, 3000);
      return;
    }
    gStatus.textContent = 'granting…';
    const r = await j(api('/connectors'), {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: gSel.value, credential: gCred.value || null }),
    });
    gStatus.textContent = r.ok ? `granted ${r.kind} — re-ratify in Configuration` : 'failed: ' + r.error;
    gCred.value = '';
    loadRoster(); if (r.ok) render();
  };


}

// ------------------------------------------------------------ host library (host-scoped, all agents)

/// Detail rows for a connector's caps, one fact per line, into `card`.
/// `onAccess(mode, select)` renders an editable access selector when the
/// connector can provide both read-only and read/write behavior.
function connectorDetails(card, kind, caps, onAccess) {
  caps = caps || {};
  if (kind === 'obsidian' || kind === 'markdown-vault') {
    for (const v of (caps.vaults || [])) card.append(kv(v.name, v.path));
    const row = el('div', 'kv');
    const val = el('span', 'v');
    if (onAccess) {
      const select = accessSelect(connectorAccessMode(kind, caps));
      select.onchange = () => onAccess(select.value, select);
      val.append(select);
    } else val.textContent = caps.write ? 'Read + write' : 'Read only';
    row.append(el('span', 'k', 'access'), val); card.append(row);
  } else if (kind === 'mcp') {
    card.append(kv('transport', caps.transport === 'http' ? `remote · ${caps.url}` : `local · ${caps.command || '?'} ${(caps.args || []).join(' ')}`.trim()));
    if (caps.oauth_client_id) card.append(kv('auth', 'OAuth (sign-in at grant)'));
    const mode = connectorAccessMode(kind, caps);
    if (mode === 'mixed') {
      card.append(kv('access', 'Per tool · open Discover tools to edit'));
    } else if (onAccess && connectorSupportsReadWrite(kind, caps)) {
      const select = accessSelect(mode); select.onchange = () => onAccess(select.value, select);
      const accessRow = el('div', 'kv'); const value = el('span', 'v'); value.append(select);
      accessRow.append(el('span', 'k', 'access'), value); card.append(accessRow);
    } else card.append(kv('access', mode === 'read-only' ? 'Read only' : 'Read + write'));
    const tools = caps.allowed_tools || [];
    const tv = el('span', 'v');
    if (!tools.length) tv.textContent = caps.oauth || caps.oauth_client_id ? 'none selected yet' : 'none allowed';
    else if (tools.includes('*')) tv.textContent = 'all tools (*)';
    else for (const t of tools) {
      const policy = caps.tool_access && caps.tool_access[t];
      const chip = el('span', 'chip', policy ? `${t} · ${policy === 'read-only' ? 'R' : 'R/W'}` : t);
      chip.style.marginRight = '4px'; tv.append(chip);
    }
    const row = el('div', 'kv'); row.append(el('span', 'k', 'tools'), tv); card.append(row);
  } else if (kind === 'nostr-publish') {
    card.append(kv('access', 'Write only · publish public notes'), kv('relays', (caps.relays || []).join(', ')));
  } else if (kind === 'web-search') {
    card.append(kv('provider', caps.provider === 'brave' || !caps.provider ? 'Brave Search API' : caps.provider),
      kv('results', `up to ${caps.max_results || 10} per search`),
      kv('region', `${caps.country || 'US'} · ${caps.search_lang || 'en'}`),
      kv('SafeSearch', caps.safesearch || 'moderate'),
      kv('page reader', caps.fetch_public_pages ? 'all public HTTPS pages included' : 'not included'));
  } else if (kind === 'web-fetch') {
    card.append(kv('access', caps.allow_all_public ? 'all public HTTPS websites' : (caps.allowed_domains || []).join(', ')));
    if (!caps.allow_all_public) card.append(kv('subdomains', caps.allow_subdomains ? 'allowed' : 'not allowed'));
    card.append(kv('safety', 'private and special-use networks blocked'),
      kv('response limit', `${Math.round((caps.max_bytes || 262144) / 1024)} KiB`));
  } else if (kind === 'files') {
    for (const root of (caps.roots || [])) card.append(kv(root.name, root.path));
    card.append(kv('access', 'read-only'), kv('file types', (caps.extensions || []).join(', ')));
  } else if (kind === 'git') {
    for (const repo of (caps.repos || [])) card.append(kv(repo.name, repo.path));
    card.append(kv('access', 'read-only · no hooks or external diff programs'));
  } else {
    card.append(kv('caps', JSON.stringify(caps)));
  }
}

function capsSummary(kind, caps) {
  if (kind === 'obsidian' || kind === 'markdown-vault') {
    const v = (caps.vaults || []).map(x => `${x.name} → ${x.path}`).join('; ');
    return `${v || 'no vaults'}${caps.write ? ' · writable' : ' · read-only'}`;
  }
  if (kind === 'mcp') {
    const where = caps.transport === 'http' ? caps.url : `${caps.command || '?'} ${(caps.args || []).join(' ')}`.trim();
    const tools = (caps.allowed_tools || []).join(', ') || 'no tools allowed';
    const mode = connectorAccessMode(kind, caps);
    const access = mode === 'mixed' ? 'Per tool' : mode === 'read-only' ? 'Read only' : 'Read + write';
    return `${where}${caps.oauth_client_id ? ' · OAuth' : ''} · ${access} · tools: ${tools}`;
  }
  if (kind === 'nostr-publish') return `relays: ${(caps.relays || []).join(', ')}`;
  if (kind === 'web-search') return `Brave Search · up to ${caps.max_results || 10} results · ${caps.country || 'US'}/${caps.search_lang || 'en'}${caps.fetch_public_pages ? ' · public page reader included' : ''}`;
  if (kind === 'web-fetch') return caps.allow_all_public
    ? 'all public HTTPS websites · private networks blocked'
    : `HTTPS: ${(caps.allowed_domains || []).join(', ') || 'no domains'}`;
  if (kind === 'files') return `${(caps.roots || []).map(x => `${x.name} → ${x.path}`).join('; ') || 'no roots'} · read-only`;
  if (kind === 'git') return `${(caps.repos || []).map(x => `${x.name} → ${x.path}`).join('; ') || 'no repositories'} · read-only`;
  return JSON.stringify(caps);
}

async function renderLibrary(c) {
  c.append(help('Host-scoped: named connector configurations (kind + caps — never secrets), shared by all agents. Grant from an agent’s Capabilities; each grant is a ratified amendment for that agent alone.'));
  const lib = await j('/api/connectors');
  if (!lib.ok) { c.append(el('div', 'ev err', 'error: ' + lib.error)); return; }

  // Which agents hold a grant of each kind — the all-agents view.
  const grantsByKind = {};
  for (const a of agents) {
    const d = await j(`/api/agents/${encodeURIComponent(a.npub)}/manifest`);
    if (!d.ok) continue;
    for (const g of (d.manifest.connectors || [])) {
      (grantsByKind[g.type] = grantsByKind[g.type] || []).push(a.name || shortNostrId(a.npub));
    }
  }

  const lSec = section('Entries',
    'Kinds this host binds: ' + (lib.host_binds || []).join(', ') + '.');
  const catalogSec = section('Recommended connectors',
    'Trusted templates with narrow defaults. Adding one creates a library entry only; an agent receives nothing until you grant it and ratify the change.');
  const catalogList = el('div', 'catalog-list');
  catalogSec.append(catalogList);
  if (window.__libFlash) {
    const f = el('div', 'ev'); f.style.borderColor = 'var(--amber)';
    f.append(el('b', null, '✓ ' + window.__libFlash));
    lSec.append(f);
    window.__libFlash = null;
  }
  const entries = (lib.library || []).slice();
  const list = el('div');
  const lStatus = el('span', 'meta', '');
  const drawList = () => {
    list.replaceChildren();
    if (!entries.length) { list.append(el('div', 'meta', 'no entries yet — add your first below')); return; }
    entries.forEach((e, i) => {
      const card = el('div', 'ev');
      const head = el('div', 'row');
      head.append(el('b', null, e.name), el('span', 'meta', connectorKindLabel[e.kind] || e.kind));
      const holders = grantsByKind[e.kind] || [];
      const spacer = el('span', 'grow', ''); head.append(spacer);
      const del = el('button', 'btn danger', 'REMOVE');
      head.append(del);
      card.append(head);
      const caps = e.caps || {};
      connectorDetails(card, e.kind, caps, async (mode, select) => {
        const previous = connectorAccessMode(e.kind, caps);
        setConnectorAccess(e.kind, caps, mode); e.caps = caps; select.disabled = true;
        window.__libFlash = `${e.name}: ${mode === 'read-write' ? 'read + write' : 'read-only'} for future grants (existing grants keep their own setting — change it on the agent’s Capabilities)`;
        const ok = await saveLib();
        select.disabled = false;
        if (!ok) { setConnectorAccess(e.kind, caps, previous); select.value = previous; }
      });
      // Who has it, and grant from here.
      const gRow = el('div', 'row');
      gRow.append(el('span', 'meta', holders.length ? 'granted to: ' + holders.join(', ') : 'granted to: nobody yet'));
      const sel = el('select');
      const eligible = agents.filter(a => !holders.includes(a.name || shortNostrId(a.npub)));
      for (const a of eligible) { const o = el('option', null, a.name || shortNostrId(a.npub)); o.value = a.npub; sel.append(o); }
      const gBtn = el('button', 'btn', 'GRANT TO ▸');
      const gSt = el('span', 'meta', '');
      if (eligible.length) gRow.append(sel, gBtn, gSt);
      card.append(gRow);
      list.append(card);
      del.onclick = async () => { entries.splice(i, 1); window.__libFlash = `removed ${e.name} (grants already made are untouched)`; await saveLib(); };
      gBtn.onclick = async () => {
        const npub = sel.value; if (!npub) return;
        const needsSecret = e.kind === 'web-search' || (e.kind === 'mcp' && caps.transport === 'http' && !caps.oauth && !caps.oauth_client_id);
        if (needsSecret) { gSt.textContent = 'this one needs an API key sealed to the agent — grant it from the agent’s Capabilities'; return; }
        gBtn.disabled = true; gSt.textContent = 'granting…';
        const r = await j(`/api/agents/${encodeURIComponent(npub)}/connectors`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name: e.name }) });
        gBtn.disabled = false;
        if (r.ok) {
          const who = (agents.find(a => a.npub === npub) || {}).name || shortNostrId(npub);
          window.__libFlash = `granted ${e.name} to ${who} — ratify on ${who}’s Configuration before it takes effect`;
          loadRoster(); render();
        } else if (r.oauth_url || (r.error && /oauth/i.test(r.error))) {
          gSt.textContent = 'needs OAuth sign-in — grant from the agent’s Capabilities (it opens the flow)';
        } else gSt.textContent = 'failed: ' + r.error;
      };
    });
  };
  // ---- add: a form per kind (JSON is the advanced view, not the way in)
  const addSec = section('Add a connector',
    'Pick a kind and fill in the fields. Nothing here is secret — secrets are sealed to an agent at grant time. Removing a library entry does not revoke grants; those live in agent manifests.');
  const nName = el('input'); nName.placeholder = 'library name (e.g. my-notes)';
  nName.title = 'How this entry is listed in the library and picked when granting to an agent';
  nName.oninput = () => { nName.dataset.auto = ''; };
  const nKind = el('select');
  const kindLabels = {
    'web-search': 'Full web search & research (Brave)',
    'web-fetch': 'Web page reader (open known URLs)',
    'files': 'Files and documents (read-only folders)',
    'git': 'Git repositories (read-only)',
    'obsidian': 'Obsidian vault (memory + notes tools)',
    'markdown-vault': 'Markdown folder (memory + notes tools)',
    'mcp': 'MCP server (tools; stdio or remote/OAuth)',
    'nostr-publish': 'Nostr publish (post notes to relays)',
  };
  for (const k of (lib.host_binds || []).filter(k => k !== 'mock-echo')) { const o = el('option', null, kindLabels[k] || k); o.value = k; nKind.append(o); }
  const kindRow = el('div', 'row'); kindRow.append(nName, nKind);
  const fields = el('div');
  const advanced = el('details');
  advanced.append(el('summary', null, 'advanced: caps as JSON'));
  const nCaps = el('textarea'); nCaps.rows = 3; nCaps.placeholder = '{}';
  advanced.append(nCaps, help('This is exactly what the form writes. Edit it if you know what you want; the form fields above are ignored while this has content.'));
  const nGo = el('button', 'btn solid', 'ADD TO LIBRARY');
  const goRow = el('div', 'row'); goRow.append(nGo, lStatus);
  addSec.append(kindRow, fields, advanced, goRow);
  lSec.append(list);
  c.append(catalogSec, lSec, addSec);

  // Per-kind field builders. Each returns { caps() → object, validate() → error|null }.
  let current = null;
  let selectedCatalogId = null;
  const vaultBuilder = (obsidian) => {
    fields.replaceChildren();
    const rows = [];
    const vaultsBox = el('div');
    const addVault = (name = '', path = '') => {
      const r = el('div', 'row');
      const n = el('input'); n.placeholder = 'vault name (e.g. notes)'; n.value = name;
      const pth = technicalInput(el('input', 'grow')); pth.placeholder = obsidian ? '/Users/you/Obsidian/MyVault' : '/Users/you/repos/some-kb/docs'; pth.value = path;
      const choose = el('button', 'btn', 'CHOOSE…');
      choose.title = 'open the system folder picker';
      choose.onclick = async () => {
        choose.disabled = true;
        const r = await j('/api/host/pick-folder', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
        choose.disabled = false;
        if (r.ok && r.path) {
          pth.value = r.path;
          const slug = r.path.split('/').filter(Boolean).pop().toLowerCase().replace(/[^a-z0-9_-]+/g, '-');
          if (!n.value.trim()) n.value = slug;
          if (!nName.value.trim()) nName.value = slug; // the library entry name, too
        } else if (r.unavailable) { lStatus.textContent = 'no folder picker on this host (headless) — type the path'; }
      };
      n.oninput = () => { if (!nName.value.trim() || nName.dataset.auto === '1') { nName.value = n.value.trim(); nName.dataset.auto = '1'; } };
      const rm = el('button', 'btn', '−');
      r.append(n, pth, choose, rm); vaultsBox.append(r); rows.push({ n, pth, r });
      rm.onclick = () => { r.remove(); rows.splice(rows.findIndex(x => x.r === r), 1); };
    };
    addVault();
    const more = el('button', 'btn', '+ another vault');
    more.onclick = () => addVault();
    const access = accessSelect('read-only');
    fields.append(
      help(obsidian
        ? 'An Obsidian vault is a folder of markdown. Paste the folder path (Finder: right-click the vault → Get Info, or drag it into a Terminal). The agent gets search / read tools (and write, only if you allow it), and the notes also feed its memory retrieval as DATA. Tags, [[wikilinks]] and frontmatter are understood. .obsidian and hidden folders are skipped.'
        : 'Any folder of markdown files — a knowledge-base repo checkout, docs, meeting notes. Same tools as Obsidian without the Obsidian-specific parsing.'),
      vaultsBox, more, field('Access', access, 'Read + write adds create, append, and edit tools. Read only is the default.'),
      help('Paths are jailed: the agent cannot read or write outside the folders you list, even via symlinks. Ceiling 5000 notes per vault.'));
    current = {
      caps: () => ({ vaults: rows.map(x => ({ name: x.n.value.trim(), path: x.pth.value.trim() })).filter(v => v.name && v.path), write: access.value === 'read-write' }),
      validate: () => rows.some(x => x.n.value.trim() && x.pth.value.trim()) ? null : 'add at least one vault (name + path)',
    };
  };
  const namedRootsBuilder = ({ noun, pathHint, helpText }) => {
    const rows = [];
    const box = el('div');
    const addRoot = (name = '', path = '') => {
      const row = el('div', 'row');
      const rootName = el('input'); rootName.placeholder = `${noun} name`; rootName.value = name;
      const rootPath = technicalInput(el('input', 'grow')); rootPath.placeholder = pathHint; rootPath.value = path;
      const choose = el('button', 'btn', 'CHOOSE…'); choose.type = 'button';
      const remove = el('button', 'btn', '−'); remove.type = 'button';
      choose.onclick = async () => {
        choose.disabled = true;
        const picked = await j('/api/host/pick-folder', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
        choose.disabled = false;
        if (picked.ok && picked.path) {
          rootPath.value = picked.path;
          const slug = picked.path.split('/').filter(Boolean).pop().toLowerCase().replace(/[^a-z0-9_-]+/g, '-');
          if (!rootName.value.trim()) rootName.value = slug;
          if (!nName.value.trim() || nName.dataset.auto === '1') { nName.value = slug; nName.dataset.auto = '1'; }
        } else if (picked.unavailable) lStatus.textContent = 'no folder picker on this host (headless) — type the path';
      };
      rootName.oninput = () => {
        if (!nName.value.trim() || nName.dataset.auto === '1') { nName.value = rootName.value.trim(); nName.dataset.auto = '1'; }
      };
      row.append(rootName, rootPath, choose, remove); box.append(row);
      const record = { name: rootName, path: rootPath, row }; rows.push(record);
      remove.onclick = () => { row.remove(); rows.splice(rows.indexOf(record), 1); };
    };
    addRoot();
    const more = el('button', 'btn', `+ another ${noun}`); more.type = 'button'; more.onclick = () => addRoot();
    fields.append(help(helpText), box, more);
    return {
      values: () => rows.map(x => ({ name: x.name.value.trim(), path: x.path.value.trim() })).filter(x => x.name && x.path),
      valid: () => rows.some(x => x.name.value.trim() && x.path.value.trim()),
    };
  };
  const webBuilder = () => {
    fields.replaceChildren();
    const restrict = el('input'); restrict.type = 'checkbox'; restrict.style.width = 'auto';
    const restrictLabel = el('label', null, ' restrict access to specific domains'); restrictLabel.prepend(restrict);
    const domains = technicalInput(el('textarea')); domains.rows = 3; domains.placeholder = 'docs.example.com\napi.example.com';
    const subdomains = el('input'); subdomains.type = 'checkbox'; subdomains.style.width = 'auto';
    const subdomainsLabel = el('label', null, ' also allow subdomains of each domain'); subdomainsLabel.prepend(subdomains);
    const domainBox = el('div'); domainBox.style.display = 'none';
    domainBox.append(field('Approved domains', domains, 'One per line or comma-separated. Exact hosts only unless you allow subdomains.'), subdomainsLabel);
    const maxKiB = el('input'); maxKiB.type = 'number'; maxKiB.min = '16'; maxKiB.max = '2048'; maxKiB.value = '256';
    const limitRow = el('div', 'row'); limitRow.append(field('Maximum response (KiB)', maxKiB, '16–2048 KiB'));
    restrict.onchange = () => { domainBox.style.display = restrict.checked ? '' : 'none'; if (restrict.checked) domains.focus(); };
    fields.append(
      help('By default the agent may read any public HTTPS website. DNS is resolved and pinned for every request; loopback, private, link-local, and other special-use networks stay blocked, including after redirects.'),
      restrictLabel, domainBox, limitRow);
    const parsed = () => domains.value.split(/[\s,]+/).map(x => x.trim().toLowerCase()).filter(Boolean);
    current = {
      caps: () => ({ allow_all_public: !restrict.checked, allowed_domains: restrict.checked ? [...new Set(parsed())] : [], allow_subdomains: restrict.checked && subdomains.checked, max_bytes: Number(maxKiB.value) * 1024 }),
      validate: () => {
        if (restrict.checked && !parsed().length) return 'add at least one approved domain or turn off the restriction';
        if (restrict.checked && parsed().some(x => !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(x))) return 'domains must be host names only (no scheme, port, or path)';
        const size = Number(maxKiB.value);
        return Number.isFinite(size) && size >= 16 && size <= 2048 ? null : 'response limit must be between 16 and 2048 KiB';
      },
    };
  };
  const webSearchBuilder = () => {
    fields.replaceChildren();
    const country = el('input'); country.value = 'US'; country.maxLength = 2; country.placeholder = 'US';
    const language = el('input'); language.value = 'en'; language.maxLength = 5; language.placeholder = 'en';
    const maxResults = el('input'); maxResults.type = 'number'; maxResults.min = '1'; maxResults.max = '20'; maxResults.value = '10';
    const safe = el('select');
    for (const [value, label] of [['moderate', 'Moderate (recommended)'], ['strict', 'Strict'], ['off', 'Off']]) { const option = el('option', null, label); option.value = value; safe.append(option); }
    const fetch = el('input'); fetch.type = 'checkbox'; fetch.style.width = 'auto'; fetch.checked = true;
    const fetchLabel = el('label', null, ' include the public HTTPS page reader for full research'); fetchLabel.prepend(fetch);
    const localeRow = el('div', 'row'); localeRow.append(field('Result country', country, 'Two-letter country code'), field('Search language', language, 'Language code'));
    fields.append(
      help('Adds a real search-engine tool backed by the Brave Search API. The API key is not stored in this library entry; paste it only when granting the connector to an agent, where it is encrypted to that agent.'),
      localeRow,
      field('Maximum results per query', maxResults, '1–20; the agent may request fewer'),
      field('SafeSearch', safe, 'Applied by the provider to every query'),
      fetchLabel,
      help('With the page reader enabled, one grant supplies both web_search for discovery and web_fetch for reading sources. Private and special-use networks remain blocked.'));
    current = {
      caps: () => ({ provider: 'brave', country: country.value.trim().toUpperCase(), search_lang: language.value.trim().toLowerCase(), safesearch: safe.value, max_results: Number(maxResults.value), fetch_public_pages: fetch.checked, fetch_max_bytes: 262144 }),
      validate: () => {
        if (!/^[A-Za-z]{2}$/.test(country.value.trim())) return 'country must be a two-letter code';
        if (!/^[A-Za-z]{2,3}(?:-[A-Za-z]{2})?$/.test(language.value.trim())) return 'enter a short language code such as en';
        const count = Number(maxResults.value);
        return Number.isInteger(count) && count >= 1 && count <= 20 ? null : 'maximum results must be between 1 and 20';
      },
    };
  };
  const filesBuilder = () => {
    fields.replaceChildren();
    const roots = namedRootsBuilder({
      noun: 'folder',
      pathHint: '/Users/you/Documents/project',
      helpText: 'The agent can list, search, and read matching text files under only these folders. Symlinks that escape a folder are refused. There are no create, edit, move, or delete tools.',
    });
    const extensions = el('input'); extensions.value = 'txt, md, json, jsonl, yaml, yml, csv, tsv, log, xml, html, toml';
    const maxKiB = el('input'); maxKiB.type = 'number'; maxKiB.min = '16'; maxKiB.max = '1024'; maxKiB.value = '256';
    const hidden = el('input'); hidden.type = 'checkbox'; hidden.style.width = 'auto';
    const hiddenLabel = el('label', null, ' include hidden files and folders (usually unsafe)'); hiddenLabel.prepend(hidden);
    fields.append(field('Allowed file extensions', extensions, 'Comma-separated, without dots.'), field('Maximum file size (KiB)', maxKiB, '16–1024 KiB'), hiddenLabel);
    const parsedExtensions = () => extensions.value.split(/[\s,]+/).map(x => x.trim().replace(/^\./, '').toLowerCase()).filter(Boolean);
    current = {
      caps: () => ({ roots: roots.values(), extensions: [...new Set(parsedExtensions())], max_bytes: Number(maxKiB.value) * 1024, include_hidden: hidden.checked }),
      validate: () => {
        if (!roots.valid()) return 'add at least one folder (name + path)';
        if (!parsedExtensions().length || parsedExtensions().some(x => !/^[a-z0-9][a-z0-9_-]*$/.test(x))) return 'add one or more simple file extensions';
        const size = Number(maxKiB.value);
        return Number.isFinite(size) && size >= 16 && size <= 1024 ? null : 'file limit must be between 16 and 1024 KiB';
      },
    };
  };
  const gitBuilder = () => {
    fields.replaceChildren();
    const repos = namedRootsBuilder({
      noun: 'repository',
      pathHint: '/Users/you/code/project',
      helpText: 'Read-only Git inspection: status, log, diff, show, and tracked-text search. Apiary invokes Git directly with hooks, external diff programs, pagers, and global configuration disabled.',
    });
    fields.append(help('Each selected folder must already be a Git repository. Working-tree changes can be read but never modified.'));
    current = {
      caps: () => ({ repos: repos.values() }),
      validate: () => repos.valid() ? null : 'add at least one repository (name + path)',
    };
  };
  const mcpBuilder = () => {
    fields.replaceChildren();
    const tr = el('select');
    for (const [v, t] of [['stdio', 'local program (stdio) — e.g. npx @modelcontextprotocol/server-filesystem'], ['http', 'remote server (HTTP) — URL, optionally OAuth']]) { const o = el('option', null, t); o.value = v; tr.append(o); }
    const access = accessSelect('read-only');
    const stdioBox = el('div');
    const cmd = technicalInput(el('input')); cmd.placeholder = 'command (npx, uvx, /path/to/server)';
    const args = technicalInput(el('input', 'grow')); args.placeholder = 'arguments, space-separated (-y @modelcontextprotocol/server-filesystem /Users/you/docs)';
    const envs = technicalInput(el('input')); envs.placeholder = 'env vars to pass through (optional, comma-separated)';
    const r1 = el('div', 'row'); r1.append(cmd, args); const r1b = el('div', 'row'); r1b.append(envs);
    stdioBox.append(r1, r1b, help('The program is spawned with a scrubbed environment (PATH, HOME, TMPDIR, LANG + what you list). Pre-run `npx …` once in a terminal so the first probe isn’t a download.'));
    const httpBox = el('div'); httpBox.style.display = 'none';
    const url = technicalInput(el('input', 'grow')); url.placeholder = 'https://mcp.example.com/mcp';
    const authMode = el('select');
    for (const [value, label] of [
      ['oauth', 'OAuth sign-in (recommended)'],
      ['bearer', 'API key / bearer token'],
      ['none', 'No authentication'],
    ]) { const option = el('option', null, label); option.value = value; authMode.append(option); }
    const oauth = technicalInput(el('input')); oauth.placeholder = 'OAuth client id (advanced; usually automatic)';
    const bearer = technicalInput(el('input')); bearer.type = 'password'; bearer.placeholder = 'API key / bearer for discovery only (not stored)';
    const r2 = el('div', 'row'); r2.append(url); const r2b = el('div', 'row'); r2b.append(authMode, oauth, bearer);
    const oauthTarget = el('select');
    for (const agent of agents) { const option = el('option', null, agent.name || shortNostrId(agent.npub)); option.value = agent.npub; oauthTarget.append(option); }
    const oauthTargetField = field('Connect for agent', oauthTarget, 'OAuth credentials are sealed to one agent. No tools are enabled until you explicitly choose them.');
    oauthTargetField.style.display = 'none';
    const authHelp = help('OAuth signs in first and then discovers the authenticated tool list. A client id is only needed when the server does not support automatic registration. API keys are entered again when granting and are sealed to that agent.');
    httpBox.append(r2, r2b, authHelp, oauthTargetField);
    const disc = el('button', 'btn', 'DISCOVER TOOLS');
    const dStatus = el('span', 'meta', '');
    const toolsBox = el('div');
    const dRow = el('div', 'row'); dRow.append(disc, dStatus);
    let policies = new Map();
    let known = [];
    const syncHttpAuth = () => {
      const isHttp = tr.value === 'http';
      const isOauth = isHttp && authMode.value === 'oauth';
      oauth.style.display = isOauth ? '' : 'none';
      bearer.style.display = isHttp && authMode.value === 'bearer' ? '' : 'none';
      oauthTargetField.style.display = isOauth && agents.length ? '' : 'none';
      dRow.style.display = isOauth ? 'none' : '';
      nGo.textContent = isOauth
        ? (agents.length ? 'SAVE & CONNECT WITH OAUTH' : 'SAVE OAUTH CONNECTOR')
        : 'ADD TO LIBRARY';
      drawTools();
    };
    const drawTools = () => {
      toolsBox.replaceChildren();
      if (tr.value === 'http' && authMode.value === 'oauth') {
        toolsBox.append(help('Authenticate first. Apiary will discover this agent’s tools automatically after the OAuth callback, then ask you to select the allowed tools.'));
        return;
      }
      if (!known.length) { toolsBox.append(help('Tools must be allowed by name. Discover the server first; in Read only mode, Apiary exposes only tools explicitly marked readOnlyHint=true.')); return; }
      renderMcpToolPolicyPicker(toolsBox, known, policies);
    };
    drawTools();
    tr.onchange = () => {
      stdioBox.style.display = tr.value === 'stdio' ? '' : 'none';
      httpBox.style.display = tr.value === 'http' ? '' : 'none';
      syncHttpAuth();
    };
    authMode.onchange = syncHttpAuth;
    access.onchange = drawTools;
    const trRow = el('div', 'row'); trRow.append(tr);
    fields.append(trRow, field('Access', access, 'Read only fails closed: unmarked tools are excluded. Read + write permits every tool you explicitly select.'), stdioBox, httpBox, dRow, toolsBox);
    const buildCaps = () => {
      const toolAccess = mcpToolPolicyObject(policies);
      const caps = {
        transport: tr.value,
        access: Object.keys(toolAccess).length ? 'mixed' : access.value,
        allowed_tools: Object.keys(toolAccess),
      };
      if (Object.keys(toolAccess).length) caps.tool_access = toolAccess;
      if (tr.value === 'stdio') { caps.command = cmd.value.trim(); caps.args = args.value.trim() ? args.value.trim().split(/\s+/) : []; if (envs.value.trim()) caps.env = envs.value.split(',').map(x => x.trim()).filter(Boolean); }
      else {
        caps.url = url.value.trim();
        if (authMode.value === 'oauth') {
          caps.oauth = true;
          if (oauth.value.trim()) caps.oauth_client_id = oauth.value.trim();
        }
      }
      return caps;
    };
    disc.onclick = async () => {
      dStatus.textContent = 'probing…';
      const caps = buildCaps();
      if (caps.oauth) {
        dStatus.textContent = 'Authenticate with OAuth before discovering tools.';
        return;
      }
      const r = await j('/api/connectors/discover', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ caps, bearer: bearer.value || undefined }) });
      if (r.ok) { known = r.tools || []; policies = mcpToolPolicies(known, {}); dStatus.textContent = `${known.length} tools grouped by category`; drawTools(); }
      else if (r.auth_required) {
        authMode.value = 'oauth';
        syncHttpAuth();
        dStatus.textContent = agents.length
          ? 'OAuth required — save and connect; Apiary will discover tools after authorization'
          : 'OAuth required — save this disabled connector, then create an agent to complete sign-in and tool discovery';
      }
      else dStatus.textContent = 'failed: ' + r.error;
    };
    current = {
      caps: buildCaps,
      validate: () => {
        if (tr.value === 'stdio' && !cmd.value.trim()) return 'command required';
        if (tr.value === 'http' && !(/^(https?:\/\/|apiary:\/\/local\/mcp$)/.test(url.value.trim()))) return 'use a full HTTP URL or apiary://local/mcp';
        const oauthFlow = tr.value === 'http' && authMode.value === 'oauth';
        if (!policies.size && !oauthFlow) return 'allow at least one category or tool after discovery';
        return null;
      },
      afterSave: async (name, caps) => {
        if (!caps.oauth) return false;
        if (!agents.length || !oauthTarget.value) {
          lStatus.textContent = 'saved with no tools enabled — create an agent, then connect from that agent’s Capabilities';
          return true;
        }
        const npub = oauthTarget.value;
        lStatus.textContent = 'starting OAuth…';
        const started = await j(`/api/agents/${encodeURIComponent(npub)}/connectors/oauth`, {
          method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name }),
        });
        if (!started.ok) {
          lStatus.textContent = 'saved safely with no tools enabled; OAuth could not start: ' + started.error;
          return true;
        }
        lStatus.replaceChildren();
        const authorize = oauthAuthorizeControl('AUTHORIZE WITH OAUTH →', started.auth_url);
        lStatus.append(authorize, el('span', 'meta', ' then return here; Apiary will discover tools automatically'));
        const poll = setInterval(async () => {
          const manifest = await j(`/api/agents/${encodeURIComponent(npub)}/manifest`);
          const connected = manifest.ok && (manifest.manifest.connectors || []).some(connector =>
            connector.type === 'mcp' && connector.credential && connector.caps && connector.caps.library_name === name);
          if (connected) {
            clearInterval(poll);
            sel = npub;
            window.__autoDiscoverMcp = name;
            await loadRoster();
            openTab('connectors');
          }
        }, 2000);
        return true;
      },
    };
    syncHttpAuth();
  };
  const nostrBuilder = () => {
    fields.replaceChildren();
    const relays = technicalInput(el('textarea', 'address-list')); relays.rows = 4;
    relays.placeholder = 'wss://nos.lol\nwss://relay.damus.io';
    relays.value = 'wss://nos.lol\nwss://relay.damus.io';
    const relayValues = () => relays.value.split(/[\s,]+/).map(x => x.trim()).filter(Boolean);
    fields.append(help('The agent may publish public notes (kind 1) signed with its own key — only to these relays. This is the allowlist; the agent cannot add relays.'),
      field('Relay addresses', relays, 'Enter one WebSocket address per line. Comma-separated paste also works.'));
    current = {
      caps: () => ({ relays: relayValues() }),
      validate: () => {
        const values = relayValues();
        if (!values.length) return 'add at least one relay address';
        return values.every(x => /^wss?:\/\//.test(x)) ? null : 'each relay must begin with wss:// or ws://';
      },
    };
  };
  const mockBuilder = () => { fields.replaceChildren(); fields.append(help('Echoes its input — for tests.')); current = { caps: () => ({}), validate: () => null }; };
  const pickBuilder = () => {
    nCaps.value = '';
    ({
      'web-search': webSearchBuilder,
      'web-fetch': webBuilder,
      'files': filesBuilder,
      'git': gitBuilder,
      'obsidian': () => vaultBuilder(true),
      'markdown-vault': () => vaultBuilder(false),
      'mcp': mcpBuilder,
      'nostr-publish': nostrBuilder,
    }[nKind.value] || mockBuilder)();
  };
  nKind.onchange = () => { selectedCatalogId = null; pickBuilder(); };
  pickBuilder();

  const saveLib = async (rerender = true) => {
    const r = await j('/api/connectors', {
      method: 'PUT', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ library: entries }),
    });
    lStatus.textContent = r.ok ? `saved (${r.count} entries)` : 'rejected: ' + r.error;
    if (r.ok && rerender) render();
    return r.ok;
  };
  const uniqueName = (base) => {
    const slug = base.toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-|-$/g, '') || 'connector';
    if (!entries.some(e => e.name === slug)) return slug;
    let suffix = 2;
    while (entries.some(e => e.name === `${slug}-${suffix}`)) suffix++;
    return `${slug}-${suffix}`;
  };
  const drawCatalog = () => {
    catalogList.replaceChildren();
    for (const item of (lib.catalog || [])) {
      const card = el('article', 'catalog-item');
      card.append(el('h4', null, item.name), el('p', null, item.description));
      const meta = el('div', 'catalog-meta');
      meta.append(el('span', null, item.publisher), el('span', 'risk', item.risk));
      const row = el('div', 'row'); row.append(meta, el('span', 'grow', ''));
      const installed = entries.find(e => e.caps && e.caps.catalog_id === item.id);
      const directAdd = item.setup === 'credential' || item.setup === 'none';
      const action = el('button', 'btn', installed ? 'ADDED ✓' : (directAdd ? 'ADD TO LIBRARY' : 'CONFIGURE'));
      action.disabled = !!installed;
      row.append(action); card.append(row); catalogList.append(card);
      action.onclick = async () => {
        if (directAdd) {
          action.disabled = true; action.textContent = 'ADDING…';
          const caps = JSON.parse(JSON.stringify(item.caps || {})); caps.catalog_id = item.id;
          entries.push({ name: uniqueName(item.name), kind: item.kind, caps });
          window.__libFlash = item.setup === 'credential'
            ? `added ${item.name} — grant it from an agent’s Capabilities and seal the requested credential there`
            : `added ${item.name} — grant it to an agent, then ratify the capability change`;
          await saveLib();
          return;
        }
        selectedCatalogId = item.id;
        nKind.value = item.kind;
        nName.value = uniqueName(item.name);
        nName.dataset.auto = '1';
        pickBuilder();
        addSec.scrollIntoView({ behavior: 'smooth', block: 'start' });
        fields.querySelector('input, textarea, select')?.focus();
      };
    }
  };
  drawList();
  drawCatalog();
  const flag = (elm, msg) => {
    lStatus.textContent = msg; lStatus.style.color = '#e07070';
    if (elm) { elm.style.outline = '2px solid #e07070'; elm.focus(); setTimeout(() => { elm.style.outline = ''; }, 2500); }
  };
  nGo.onclick = async () => {
    lStatus.style.color = '';
    let caps;
    if (nCaps.value.trim()) {
      try { caps = JSON.parse(nCaps.value); } catch { flag(nCaps, 'advanced caps is not valid JSON'); return; }
    } else {
      const bad = current.validate();
      if (bad) { flag(fields.querySelector('input, select'), bad); return; }
      caps = current.caps();
    }
    if (!nName.value.trim()) { flag(nName, 'name this library entry (top-left field) — e.g. the vault’s name'); return; }
    const name = nName.value.trim().replace(/[^A-Za-z0-9_-]/g, '-');
    if (entries.some(e => e.name === name)) { flag(nName, `“${name}” already exists in the library`); return; }
    if (selectedCatalogId) caps.catalog_id = selectedCatalogId;
    nGo.disabled = true; nGo.textContent = 'ADDING…';
    entries.push({ name, kind: nKind.value, caps });
    window.__libFlash = `added ${name} (${nKind.value}) — now GRANT it from an agent’s Capabilities, then ratify`;
    const saved = await saveLib(false);
    const handled = saved && current.afterSave ? await current.afterSave(name, caps) : false;
    if (saved && !handled) render();
    nGo.disabled = false; nGo.textContent = 'ADD TO LIBRARY';
  };

  const libRow = el('div', 'row');
  const libBtn = el('button', 'btn', 'OPEN HOST CONNECTOR LIBRARY');
  libBtn.onclick = () => { hostView = 'library'; render(); };
  libRow.append(libBtn, el('span', 'meta', 'definitions live host-side, shared by all agents — caps examples are in the library’s reference'));
  c.append(libRow);

  const docs = el('details');
  docs.append(el('summary', null, 'how connectors work'));
  const docsBody = el('div');
  docsBody.append(help('Two layers: the host library holds named configurations (kind + caps, never secrets); grants are per-agent and constitutional — they travel in the manifest, so portability includes capabilities and their sealed credentials. A destination host only needs to bind the kind; a declared kind it cannot bind fails loudly at run start.'));
  docsBody.append(help('The mcp kind speaks the Model Context Protocol (2026-07-28, automatic fallback to initialize-era servers). OAuth connectors are saved with no tools enabled, authorized for one agent, and discovered only after sign-in. Apiary then requires an explicit tool allowlist before the connector can run; the server offers tools, but the manifest decides what the agent receives.'));
  docs.append(docsBody);
  c.append(docs);
}

// ------------------------------------------------------------ credentials

function renderCreds(c) {
  c.append(help('Credential custody: secrets are sealed with NIP-44 to the agent’s own key, so the manifest can carry connector credentials without carrying plaintext. The plaintext exists only transiently, per-credential, at the instant of use — exposure at the instant of use is a pre-existing property of any credential, not new risk.'));

  const sealSec = section('Seal a secret', 'Paste a secret (API key, token); get back a NIP-44 blob to put in a manifest connector’s credential field. The blob is useless to anyone but this agent.');
  const sIn = el('textarea'); sIn.rows = 3; sIn.placeholder = 'plaintext secret…';
  const sGo = el('button', 'btn', 'SEAL');
  const sSt = el('span', 'meta', '');
  const sRow = el('div', 'row'); sRow.append(sGo, sSt);
  const sOut = el('pre'); sOut.style.display = 'none'; sOut.style.userSelect = 'all';
  sealSec.append(sIn, sRow, sOut);
  c.append(sealSec);
  sGo.onclick = async () => {
    sSt.textContent = 'sealing…';
    const r = await j(api('/credential/seal'), {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ plaintext: sIn.value }),
    });
    if (r.ok) { sIn.value = ''; sSt.textContent = 'sealed ✓ (plaintext cleared)'; sOut.style.display = 'block'; sOut.textContent = r.nip44; }
    else sSt.textContent = 'failed: ' + r.error;
  };

  const openSec = section('Open a sealed blob (debug)', 'Decrypts a blob with the agent’s key and SHOWS THE PLAINTEXT on screen. Debug tool only — prefer letting connectors decrypt at the instant of use.');
  const oIn = el('textarea'); oIn.rows = 3; oIn.placeholder = 'nip44 blob…';
  const oGo = el('button', 'btn danger', 'OPEN (REVEALS PLAINTEXT)');
  const oSt = el('span', 'meta', '');
  const oRow = el('div', 'row'); oRow.append(oGo, oSt);
  const oOut = el('pre'); oOut.style.display = 'none';
  openSec.append(oIn, oRow, oOut);
  c.append(openSec);
  oGo.onclick = async () => {
    const r = await j(api('/credential/open'), {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ nip44: oIn.value }),
    });
    oSt.textContent = r.ok ? 'decrypted' : 'failed: ' + r.error;
    if (r.ok) { oOut.style.display = 'block'; oOut.textContent = r.plaintext; }
  };
}

// ------------------------------------------------------------ founding

const hostViewButtons = {
  found: 'foundtoggle',
  managers: 'managerstoggle',
  audit: 'audittoggle',
  library: 'libtoggle',
  import: 'importtoggle',
};

function syncSidebarSelection() {
  const activeId = hostView ? hostViewButtons[hostView] : null;
  document.querySelectorAll('.side-action').forEach(button => {
    const current = button.id === activeId;
    button.classList.toggle('sel', current);
    if (current) button.setAttribute('aria-current', 'page');
    else button.removeAttribute('aria-current');
  });
}

document.getElementById('managerstoggle').onclick = () => {
  hostView = 'managers';
  document.querySelectorAll('nav button').forEach(x => x.classList.remove('sel'));
  render();
};
document.getElementById('audittoggle').onclick = () => {
  hostView = 'audit';
  document.querySelectorAll('nav button').forEach(x => x.classList.remove('sel'));
  render();
};
document.getElementById('libtoggle').onclick = () => {
  hostView = 'library';
  document.querySelectorAll('nav button').forEach(x => x.classList.remove('sel'));
  render();
};
document.getElementById('foundtoggle').onclick = () => {
  hostView = 'found';
  document.querySelectorAll('nav button').forEach(x => x.classList.remove('sel'));
  render();
};
document.getElementById('importtoggle').onclick = () => {
  hostView = 'import';
  document.querySelectorAll('nav button').forEach(x => x.classList.remove('sel'));
  render();
};

// ------------------------------------------------------ people and access

async function renderControlAudit(c) {
  const head = el('div', 'page-head');
  head.append(el('div', 'eyebrow', 'Host security'),
    el('h2', 'page-title', 'Management audit'),
    el('p', 'page-lede', 'Hash-chained MCP management calls. Request bodies and bearer credentials are never recorded.'));
  c.append(head);
  const [result, tokenHistory] = await Promise.all([
    j('/api/control/audit?tail=250'), j('/api/control/tokens'),
  ]);
  if (!result.ok) { c.append(el('div', 'ev err', 'Audit unavailable: ' + result.error)); return; }
  const audit = section('Recent control activity', 'Newest first. The actor is the authenticated Nostr identity or the trusted local desktop operator.');
  const chain = result.chain || {};
  audit.append(el('div', chain.valid ? 'state ready' : 'ev err', chain.valid
    ? `Audit chain verified · ${chain.entries || 0} entries`
    : `Audit chain failed verification · ${chain.error || 'unknown error'}`));
  if (!(result.entries || []).length) audit.append(el('div', 'none', 'No MCP management calls recorded'));
  for (const entry of (result.entries || [])) {
    const summary = entry.summary || {};
    const target = summary.agent || summary.path || '—';
    const card = el('div', 'item');
    card.append(el('b', null, entry.tool || 'unknown operation'),
      kv('result', entry.status || 'unknown'),
      kv('actor', entry.caller || 'unknown'),
      kv('target', typeof target === 'string' ? target : JSON.stringify(target)),
      kv('request', [summary.method, summary.path].filter(Boolean).join(' ') || 'convenience tool'),
      kv('time', entry.at ? new Date(entry.at * 1000).toLocaleString() : '—'),
      kv('chain hash', entry.hash ? entry.hash.slice(0, 20) + '…' : '—'));
    audit.append(card);
  }
  c.append(audit);
  if (tokenHistory.ok) {
    const lifecycle = section('Management-token lifecycle', 'Active, expired, and revoked agent credentials. Token plaintext is never retained.');
    if (!(tokenHistory.tokens || []).length) lifecycle.append(el('div', 'none', 'No management tokens recorded'));
    for (const token of (tokenHistory.tokens || [])) {
      const state = token.active ? 'active' : token.revoked_at ? 'revoked' : 'expired';
      const card = el('div', 'item');
      card.append(el('b', null, token.label || 'Unlabeled token'),
        kv('state', state), kv('agent', token.agent), kv('ID', token.id.slice(0, 20) + '…'),
        kv('created', new Date(token.created_at * 1000).toLocaleString()),
        kv('expires', new Date(token.expires_at * 1000).toLocaleString()),
        token.revoked_at ? kv('revoked', new Date(token.revoked_at * 1000).toLocaleString()) : el('span'));
      lifecycle.append(card);
    }
    c.append(lifecycle);
  }
}

// ------------------------------------------------------ people and access

function renderManagers(c) {
  const head = el('div', 'page-head');
  head.append(el('div', 'eyebrow', 'Host settings'),
    el('h2', 'page-title', 'People & access'),
    el('p', 'page-lede', 'Host managers administer Apiary itself. Agent governors approve and operate only the agents that name them. A person may be both.'));
  c.append(head);

  const current = section('Host managers',
    'Every person listed here has the same independent authority over this host: agents, integrations, credentials, lock state, and configuration. Apiary does not copy or store their private key.');
  if (hostStatus.auth !== 'nip98') {
    const boundary = el('div', 'attention');
    boundary.append(el('b', null, 'Current access boundary: '),
      document.createTextNode(hostStatus.token_gated
        ? 'this desktop’s per-launch token. Nostr signatures are enforced when the host runs in NIP-98 mode.'
        : 'local or SSH access. Nostr signatures are enforced when the host runs in NIP-98 mode.'));
    current.append(boundary);
  }
  if (!managers.length) {
    current.append(el('div', 'none', 'No persistent Nostr managers yet. Local token or SSH access is currently the host boundary.'));
  }
  for (const manager of managers) {
    const row = el('div', 'lib');
    row.append(el('b', null, manager.name || 'Manager'),
      nostrId(manager.npub, 'code'),
      el('span', 'meta', manager.source === 'startup' ? 'started with --admin' : 'stored on this host'),
      el('span', 'spacer'));
    if (manager.removable) {
      const remove = el('button', 'btn danger', 'Remove');
      remove.onclick = async () => {
        if (!confirm(`Remove ${manager.name || manager.npub} as a host manager?`)) return;
        remove.disabled = true;
        const result = await j('/api/managers/' + encodeURIComponent(manager.npub), { method: 'DELETE' });
        if (!result.ok) { remove.disabled = false; alert('Could not remove manager: ' + result.error); return; }
        managers = result.managers || []; render();
      };
      row.append(remove);
    }
    current.append(row);
  }
  c.append(current);

  const add = section('Add a person by Nostr ID',
    'Paste an npub or public-key hex. They authenticate with their own signer; never ask them for an nsec or private key.');
  const name = el('input', 'grow'); name.placeholder = 'Name or local label';
  const npub = technicalInput(el('input', 'grow')); npub.placeholder = 'npub1… or 64-character public key';
  const go = el('button', 'btn solid', 'Add host manager');
  const status = el('span', 'meta', '');
  const row = el('div', 'row'); row.append(go, status);
  add.append(field('Name', name), field('Nostr ID', npub),
    help('Granting host access does not automatically add this identity to existing agents. Assign its per-agent role from that agent’s overview.'),
    row);
  go.onclick = async () => {
    if (!name.value.trim()) { status.textContent = 'Enter a name.'; name.focus(); return; }
    if (!npub.value.trim()) { status.textContent = 'Enter a Nostr public identity.'; npub.focus(); return; }
    go.disabled = true; status.textContent = 'Validating and saving…';
    const result = await j('/api/managers', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: name.value.trim(), npub: npub.value.trim() }),
    });
    go.disabled = false;
    if (!result.ok) { status.textContent = 'Could not add manager: ' + result.error; return; }
    managers = result.managers || []; name.value = ''; npub.value = '';
    status.textContent = 'Manager added.'; render();
  };
  c.append(add);

  const localOnly = owners.filter(owner => !managers.some(manager => manager.npub === owner.npub));
  if (localOnly.length) {
    const local = section('Local approval identities',
      'These encrypted keys can already approve agents on this host. Grant host access only if that human identity should also administer Apiary itself.');
    for (const owner of localOnly) {
      const row = el('div', 'lib');
      row.append(el('b', null, owner.name), nostrId(owner.npub, 'code'), el('span', 'spacer'));
      const grant = el('button', 'btn', 'Grant host access');
      grant.onclick = async () => {
        grant.disabled = true;
        const result = await j('/api/managers', {
          method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ name: owner.name, npub: owner.npub }),
        });
        if (!result.ok) { grant.disabled = false; alert('Could not grant access: ' + result.error); return; }
        managers = result.managers || []; render();
      };
      row.append(grant); local.append(row);
    }
    c.append(local);
  }
}

// ------------------------------------------------------------ found (pane)

function renderFound(c) {
  if (!approvalPeople().length) {
    const setup = section('Create an approval identity',
      'Before creating another agent, add the human identity that will review its configuration and permissions.');
    const ownerName = el('input'); ownerName.placeholder = 'Your name';
    const ownerGo = el('button', 'btn solid', 'Create approval identity');
    const ownerSt = el('span', 'meta', '');
    const ownerRow = el('div', 'row'); ownerRow.append(ownerGo, ownerSt);
    setup.append(field('Local label', ownerName), ownerRow,
      help('This encrypted key is separate from every agent and is never shown as a runnable agent.'));
    c.append(setup);
    ownerGo.onclick = async () => {
      if (!ownerName.value.trim()) { ownerSt.textContent = 'Enter a name.'; ownerName.focus(); return; }
      ownerGo.disabled = true; ownerSt.textContent = 'Creating encrypted identity…';
      const r = await j('/api/owners', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name: ownerName.value.trim() }) });
      ownerGo.disabled = false;
      if (!r.ok) { ownerSt.textContent = 'Could not create identity: ' + r.error; return; }
      await loadOwners(); render();
    };
    return;
  }
  const sec = section('Create a new agent',
    'Describe a clear job. Apiary creates a conservative configuration for you to review before anything can run.');
  const fName = el('input'); fName.placeholder = 'e.g. Research assistant';
  const fPurpose = el('textarea'); fPurpose.rows = 4; fPurpose.placeholder = 'What should this agent reliably help you do?';
  if (foundingPrefill) {
    const q = foundingPrefill; foundingPrefill = null;
    const from = agents.find(a => a.npub === q.by);
    sec.append(el('div', 'state ready',
      `Prefilled from ${from ? from.name : 'an agent'}’s approved founding request — edit anything before creating.`));
    fName.value = q.name || '';
    fPurpose.rows = 10;
    fPurpose.value = [
      q.purpose || '',
      q.role ? `\nRole: ${q.role}` : '',
      (q.principles || []).length ? `\nPrinciples:\n- ${q.principles.join('\n- ')}` : '',
      (q.boundaries || []).length ? `\nBoundaries:\n- ${q.boundaries.join('\n- ')}` : '',
      (q.skills || []).length ? `\nSkills it needs:\n- ${q.skills.join('\n- ')}` : '',
      (q.connectors || []).length ? `\nCapabilities it needs:\n- ${q.connectors.join('\n- ')}` : '',
      q.tokens_per_day ? `\nProposed spend ceiling: ${q.tokens_per_day} tokens/day` : '',
    ].filter(Boolean).join('\n');
  }
  const people = approvalPeople();
  const fSuspend = el('select', 'grow'); fSuspend.multiple = true;
  fSuspend.size = Math.min(6, Math.max(2, people.length));
  people.forEach((identity, index) => {
    const option = el('option', null, identity.name || shortNostrId(identity.npub));
    option.value = identity.npub; option.selected = index === 0; fSuspend.append(option);
  });
  if (!people.length) {
    const option = el('option', null, 'No local approval identity'); option.value = ''; fSuspend.append(option);
  }
  const fDraft = el('input'); fDraft.type = 'checkbox'; fDraft.style.width = 'auto';
  fDraft.checked = !!hostStatus.anthropic_key_present;
  fDraft.disabled = !hostStatus.anthropic_key_present;
  const draftLabel = el('label', null, ' Tailor the draft with the connected model'); draftLabel.prepend(fDraft);
  const go = el('button', 'btn solid', 'Create draft');
  const st = el('span', 'meta', '');
  const r4 = el('div', 'row'); r4.append(draftLabel, go, st);
  sec.append(field('Agent name', fName), field('Purpose', fPurpose),
    field('Managed by', fSuspend, people.length
      ? 'Choose one or more people. Each selected person can independently approve or stop this agent.'
      : 'Create an approval identity or add an external Nostr ID under People & access.'),
    r4, help(hostStatus.anthropic_key_present
      ? 'The model can tailor routing and budgets to the purpose. You will review all changes before approval.'
      : 'No host model credential is configured, so Apiary will use its conservative template.'));
  c.append(sec);
  go.onclick = async () => {
    if (!fName.value.trim()) { st.textContent = 'Enter an agent name.'; fName.focus(); return; }
    if (!fPurpose.value.trim()) { st.textContent = 'Describe the agent’s purpose.'; fPurpose.focus(); return; }
    const selectedManagers = [...fSuspend.selectedOptions].map(option => option.value).filter(Boolean);
    if (!selectedManagers.length) { st.textContent = 'Choose at least one manager.'; fSuspend.focus(); return; }
    go.disabled = true; st.textContent = 'Creating the identity and draft configuration…';
    const r = await j('/api/agents/found', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        name: fName.value.trim(),
        purpose: fPurpose.value.trim(),
        suspend_keys: selectedManagers,
        draft_with: fDraft.checked ? 'anthropic' : null,
      }),
    });
    go.disabled = false;
    if (!r.ok) { st.textContent = 'Could not create the draft: ' + r.error; return; }
    st.textContent = `Draft created with ${r.drafted_by}.`;
    hostView = null; sel = r.npub; tab = 'manifest';
    document.querySelectorAll('nav button').forEach(x => x.classList.toggle('sel', x.dataset.tab === 'manifest'));
    await loadRoster(); render();
  };
}

// ------------------------------------------------------------ import (pane)

function renderImport(c) {
  const sec = section('Import an agent',
    'Choose an Apiary export bundle. Apiary verifies its identity, configuration, signatures, and history before saving anything. Imported agents arrive inactive.');
  const file = el('input'); file.type = 'file'; file.accept = '.json,.apiary.json,application/json';
  const bundle = el('textarea'); bundle.rows = 8; bundle.placeholder = 'paste .apiary.json bundle or sealed envelope';
  bundle.setAttribute('aria-label', 'Bundle JSON');
  const pass = el('input', 'grow'); pass.type = 'password';
  pass.placeholder = 'Handoff or source workspace passphrase';
  const paste = el('details', 'technical'); paste.append(el('summary', null, 'Or paste bundle JSON'), bundle);
  const go = el('button', 'btn solid', 'Verify and import');
  const st = el('div', 'meta', '');
  st.setAttribute('role', 'status');
  st.setAttribute('aria-live', 'polite');
  const row = el('div', 'row'); row.append(pass, go);
  const passField = field('Transfer or source workspace passphrase', pass);
  const passLabel = passField.querySelector('span');
  sec.append(field('Export bundle', file), paste, passField, row, st,
    help('Agents do not have passphrases. This field only opens the encrypted private key carried by a plain export: use its disposable transfer passphrase or, for an older same-workspace backup, the source workspace passphrase. Recipient-sealed bundles need neither.'));
  c.append(sec);

  const inspectBundle = (parsed, loadedName = '') => {
    const sealed = parsed && Number(parsed.kind) === 4602 && !!parsed.sig;
    const protection = parsed && parsed.key_protection;
    pass.disabled = sealed;
    if (sealed) {
      pass.value = '';
      passLabel.textContent = 'No passphrase needed';
      pass.placeholder = 'Not needed — sealed to a recipient identity';
      st.textContent = `${loadedName ? `Loaded ${loadedName}. ` : ''}Recipient-sealed bundle; no passphrase is needed.`;
    } else if (protection === 'handoff_passphrase') {
      passLabel.textContent = 'One-time transfer passphrase';
      pass.placeholder = 'Passphrase chosen when this bundle was exported';
      st.textContent = `${loadedName ? `Loaded ${loadedName}. ` : ''}Enter the handoff passphrase used during export.`;
    } else if (protection === 'source_workspace_passphrase') {
      passLabel.textContent = 'Source workspace passphrase';
      pass.placeholder = 'Passphrase for the workspace that exported this agent';
      st.textContent = `${loadedName ? `Loaded ${loadedName}. ` : ''}Enter the source workspace passphrase.`;
    } else {
      passLabel.textContent = 'Transfer or source workspace passphrase';
      pass.placeholder = 'Handoff passphrase, or the source workspace passphrase';
      st.textContent = `${loadedName ? `Loaded ${loadedName}. ` : ''}This legacy bundle does not identify its protection mode. Enter its handoff passphrase; if none was set, use the source workspace passphrase.`;
    }
  };
  file.onchange = async () => {
    const chosen = file.files && file.files[0];
    if (!chosen) return;
    try {
      bundle.value = await chosen.text();
      inspectBundle(JSON.parse(bundle.value), chosen.name);
    }
    catch (err) {
      if (bundle.value) st.textContent = 'The selected file is not valid JSON.';
      else st.textContent = 'Could not read the file: ' + err;
    }
  };
  go.onclick = async () => {
    let parsed;
    try { parsed = JSON.parse(bundle.value); }
    catch { st.textContent = 'The selected bundle is not valid JSON.'; return; }
    go.disabled = true; st.textContent = 'Verifying identity, signatures, and history…';
    try {
      const r = await j('/api/agents/import', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ bundle: parsed, bundle_passphrase: pass.value || null }),
      });
      const mismatch = !r.ok && (
        String(r.error || '').includes('passphrase mismatch')
        || String(r.error || '').includes('the agent has no passphrase')
      );
      st.textContent = r.ok
        ? `Imported ${r.name || shortNostrId(r.npub)} with ${r.log_entries} signed history entries. It is inactive on this host.`
        : mismatch
          ? 'The agent has no passphrase. This older export copied its workspace-encrypted private key. Enter the source workspace passphrase, or re-export the agent from that workspace with a disposable transfer passphrase.'
          : 'Could not import: ' + (r.error || 'The host refused the bundle.');
      if (mismatch) { pass.disabled = false; pass.focus(); }
      if (r.ok) {
        bundle.value = ''; file.value = ''; hostView = null; sel = r.npub; tab = 'overview';
        await loadRoster(); openTab('overview');
      }
    } catch (error) {
      const message = error && error.message ? error.message : String(error);
      st.textContent = 'Could not import: ' + message + ' Sign in to this workspace, then try again.';
    } finally {
      go.disabled = false;
    }
  };
}

function renderStartupError(error) {
  const root = document.getElementById('content');
  root.replaceChildren();
  const card = section('Sign in to Apiary', error && error.message ? error.message : String(error));
  const desktopManagers = error && Array.isArray(error.desktopManagers) ? error.desktopManagers : [];
  if (desktopManagers.length) {
    const manager = el('select');
    manager.setAttribute('aria-label', 'Approved host manager');
    for (const identity of desktopManagers) {
      const option = el('option', null, `${identity.name} (${shortNostrId(identity.npub)})`);
      option.value = identity.npub;
      manager.append(option);
    }
    const retry = el('button', 'btn solid', 'Continue as selected manager');
    const status = el('span', 'meta');
    const row = el('div', 'row');
    row.append(manager, retry, status);
    retry.onclick = async () => {
      retry.disabled = true;
      status.textContent = 'Opening the desktop session…';
      try {
        await establishDesktopSession(manager.value);
        location.reload();
      } catch (retryError) {
        retry.disabled = false;
        status.textContent = retryError && retryError.message ? retryError.message : 'Could not open the desktop session.';
      }
    };
    card.append(row, help('Choose which approved identity this SSH-authenticated desktop session should use.'));
  } else if (DESKTOP) {
    const reconnect = el('button', 'btn solid', 'Reconnect desktop session');
    reconnect.onclick = () => desktopAction('reconnect');
    card.append(reconnect, help('Apiary will reopen the SSH connection and obtain a fresh desktop credential. A browser Nostr extension is not required.'));
  } else {
    const retry = el('button', 'btn solid', 'Try Nostr sign-in again');
    retry.onclick = () => location.reload();
    card.append(retry, help('Apiary asks your signer once, opens an eight-hour off-chain session, and still enforces your role separately for every agent.'));
  }
  root.append(card);
  document.getElementById('roster').replaceChildren(el('div', 'empty', 'Authentication required'));
}

loadStatus()
  .then(() => Promise.all([loadOwners(), loadManagers()]))
  .then(loadRoster)
  .then(() => {
    if (INITIAL_AGENT && agents.some(agent => agent.npub === INITIAL_AGENT)) sel = INITIAL_AGENT;
    if (INITIAL_TAB && document.querySelector(`nav button[data-tab="${CSS.escape(INITIAL_TAB)}"]`)) tab = INITIAL_TAB;
    return render();
  })
  .then(() => { setInterval(() => loadStatus().catch(() => {}), 15000); })
  .catch(renderStartupError);
