// app.js — the frontend. Talks to the API with fetch() and to the
// authenticator through the browser's WebAuthn API (wrapped by SimpleWebAuthn).

const { startRegistration, startAuthentication, browserSupportsWebAuthn } = SimpleWebAuthnBrowser;

const $ = (id) => document.getElementById(id);
let currentUser = null;

// ---------- Small helpers ----------

function setStatus(message, kind = '') {
  const el = $('status');
  el.textContent = message;
  el.className = kind;
}

// Call our API and turn non-2xx responses into thrown errors.
async function api(path, { method = 'GET', body } = {}) {
  const res = await fetch(path, {
    method,
    headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));   // 204 No Content has no body
  if (!res.ok) {
    const err = new Error(data.error || `Request failed (${res.status})`);
    err.status = res.status;
    throw err;
  }
  return data;
}

// Disable a button while its request runs, so a double-click can't send two.
async function withBusy(button, fn) {
  button.disabled = true;
  try { await fn(); } finally { button.disabled = false; }
}

function friendlyError(err) {
  if (err.name === 'NotAllowedError') return 'Cancelled or timed out.';
  if (err.name === 'InvalidStateError') return 'This key is already registered on this account.';
  return err.message;
}

// SQLite stores UTC as "YYYY-MM-DD HH:MM:SS". Convert to the viewer's local time.
function localTime(utc) {
  if (!utc) return '—';
  return new Date(utc.replace(' ', 'T') + 'Z').toLocaleString([], {
    month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit',
  });
}

// Very small user-agent summary: "Chrome on Windows". Display only, never trusted.
function browserSummary(ua) {
  if (!ua) return '—';
  const browser = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox'
    : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
  const os = /Windows/.test(ua) ? 'Windows' : /iPhone|iPad/.test(ua) ? 'iOS' : /Android/.test(ua) ? 'Android'
    : /Mac OS X/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : '';
  return os ? `${browser} on ${os}` : browser;
}

const EVENT_LABELS = {
  login:           ['Signed in', 'ev-good'],
  login_failed:    ['Failed sign-in', 'ev-bad'],
  account_created: ['Account created', 'ev-good'],
  key_added:       ['Key added', ''],
  key_renamed:     ['Key renamed', ''],
  key_removed:     ['Key removed', 'ev-bad'],
  logout:          ['Signed out', 'muted'],
};

// Build a table cell. textContent (not innerHTML), so nothing from the
// server or the authenticator is ever run as HTML.
function cell(text, className = '') {
  const td = document.createElement('td');
  td.textContent = text;
  if (className) td.className = className;
  return td;
}

function smallButton(label, extraClass, onClick) {
  const b = document.createElement('button');
  b.textContent = label;
  b.className = `small ${extraClass}`.trim();
  b.addEventListener('click', (e) => withBusy(e.currentTarget, onClick));
  return b;
}

// ---------- Views ----------

function renderKeys(credentials) {
  const onlyOne = credentials.length <= 1;
  $('credRows').replaceChildren(...credentials.map((c) => {
    const tr = document.createElement('tr');
    tr.append(
      cell(c.nickname),
      cell(c.deviceType === 'multiDevice' ? 'synced passkey' : 'device-bound'),
      cell(localTime(c.createdAt)),
      cell(localTime(c.lastUsedAt)),
    );

    const actions = cell('', 'actions');
    actions.append(smallButton('Rename', 'secondary', () => renameKey(c)));
    const remove = smallButton('Remove', 'danger', () => removeKey(c));
    // The server enforces this too; the disabled button is just a hint.
    remove.disabled = onlyOne;
    remove.title = onlyOne ? 'Add another key before removing this one' : '';
    actions.append(remove);
    tr.append(actions);
    return tr;
  }));

  $('keyHint').textContent = onlyOne
    ? 'You have one key. Add a backup so losing it doesn\'t lock you out.'
    : `${credentials.length} keys registered. Any of them can sign you in.`;
}

function renderActivity(events) {
  if (events.length === 0) {
    const tr = document.createElement('tr');
    tr.append(cell('No activity yet', 'muted'));
    $('activityRows').replaceChildren(tr);
    return;
  }
  $('activityRows').replaceChildren(...events.map((e) => {
    const [label, cls] = EVENT_LABELS[e.event] || [e.event, ''];
    const tr = document.createElement('tr');
    tr.append(
      cell(localTime(e.at)),
      cell(label, cls),
      cell(e.credentialName || (e.credentialRemoved ? 'removed key' : '—'), e.credentialName ? '' : 'muted'),
      cell(e.ip || '—'),
      cell(browserSummary(e.userAgent)),
    );
    return tr;
  }));
}

async function refresh() {
  try {
    const me = await api('api/me');
    const { events } = await api('api/activity');
    currentUser = me.username;
    $('meUsername').textContent = me.username;
    $('meSince').textContent = localTime(me.createdAt);
    renderKeys(me.credentials);
    renderActivity(events);
    $('loggedOut').hidden = true;
    $('loggedIn').hidden = false;
    setStatus(`Logged in as ${me.username}`, 'ok');
  } catch (err) {
    if (err.status !== 401) setStatus(friendlyError(err), 'err');
    else setStatus('Not logged in');
    currentUser = null;
    $('loggedIn').hidden = true;
    $('loggedOut').hidden = false;
  }
}

// ---------- Flows ----------

// Registration: 1) get options  2) authenticator creates a key pair  3) server verifies + stores public key
async function register(username) {
  setStatus('Requesting registration options…');
  const optionsJSON = await api('api/register/options', { method: 'POST', body: { username } });

  setStatus('Touch your security key or confirm your passkey…');
  const attestation = await startRegistration({ optionsJSON });

  setStatus('Verifying with server…');
  await api('api/register/verify', { method: 'POST', body: attestation });
  await refresh();
}

// Login: 1) get a challenge  2) authenticator signs it with the private key  3) server checks the signature
async function login(username) {
  setStatus('Requesting challenge…');
  const optionsJSON = await api('api/login/options', { method: 'POST', body: { username } });

  setStatus('Touch your security key or confirm your passkey…');
  const assertion = await startAuthentication({ optionsJSON });

  setStatus('Verifying with server…');
  await api('api/login/verify', { method: 'POST', body: assertion });
  await refresh();
}

async function renameKey(cred) {
  const nickname = prompt('New name for this key (1-40 characters):', cred.nickname);
  if (nickname === null) return;                       // cancelled
  try {
    await api(`api/credentials/${encodeURIComponent(cred.id)}`, { method: 'PATCH', body: { nickname } });
    await refresh();
    setStatus('Key renamed', 'ok');
  } catch (err) {
    setStatus(friendlyError(err), 'err');
  }
}

async function removeKey(cred) {
  if (!confirm(`Remove "${cred.nickname}"? It will no longer be able to sign in to this account.`)) return;
  try {
    await api(`api/credentials/${encodeURIComponent(cred.id)}`, { method: 'DELETE' });
    await refresh();
    setStatus(`Removed "${cred.nickname}"`, 'ok');
  } catch (err) {
    setStatus(friendlyError(err), 'err');
  }
}

// ---------- Wire up buttons ----------

$('btnRegister').addEventListener('click', (e) => withBusy(e.currentTarget, async () => {
  try { await register($('regUsername').value); }
  catch (err) { setStatus(friendlyError(err), 'err'); }
}));

$('btnLogin').addEventListener('click', (e) => withBusy(e.currentTarget, async () => {
  try { await login($('loginUsername').value); }
  catch (err) { setStatus(friendlyError(err), 'err'); }
}));

$('btnAddKey').addEventListener('click', (e) => withBusy(e.currentTarget, async () => {
  try { await register(currentUser); }
  catch (err) { setStatus(friendlyError(err), 'err'); }
}));

$('btnLogout').addEventListener('click', (e) => withBusy(e.currentTarget, async () => {
  try { await api('api/logout', { method: 'POST', body: {} }); await refresh(); }
  catch (err) { setStatus(friendlyError(err), 'err'); }
}));

if (!browserSupportsWebAuthn()) {
  setStatus('This browser does not support WebAuthn.', 'err');
} else {
  refresh();
}
