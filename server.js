// server.js — the API. Apache terminates HTTPS and forwards /fido/ here.
//
//   Browser --HTTPS--> Apache (lab.home.arpa:443) --HTTP--> Express (127.0.0.1:3000) --> SQLite

const path = require('node:path');
const express = require('express');
const session = require('express-session');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');
const db = require('./db');

// ---------- Config (from environment, never hard-coded secrets) ----------
const RP_ID = process.env.RP_ID || 'lab.home.arpa';          // relying-party ID: must be a domain
const ORIGIN = process.env.ORIGIN || `https://${RP_ID}`;      // exact origin the browser reports
const PORT = Number(process.env.PORT || 3000);
const SESSION_SECRET = process.env.SESSION_SECRET;
const CHALLENGE_TTL_MS = 2 * 60 * 1000;                       // a challenge is good for 2 minutes
const USERNAME_RE = /^[a-z0-9_.-]{3,32}$/;

if (!SESSION_SECRET) {
  console.error('SESSION_SECRET is not set. Generate one with: openssl rand -hex 32');
  process.exit(1);
}

const app = express();

// Apache is the only client that talks to us directly, from 127.0.0.1.
// Trusting it lets Express believe its X-Forwarded-Proto: https header,
// which is required before express-session will send a Secure cookie.
app.set('trust proxy', 'loopback');
app.disable('x-powered-by');                                  // same idea as ServerTokens Prod

app.use(express.json({ limit: '20kb' }));                     // reject oversized bodies

app.use(session({
  name: 'fido.sid',
  secret: SESSION_SECRET,                                     // signs the cookie so it can't be forged
  resave: false,
  saveUninitialized: false,                                   // no cookie until there is something to store
  cookie: {
    httpOnly: true,                                           // JavaScript can't read it (limits XSS damage)
    secure: ORIGIN.startsWith('https://'),                    // only sent over HTTPS
    sameSite: 'strict',                                       // not sent on cross-site requests (CSRF defense)
    maxAge: 30 * 60 * 1000,                                   // 30-minute session
  },
  // Default MemoryStore: sessions are lost on restart. Fine for a lab; production would use Redis or a DB.
}));

// ---------- Static frontend ----------
app.use(express.static(path.join(__dirname, 'public')));
app.get('/vendor/simplewebauthn-browser.js', (req, res) => {
  res.sendFile(path.join(__dirname, 'node_modules/@simplewebauthn/browser/dist/bundle/index.umd.min.js'));
});

// ---------- Helpers ----------

// Creates a brand-new session ID after login, so an attacker who planted
// a session ID before login can't ride along afterwards (session fixation).
function startLoggedInSession(req, userId) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((err) => {
      if (err) return reject(err);
      req.session.userId = userId;
      req.session.save((err2) => (err2 ? reject(err2) : resolve()));
    });
  });
}

// Takes the pending challenge out of the session. Deleting it here makes
// every challenge single-use, which stops replayed responses.
function takeChallenge(req, key) {
  const pending = req.session[key];
  delete req.session[key];
  if (!pending || Date.now() - pending.createdAt > CHALLENGE_TTL_MS) return null;
  return pending;
}

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  next();
}

const parseTransports = (json) => {
  try { return JSON.parse(json || '[]'); } catch { return []; }
};

// Who made this request, for the activity log. req.ip is the real client
// address because Apache sends X-Forwarded-For and we trust Apache (loopback).
const clientInfo = (req) => ({ ip: req.ip, userAgent: req.get('user-agent') });

const defaultNickname = (deviceType) => (deviceType === 'multiDevice' ? 'Passkey' : 'Security key');

// ---------- Registration (create account / add a passkey) ----------

// Step 1: browser asks for options. Server picks a random challenge and remembers it.
app.post('/api/register/options', async (req, res, next) => {
  try {
    const username = String(req.body?.username || '').trim().toLowerCase();
    if (!USERNAME_RE.test(username)) {
      return res.status(400).json({ error: 'Username must be 3-32 characters: a-z, 0-9, . _ -' });
    }

    const user = db.getUserByUsername(username);
    if (user && user.id !== req.session.userId) {
      return res.status(409).json({ error: 'Username is taken. Log in first to add another key.' });
    }

    const existingCreds = user ? db.getCredentialsByUserId(user.id) : [];

    const options = await generateRegistrationOptions({
      rpName: 'Home Lab FIDO2 Demo',
      rpID: RP_ID,
      userName: username,
      // Existing user: reuse their handle. New user: library generates a random one.
      userID: user ? Buffer.from(user.webauthn_user_id, 'base64url') : undefined,
      attestationType: 'none',
      // Don't let the same authenticator register twice on one account.
      excludeCredentials: existingCreds.map((c) => ({ id: c.id, transports: parseTransports(c.transports) })),
      authenticatorSelection: {
        residentKey: 'preferred',          // store a discoverable passkey when the device supports it
        userVerification: 'preferred',     // ask for PIN/biometric when available
      },
    });

    req.session.registration = {
      challenge: options.challenge,
      username,
      webauthnUserId: options.user.id,
      createdAt: Date.now(),
    };

    res.json(options);
  } catch (err) {
    next(err);
  }
});

// Step 2: browser sends back the new credential. Server checks it and saves the public key.
app.post('/api/register/verify', async (req, res, next) => {
  try {
    const pending = takeChallenge(req, 'registration');
    if (!pending) return res.status(400).json({ error: 'Registration expired. Try again.' });

    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response: req.body,
        expectedChallenge: pending.challenge,   // is this the challenge WE issued?
        expectedOrigin: ORIGIN,                 // did it come from OUR site (not a phishing page)?
        expectedRPID: RP_ID,                    // was the credential made for OUR domain?
        requireUserVerification: false,
      });
    } catch (err) {
      console.warn('Registration verification failed:', err.message);
      return res.status(400).json({ error: 'Registration could not be verified' });
    }

    if (!verification.verified) {
      return res.status(400).json({ error: 'Registration could not be verified' });
    }

    const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;

    let saved;
    try {
      saved = db.saveRegistration({
        username: pending.username,
        webauthnUserId: pending.webauthnUserId,
        sessionUserId: req.session.userId,
        credential: {
          id: credential.id,
          publicKey: credential.publicKey,
          counter: credential.counter,
          transports: credential.transports,
          deviceType: credentialDeviceType,
          backedUp: credentialBackedUp,
          nickname: defaultNickname(credentialDeviceType),
        },
      });
    } catch (err) {
      if (err instanceof db.ConflictError) return res.status(409).json({ error: err.message });
      throw err;
    }

    const { user, created } = saved;
    db.logEvent({
      userId: user.id,
      event: created ? 'account_created' : 'key_added',
      credentialId: credential.id,
      ...clientInfo(req),
    });

    await startLoggedInSession(req, user.id);
    res.status(201).json({ ok: true, username: user.username });
  } catch (err) {
    next(err);
  }
});

// ---------- Authentication (log in) ----------

// Step 1: browser asks for a challenge. Username is optional:
//   - given: we list that user's credentials (works with any security key)
//   - blank: the browser shows its passkey picker (discoverable credentials)
// An unknown username gets the same response as a blank one, so this
// endpoint doesn't reveal which usernames exist.
app.post('/api/login/options', async (req, res, next) => {
  try {
    const username = String(req.body?.username || '').trim().toLowerCase();
    const user = username ? db.getUserByUsername(username) : undefined;
    const creds = user ? db.getCredentialsByUserId(user.id) : [];

    const options = await generateAuthenticationOptions({
      rpID: RP_ID,
      userVerification: 'preferred',
      allowCredentials: creds.map((c) => ({ id: c.id, transports: parseTransports(c.transports) })),
    });

    req.session.authentication = { challenge: options.challenge, createdAt: Date.now() };
    res.json(options);
  } catch (err) {
    next(err);
  }
});

// Step 2: browser sends a signature over the challenge. Server checks it
// with the stored PUBLIC key. No password or secret is ever sent.
app.post('/api/login/verify', async (req, res, next) => {
  try {
    const pending = takeChallenge(req, 'authentication');
    if (!pending) return res.status(400).json({ error: 'Login expired. Try again.' });

    const stored = db.getCredentialById(String(req.body?.id || ''));
    if (!stored) return res.status(400).json({ error: 'Login could not be verified' });

    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response: req.body,
        expectedChallenge: pending.challenge,
        expectedOrigin: ORIGIN,
        expectedRPID: RP_ID,
        credential: {
          id: stored.id,
          publicKey: new Uint8Array(stored.public_key),
          counter: stored.counter,
          transports: parseTransports(stored.transports),
        },
        requireUserVerification: false,
      });
    } catch (err) {
      // Also lands here if the signature counter went backwards (possible cloned key).
      console.warn('Authentication verification failed:', err.message);
      db.logEvent({ userId: stored.user_id, event: 'login_failed', credentialId: stored.id, ...clientInfo(req) });
      return res.status(400).json({ error: 'Login could not be verified' });
    }

    if (!verification.verified) {
      db.logEvent({ userId: stored.user_id, event: 'login_failed', credentialId: stored.id, ...clientInfo(req) });
      return res.status(400).json({ error: 'Login could not be verified' });
    }

    db.updateCounter(stored.id, verification.authenticationInfo.newCounter);
    db.logEvent({ userId: stored.user_id, event: 'login', credentialId: stored.id, ...clientInfo(req) });
    await startLoggedInSession(req, stored.user_id);

    const user = db.getUserById(stored.user_id);
    res.json({ ok: true, username: user.username });
  } catch (err) {
    next(err);
  }
});

// ---------- Account ----------

app.get('/api/me', requireAuth, (req, res) => {
  const user = db.getUserById(req.session.userId);
  if (!user) return res.status(401).json({ error: 'Not logged in' });

  // The full credential ID is sent so the page can rename/remove a key.
  // Credential IDs aren't secrets: the login endpoint hands them to anyone
  // who types a username. What protects a key is the ownership check below.
  const credentials = db.getCredentialsByUserId(user.id).map((c) => ({
    id: c.id,
    nickname: c.nickname || defaultNickname(c.device_type),
    deviceType: c.device_type,
    backedUp: Boolean(c.backed_up),
    transports: parseTransports(c.transports),
    createdAt: c.created_at,
    lastUsedAt: c.last_used_at,
  }));

  res.json({ username: user.username, createdAt: user.created_at, credentials });
});

app.get('/api/activity', requireAuth, (req, res) => {
  const events = db.getRecentEvents(req.session.userId, 15).map((e) => ({
    event: e.event,
    // Three cases: no key involved (logout), key still exists, key removed since.
    credentialName: e.existing_credential_id ? (e.credential_name || defaultNickname(e.credential_type)) : null,
    credentialRemoved: Boolean(e.credential_id && !e.existing_credential_id),
    ip: e.ip,
    userAgent: e.user_agent,
    at: e.created_at,
  }));
  res.json({ events });
});

// Rename a key. Scoped to the logged-in user, so you can only rename your own.
app.patch('/api/credentials/:id', requireAuth, (req, res) => {
  const nickname = String(req.body?.nickname || '')
    .replace(/[\u0000-\u001f\u007f]/g, '')     // strip control characters
    .trim();
  if (nickname.length < 1 || nickname.length > 40) {
    return res.status(400).json({ error: 'Name must be 1-40 characters' });
  }
  try {
    db.renameCredential(req.session.userId, req.params.id, nickname);
  } catch (err) {
    if (err instanceof db.NotFoundError) return res.status(404).json({ error: err.message });
    throw err;
  }
  db.logEvent({ userId: req.session.userId, event: 'key_renamed', credentialId: req.params.id, ...clientInfo(req) });
  res.json({ ok: true });
});

// Remove a key. Refuses to remove the last one (409).
app.delete('/api/credentials/:id', requireAuth, (req, res) => {
  try {
    db.deleteCredential(req.session.userId, req.params.id);
  } catch (err) {
    if (err instanceof db.NotFoundError) return res.status(404).json({ error: err.message });
    if (err instanceof db.ConflictError) return res.status(409).json({ error: err.message });
    throw err;
  }
  db.logEvent({ userId: req.session.userId, event: 'key_removed', credentialId: req.params.id, ...clientInfo(req) });
  res.status(204).end();
});

app.post('/api/logout', (req, res, next) => {
  if (req.session.userId) {
    db.logEvent({ userId: req.session.userId, event: 'logout', ...clientInfo(req) });
  }
  req.session.destroy((err) => {
    if (err) return next(err);
    res.clearCookie('fido.sid');
    res.json({ ok: true });
  });
});

// ---------- Errors ----------

app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));

// Log the details on the server; send the browser nothing it could use.
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Something went wrong' });
});

// Listen on loopback only: the app is reachable through Apache, not directly from the LAN.
app.listen(PORT, '127.0.0.1', () => {
  console.log(`FIDO app listening on http://127.0.0.1:${PORT}  (RP_ID=${RP_ID}, ORIGIN=${ORIGIN})`);
});
