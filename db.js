// db.js — the data layer. Everything that touches SQLite lives here,
// so server.js never builds SQL itself.
//
// Uses node:sqlite (built into Node 22.13+), so there is no native module
// to compile and one less third-party dependency to trust.

const path = require('node:path');
const fs = require('node:fs');
const { DatabaseSync } = require('node:sqlite');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'fido.db');

// The data folder is readable only by the account running the app (700).
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true, mode: 0o700 });

const db = new DatabaseSync(DB_PATH);

// ---------- Schema ----------

// Version 1: the original tables. "IF NOT EXISTS" makes this safe to run every start.
db.exec(`
  PRAGMA foreign_keys = ON;
  PRAGMA journal_mode = WAL;

  -- One row per person.
  CREATE TABLE IF NOT EXISTS users (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    username         TEXT    NOT NULL UNIQUE,
    webauthn_user_id TEXT    NOT NULL UNIQUE,   -- random handle given to the authenticator, never the username
    created_at       TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  -- One row per passkey / security key. A user can have many (one-to-many).
  CREATE TABLE IF NOT EXISTS credentials (
    id           TEXT    PRIMARY KEY,           -- credential ID (base64url), chosen by the authenticator
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key   BLOB    NOT NULL,              -- only the PUBLIC key; the private key never leaves the authenticator
    counter      INTEGER NOT NULL DEFAULT 0,    -- signature counter, used to spot cloned authenticators
    transports   TEXT,                          -- JSON array, e.g. ["usb","nfc"]
    device_type  TEXT,                          -- 'singleDevice' (security key) or 'multiDevice' (synced passkey)
    backed_up    INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    last_used_at TEXT
  );

  -- Speeds up "list this user's credentials" (WHERE user_id = ?).
  CREATE INDEX IF NOT EXISTS idx_credentials_user_id ON credentials(user_id);
`);

// Migrations: changes to a database that already has data in it.
// CREATE TABLE IF NOT EXISTS can't add a column to an existing table,
// so each change after version 1 runs once, and the database remembers
// its version in PRAGMA user_version.
const MIGRATIONS = [
  // Version 2: key nicknames + a sign-in activity log.
  `
    ALTER TABLE credentials ADD COLUMN nickname TEXT;

    CREATE TABLE auth_events (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      event         TEXT    NOT NULL,   -- login, login_failed, account_created, key_added, key_renamed, key_removed, logout
      credential_id TEXT,               -- no foreign key on purpose: history stays after a key is removed
      ip            TEXT,
      user_agent    TEXT,
      created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX idx_auth_events_user_time ON auth_events(user_id, created_at);
  `,
];

function migrate() {
  let version = db.prepare('PRAGMA user_version').get().user_version || 1;
  for (let target = version + 1; target <= MIGRATIONS.length + 1; target++) {
    db.exec('BEGIN');
    try {
      db.exec(MIGRATIONS[target - 2]);
      db.exec(`PRAGMA user_version = ${target}`);
      db.exec('COMMIT');
      console.log(`Database migrated to version ${target}`);
    } catch (err) {
      db.exec('ROLLBACK');
      throw err;
    }
    version = target;
  }
}
migrate();

// ---------- Queries ----------

// Every query is a prepared statement with ? placeholders.
// User input is passed as data, never pasted into the SQL text,
// which is what prevents SQL injection.
const q = {
  userByUsername:  db.prepare('SELECT * FROM users WHERE username = ?'),
  userById:        db.prepare('SELECT id, username, created_at FROM users WHERE id = ?'),
  insertUser:      db.prepare('INSERT INTO users (username, webauthn_user_id) VALUES (?, ?)'),
  credsByUser:     db.prepare('SELECT * FROM credentials WHERE user_id = ? ORDER BY created_at'),
  credById:        db.prepare('SELECT * FROM credentials WHERE id = ?'),
  countCreds:      db.prepare('SELECT COUNT(*) AS n FROM credentials WHERE user_id = ?'),
  insertCred:      db.prepare(`INSERT INTO credentials
                     (id, user_id, public_key, counter, transports, device_type, backed_up, nickname)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
  updateCounter:   db.prepare(`UPDATE credentials
                     SET counter = ?, last_used_at = datetime('now') WHERE id = ?`),
  // Every change to a credential is scoped by BOTH its id AND the logged-in
  // user's id. Knowing someone else's credential ID isn't enough to touch it.
  renameCred:      db.prepare('UPDATE credentials SET nickname = ? WHERE id = ? AND user_id = ?'),
  deleteCred:      db.prepare('DELETE FROM credentials WHERE id = ? AND user_id = ?'),
  insertEvent:     db.prepare(`INSERT INTO auth_events (user_id, event, credential_id, ip, user_agent)
                     VALUES (?, ?, ?, ?, ?)`),
  // LEFT JOIN keeps events whose key was since removed. For those, every c.* column is NULL,
  // so we check c.id (never NULL for a real row), not c.nickname (NULL until a key is renamed).
  recentEvents:    db.prepare(`SELECT e.event, e.credential_id, e.ip, e.user_agent, e.created_at,
                            c.id AS existing_credential_id, c.nickname AS credential_name,
                            c.device_type AS credential_type
                     FROM auth_events e
                     LEFT JOIN credentials c ON c.id = e.credential_id
                     WHERE e.user_id = ?
                     ORDER BY e.id DESC
                     LIMIT ?`),
};

function getUserByUsername(username) {
  return q.userByUsername.get(username);
}

function getUserById(id) {
  return q.userById.get(id);
}

function getCredentialsByUserId(userId) {
  return q.credsByUser.all(userId);
}

function getCredentialById(id) {
  return q.credById.get(id);
}

class ConflictError extends Error {}
class NotFoundError extends Error {}

// Saves a newly registered credential. Creating the user (if new) and
// inserting the credential happen in ONE transaction: either both are
// saved or neither is, so we never end up with a user who has no passkey.
//
// sessionUserId is who is currently logged in (or undefined).
// Adding a key to an EXISTING account is only allowed when you are logged
// in as that account; otherwise anyone could attach their key to your
// username and take it over.
//
// Returns { user, created } where created = true for a brand-new account.
function saveRegistration({ username, webauthnUserId, sessionUserId, credential }) {
  db.exec('BEGIN IMMEDIATE');
  try {
    let user = q.userByUsername.get(username);
    let created = false;
    if (user && user.id !== sessionUserId) {
      throw new ConflictError('Username is taken');
    }
    if (!user) {
      const result = q.insertUser.run(username, webauthnUserId);
      user = { id: Number(result.lastInsertRowid), username };
      created = true;
    }
    q.insertCred.run(
      credential.id,
      user.id,
      credential.publicKey,
      credential.counter,
      JSON.stringify(credential.transports || []),
      credential.deviceType,
      credential.backedUp ? 1 : 0,
      credential.nickname || null,
    );
    db.exec('COMMIT');
    return { user, created };
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

function updateCounter(credentialId, newCounter) {
  q.updateCounter.run(newCounter, credentialId);
}

function renameCredential(userId, credentialId, nickname) {
  const result = q.renameCred.run(nickname, credentialId, userId);
  if (result.changes === 0) throw new NotFoundError('Key not found');
}

// Removes a key, but never the last one: with no keys left, nobody could
// ever log in to the account again. The count and the delete share one
// transaction so two removals at once can't both pass the check.
function deleteCredential(userId, credentialId) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const cred = q.credById.get(credentialId);
    if (!cred || cred.user_id !== userId) throw new NotFoundError('Key not found');
    if (q.countCreds.get(userId).n <= 1) {
      throw new ConflictError("You can't remove your only key. Add another one first.");
    }
    q.deleteCred.run(credentialId, userId);
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

function logEvent({ userId, event, credentialId = null, ip = null, userAgent = null }) {
  q.insertEvent.run(userId, event, credentialId, ip, userAgent ? userAgent.slice(0, 300) : null);
}

function getRecentEvents(userId, limit = 15) {
  return q.recentEvents.all(userId, limit);
}

module.exports = {
  getUserByUsername,
  getUserById,
  getCredentialsByUserId,
  getCredentialById,
  saveRegistration,
  updateCounter,
  renameCredential,
  deleteCredential,
  logEvent,
  getRecentEvents,
  ConflictError,
  NotFoundError,
};
