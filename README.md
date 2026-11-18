# FIDO2 / WebAuthn Passwordless Authentication

A full-stack passwordless login system built from scratch to understand how secure authentication works end to end. Users register and sign in with a hardware security key or passkey designed specifically so that **no passwords and no shared secret ever crosses the network.** The server issues a random challenge, the authenticator signs it with a private key that never leaves the device, and the server verifies that signature against a stored public key. *(Tested with a YubiKey Security Key C NFC and a synced Google passkey.)*

Built and deployed on a self-hosted home lab behind Apache over HTTPS.

> Even if the entire database leaked, there is nothing in it an attacker could log in with since the server stores only public keys, which can verify a signature but never create one.

---

## Screenshots
<img width="1315" height="792" alt="image" src="https://github.com/user-attachments/assets/ac3b6baa-b11e-4fba-89b7-825ced2265f6" />


> Login Screen: Users have the option to register a new account using their key, or log in using an existing key. Username is completely optional.
> 

<img width="1315" height="792" alt="image" src="https://github.com/user-attachments/assets/f16820a9-fde4-4501-b6fe-b4125716c772" />

> User is prompted to **physically interact** with their key **and** provide a secure **4-digit PIN**.
> 
<img width="1319" height="1002" alt="image" src="https://github.com/user-attachments/assets/aba669e6-0f70-4988-9d62-45f361afdedb" />

> Account dashboard: manage keys and review sign-in activity.

---

## Security design

This project is as much a study in secure-by-design decisions as it is an app. Each choice below maps to a specific attack it prevents:

| Decision | Attack prevented |
| --- | --- |
| Random, single-use challenge (2-min expiry), deleted on use | **Replay** — a captured response can't be reused |
| Server verifies origin + relying-party ID on every ceremony | **Phishing** — a credential is bound to its origin and won't sign for a look-alike site |
| Only **public** keys stored | **Database theft** — nothing to crack or reuse offline |
| Session ID regenerated on login | **Session fixation** |
| Cookies `httpOnly` + `Secure` + `SameSite=Strict` | **XSS cookie theft, sniffing, CSRF** |
| Signature counter must increase | **Cloned hardware authenticators** |
| Key rename/remove scoped by credential ID **and** session user ID | **IDOR / broken object-level authorization** (OWASP API #1) — returns 404, not 403, so it doesn't confirm another user's key exists |
| Parameterized queries throughout; all SQL isolated in one module | **SQL injection** |
| User + credential saved in one transaction; can't remove your last key | **Orphaned accounts & lockout race conditions** |
| Identical response for unknown vs. blank username | **Account enumeration** |
| App bound to loopback behind Apache; UFW LAN-only | **Defense in depth** — the app isn't reachable from the network directly |

---

## Architecture

```
Browser ──HTTPS──> Apache (reverse proxy) ──HTTP──> Express (127.0.0.1:3000) ──> SQLite
         TLS + security headers,            API, session cookies,         users, credentials,
         private lab CA                     WebAuthn verification         activity log
```

- **Apache** terminates TLS (certificate from a private lab CA), adds security headers, and proxies `/fido/` to the app.
- **Express** is bound to loopback only — it can't be reached from the network, only through Apache.
- **Express runs as a systemd service** under a non-root user, with secrets loaded from a root-only environment file.

## Tech stack

**Backend:** Node.js 22, Express, express-session, [@simplewebauthn/server](https://simplewebauthn.dev)
**Frontend:** Vanilla JavaScript, [@simplewebauthn/browser](https://simplewebauthn.dev)
**Data:** SQLite (`node:sqlite`) with versioned migrations
**Infra:** Apache (reverse proxy + TLS), systemd, UFW

## Features

- Register and sign in with security keys **or** passkeys (usernameless login supported)
- Multiple keys per account, with a device-bound vs. synced-passkey distinction
- **Account dashboard:** rename and remove keys, with a live sign-in activity log (logins, failed attempts, key changes — with IP and browser)
- Account-recovery–aware design (backup authenticator guidance; can't remove your only key)
- Schema migrations tracked via `PRAGMA user_version`, so the database upgrades in place

## API

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/api/register/options` | Validate username, issue a challenge |
| POST | `/api/register/verify` | Verify attestation, store public key, log in |
| POST | `/api/login/options` | Issue a challenge (username optional) |
| POST | `/api/login/verify` | Verify signature with stored public key, update counter, log in |
| GET | `/api/me` | Current user + their credentials |
| GET | `/api/activity` | Recent sign-in / key events |
| PATCH | `/api/credentials/:id` | Rename one of your keys |
| DELETE | `/api/credentials/:id` | Remove a key (refuses your last one) |
| POST | `/api/logout` | Destroy session |

## Running it locally

Requires **Node 22.13+** (uses the built-in `node:sqlite`).

```bash
npm install
npm run dev     # serves on http://localhost:3000
```

Open `http://localhost:3000` **on the same machine** and register. (WebAuthn requires a secure context — `localhost` qualifies; any other host needs HTTPS with a trusted certificate.)

Full production setup (Apache reverse proxy, systemd service, TLS with a private CA) is documented in [`deploy/`](deploy/).

## Next Steps

- Rate limiting on registration and login
- Containerize with Docker; add a Wazuh SIEM to monitor attacks against the app

---

*Built as a hands-on study in secure full-stack engineering. Not intended for production use as-is.*
