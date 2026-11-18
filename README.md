# Home Lab FIDO2 / WebAuthn App

Passwordless accounts with security keys and passkeys. The browser creates and signs; the **server verifies** and stores only public keys.

```
Browser ──HTTPS──> Apache (lab.home.arpa:443) ──HTTP──> Express (127.0.0.1:3000) ──> SQLite
         TLS ends here, security headers         API + session cookie          users, credentials
```

## Files

| File | Layer | What it does |
| --- | --- | --- |
| `public/index.html`, `public/app.js` | Frontend | UI; calls the API with `fetch`; calls WebAuthn via SimpleWebAuthn |
| `server.js` | Backend | 9 API endpoints, challenge handling, signature verification, sessions |
| `db.js` | Data | SQLite schema + migrations (`PRAGMA user_version`), prepared statements, transactions |
| `deploy/` | Infra | Apache reverse-proxy lines, systemd unit, env file template |

## API

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/api/register/options` | Validate username, issue a challenge |
| POST | `/api/register/verify` | Verify attestation, save user + public key, log in |
| POST | `/api/login/options` | Issue a challenge (username optional) |
| POST | `/api/login/verify` | Verify signature with stored public key, update counter, log in |
| GET | `/api/me` | Current user + their credentials (401 if not logged in) |
| GET | `/api/activity` | Last 15 sign-in / key events for the current user |
| PATCH | `/api/credentials/:id` | Rename one of your keys (`{ "nickname": "..." }`) |
| DELETE | `/api/credentials/:id` | Remove one of your keys (409 if it's your last one) |
| POST | `/api/logout` | Destroy session |

## Build steps on the Ubuntu server

1. **Node 22 LTS** (Ubuntu's apt version is too old):
   ```bash
   curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
   source ~/.bashrc && nvm install 22 && node -v     # needs 22.13 or newer
   ```
2. **Install dependencies**: copy the folder to `~/fido-app`, then
   ```bash
   cd ~/fido-app && npm install
   ```
3. **Run locally first** (no Apache): `npm run dev`, then open `http://localhost:3000` on Ubuntu. Register and log in.
4. **Put it behind Apache**: add `deploy/apache-fido-proxy.conf` inside the 443 VirtualHost, then
   ```bash
   sudo a2enmod proxy proxy_http headers
   sudo apache2ctl configtest && sudo systemctl reload apache2
   ```
   Move the old static demo out of `/var/www/html/fido/` (the proxy now owns `/fido/`).
5. **Run it as a service**: create `/etc/fido-app.env` from the example (`chmod 600`), edit `deploy/fido-app.service`, then
   ```bash
   sudo cp deploy/fido-app.service /etc/systemd/system/
   sudo systemctl daemon-reload && sudo systemctl enable --now fido-app
   ```
   systemd doesn't load nvm, so set `ExecStart` to the full path from `which node`.
6. **Test from Windows**: `https://lab.home.arpa/fido/`

## Inspect the data

```bash
sqlite3 data/fido.db '.tables' 'SELECT id, username FROM users;' 'SELECT substr(id,1,12), user_id, counter FROM credentials;'
```
