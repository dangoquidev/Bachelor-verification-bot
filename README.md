# Bachelor Verification Bot

Discord bot that verifies Epitech first-year students: every newcomer must prove they own an `@epitech.eu` address before getting access to the server.

## How it works

1. The student runs `/verify email:firstname.lastname@epitech.eu` on the server.
2. The bot emails a 6-character code through **Microsoft Graph** (the school's Microsoft 365 account).
3. The student pastes the code in the channel: the bot records the verification in **MySQL**, grants the verified role, renames the member `Firstname LASTNAME` from their address, and deletes the message containing the code.

```
Discord ──/verify──▶ Bot ──Graph API /me/sendMail──▶ Student mailbox
   ▲                  │
   └── role + nickname ◀── code typed in the channel
```

## Technical highlights

- **Delegated OAuth2 (MSAL)**: a small Express server (`/login`, `/get_token`) lets an admin sign in the Microsoft account that sends the emails; tokens are refreshed silently.
- **MySQL persistence**: `verified_users` table with a `UNIQUE` constraint on the email, guaranteeing one address verifies only one Discord account even under concurrent requests; prepared statements through a `mysql2` pool, schema created at startup, automatic import of the legacy CSV file.
- **Abuse protection**: max 3 requests per 15 minutes, 5 code attempts, codes expire after 10 minutes, one email address can only verify one Discord account.
- **Codes generated with `crypto.randomInt`** (cryptographically secure RNG).
- **Docker**: multi-stage build, runs as a non-root user, MySQL 8.4 in Docker Compose with a healthcheck and a persistent volume; the bot waits for the database before starting.
- Timestamped, structured logs to trace every verification.

## Stack

TypeScript · Node.js · discord.js v14 · Express · MySQL 8.4 · MSAL Node · Microsoft Graph · Docker Compose

## Getting started

Requirements: a Discord application (bot) and an Azure AD App Registration with the delegated `Mail.Send` permission.

```bash
cp example.env .env   # fill in the variables
docker compose up -d --build
```

Then open `http://localhost:8000/login` once to sign in the sender Microsoft account.

Without Docker (requires a reachable MySQL server):

```bash
npm install
npm run dev
```

| Variable | Purpose |
|---|---|
| `DISCORD_TOKEN` | Discord bot token |
| `VERIFIED_ROLE_NAME` | Name of the role granted after verification |
| `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` | Azure AD App Registration |
| `APP_BASE_URL`, `PORT`, `MSAL_REDIRECT_URI` | Auth server |
| `MYSQL_HOST`, `MYSQL_PORT`, `MYSQL_DATABASE`, `MYSQL_USER`, `MYSQL_PASSWORD` | MySQL connection |
| `MYSQL_ROOT_PASSWORD` | Root password of the MySQL container (Docker only) |

## Project structure

```
src/
├── index.ts                    # entry point: auth server + bot
├── server.ts                   # Express OAuth2 routes
├── auth/AuthService.ts         # MSAL: login URL, code exchange, tokens
├── bot/EmailVerificationBot.ts # /verify command, codes, roles, rate limiting
├── db/VerificationStore.ts     # MySQL access: schema, reads/writes, CSV import
└── utils/index.html            # email template
```
