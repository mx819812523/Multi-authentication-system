# Multi-Subject Auth + Session Demo

Three independent subjects with multi-device sessions and three credential dimensions:
- Member (`member`)
- Community Staff (`community_staff`)
- Platform Staff (`platform_staff`)

Credentials:
- Password
- OTP
- Passkey (WebAuthn ceremony)
- Optional MFA (enabled by default for `platform_staff`)

## Stack

- Frontend: React + TypeScript + Vite + Framer Motion
- Backend: Axum + Rust + SQLx
- DB: PostgreSQL

## Quick Start

1. Start Postgres:

```bash
docker compose up -d
```

2. Run backend:

```bash
cd backend
cp .env.example .env
cargo run
```

3. Run frontend:

```bash
cd frontend
npm install
npm run dev
```

Open [http://localhost:5173](http://localhost:5173).

## Demo Accounts

- Member: `member@demo.local` / `Member#123`
- Community Staff: `community@demo.local` / `Community#123`
- Platform Staff: `platform@demo.local` / `Platform#123` (MFA enabled)

## Key API Endpoints

- `POST /auth/:subject/password/login`
- `POST /auth/:subject/otp/request`
- `POST /auth/:subject/otp/verify`
- `POST /auth/:subject/passkey/register/start`
- `POST /auth/:subject/passkey/register/finish`
- `POST /auth/:subject/passkey/login/start`
- `POST /auth/:subject/passkey/login/finish`
- `POST /auth/:subject/mfa/verify`
- `GET /me/profile`
- `POST /me/profile`
- `GET /me/linked-subjects`
- `GET /me/sessions`
- `POST /me/sessions/revoke`
- `POST /auth/logout`

## Notes

- Passkey uses standard browser WebAuthn ceremony (`navigator.credentials.create/get`).
- Sessions store only hashed token digests server-side (plaintext token is returned once at sign-in).
- Person layer is enabled: one `person` can link multiple `subject` identities, query with `/me/linked-subjects`.
- Same subject logging in repeatedly from the same device fingerprint will keep only the latest active session (soft dedupe).
- OTP is not returned in API responses; connect your out-of-band OTP channel in production.
