# Cloudflare Facebook OAuth Worker

[`Xzese/cloudflare-facebook-oauth-worker`](https://github.com/Xzese/cloudflare-facebook-oauth-worker)
is a **public-source, private-deployments** template for obtaining and exposing Facebook OAuth
tokens with Cloudflare Workers.

## Public source, private deployments

This repository is not a shared token service.

Each operator is expected to deploy their own:

- Worker instance
- KV namespace
- Facebook app
- Cloudflare Access application
- Secrets and non-secret runtime variables

The checked-in `wrangler.toml` is intentionally public-template only and uses placeholders.
Manual production deployment uses `wrangler.production.toml`.
Cloudflare repository builds generate `wrangler.generated.json` from a protected build variable.
Both configs set `keep_vars = true` and omit a `vars` block so deployments retain
runtime variables configured in the Cloudflare dashboard.

## Features

- Cloudflare Access validation for interactive routes.
- Facebook OAuth flow (`/`, `/authenticate`, `/callback`).
- Server-to-server token endpoint (`/api/token`).
- Token metadata persistence in Workers KV:
    - `accessToken`
    - `updatedAt`
    - `expiresAt`
    - `expired` (derived)
- Token expiry display and re-authentication guidance.
- Public safety checks that enforce a sanitized public release configuration.

## Prerequisites

- Node.js 22.18.0
- Cloudflare account with Workers + KV
- Cloudflare Access for the worker routes
- A Facebook app configured for OAuth

## Variables, bindings, and secrets

### Required non-secret runtime variables

- `APP_ID` — Facebook app ID
- `GRAPH_SCOPE` — OAuth scope (example: `publish_video,pages_show_list,instagram_basic`)
- `GRAPH_API_VERSION` — Graph API version (example: `v25.0`)
- `TEAM_DOMAIN` — Cloudflare Access team domain
- `POLICY_AUD` — Cloudflare Access policy audience

### Required secrets

- `APP_SECRET`
- `TOKEN_API_KEY`

### Required KV binding

- `FACEBOOK_AUTH`

OAuth callback and post-authentication URLs are derived from each incoming
request's origin. Production requests must use HTTPS. Exact loopback hostnames
automatically use the local-development Access exception.

## Local development

1. Install dependencies:

    ```sh
    npm install
    ```

2. Create local vars from the example:

    ```sh
    cp .dev.vars.example .dev.vars
    ```

3. Fill `.dev.vars` with the Facebook app values, Access placeholders, and
   local-only secrets shown in the example:

    ```dotenv
    APP_ID=your-facebook-app-id
    APP_SECRET=development-secret
    TOKEN_API_KEY=development-token-key
    GRAPH_SCOPE=publish_video,pages_show_list,instagram_basic
    GRAPH_API_VERSION=v25.0
    TEAM_DOMAIN=https://your-team.cloudflareaccess.com
    POLICY_AUD=your-access-application-aud-tag
    ```

4. Run the worker:

    ```sh
    npm run dev
    ```

Local development runs against local KV, not production.

## Facebook setup

In the Facebook App dashboard:

1. Add the OAuth callback URL:

    ```text
    https://<your-worker-hostname>/callback
    ```

2. Optionally add local callback for testing:

    ```text
    http://localhost:8787/callback
    ```

3. Configure app secret and ID in deployment configuration.

4. Keep `GRAPH_SCOPE` to only what you need.

## Cloudflare Access setup

Cloudflare Access remains the authentication boundary. You need:

- Worker hostname protection for `/`, `/authenticate`, `/callback`, and `/api/token`.
- An Access application with a browser identity for operator flows.
- A service token for backend automation when calling `/api/token`.
- Access coverage for every enabled Worker hostname. Protect or disable unused
  preview and alternate `workers.dev` routes; do not add an `/api/token` bypass.
- `/` is intentionally for human operators and returns the full Facebook bearer
  token in the response; restrict Access policy membership tightly and block or
  protect every active, preview, or alternate hostname.

### `/api/token` and service identity

`/api/token` accepts either:

- Human Access JWT with valid Access identity, and
- A service token assertion for backend automation

In both cases, the route still requires `TOKEN_API_KEY`.

Service token identities may not include normal email claim fields; they are intended as service credentials.

## Routes

- `GET /`
    - Protected by Access.
    - Shows token metadata and expiry status. This response intentionally includes
      the full Facebook bearer token; grant access only to trusted human users
      and secure all worker/preview hostnames that expose it.
- `POST /authenticate`
    - Protected by Access.
    - Starts the OAuth handshake.
- `GET /callback`
    - Protected by Access.
    - Exchanges code for token and stores data.
- `GET /api/token`
    - Protected by Access + `TOKEN_API_KEY`.
    - Returns JSON for backend services only.

## Token endpoint usage

Call from server-side systems only.

```sh
curl https://<your-worker-hostname>/api/token \
  -H "CF-Access-Client-Id: <ACCESS_SERVICE_TOKEN_ID>" \
  -H "CF-Access-Client-Secret: <ACCESS_SERVICE_TOKEN_SECRET>" \
  -H "Authorization: Bearer <TOKEN_API_KEY>"
```

Expected response:

```json
{
	"accessToken": "<facebook-access-token>",
	"expiresAt": "2026-08-06T12:00:00.000Z",
	"updatedAt": "2026-06-07T12:00:00.000Z",
	"expired": false
}
```

## Token expiry and reauthentication

- Re-run `/authenticate` when `expired` is `true`.
- Re-run before the expiry window ends in your background jobs.
- `/api/token` returns `410 Gone` with expiry metadata instead of returning a
  known-expired access token.
- `/api/token` should be treated as long-lived credential material.

## Manual deployment

For manual production deploys, run:

```sh
cp wrangler.toml wrangler.production.toml
# Replace every placeholder in wrangler.production.toml.
npm run deploy
```

`wrangler.production.toml` is private configuration and should not be committed.

## Cloudflare repository builds

For repository-based deployments:

1. Configure `APP_ID`, `GRAPH_SCOPE`, `GRAPH_API_VERSION`, `TEAM_DOMAIN`, and
   `POLICY_AUD` as runtime plaintext variables in the Cloudflare dashboard.
2. Keep `APP_SECRET` and `TOKEN_API_KEY` as existing runtime secrets.
   The generated config declares these required secret names, but does not set
   or overwrite their values.
3. Add `FACEBOOK_AUTH_KV_NAMESPACE_ID` as a private build variable. Store it as
   an encrypted/secret build variable where the build platform supports that:

    - `FACEBOOK_AUTH_KV_NAMESPACE_ID`

4. Use `npm run cloudflare:deploy` as the production deploy command.
5. Use `npm run cloudflare:upload` as the non-production/version command when
   you want to upload a Worker version without deploying it immediately.
6. Verify that the uploaded or deployed version retains the dashboard
   variables, Worker secrets, and existing KV token.

`npm run cloudflare:config` can be used locally to inspect the generated
deployment shape without deploying.

The generated deploy config is written to `wrangler.generated.json`. It sets
`keep_vars` and omits `vars`, retaining dashboard runtime variables rather than
replacing them.

## CI and repository hardening

- `npm run public-config:check` must pass before releasing.
- The repository CI verifies formatting, lint, typing, tests, and generated type/config checks.
- Dependabot updates are enabled for:
    - npm dependencies
    - GitHub Actions

## Warnings

- `/api/token` must never be called from browser/client-side code.
- Do not commit:
    - `.dev.vars`
    - `wrangler.production.toml`
    - `wrangler.generated.json`
    - `.wrangler/`
    - production hostnames, real account IDs, or token/secrets
- Keep production and placeholder runtime values separate.
- Never replace existing secrets unless required by rotation or incident response.
