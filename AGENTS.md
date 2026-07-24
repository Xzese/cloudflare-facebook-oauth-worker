# Cloudflare Facebook OAuth Worker AGENTS

## Scope

This repository intentionally keeps deployment secrets and private configuration out
of version control. Do not store secrets, `.dev.vars`, private Wrangler files,
or production identifiers in public sources.

## Edit guidance

- Keep changes narrowly focused.
- Preserve route and authentication behavior unless explicitly changing the public
  release contract.
- Prefer documentation clarity and explicit warnings for operators.

## Recommended review checks

- Confirm `README.md` documents Access, variables, token API, and deployment split.
- Confirm `.github/workflows/ci.yml` uses read-only permissions and required command checks.
- Confirm `.github/dependabot.yml` is weekly for npm and GitHub Actions.
