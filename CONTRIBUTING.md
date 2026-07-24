# Contributing

Thank you for contributing to this repository.

## How to contribute

1. Keep changes scoped to public release-safe content and deployment guidance.
2. Update docs and metadata when changing auth, deployment, or config behavior.
3. Preserve existing behavior for other paths unless the change is part of the public-release migration.

## Local checks

Run these before opening a PR:

```sh
npm install
npm run format:check
npm run lint
npm run type-check
npm test
npm run cf-typegen:check
npm run public-config:check
```

## Development workflow notes

- Use PR branches and small, reviewable commits.
- Include relevant notes when modifying deployment/config docs.
- Avoid committing secrets, `.dev.vars`, `.wrangler`, or private build outputs.
- If you touch Access/Facebook settings, include explicit replacement and rotation guidance.

## CI behavior

The repository has pull-request checks for format, lint, typing, tests,
and Cloudflare/public-configuration checks. Keep those green before merge.
