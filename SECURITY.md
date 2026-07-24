# Security Policy

## Reporting a vulnerability

If you discover a security issue, report it privately using the GitHub private
vulnerability reporting flow. Do not open a public issue for security matters.

When reporting, include:

- A reproduction summary
- Steps to reproduce
- Impact assessment
- Affected file(s) or deployment assumptions
- Suggested mitigation, if any

If possible, provide request headers/paths and any deployment identifiers used.

## Scope and operational security notes

- Do not commit:
    - production secrets
    - token-like values
    - private KV identifiers
    - `.dev.vars`
    - build artifacts containing runtime-sensitive data
- The project is scoped for operator-owned deployments only.
- Keep Facebook and Access configuration secrets in Cloudflare secrets/built-in dashboards.
