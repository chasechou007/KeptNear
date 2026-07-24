# Security Policy

KeptNear is pre-alpha software. Do not use it for production secrets
until external security review, public alpha readiness, and signed distribution
gates are complete.

## Reporting A Vulnerability

Please report security issues privately by email:

```text
Chase Chou <chasechou007@gmail.com>
```

Do not file public issues for vulnerabilities that include exploit details,
real vault material, real passwords, real exports, signing credentials, or
private local paths.

Helpful reports include:

- affected commit or version
- operating system and architecture
- clear reproduction steps using synthetic data
- expected and actual behavior
- impact assessment
- whether the issue exposes plaintext, weakens encryption, bypasses unlock, or
  leaks diagnostics/logging data

## Current Support Status

| Version | Security support |
| --- | --- |
| pre-alpha source | Best-effort private reports only |
| public alpha releases | Not started |

Security review state is tracked in `docs/security-review-evidence.md`.
