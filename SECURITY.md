# Security policy

## Handling of sensitive data

This repository is a sanitized portfolio rewrite. It contains no real credentials, account IDs, public IP addresses, or internal identifiers.

| Value | Placeholder used here |
|---|---|
| Public IP addresses | RFC 5737 ranges only: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` |
| Private networks | `10.0.0.0/8` examples |
| Account ID | `<ACCOUNT_ID>` or `111111111111` |
| Project ID | `<PROJECT_ID>` |
| Domain | `example.com` |
| Secrets | Never written down. Inject through environment variables or the provider's standard credential chain |

Every push is scanned by [gitleaks](https://github.com/gitleaks/gitleaks) with the rules in `.gitleaks.toml`.

## Reporting a vulnerability

Please use [GitHub Security Advisories](../../security/advisories/new) to report a problem privately. Do not open a public issue.
