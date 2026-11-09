# Refactor notes

## Feature map

| Original feature | Location in this repository |
|---|---|
| Identify IP, CIDR, IP range, and RDS address | `resolve.py` |
| Outbound and inbound rule diagnosis | `analyze/sg.py`, `analyze/confirm.py` |
| Route diagnosis | `analyze/route.py` |
| Workbook for blocked flows | `netops confirm`, `io/excel.py` |
| Security group recommendation and rule slot check | `apply/modify.py` |
| Preview before apply, bundled by security group | `netops modify` |
| Flow log search with CloudWatch and Athena | `flowlog/athena.py` |
| Six inventory workbooks | `collect/` |
| SSO sign-in, renewal loop, desktop notice | `auth/sso.py` |
| Proxy support | `aws/session.py`, `docs/PROXY.md` |

## What changed and why

| Change | Reason |
|---|---|
| About 5,500 lines became about 1737 | Identification and session code existed in several scripts |
| TLS verification always on, CA bundle setting added | See ADR-003 |
| Apply needs a flag and a typed confirmation | See ADR-002 |
| Credentials moved out of the project folder | They now live in `~/.aws` |
| Credentials file written with owner-only permissions | Security hardening |
| Athena identifiers validated | Prevents query injection |
| Security group choice is automatic, with reasons printed | Replaces the numbered prompt so that runs can be repeated |
| Output file names and account names made neutral | See `SECURITY.md` |
| Interactive prompts and Korean console text replaced | One consistent CLI |
| Tests added with moto | No test coverage existed |
| Demo mode added | Usable without an AWS account |
