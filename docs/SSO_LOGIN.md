# IAM Identity Center sign-in

`netops sso-login` uses the device authorization flow, so no password or long-lived key is stored.

1. Set `sso_start_url` and `sso_region` in the settings file.
2. Run `netops sso-login --role <permission-set>`.
3. Approve the request in the browser.

Temporary credentials for every account you can reach are written to `~/.aws/credentials`, readable only by you. Profile names are the account names from Identity Center.

While the command keeps running, it checks every 10 minutes and renews credentials that expire within 15 minutes. If the sign-in itself expires, it asks you to approve again. Use `--once` to exit after the first sign-in.
