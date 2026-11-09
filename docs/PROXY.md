# Corporate proxy and private CA

Set the proxy in the settings file or through `NETOPS_PROXY`.

```yaml
proxy: "http://<proxy-host>:<port>"
```

Leave it empty to connect directly.

## TLS inspection

Some proxies replace certificates with ones signed by a private CA. Python then rejects the connection, because it does not trust that CA.

**The fix is to trust your CA, not to turn checking off.** Export the CA certificate from your company in PEM format, then point to it:

```yaml
ca_bundle: "/path/to/company-ca.pem"
```

`NETOPS_CA_BUNDLE` works too.

This tool has no option to disable certificate verification. Without verification, anyone on the network path could read or change requests that carry your AWS credentials.
