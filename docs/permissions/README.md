# Permissions

| File | Used by | Grants |
|---|---|---|
| `readonly-policy.json` | `confirm`, `collect`, `flowlog`, and the preview step of `modify` | Read only |
| `apply-policy.json` | `modify --apply` | Add rules only. This tool never removes a rule |

Grant the apply policy to a separate role, so a preview can never change anything.

The log archive account also needs Athena query access and read access to the flow log bucket.
