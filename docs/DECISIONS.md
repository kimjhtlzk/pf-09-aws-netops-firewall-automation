# Design decisions

## ADR-001: Check before changing

- **Context:** Firewall requests often ask for a flow that is already open, which creates duplicate rules.
- **Decision:** `confirm` runs first and produces the input for `modify`.
- **Reason:** Only blocked flows reach the apply step.

## ADR-002: Preview is the default

- **Context:** A security group change takes effect immediately.
- **Decision:** `modify` only prints a plan. Changes need `--apply` and a typed `apply`.
- **Reason:** The safe action should be the one that needs no flag.
- **Alternative:** A `--dry-run` flag, which fails dangerously if someone forgets it.

## ADR-003: TLS verification cannot be turned off

- **Context:** Corporate proxies that inspect TLS make certificate errors common, and turning verification off is a tempting fix.
- **Decision:** There is a `ca_bundle` setting and no switch to disable verification.
- **Reason:** These requests carry AWS credentials.

## ADR-004: Rules are only added

- **Context:** Removing a rule can break traffic that nobody knew about.
- **Decision:** The tool never revokes a rule, and the apply policy does not allow it.
- **Reason:** Removal needs a person who understands the traffic.

## ADR-005: Keep Excel as the interface

- **Context:** Requests already arrive as spreadsheets.
- **Decision:** The columns of the input forms stay the same.
- **Reason:** People do not need to learn a new format.
