# Architecture

| Step | Module | Question it answers |
|---|---|---|
| Identify | `resolve.py` | Which EC2, load balancer, RDS, or ENI is behind this address? |
| Check | `analyze/sg.py`, `analyze/route.py`, `analyze/confirm.py` | Do the rules and the routes already allow this flow? |
| Apply | `apply/modify.py` | Which security group should change, is there room, and who is affected? |
| Verify | `flowlog/athena.py` | Did the traffic actually pass? |

`analyze/sg.py` and `analyze/route.py` contain pure functions with no AWS calls, so the decision logic is easy to test.

## Evaluation order

1. Turn the source and destination into resources.
2. Check the source's outbound rules.
3. Check the destination's inbound rules.
4. If the destination is outside AWS, check that the source subnet has a route.
5. A destination given as an RDS address also accepts a security group reference.

## Choosing a security group

Candidates are ranked: names that match `common_patterns` or the role shared by the members come first, then groups used by more resources. A group needs enough free rule slots to be chosen.
