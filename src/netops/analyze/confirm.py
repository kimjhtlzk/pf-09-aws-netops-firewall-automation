"""Step 1: can this flow already pass? Only the flows that cannot need any work."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from netops.analyze import route as route_analysis
from netops.analyze import sg
from netops.aws.session import SessionFactory
from netops.resolve import Resolved, Resolver, Resource


@dataclass
class Check:
    side: str
    resource: str
    ok: bool
    detail: str


@dataclass
class Verdict:
    src: str
    dst: str
    port: str
    proto: str
    ok: bool
    checks: list[Check] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    src_account: str = ""
    dst_account: str = ""


class Confirmer:
    def __init__(self, sessions: SessionFactory) -> None:
        self.sessions = sessions
        self.resolver = Resolver(sessions)

    def _groups(self, resource: Resource) -> list[dict[str, Any]]:
        if not resource.sg_ids:
            return []
        ec2 = self.sessions.client("ec2", resource.account)
        return ec2.describe_security_groups(GroupIds=resource.sg_ids)["SecurityGroups"]

    def _rule_check(self, resource: Resource, direction: str, peer: str, port: str, proto: str) -> Check:
        coverage = sg.check_coverage(self._groups(resource), direction, peer, port, proto)
        if coverage.allowed:
            detail = "allowed by " + ", ".join(sorted({m["sg_id"] for m in coverage.matched}))
        elif coverage.port_mismatch:
            detail = "address matches, but the port differs"
        elif coverage.proto_mismatch:
            detail = "address matches, but the protocol differs"
        elif coverage.matched:
            detail = "partly open, missing " + ", ".join(coverage.uncovered)
        else:
            detail = "no matching rule"
        return Check(direction, resource.label, coverage.allowed, detail)

    def _egress_to_rds(self, source: Resource, db: Resource, port: str, proto: str) -> Check:
        groups = self._groups(source)
        if sg.sg_reference_allows(groups, "egress", db.sg_ids, port, proto):
            return Check("egress", source.label, True, "allowed by security group reference")
        results = [sg.check_coverage(groups, "egress", cidr, port, proto) for cidr in db.subnet_cidrs]
        ok = bool(results) and all(r.allowed for r in results)
        return Check(
            "egress", source.label, ok, "allowed to database subnets" if ok else "no rule to database subnets"
        )

    def analyze(self, src: str, dst: str, port: str, proto: str = "tcp") -> Verdict:
        source: Resolved = self.resolver.resolve(src)
        target: Resolved = self.resolver.resolve(dst)
        verdict = Verdict(src, dst, port, proto, ok=True)
        verdict.src_account = source.resources[0].account if source.resources else ""
        verdict.dst_account = target.resources[0].account if target.resources else ""

        if not source.resources and not target.resources:
            verdict.ok = False
            verdict.issues.append("No AWS resource found on either side")
            return verdict

        database = target.resources[0] if target.kind == "endpoint" and target.resources else None
        for resource in source.resources:
            check = (
                self._egress_to_rds(resource, database, port, proto)
                if database
                else self._rule_check(resource, "egress", dst, port, proto)
            )
            verdict.checks.append(check)
        for resource in target.resources:
            peer = src
            verdict.checks.append(self._rule_check(resource, "ingress", peer, port, proto))

        if any(not c.ok for c in verdict.checks):
            verdict.ok = False
            verdict.issues.append("Security group rule needed")

        if source.resources and not target.resources:
            for resource in source.resources:
                ec2 = self.sessions.client("ec2", resource.account)
                result = route_analysis.evaluate(
                    route_analysis.find_table(ec2, resource.subnet_id, resource.vpc_id), dst
                )
                detail = (
                    f"via {route_analysis.next_hop(result.routes[0])}"
                    if result.ok
                    else f"no route in {result.table_id or 'any table'}"
                )
                verdict.checks.append(Check("route", resource.label, result.ok, detail))
                if not result.ok:
                    verdict.ok = False
                    verdict.issues.append("Route needed")
        return verdict
