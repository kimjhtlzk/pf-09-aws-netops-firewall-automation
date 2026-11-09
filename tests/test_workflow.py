import pytest
from moto import mock_aws

from netops import cli, demo
from netops.analyze.confirm import Confirmer
from netops.apply.modify import (
    Modifier,
    build_ip_permissions,
    common_token,
    merge_by_group,
    rank_candidates,
    rule_count,
)
from netops.config import Settings
from netops.io import excel
from netops.resolve import Resource


@pytest.fixture
def env():
    demo.fake_environment()
    with mock_aws():
        sessions = demo.DemoSessions(Settings())
        demo.seed(sessions)
        yield sessions


def test_confirm_identifies_resources_across_accounts(env):
    verdict = Confirmer(env).analyze("10.0.1.10", "10.1.1.20", "443")
    assert verdict.ok
    assert (verdict.src_account, verdict.dst_account) == ("svc-a-dev", "svc-b-prd")


def test_confirm_flags_a_blocked_port(env):
    verdict = Confirmer(env).analyze("10.0.1.10", "10.1.1.20", "8443")
    assert not verdict.ok
    assert verdict.issues == ["Security group rule needed"]


def test_confirm_checks_routing_to_external_destinations(env):
    verdict = Confirmer(env).analyze("10.0.1.10", "203.0.113.50", "443")
    assert not verdict.ok
    assert "Route needed" in verdict.issues


def test_confirm_reports_unknown_addresses(env):
    verdict = Confirmer(env).analyze("10.9.9.9", "10.9.9.8", "443")
    assert verdict.issues == ["No AWS resource found on either side"]


def test_modify_plan_then_apply_opens_the_flow(env):
    settings = Settings()
    modifier = Modifier(env, settings)
    request = excel.ModifyRequest(
        "svc-a-dev", "10.0.1.10", "svc-b-prd", "10.1.1.20", "8443", "tcp", "ticket-1"
    )
    changes = merge_by_group([modifier.plan(request)])
    assert {c.direction for c in changes} == {"egress", "ingress"}
    assert not Confirmer(env).analyze("10.0.1.10", "10.1.1.20", "8443").ok

    assert {modifier.apply(c) for c in changes} == {"applied"}
    assert Confirmer(env).analyze("10.0.1.10", "10.1.1.20", "8443").ok
    assert {modifier.apply(c) for c in changes} == {"already present"}


def test_dry_run_changes_nothing(env, capsys, monkeypatch):
    settings = Settings()
    args = cli.build_parser().parse_args(["modify", "--demo"])
    request = excel.ModifyRequest("svc-a-dev", "10.0.1.10", "svc-b-prd", "10.1.1.20", "8443", "tcp", "t")
    assert cli.run_modify(args, settings, env, [request]) == 0
    assert "Nothing was changed" in capsys.readouterr().out
    assert not Confirmer(env).analyze("10.0.1.10", "10.1.1.20", "8443").ok


def test_apply_requires_typed_confirmation(env, monkeypatch, capsys):
    args = cli.build_parser().parse_args(["modify", "--apply", "--demo"])
    monkeypatch.setattr("builtins.input", lambda _: "no")
    request = excel.ModifyRequest("svc-a-dev", "10.0.1.10", "svc-b-prd", "10.1.1.20", "8443", "tcp", "t")
    assert cli.run_modify(args, Settings(), env, [request]) == 1
    assert not Confirmer(env).analyze("10.0.1.10", "10.1.1.20", "8443").ok


def test_plan_refuses_groups_without_free_slots(env):
    modifier = Modifier(env, Settings(sg_max_rules=1))
    request = excel.ModifyRequest("svc-a-dev", "10.0.1.10", "svc-b-prd", "10.1.1.20", "8443", "tcp", "t")
    plan = modifier.plan(request)
    assert not plan.changes
    assert any("free rule slots" in p for p in plan.problems)


def test_build_permissions_for_each_protocol():
    assert build_ip_permissions("443", "tcp", ["10.0.0.0/8"], "d")[0]["FromPort"] == 443
    assert build_ip_permissions("80-90", "tcp", ["10.0.0.0/8"], "d")[0]["ToPort"] == 90
    assert build_ip_permissions("any", "any", ["10.0.0.0/8"], "d")[0]["IpProtocol"] == "-1"
    assert build_ip_permissions("any", "icmp", ["10.0.0.0/8"], "d")[0]["FromPort"] == -1


def test_common_token():
    assert common_token(["a-proxy1", "a-proxy2"]) == "proxy"
    assert common_token(["web", "db"]) is None


def test_rank_prefers_shared_groups():
    def resource(name, sg_id, sg_name):
        return Resource("EC2", "a", name, name, "10.0.0.1", security_groups=[{"id": sg_id, "name": sg_name}])

    ranked = rank_candidates(
        [resource("x", "sg-1", "svc-only"), resource("y", "sg-2", "svc-comm")], {}, Settings()
    )
    assert ranked[0].sg_id == "sg-2"
    assert ranked[0].reasons == ["shared (comm)"]


def test_rule_count_counts_every_peer():
    group = {"IpPermissions": [{"IpRanges": [{}, {}]}], "IpPermissionsEgress": [{"UserIdGroupPairs": [{}]}]}
    assert rule_count(group) == 3


def test_excel_round_trip_keeps_columns(tmp_path):
    path = excel.write_modify(
        tmp_path / "m.xlsx", [excel.ModifyRequest("a", "10.0.0.1", "b", "10.0.0.2", "443", "tcp", "d")]
    )
    assert excel.read_modify(path)[0].description == "d"
    confirm = excel.write_confirm_template(
        tmp_path / "c.xlsx", [excel.ConfirmRequest("10.0.0.1", "10.0.0.2", "443", "udp")]
    )
    assert excel.read_confirm(confirm)[0].proto == "udp"
