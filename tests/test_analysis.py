import ipaddress

import pytest

from netops.analyze import route, sg
from netops.resolve import is_domain, parse_networks


@pytest.mark.parametrize(
    ("port", "rule", "expected"),
    [
        ("443", "443-443", True),
        ("443", "0-1024", True),
        ("8443", "443-443", False),
        ("any", "-1", True),
        ("any", "443-443", False),
        ("80-90", "80-85", False),
        ("443", "-1", True),
    ],
)
def test_port_in_range(port, rule, expected):
    assert sg.port_in_range(port, rule) is expected


@pytest.mark.parametrize(
    ("proto", "rule", "expected"),
    [
        ("tcp", "tcp", True),
        ("tcp", "udp", False),
        ("tcp", "-1", True),
        ("any", "tcp", False),
        ("any", "-1", True),
    ],
)
def test_proto_match(proto, rule, expected):
    assert sg.proto_match(proto, rule) is expected


def test_parse_networks_accepts_all_input_formats():
    assert parse_networks("10.0.0.1") == [ipaddress.IPv4Network("10.0.0.1/32")]
    assert parse_networks("10.0.0.0/30") == [ipaddress.IPv4Network("10.0.0.0/30")]
    assert parse_networks("10.0.0.0-10.0.0.3") == [ipaddress.IPv4Network("10.0.0.0/30")]
    assert parse_networks("demo.example.com") == []


def test_is_domain_rejects_addresses():
    assert is_domain("demo.example.com")
    assert not is_domain("10.0.0.1")
    assert not is_domain("10.0.0.0/24")


def test_uncovered_splits_partial_coverage():
    left = sg.uncovered_networks([ipaddress.IPv4Network("10.0.0.0/24")], ["10.0.0.0/25"])
    assert left == [ipaddress.IPv4Network("10.0.0.128/25")]


def _group(key, **rule):
    return {"GroupId": "sg-1", key: [rule]}


def test_coverage_allows_matching_rule():
    group = _group(
        "IpPermissions", IpProtocol="tcp", FromPort=443, ToPort=443, IpRanges=[{"CidrIp": "10.0.0.0/16"}]
    )
    result = sg.check_coverage([group], "ingress", "10.0.1.5", "443", "tcp")
    assert result.allowed
    assert result.matched[0]["sg_id"] == "sg-1"


def test_coverage_explains_port_mismatch():
    group = _group(
        "IpPermissions", IpProtocol="tcp", FromPort=443, ToPort=443, IpRanges=[{"CidrIp": "10.0.0.0/16"}]
    )
    result = sg.check_coverage([group], "ingress", "10.0.1.5", "8443", "tcp")
    assert not result.allowed
    assert result.port_mismatch


def test_coverage_needs_every_part_of_a_range():
    group = _group("IpPermissionsEgress", IpProtocol="-1", IpRanges=[{"CidrIp": "10.0.0.0/25"}])
    result = sg.check_coverage([group], "egress", "10.0.0.0/24", "443", "tcp")
    assert not result.allowed
    assert result.uncovered == ["10.0.0.128/25"]


def test_no_rules_is_reported():
    assert sg.check_coverage([{"GroupId": "sg-1"}], "ingress", "10.0.0.1", "443", "tcp").no_rules


def test_sg_reference():
    group = _group(
        "IpPermissionsEgress",
        IpProtocol="tcp",
        FromPort=3306,
        ToPort=3306,
        UserIdGroupPairs=[{"GroupId": "sg-db"}],
    )
    assert sg.sg_reference_allows([group], "egress", ["sg-db"], "3306", "tcp")
    assert not sg.sg_reference_allows([group], "egress", ["sg-other"], "3306", "tcp")


def test_route_prefers_longest_prefix_and_skips_blackholes():
    table = {
        "RouteTableId": "rtb-1",
        "Routes": [
            {"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1"},
            {"DestinationCidrBlock": "10.1.0.0/16", "VpcPeeringConnectionId": "pcx-1"},
            {"DestinationCidrBlock": "10.1.1.0/24", "State": "blackhole", "GatewayId": "x"},
        ],
    }
    result = route.evaluate(table, "10.1.1.5")
    assert result.ok
    assert route.next_hop(result.routes[0]) == "pcx-1"


def test_route_missing():
    assert not route.evaluate(
        {"RouteTableId": "r", "Routes": [{"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local"}]},
        "203.0.113.5",
    ).ok
    assert not route.evaluate(None, "203.0.113.5").ok
