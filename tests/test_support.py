import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from netops import collect
from netops.auth import sso
from netops.aws.session import SessionFactory
from netops.config import Settings, from_mapping
from netops.flowlog import athena


def test_tls_verification_is_on_by_default(monkeypatch):
    session = MagicMock()
    factory = SessionFactory(Settings())
    monkeypatch.setattr(factory, "_session", lambda account: session)
    factory.client("ec2", "svc-a-dev")
    assert session.client.call_args.kwargs["verify"] is True


def test_ca_bundle_replaces_the_default(monkeypatch):
    session = MagicMock()
    factory = SessionFactory(Settings(ca_bundle="corp-ca.pem"))
    monkeypatch.setattr(factory, "_session", lambda account: session)
    factory.client("ec2", "svc-a-dev")
    assert session.client.call_args.kwargs["verify"] == "corp-ca.pem"


def test_no_setting_can_disable_tls():
    with pytest.raises(ValueError, match="Unknown settings"):
        from_mapping({"verify": False})


def test_accounts_come_from_the_credentials_file(tmp_path):
    path = tmp_path / "credentials"
    path.write_text("[default]\nx=1\n[svc-a-dev]\nx=1\n[svc-b-prd]\nx=1\n")
    assert SessionFactory(Settings(credentials_path=str(path))).accounts() == ["svc-a-dev", "svc-b-prd"]


def test_output_name_has_no_organization_in_it():
    assert collect.output_name("aws", "ec2", datetime(2026, 1, 2)) == "aws_ec2_inventory_20260102.xlsx"
    assert collect.output_name("team", "sg", datetime(2026, 1, 2)) == "team_sg_inventory_20260102.xlsx"


@pytest.mark.parametrize(("value", "minutes"), [("30", 30), ("30m", 30), ("2h", 120), ("1d", 1440)])
def test_parse_interval(value, minutes):
    assert athena.parse_interval(value) == minutes


def test_parse_interval_rejects_garbage():
    with pytest.raises(ValueError, match="Invalid interval"):
        athena.parse_interval("soon")


def test_query_rejects_injection():
    with pytest.raises(ValueError, match="table"):
        athena.build_query("flow; DROP", "db", "10.0.0.1", 60)
    with pytest.raises(ValueError, match="IPv4"):
        athena.build_query("flow", "db", "10.0.0.1' OR '1'='1", 60)


def test_query_uses_the_time_window():
    query = athena.build_query("flow", "db", "10.0.0.1", 60, datetime(2026, 1, 1, 1, tzinfo=UTC))
    assert f"start > {int(datetime(2026, 1, 1, tzinfo=UTC).timestamp())}" in query
    assert "db.flow" in query


def test_query_athena_maps_rows():
    client = MagicMock()
    client.start_query_execution.return_value = {"QueryExecutionId": "1"}
    client.get_query_execution.return_value = {"QueryExecution": {"Status": {"State": "SUCCEEDED"}}}
    client.get_query_results.return_value = {
        "ResultSet": {
            "Rows": [{"Data": [{"VarCharValue": "srcaddr"}]}, {"Data": [{"VarCharValue": "10.0.0.1"}]}]
        }
    }
    assert athena.query_athena(client, "q", "db", "s3://x/") == [{"srcaddr": "10.0.0.1"}]


def test_query_athena_raises_on_failure():
    client = MagicMock()
    client.start_query_execution.return_value = {"QueryExecutionId": "1"}
    client.get_query_execution.return_value = {"QueryExecution": {"Status": {"State": "FAILED"}}}
    with pytest.raises(RuntimeError, match="FAILED"):
        athena.query_athena(client, "q", "db", "s3://x/")


def _credentials(expiration):
    return {"accessKeyId": "a", "secretAccessKey": "b", "sessionToken": "c", "expiration": expiration}


def test_credentials_are_written_with_owner_only_permissions(tmp_path):
    path = tmp_path / "aws" / "credentials"
    sso.write_credentials(path, {"svc-a-dev": _credentials(2_000_000_000_000)})
    assert oct(Path(path).stat().st_mode)[-3:] == "600"
    assert "[svc-a-dev]" in path.read_text()
    assert json.loads(path.with_name("credentials_expiry.json").read_text())["expires_at"] == 2_000_000_000


def test_expiry_margin(tmp_path):
    path = tmp_path / "credentials"
    assert sso.is_expiring(path)
    now = datetime(2026, 1, 1, tzinfo=UTC)
    path.with_name("credentials_expiry.json").write_text(json.dumps({"expires_at": now.timestamp() + 600}))
    assert sso.is_expiring(path, now)
    path.with_name("credentials_expiry.json").write_text(json.dumps({"expires_at": now.timestamp() + 3600}))
    assert not sso.is_expiring(path, now)


def test_fetch_credentials_uses_account_names():
    client = MagicMock()
    client.get_paginator.return_value.paginate.return_value = [
        {"accountList": [{"accountId": "1", "accountName": "svc-a-dev"}]}
    ]
    client.get_role_credentials.return_value = {"roleCredentials": _credentials(1)}
    assert list(sso.fetch_credentials(client, "token", "ReadOnly")) == ["svc-a-dev"]
