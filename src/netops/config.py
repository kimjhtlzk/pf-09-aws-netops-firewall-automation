"""Settings from YAML and environment variables. Credentials stay in the standard AWS location."""

from __future__ import annotations

import os
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class Settings:
    region: str = "ap-northeast-2"
    proxy: str = ""
    ca_bundle: str = ""
    workspace: str = "workspace"
    output_prefix: str = "aws"
    credentials_path: str = "~/.aws/credentials"
    sso_start_url: str = "https://<your-sso-portal>.awsapps.com/start"
    sso_region: str = "ap-northeast-2"
    sso_client_name: str = "aws-netops-firewall-automation"
    log_archive_profile: str = "log-archive"
    athena_database: str = "vpc_flow_logs"
    athena_output_location: str = "s3://example-log-archive-bucket/athena-results/"
    common_patterns: tuple[str, ...] = ("comm", "common")
    sg_max_rules: int = 60

    @property
    def workspace_path(self) -> Path:
        path = Path(self.workspace).expanduser()
        path.mkdir(parents=True, exist_ok=True)
        return path


ENV_OVERRIDES = {"proxy": "NETOPS_PROXY", "ca_bundle": "NETOPS_CA_BUNDLE", "region": "NETOPS_REGION"}


def from_mapping(raw: dict[str, Any]) -> Settings:
    known = {f.name for f in fields(Settings)}
    unknown = set(raw) - known
    if unknown:
        raise ValueError(f"Unknown settings: {', '.join(sorted(unknown))}")
    values = dict(raw)
    if "common_patterns" in values:
        values["common_patterns"] = tuple(values["common_patterns"])
    for name, env in ENV_OVERRIDES.items():
        if os.environ.get(env):
            values[name] = os.environ[env]
    return Settings(**values)


def load(path: str | Path | None) -> Settings:
    if path is None:
        return from_mapping({})
    return from_mapping(yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {})
