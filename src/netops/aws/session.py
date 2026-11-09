"""Clients per account profile. TLS verification is always on; a private CA goes in ca_bundle."""

from __future__ import annotations

import configparser
from pathlib import Path
from typing import Any

import boto3
from botocore.config import Config

from netops.config import Settings


class SessionFactory:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._clients: dict[tuple[str, str], Any] = {}

    def accounts(self) -> list[str]:
        parser = configparser.ConfigParser()
        parser.read(Path(self.settings.credentials_path).expanduser(), encoding="utf-8")
        return [name for name in parser.sections() if name != "default"]

    def _session(self, account: str) -> Any:
        return boto3.Session(profile_name=account, region_name=self.settings.region)

    def _client_config(self) -> Config:
        proxy = self.settings.proxy
        return Config(proxies={"http": proxy, "https": proxy}) if proxy else Config()

    def client(self, service: str, account: str) -> Any:
        key = (service, account)
        if key not in self._clients:
            verify = self.settings.ca_bundle or True
            self._clients[key] = self._session(account).client(
                service, config=self._client_config(), verify=verify
            )
        return self._clients[key]
