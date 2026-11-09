"""Sign in once with IAM Identity Center and write short-lived credentials for every account."""

from __future__ import annotations

import configparser
import json
import os
import platform
import subprocess
import time
import webbrowser
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import boto3

from netops.config import Settings

REFRESH_SECONDS = 600
EXPIRY_MARGIN_SECONDS = 900


def notify(title: str, message: str) -> None:
    print(f"[{title}] {message}")
    if platform.system() != "Windows":
        return
    script = (
        "Add-Type -AssemblyName System.Windows.Forms;$n=New-Object System.Windows.Forms.NotifyIcon;"
        "$n.Icon=[System.Drawing.SystemIcons]::Information;$n.Visible=$true;"
        "$n.ShowBalloonTip(8000,$env:NOTIFY_TITLE,$env:NOTIFY_TEXT,'Info');Start-Sleep 9;$n.Dispose()"
    )
    env = {**os.environ, "NOTIFY_TITLE": title, "NOTIFY_TEXT": message}
    subprocess.Popen(["powershell", "-NoProfile", "-Command", script], env=env)  # noqa: S603, S607


def device_login(oidc: Any, settings: Settings, open_browser: bool = True) -> str:
    client = oidc.register_client(clientName=settings.sso_client_name, clientType="public")
    auth = oidc.start_device_authorization(
        clientId=client["clientId"], clientSecret=client["clientSecret"], startUrl=settings.sso_start_url
    )
    print(f"Open {auth['verificationUriComplete']} and approve the request.")
    if open_browser:
        webbrowser.open(auth["verificationUriComplete"])
    interval = auth.get("interval", 5)
    while True:
        time.sleep(interval)
        try:
            return oidc.create_token(
                clientId=client["clientId"],
                clientSecret=client["clientSecret"],
                grantType="urn:ietf:params:oauth:grant-type:device_code",
                deviceCode=auth["deviceCode"],
            )["accessToken"]
        except oidc.exceptions.AuthorizationPendingException:
            continue
        except oidc.exceptions.SlowDownException:
            interval += 5


def fetch_credentials(sso: Any, access_token: str, role_name: str) -> dict[str, dict[str, Any]]:
    """Profile names come from the account names in Identity Center."""
    profiles: dict[str, dict[str, Any]] = {}
    for page in sso.get_paginator("list_accounts").paginate(accessToken=access_token):
        for account in page["accountList"]:
            credentials = sso.get_role_credentials(
                accessToken=access_token, accountId=account["accountId"], roleName=role_name
            )["roleCredentials"]
            profiles[account["accountName"]] = credentials
    return profiles


def write_credentials(path: Path, profiles: dict[str, dict[str, Any]]) -> None:
    parser = configparser.ConfigParser()
    for name, credentials in profiles.items():
        parser[name] = {
            "aws_access_key_id": credentials["accessKeyId"],
            "aws_secret_access_key": credentials["secretAccessKey"],
            "aws_session_token": credentials["sessionToken"],
        }
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        parser.write(handle)
    expiry = min(c["expiration"] for c in profiles.values()) / 1000
    path.with_name("credentials_expiry.json").write_text(json.dumps({"expires_at": expiry}), encoding="utf-8")


def is_expiring(path: Path, now: datetime | None = None) -> bool:
    marker = path.with_name("credentials_expiry.json")
    if not marker.exists():
        return True
    current = (now or datetime.now(UTC)).timestamp()
    return json.loads(marker.read_text(encoding="utf-8"))["expires_at"] - current < EXPIRY_MARGIN_SECONDS


def run(settings: Settings, role_name: str, keep_alive: bool = True) -> None:
    oidc = boto3.client("sso-oidc", region_name=settings.sso_region)
    sso = boto3.client("sso", region_name=settings.sso_region)
    path = Path(settings.credentials_path).expanduser()
    token = device_login(oidc, settings)
    write_credentials(path, fetch_credentials(sso, token, role_name))
    notify("netops", "Credentials are ready.")
    while keep_alive:
        time.sleep(REFRESH_SECONDS)
        if not is_expiring(path):
            continue
        try:
            write_credentials(path, fetch_credentials(sso, token, role_name))
            notify("netops", "Credentials refreshed.")
        except sso.exceptions.UnauthorizedException:
            notify("netops", "Sign-in expired. Please approve again.")
            token = device_login(oidc, settings)
