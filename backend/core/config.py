"""Application settings.

Values are read from environment variables (prefix ``NETGUARD_``) with
sensible defaults for local prototype development. No extra settings
library is used to keep dependencies minimal.
"""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = PROJECT_ROOT / "backend"
FRONTEND_DIR = PROJECT_ROOT / "frontend"
DATA_DIR = Path(os.getenv("NETGUARD_DATA_DIR") or PROJECT_ROOT / "data")


def _load_secret_key() -> str:
    """Use NETGUARD_SECRET_KEY if set, otherwise a key persisted in data/.

    Persisting the generated key means login tokens survive a server restart.
    """
    env_key = os.getenv("NETGUARD_SECRET_KEY")
    if env_key:
        return env_key
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    key_file = DATA_DIR / ".secret_key"
    if key_file.exists():
        return key_file.read_text(encoding="utf-8").strip()
    key = secrets.token_urlsafe(48)
    key_file.write_text(key, encoding="utf-8")
    return key


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    app_name: str = "NetGuard"
    database_url: str = field(
        default_factory=lambda: os.getenv(
            "NETGUARD_DATABASE_URL", f"sqlite:///{(DATA_DIR / 'netguard.db').as_posix()}"
        )
    )
    secret_key: str = field(default_factory=_load_secret_key)
    token_expire_minutes: int = field(
        default_factory=lambda: int(os.getenv("NETGUARD_TOKEN_EXPIRE_MINUTES", "480"))
    )
    # Only needed when the frontend is served from a different origin
    # (e.g. VS Code Live Server). The bundled frontend is same-origin.
    cors_origins: list[str] = field(default_factory=lambda: _split_csv(os.getenv("NETGUARD_CORS_ORIGINS", "")))
    # Host headers accepted by the local service (DNS-rebinding protection). The port is checked separately.
    allowed_hosts: list[str] = field(
        default_factory=lambda: _split_csv(os.getenv("NETGUARD_ALLOWED_HOSTS", "127.0.0.1,localhost,testserver"))
    )
    # Set by the desktop launcher for each start; when set, browser access needs the web-access setting.
    desktop_key: str | None = field(default_factory=lambda: os.getenv("NETGUARD_DESKTOP_KEY") or None)
    settings_file: str = field(default_factory=lambda: os.getenv("NETGUARD_SETTINGS_FILE", str(DATA_DIR / "settings.json")))
    default_username: str = field(default_factory=lambda: os.getenv("NETGUARD_DEFAULT_USER", "admin"))
    default_password: str = field(
        default_factory=lambda: os.getenv("NETGUARD_DEFAULT_PASSWORD", "admin")
    )
    # The built-in account manages the Account Center, so its role says so.
    default_role: str = "Administrators"


@lru_cache
def get_settings() -> Settings:
    return Settings()
