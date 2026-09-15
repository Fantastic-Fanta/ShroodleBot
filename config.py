from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


@dataclass(frozen=True)
class Config:
    discord_token: str
    discord_guild_id: int  # 0 = no home guild (user-installed app only)
    authorized_user_ids: frozenset[int]  # allowlist for DM / user-install use
    shroodler_bin: str
    shroodler_extra_flags: str
    sherlock_bin: str
    sherlock_extra_flags: str
    sherlock_timeout_seconds: int
    max_concurrent_scans: int
    scan_timeout_seconds: int
    report_dir: Path
    sessions_dir: Path
    llm_provider: str   # "anthropic" | "deepseek"
    llm_model: str      # empty = provider default
    llm_agent: bool     # drive scans with the LLM agent loop (streams reasoning)


_config: Config | None = None


def _require(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise SystemExit(f"Missing required environment variable: {name}")
    return value


def _require_int(name: str) -> int:
    raw = _require(name)
    try:
        return int(raw)
    except ValueError:
        raise SystemExit(f"{name} must be an integer, got {raw!r}") from None


def _optional_int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        raise SystemExit(f"{name} must be an integer, got {raw!r}") from None


def _id_set(name: str) -> frozenset[int]:
    raw = os.getenv(name, "").strip()
    if not raw:
        return frozenset()
    ids: set[int] = set()
    for part in raw.replace(";", ",").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            ids.add(int(part))
        except ValueError:
            raise SystemExit(f"{name} must be comma-separated integers, got {part!r}") from None
    return frozenset(ids)


def resolve_binary(configured: str) -> str:
    """Locate an executable, including ~/.local/bin if it is not on PATH."""
    found = shutil.which(configured)
    if found:
        return found
    candidate = Path(configured).expanduser()
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return str(candidate.resolve())
    local = Path.home() / ".local" / "bin" / Path(configured).name
    if local.is_file() and os.access(local, os.X_OK):
        return str(local.resolve())
    return configured


# Backwards-compatible alias.
resolve_shroodler_bin = resolve_binary


def load() -> Config:
    global _config
    load_dotenv()
    report_raw = os.getenv("REPORT_DIR", "/tmp/shroodler-bot-reports").strip()
    report_dir = Path(report_raw or "/tmp/shroodler-bot-reports")
    sessions_raw = os.getenv("SESSIONS_DIR", "").strip()
    sessions_dir = Path(sessions_raw).expanduser() if sessions_raw else Path.home() / ".shroodler" / "bot-sessions"
    raw_bin = os.getenv("SHROODLER_BIN", "shroodler").strip() or "shroodler"
    raw_sherlock_bin = os.getenv("SHERLOCK_BIN", "sherlock").strip() or "sherlock"
    llm_provider = os.getenv("LLM_PROVIDER", "anthropic").strip().lower() or "anthropic"
    if llm_provider not in ("anthropic", "deepseek"):
        raise SystemExit(f"LLM_PROVIDER must be 'anthropic' or 'deepseek', got {llm_provider!r}")
    cfg = Config(
        discord_token=_require("DISCORD_TOKEN"),
        discord_guild_id=_optional_int("DISCORD_GUILD_ID", 0),
        authorized_user_ids=_id_set("AUTHORIZED_USER_IDS"),
        shroodler_bin=resolve_binary(raw_bin),
        shroodler_extra_flags=os.getenv("SHROODLER_EXTRA_FLAGS", "").strip(),
        sherlock_bin=resolve_binary(raw_sherlock_bin),
        sherlock_extra_flags=os.getenv("SHERLOCK_EXTRA_FLAGS", "").strip(),
        sherlock_timeout_seconds=_optional_int("SHERLOCK_TIMEOUT_SECONDS", 300),
        max_concurrent_scans=_optional_int("MAX_CONCURRENT_SCANS", 2),
        scan_timeout_seconds=_optional_int("SCAN_TIMEOUT_SECONDS", 1800),
        report_dir=report_dir,
        sessions_dir=sessions_dir,
        llm_provider=llm_provider,
        llm_model=os.getenv("LLM_MODEL", "").strip(),
        llm_agent=os.getenv("LLM_AGENT", "true").strip().lower() not in ("false", "0", "no", "off"),
    )
    if not cfg.discord_guild_id and not cfg.authorized_user_ids:
        raise SystemExit(
            "Set DISCORD_GUILD_ID (server members are authorized) and/or "
            "AUTHORIZED_USER_IDS (comma-separated user IDs for DM / user-install "
            "use). At least one is required so the scanner is not open to anyone."
        )
    if cfg.max_concurrent_scans < 1:
        raise SystemExit("MAX_CONCURRENT_SCANS must be >= 1")
    if cfg.scan_timeout_seconds < 1:
        raise SystemExit("SCAN_TIMEOUT_SECONDS must be >= 1")
    if cfg.sherlock_timeout_seconds < 1:
        raise SystemExit("SHERLOCK_TIMEOUT_SECONDS must be >= 1")
    report_dir.mkdir(parents=True, exist_ok=True)
    sessions_dir.mkdir(parents=True, exist_ok=True)
    _config = cfg
    return cfg


def get() -> Config:
    if _config is None:
        return load()
    return _config
