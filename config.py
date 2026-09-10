from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


@dataclass(frozen=True)
class Config:
    discord_token: str
    discord_guild_id: int
    shroodler_bin: str
    shroodler_extra_flags: str
    max_concurrent_scans: int
    scan_timeout_seconds: int
    report_dir: Path
    sessions_dir: Path
    llm_provider: str   # "anthropic" | "deepseek"
    llm_model: str      # empty = provider default


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


def resolve_shroodler_bin(configured: str) -> str:
    """Locate the shroodler executable, including ~/.local/bin if it is not on PATH."""
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


def load() -> Config:
    global _config
    load_dotenv()
    report_raw = os.getenv("REPORT_DIR", "/tmp/shroodler-bot-reports").strip()
    report_dir = Path(report_raw or "/tmp/shroodler-bot-reports")
    sessions_raw = os.getenv("SESSIONS_DIR", "").strip()
    sessions_dir = Path(sessions_raw).expanduser() if sessions_raw else Path.home() / ".shroodler" / "bot-sessions"
    raw_bin = os.getenv("SHROODLER_BIN", "shroodler").strip() or "shroodler"
    llm_provider = os.getenv("LLM_PROVIDER", "anthropic").strip().lower() or "anthropic"
    if llm_provider not in ("anthropic", "deepseek"):
        raise SystemExit(f"LLM_PROVIDER must be 'anthropic' or 'deepseek', got {llm_provider!r}")
    cfg = Config(
        discord_token=_require("DISCORD_TOKEN"),
        discord_guild_id=_require_int("DISCORD_GUILD_ID"),
        shroodler_bin=resolve_shroodler_bin(raw_bin),
        shroodler_extra_flags=os.getenv("SHROODLER_EXTRA_FLAGS", "").strip(),
        max_concurrent_scans=_optional_int("MAX_CONCURRENT_SCANS", 2),
        scan_timeout_seconds=_optional_int("SCAN_TIMEOUT_SECONDS", 1800),
        report_dir=report_dir,
        sessions_dir=sessions_dir,
        llm_provider=llm_provider,
        llm_model=os.getenv("LLM_MODEL", "").strip(),
    )
    if cfg.max_concurrent_scans < 1:
        raise SystemExit("MAX_CONCURRENT_SCANS must be >= 1")
    if cfg.scan_timeout_seconds < 1:
        raise SystemExit("SCAN_TIMEOUT_SECONDS must be >= 1")
    report_dir.mkdir(parents=True, exist_ok=True)
    sessions_dir.mkdir(parents=True, exist_ok=True)
    _config = cfg
    return cfg


def get() -> Config:
    if _config is None:
        return load()
    return _config
