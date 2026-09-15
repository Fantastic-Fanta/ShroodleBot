from __future__ import annotations

import asyncio
import logging
import os
import re
import shlex
import signal
import tempfile
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from config import get

logger = logging.getLogger("shroodler-bot.sherlock")

OnLine = Callable[[str], Awaitable[None]]

# Usernames Sherlock can meaningfully look up. Deliberately permissive (sites
# allow a wide range) but bounded so nothing weird reaches argv or a URL.
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._@+-]{1,100}$")
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
# Sherlock prints found accounts as: "[+] SiteName: https://..."
_FOUND_RE = re.compile(r"^\[\+\]\s*(?P<site>[^:]+):\s*(?P<url>\S+)")

MAX_USERNAMES = 5


def parse_usernames(raw: str) -> tuple[list[str], list[str]]:
    """Split the free-text argument into (valid, rejected) usernames.

    Accepts whitespace- and/or comma-separated usernames, de-duplicated while
    preserving order.
    """
    valid: list[str] = []
    rejected: list[str] = []
    seen: set[str] = set()
    for token in re.split(r"[\s,]+", raw.strip()):
        if not token:
            continue
        if token in seen:
            continue
        seen.add(token)
        if _USERNAME_RE.match(token):
            valid.append(token)
        else:
            rejected.append(token)
    return valid, rejected


@dataclass
class SherlockResult:
    username: str
    status: str = "pending"  # done | error | timeout | cancelled | missing
    found: list[tuple[str, str]] = field(default_factory=list)
    error_reason: str | None = None
    stderr_tail: list[str] = field(default_factory=list)
    returncode: int | None = None

    @property
    def count(self) -> int:
        return len(self.found)


async def run(
    username: str,
    *,
    on_line: OnLine | None = None,
) -> SherlockResult:
    """Run Sherlock for a single username and collect the accounts it finds."""
    cfg = get()
    result = SherlockResult(username=username)
    extra = shlex.split(cfg.sherlock_extra_flags) if cfg.sherlock_extra_flags else []
    cmd = [cfg.sherlock_bin, *extra, username]
    env = os.environ.copy()
    env.setdefault("PYTHONUNBUFFERED", "1")

    logger.info("Sherlock lookup for %r: %s", username, cmd)
    # Sherlock may drop a "<username>.txt" report in the working directory; run
    # inside a throwaway dir so it never litters the project.
    with tempfile.TemporaryDirectory(prefix="sherlock-") as workdir:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                cwd=workdir,
                env=env,
            )
        except FileNotFoundError:
            result.status = "missing"
            result.error_reason = f"sherlock binary not found: {cfg.sherlock_bin}"
            logger.error(result.error_reason)
            return result

        tail: list[str] = []
        try:
            await asyncio.wait_for(
                _pump(proc, result, tail, on_line),
                timeout=cfg.sherlock_timeout_seconds,
            )
            await proc.wait()
        except asyncio.TimeoutError:
            result.status = "timeout"
            result.error_reason = (
                f"timed out after {cfg.sherlock_timeout_seconds / 60:g}m"
            )
            await _terminate(proc)
            result.stderr_tail = tail[-20:]
            return result
        except asyncio.CancelledError:
            result.status = "cancelled"
            await _terminate(proc)
            raise
        finally:
            result.stderr_tail = tail[-20:]

    result.returncode = proc.returncode
    if result.status == "pending":
        if proc.returncode not in (0, None):
            result.status = "error"
            result.error_reason = tail[-1][:200] if tail else "sherlock exited non-zero"
        else:
            result.status = "done"
    return result


async def _pump(
    proc: asyncio.subprocess.Process,
    result: SherlockResult,
    tail: list[str],
    on_line: OnLine | None,
) -> None:
    assert proc.stdout is not None
    while True:
        raw = await proc.stdout.readline()
        if not raw:
            break
        line = _ANSI_RE.sub("", raw.decode("utf-8", errors="replace")).rstrip("\r\n")
        if not line:
            continue
        tail.append(line)
        match = _FOUND_RE.match(line.strip())
        if match:
            site = match.group("site").strip()
            url = match.group("url").strip()
            result.found.append((site, url))
        if on_line is not None:
            try:
                await on_line(line)
            except Exception:
                logger.exception("sherlock on_line callback failed")


async def _terminate(proc: asyncio.subprocess.Process) -> None:
    if proc.returncode is not None:
        return
    try:
        proc.send_signal(signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        await asyncio.wait_for(proc.wait(), timeout=5)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            return
        await proc.wait()
