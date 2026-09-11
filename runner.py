from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shlex
import signal
import uuid
from asyncio.subprocess import Process
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable
from urllib.parse import urlparse

from config import get

logger = logging.getLogger("shroodler-bot.runner")

OnLine = Callable[[str], Awaitable[None]]


def hostname_from_url(url: str) -> str:
    host = urlparse(url).hostname
    if not host:
        return "target"
    return host.rstrip(".").lower()


def parse_finding_line(line: str) -> dict[str, Any] | None:
    stripped = line.strip()
    if not stripped:
        return None

    if stripped.startswith("{") and stripped.endswith("}"):
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            return None
        if not isinstance(data, dict):
            return None
        if "action" in data:
            return None
        type_val = str(data.get("type", "")).lower()
        if type_val == "finding" or ("severity" in data and ("id" in data or "finding_id" in data)):
            return _finding_from_mapping(data, stripped)
        return None

    if "[FINDING]" in stripped.upper():
        return _finding_from_text(stripped)
    return None


def _finding_from_mapping(data: dict[str, Any], raw: str) -> dict[str, Any]:
    finding_id = (
        data.get("id")
        or data.get("finding_id")
        or data.get("identifier")
        or data.get("title")
        or data.get("name")
        or "unknown"
    )
    severity = data.get("severity") or data.get("sev") or data.get("level") or "info"
    return {
        "id": str(finding_id),
        "severity": str(severity).lower(),
        "raw": raw,
    }


def _finding_from_text(raw: str) -> dict[str, Any]:
    severity = "info"
    bracket = re.search(r"\[(critical|high|medium|low|info|informational)\]", raw, re.I)
    word = re.search(r"\b(critical|high|medium|low|info|informational)\b", raw, re.I)
    if bracket:
        severity = bracket.group(1).lower()
    elif word:
        severity = word.group(1).lower()

    finding_id = "unknown"
    id_match = re.search(
        r"\b(?:id|finding[_-]?id)[=:\s]+([A-Za-z0-9_.-]+)",
        raw,
        re.I,
    )
    tagged = re.search(r"\[FINDING\]\s*\[?[A-Za-z0-9_.-]*\]?\s*([A-Za-z0-9_.-]+)", raw, re.I)
    if id_match:
        finding_id = id_match.group(1)
    elif tagged:
        candidate = tagged.group(1)
        if candidate.lower() not in {"critical", "high", "medium", "low", "info"}:
            finding_id = candidate

    return {"id": finding_id, "severity": severity, "raw": raw}


@dataclass
class ShroodlerJob:
    job_id: str
    target: str
    profile: str
    started_at: datetime
    state_file: Path
    report_file: Path
    log_file: Path
    thread_id: int
    user_id: int
    hostname: str
    guild_id: int = 0
    channel_id: int = 0
    message_id: int = 0
    process: Process | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    status: str = "pending"
    stderr_tail: deque[str] = field(default_factory=lambda: deque(maxlen=20))
    timed_out: bool = False
    returncode: int | None = None
    error_reason: str | None = None
    login_recipe: Path | None = None
    peer_recipe: Path | None = None
    owner_jar: Path | None = None
    peer_jar: Path | None = None
    owner_cookie: str | None = None
    peer_cookie: str | None = None
    auth_label: str = "unauthenticated"

    @property
    def has_auth(self) -> bool:
        return any(
            [
                self.login_recipe,
                self.peer_recipe,
                self.owner_jar,
                self.peer_jar,
                self.owner_cookie,
                self.peer_cookie,
            ]
        )

    @property
    def live_thread_id(self) -> int | None:
        return self.thread_id or None

    @classmethod
    def create(
        cls,
        *,
        target: str,
        profile: str,
        user_id: int,
        report_dir: Path,
        thread_id: int = 0,
        guild_id: int = 0,
        channel_id: int = 0,
        message_id: int = 0,
    ) -> ShroodlerJob:
        job_id = uuid.uuid4().hex[:8]
        job_dir = report_dir / job_id
        job_dir.mkdir(parents=True, exist_ok=True)
        return cls(
            job_id=job_id,
            target=target,
            profile=profile,
            started_at=datetime.now(timezone.utc),
            state_file=Path.home() / ".shroodler" / "programs" / job_id / "state.json",
            report_file=job_dir / "report.md",
            log_file=job_dir / "debug.log",
            thread_id=thread_id,
            user_id=user_id,
            hostname=hostname_from_url(target),
            guild_id=guild_id,
            channel_id=channel_id,
            message_id=message_id,
            status="pending",
        )


_PROFILE_ITERATIONS = {"safe": 5, "balanced": 10, "aggressive": 20}


def _agent_command(job: ShroodlerJob) -> list[str]:
    cfg = get()
    max_iter = _PROFILE_ITERATIONS.get(job.profile, 10)
    extra = shlex.split(cfg.shroodler_extra_flags) if cfg.shroodler_extra_flags else []
    cmd = [
        cfg.shroodler_bin,
        "--debug",
        "agent",
        "--target",
        job.target,
        "--program",
        job.job_id,
        "--max-iterations",
        str(max_iter),
        "--run-probes",
        "--llm-business-logic",
        "--ignore-robots",
    ]
    if job.profile != "aggressive":
        cmd.append("--no-time-sqli")
    else:
        cmd.append("--aggressive")
    cmd += ["--llm-provider", cfg.llm_provider]
    if cfg.llm_model:
        cmd += ["--llm-model", cfg.llm_model]
    if getattr(cfg, "llm_agent", False):
        # Drive the scan with the LLM agent loop so its per-iteration
        # reasoning streams to the Discord thread.
        cmd.append("--llm-agent")
    if "--allow-external" not in extra:
        cmd.append("--allow-external")
    if job.login_recipe is not None:
        cmd += ["--login-recipe", str(job.login_recipe)]
    if job.peer_recipe is not None:
        cmd += ["--peer-recipe", str(job.peer_recipe)]
    if job.owner_jar is not None:
        cmd += ["--higher-priv-jar", str(job.owner_jar)]
    if job.peer_jar is not None:
        cmd += ["--lower-priv-jar", str(job.peer_jar)]
    if job.owner_cookie:
        cmd += ["--owner-cookie", job.owner_cookie]
    if job.peer_cookie:
        cmd += ["--peer-cookie", job.peer_cookie]
    cmd.extend(extra)
    return cmd


def _redact_cmd(cmd: list[str]) -> list[str]:
    secret_flags = {"--owner-cookie", "--peer-cookie"}
    out: list[str] = []
    hide_next = False
    for part in cmd:
        if hide_next:
            out.append("<redacted>")
            hide_next = False
            continue
        if part in secret_flags:
            hide_next = True
        out.append(part)
    return out


def _write_log_header(job: ShroodlerJob, cmd: list[str]) -> None:
    lines = [
        f"target: {job.target}",
        f"profile: {job.profile}",
        f"job: {job.job_id}",
        f"started: {job.started_at.isoformat()}",
        f"command: {shlex.join(_redact_cmd(cmd))}",
        "---",
        "",
    ]
    job.log_file.parent.mkdir(parents=True, exist_ok=True)
    job.log_file.write_text("\n".join(lines), encoding="utf-8")


def _append_log(job: ShroodlerJob, text: str) -> None:
    if not text:
        return
    try:
        with job.log_file.open("a", encoding="utf-8") as handle:
            handle.write(text if text.endswith("\n") else text + "\n")
    except OSError:
        logger.exception("Failed to append debug log for job %s", job.job_id)


def _append_state_trace(job: ShroodlerJob) -> None:
    if not job.state_file.is_file():
        return
    try:
        data = json.loads(job.state_file.read_text(encoding="utf-8"))
    except Exception:
        return
    history = data.get("run_history") or []
    findings = [item for item in (data.get("findings") or []) if isinstance(item, dict)]
    _append_log(job, "--- run_history ---")
    if history:
        _append_log(job, json.dumps(history, indent=2, default=str))
    else:
        _append_log(job, "(empty)")
    _append_log(job, f"--- findings ({len(findings)}) ---")
    for item in findings:
        fid = item.get("id") or "unknown"
        sev = item.get("severity") or "info"
        url = item.get("url") or ""
        _append_log(job, f"{sev}  {fid}  {url}")


async def start(job: ShroodlerJob, on_line: OnLine) -> None:
    if job.status == "cancelled":
        return

    cfg = get()
    job.status = "running"
    cmd = _agent_command(job)
    logger.info("Starting job %s: %s", job.job_id, _redact_cmd(cmd))
    env = os.environ.copy()
    env.setdefault("PYTHONUNBUFFERED", "1")
    _write_log_header(job, cmd)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=env,
        )
    except FileNotFoundError:
        if job.status != "cancelled":
            job.status = "error"
        msg = f"shroodler binary not found: {cfg.shroodler_bin}"
        job.error_reason = "shroodler binary not found"
        job.stderr_tail.append(msg)
        _append_log(job, msg)
        logger.error(msg)
        return

    job.process = proc
    if job.status == "cancelled":
        await cancel(job)
        return

    try:
        await _pump_output(job, proc, on_line)
        await proc.wait()
    except asyncio.CancelledError:
        await cancel(job)
        raise
    finally:
        _append_state_trace(job)

    if job.status == "cancelled":
        await _write_report(job)
        return

    job.returncode = proc.returncode
    if proc.returncode != 0:
        job.status = "error"
        tail = job.stderr_tail[-1] if job.stderr_tail else ""
        job.error_reason = (tail[:200] if tail else "Process exited with a non-zero status")
        logger.warning("Job %s exited with code %s", job.job_id, proc.returncode)
        _append_log(job, f"exit {proc.returncode}")
    else:
        job.status = "done"
        _append_log(job, "exit 0")

    await _write_report(job)


async def _pump_output(job: ShroodlerJob, proc: Process, on_line: OnLine) -> None:
    assert proc.stdout is not None
    while True:
        raw = await proc.stdout.readline()
        if not raw:
            break
        line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
        if not line:
            continue
        job.stderr_tail.append(line)
        _append_log(job, line)
        finding = parse_finding_line(line)
        if finding is not None:
            job.findings.append(finding)
        try:
            await on_line(line)
        except Exception:
            logger.exception("on_line callback failed for job %s", job.job_id)


def _reload_findings_from_state(job: ShroodlerJob) -> None:
    """Replace job.findings with the authoritative list from the state file."""
    if not job.state_file.is_file():
        return
    try:
        data = json.loads(job.state_file.read_text(encoding="utf-8"))
    except Exception:
        return
    raw = data.get("findings") or []
    job.findings = [f if isinstance(f, dict) else {} for f in raw]


async def _write_report(job: ShroodlerJob) -> None:
    if not job.state_file.is_file():
        logger.warning("No state file for job %s; skipping report", job.job_id)
        return

    cfg = get()
    cmd = [
        cfg.shroodler_bin,
        "report",
        str(job.state_file),
        "--format",
        "pentest",
        "--output",
        str(job.report_file),
    ]
    logger.info("Generating report for job %s", job.job_id)
    _append_log(job, "--- report ---")
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
    except FileNotFoundError:
        logger.error("shroodler binary not found while generating report")
        return

    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
    except asyncio.TimeoutError:
        logger.error("Report generation timed out for job %s", job.job_id)
        proc.kill()
        await proc.wait()
        return

    if proc.returncode != 0:
        extra = (stdout or b"").decode("utf-8", errors="replace").strip()
        logger.warning("Report command failed for job %s: %s", job.job_id, extra[-500:])
        if extra:
            _append_log(job, extra)
            for line in extra.splitlines()[-5:]:
                job.stderr_tail.append(line)
    elif stdout:
        text = stdout.decode("utf-8", errors="replace").strip()
        if text:
            _append_log(job, text)

    # Reload findings from the state file so the summary embed has accurate counts.
    _reload_findings_from_state(job)


async def cancel(job: ShroodlerJob) -> None:
    job.status = "cancelled"
    proc = job.process
    if proc is None or proc.returncode is not None:
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
    logger.info("Cancelled job %s", job.job_id)
    _append_log(job, "cancelled")
