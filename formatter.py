from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import discord

from runner import ShroodlerJob, parse_finding_line

logger = logging.getLogger("shroodler-bot.formatter")

_BLOCKED_HOSTS = frozenset({"localhost", "ip6-localhost", "ip6-loopback"})
_BLOCKED_SUFFIXES = (".localhost", ".local", ".internal")
_DNS_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_DISCORD_FILE_LIMIT = 24 * 1024 * 1024

# Keep in sync with shroodler.pentest_report — the bot does not import Shroodler.
_OBSERVATION_IDS = frozenset(
    {
        "missing-csp",
        "missing-hsts",
        "missing-x-frame-options",
        "missing-x-content-type-options",
        "missing-referrer-policy",
        "weak-csp",
        "weak-x-content-type-options",
        "short-hsts",
        "csp-wildcard-script",
        "csp-missing-frame-ancestors",
        "csp-report-only",
        "waf-challenge-detected",
        "waf-detected",
        "js-analysis-complete",
        "js-source-map-found",
        "admin-login-page-found",
        "openapi-spec-found",
        "graphql-endpoint-found",
        "server-version-leak",
        "x-powered-by",
        "generic-api-key",
        "ghost-route",
        "js-endpoint",
        "js-api-endpoint-found",
        "sri-missing",
        "waf-not-detected",
        "insecure-cookie",
        "cookie-not-httponly",
        "cookie-path-broad",
        "cookie-missing-host-prefix",
        "cookie-missing-secure-prefix",
        "cookie-samesite-none-without-secure",
        "cookie-domain-broad",
    }
)
_OBSERVATION_CATEGORIES = frozenset({"header", "waf-challenge", "cookie"})
_OBSERVATION_ID_PREFIXES = ("cookie-",)


def validate_target_url(url: str) -> str | None:
    candidate = url.strip()
    parsed = urlparse(candidate)
    if parsed.scheme not in ("http", "https"):
        return "Target must be a valid http:// or https:// URL."
    if parsed.username is not None or parsed.password is not None or "@" in (parsed.netloc or ""):
        return "Target URL must not contain userinfo (credentials before the host)."
    hostname = parsed.hostname
    if not hostname:
        return "Target URL must include a valid hostname."

    hostname_norm = hostname.rstrip(".").lower()
    if not hostname_norm:
        return "Target URL must include a valid hostname."
    if hostname_norm in _BLOCKED_HOSTS:
        return "Localhost and loopback targets are not allowed."
    if any(hostname_norm.endswith(suffix) for suffix in _BLOCKED_SUFFIXES):
        return "Targets on .local, .localhost, or .internal are not allowed."

    ip = _parse_ip(hostname_norm)
    if ip is not None:
        return _reject_ip(ip)

    if len(hostname_norm) > 253:
        return "Hostname is too long."
    labels = hostname_norm.split(".")
    if len(labels) < 2:
        return "Target hostname must be a fully-qualified domain name."
    if any(not _DNS_LABEL.match(label) for label in labels):
        return "Target hostname is not a valid DNS name."
    dotted = _reject_dotted_decimal(labels)
    if dotted is not None:
        return dotted
    return None


def _reject_dotted_decimal(labels: list[str]) -> str | None:
    if not labels or not all(label.isdigit() for label in labels):
        return None
    first = int(labels[0])
    second = int(labels[1]) if len(labels) > 1 else None
    if first == 127:
        return "Loopback addresses are not allowed."
    if first == 10:
        return "Private (RFC1918) addresses are not allowed."
    if first == 0:
        return "Unspecified addresses (0.0.0.0 / ::) are not allowed."
    if first == 169 and second == 254:
        return "Link-local addresses are not allowed."
    if first == 192 and second == 168:
        return "Private (RFC1918) addresses are not allowed."
    if first == 172 and second is not None and 16 <= second <= 31:
        return "Private (RFC1918) addresses are not allowed."
    return None


def _parse_ip(hostname: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _reject_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    if ip.is_loopback:
        return "Loopback addresses are not allowed."
    if ip.is_unspecified:
        return "Unspecified addresses (0.0.0.0 / ::) are not allowed."
    if ip.is_link_local:
        return "Link-local addresses are not allowed."
    if ip.is_private:
        return "Private (RFC1918) addresses are not allowed."
    if ip.is_multicast or ip.is_reserved:
        return "Reserved or multicast addresses are not allowed."
    return None


def hostname_from_url(url: str) -> str:
    host = urlparse(url).hostname
    if not host:
        return "target"
    return host.rstrip(".").lower()


def sanitize_hostname(hostname: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", hostname).strip("._")
    return cleaned or "target"


def build_thread_name(hostname: str) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
    name = f"Pentest: {hostname} - {timestamp}"
    if len(name) <= 100:
        return name
    reserved = len(f"Pentest:  - {timestamp}")
    clipped = hostname[: max(1, 100 - reserved)]
    return f"Pentest: {clipped} - {timestamp}"[:100]


def format_duration(started_at: datetime, ended_at: datetime | None = None) -> str:
    end = ended_at or datetime.now(timezone.utc)
    if started_at.tzinfo is None:
        started_at = started_at.replace(tzinfo=timezone.utc)
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    seconds = max(0, int((end - started_at).total_seconds()))
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m {secs}s"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def format_code_block(text: str, limit: int = 1900) -> str:
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return f"```\n{text}\n```"


def parse_agent_line(line: str) -> dict[str, Any] | None:
    stripped = line.strip()
    if not (stripped.startswith("{") and stripped.endswith("}")):
        return None
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    if "action" in data or ("iterations" in data and "state_path" in data):
        return data
    return None


_LIVE_FINDING_CAP = 8
_LIVE_URL_CAP = 6


def _live_finding_lines(items: list[Any]) -> list[str]:
    lines: list[str] = []
    for item in items[:_LIVE_FINDING_CAP]:
        if not isinstance(item, dict):
            continue
        sev = str(item.get("severity") or "info")
        fid = str(item.get("id") or "finding")
        url = str(item.get("url") or "").strip()
        if url:
            lines.append(f"- **{sev}** `{fid}` {url}")
        else:
            lines.append(f"- **{sev}** `{fid}`")
    extra = len(items) - _LIVE_FINDING_CAP
    if extra > 0:
        lines.append(f"- … {extra} more")
    return lines


def _live_url_lines(urls: list[Any], *, skip: set[str] | None = None) -> list[str]:
    skip = skip or set()
    filtered: list[str] = []
    seen: set[str] = set()
    for raw in urls:
        url = str(raw or "").strip()
        if not url or url in skip or url in seen:
            continue
        seen.add(url)
        filtered.append(url)
    lines = [f"- {url}" for url in filtered[:_LIVE_URL_CAP]]
    extra = len(filtered) - len(lines)
    if extra > 0:
        lines.append(f"- … {extra} more")
    return lines


def format_live_line(line: str) -> str:
    """Format a streamed line for Discord, surfacing the LLM's reasoning and
    warnings (fallbacks, verification) so the thread shows the agent reasoning
    its way through the target."""
    data = parse_agent_line(line)
    if data is None:
        warn = _format_warning_line(line)
        if warn is not None:
            return warn
        return _format_live_line_base(line)
    if data.get("action") == "llm-verify":
        warn = _format_warning_line(line)
        if warn is not None:
            return warn
    base = _format_live_line_base(line)
    reasoning = str(data.get("reasoning") or "").strip()
    if reasoning:
        base = f"{base}\n> reason: {reasoning[:400]}"
    return base


def _format_warning_line(line: str) -> str | None:
    """Surface fallback / verify / warning JSON lines for debug visibility."""
    stripped = line.strip()
    if not (stripped.startswith("{") and stripped.endswith("}")):
        return None
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    warn = data.get("warning")
    if warn == "llm-agent-fallback":
        return f"fallback: {data.get('reason', '')[:200]}"
    if warn:
        return f"{warn}: {str(data.get('reason', ''))[:200]}"
    if data.get("action") == "llm-verify" and isinstance(data.get("result"), dict):
        r = data["result"]
        return (
            f"verified {r.get('verified', 0)} findings, "
            f"{r.get('confirmed', 0)} confirmed, {r.get('removed', 0)} dropped"
        )
    return None


def _format_live_line_base(line: str) -> str:
    data = parse_agent_line(line)
    if data is None:
        parsed = parse_finding_line(line)
        if parsed is not None and "[FINDING]" in line.upper():
            sev = str(parsed.get("severity") or "info")
            fid = str(parsed.get("id") or "finding")
            url = str(parsed.get("url") or "").strip()
            if url:
                return f"**{sev}** `{fid}` {url}"
            return f"**{sev}** `{fid}`"
        return line.strip()
    action = str(data.get("action") or "")
    iteration = data.get("iteration")
    prefix = f"{iteration} {action}" if iteration and action else (action or "done")
    progress = data.get("progress")
    if progress:
        prefix = f"{prefix} {progress}"
    url = data.get("url")
    if url and not data.get("result"):
        return f"**{prefix}** {url}"
    if data.get("error"):
        return f"**{prefix}** {data['error']}"
    result = data.get("result") if isinstance(data.get("result"), dict) else None
    if result is not None:
        bits: list[str] = []
        pages = result.get("pages_crawled")
        if pages:
            bits.append(f"{pages} pages")
        added = result.get("findings_added")
        if added:
            bits.append(f"+{added} findings")
        new_eps = result.get("new_endpoints")
        if new_eps:
            bits.append(f"+{new_eps} urls")
        tested = result.get("urls_tested")
        if tested and not new_eps:
            bits.append(f"{tested} urls")
        js_files = result.get("js_files")
        if js_files:
            bits.append(f"{js_files} js")
        api_eps = result.get("api_endpoints")
        if api_eps:
            bits.append(f"{api_eps} api")
        if "waf_detected" in result:
            vendor = result.get("waf_vendor")
            bits.append(f"waf {vendor}" if result.get("waf_detected") else "no waf")
        confirmed = result.get("confirmed")
        if confirmed is not None and action == "ReportAction":
            bits.append(f"{confirmed} confirmed")
        header = f"**{prefix}** {', '.join(bits)}" if bits else f"**{prefix}**"
        if url:
            header = f"**{prefix}** {url}"
        finding_items = result.get("summary") if action == "ReportAction" else result.get("findings")
        if not finding_items:
            finding_items = result.get("findings") or result.get("summary") or []
        extra: list[str] = []
        if isinstance(finding_items, list):
            extra.extend(_live_finding_lines(finding_items))
        shown_urls = {
            str(item.get("url") or "").strip()
            for item in finding_items
            if isinstance(item, dict)
        }
        url_items = result.get("urls") or result.get("specs") or []
        if isinstance(url_items, list) and action != "ReportAction":
            extra.extend(_live_url_lines(url_items, skip=shown_urls))
        if extra:
            return "\n".join([header, *extra])
        return header
    if "iterations" in data and "state_path" in data:
        return f"**done** {data.get('iterations')} iterations, {data.get('confirmed') or 0} confirmed"
    return f"**{prefix}**"


def should_forward_line(line: str) -> bool:
    if parse_agent_line(line) is not None:
        return True
    if _format_warning_line(line) is not None:
        return True
    lower = line.lower()
    stripped = line.lstrip()
    if "[FINDING]" in line.upper():
        return True
    if stripped.startswith(("[INFO]", "[WARN]", "[ERROR]")):
        return True
    if "%" in line or "scanning" in lower or "crawling" in lower:
        return True
    return False


def count_severities(findings: list[dict[str, Any]]) -> dict[str, int]:
    """Match pentest_report.severity_counts: one Info per observation id."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    observation_ids: set[str] = set()
    for finding in findings:
        if _is_collapsed_observation(finding):
            observation_ids.add(str(finding.get("id") or "unknown"))
            continue
        severity = normalize_finding_severity(finding)
        if severity in counts:
            counts[severity] += 1
    counts["info"] += len(observation_ids)
    return counts


def _is_collapsed_observation(item: dict[str, Any]) -> bool:
    fid = str(item.get("id") or "")
    cat = str(item.get("category") or "")
    conf = str(item.get("confidence") or "").lower()
    if fid in _OBSERVATION_IDS or cat in _OBSERVATION_CATEGORIES:
        return True
    if any(fid.startswith(prefix) for prefix in _OBSERVATION_ID_PREFIXES):
        return True
    if conf == "heuristic":
        return True
    return conf != "confirmed"


def normalize_finding_severity(item: dict[str, Any]) -> str:
    """Cap observations at info and unconfirmed impact at low — same rules as pentest reports."""
    if _is_collapsed_observation(item):
        return "info"
    severity = str(item.get("severity") or "info").lower()
    if severity == "informational":
        severity = "info"
    return severity


def summary_status_text(job: ShroodlerJob) -> str:
    if job.timed_out:
        return "Timed out"
    if job.status == "cancelled":
        return "Cancelled"
    if job.status == "error":
        return "Error"
    if job.status in {"pending", "running"}:
        return "Running"
    return "Complete"


def summary_accent(job: ShroodlerJob) -> discord.Color:
    if job.timed_out:
        return discord.Color.gold()
    if job.status in {"cancelled", "error"}:
        return discord.Color.red()
    return discord.Color.green()


def layout_view(*items: discord.ui.Item, timeout: float | None = None) -> discord.ui.LayoutView:
    view = discord.ui.LayoutView(timeout=timeout)
    for item in items:
        view.add_item(item)
    return view


def message_view(
    body: str,
    *,
    accent: discord.Color | None = None,
    extra: list[discord.ui.Item] | None = None,
) -> discord.ui.LayoutView:
    children: list[discord.ui.Item] = [discord.ui.TextDisplay(body)]
    if extra:
        children.extend(extra)
    container = discord.ui.Container(*children, accent_color=accent)
    return layout_view(container)


def _auth_label(job: ShroodlerJob) -> str:
    return job.auth_label or ("authenticated" if job.has_auth else "unauthenticated")


def job_jump_url(job: ShroodlerJob) -> str | None:
    if not job.channel_id or not job.message_id:
        return None
    guild = job.guild_id or "@me"
    return f"https://discord.com/channels/{guild}/{job.channel_id}/{job.message_id}"


def report_filename(job: ShroodlerJob) -> str:
    date_str = job.started_at.strftime("%Y-%m-%d")
    return f"pentest-{sanitize_hostname(job.hostname)}-{date_str}.md"


def log_filename(job: ShroodlerJob) -> str:
    date_str = job.started_at.strftime("%Y-%m-%d")
    return f"pentest-{sanitize_hostname(job.hostname)}-{date_str}.log"


def _file_for_discord(path: Path, filename: str) -> discord.File | None:
    if not path.is_file():
        return None
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size <= 0:
        return None
    if size < _DISCORD_FILE_LIMIT:
        return discord.File(path, filename=filename)
    keep = max(1024, _DISCORD_FILE_LIMIT - (1024 * 1024))
    clipped = path.with_name(f"{path.stem}.discord{path.suffix}")
    try:
        with path.open("rb") as src, clipped.open("wb") as dst:
            src.seek(size - keep)
            dst.write(b"... truncated to last bytes ...\n")
            dst.write(src.read())
        return discord.File(clipped, filename=filename)
    except OSError:
        logger.exception("Failed to truncate %s for Discord", path)
        return None


def report_discord_file(job: ShroodlerJob) -> discord.File | None:
    return _file_for_discord(job.report_file, report_filename(job))


def log_discord_file(job: ShroodlerJob) -> discord.File | None:
    return _file_for_discord(job.log_file, log_filename(job))


def _job_facts(job: ShroodlerJob, *, thread_id: int | None = None) -> list[str]:
    live = thread_id if thread_id else job.live_thread_id
    bits = [summary_status_text(job).lower()]
    if job.status not in {"pending", "running"}:
        bits.append(format_duration(job.started_at))
        bits.append(f"{len(job.findings)} findings")
    lines = [
        job.target,
        " · ".join(bits),
        f"{job.profile} · {_auth_label(job)}",
        f"`{job.job_id}`",
    ]
    if live:
        lines.append(f"<#{live}>")
    return lines


def running_markdown(
    job: ShroodlerJob,
    *,
    preview: str | None = None,
    thread_id: int | None = None,
) -> str:
    body = "\n".join(_job_facts(job, thread_id=thread_id))
    if preview:
        body = f"{body}\n{preview}"
    return body


def running_view(
    job: ShroodlerJob,
    *,
    preview: str | None = None,
    thread_id: int | None = None,
) -> discord.ui.LayoutView:
    return message_view(
        running_markdown(job, preview=preview, thread_id=thread_id),
        accent=discord.Color.blurple(),
    )


def summary_markdown(job: ShroodlerJob, *, thread_id: int | None = None) -> str:
    counts = count_severities(job.findings)
    lines = _job_facts(job, thread_id=thread_id)
    lines.insert(
        2,
        (
            f"{counts['critical']} critical  {counts['high']} high  "
            f"{counts['medium']} medium  {counts['low']} low  {counts['info']} info"
        ),
    )
    if job.status == "error" and job.returncode is not None:
        lines.append(f"exit {job.returncode}")
    if job.error_reason:
        lines.append(job.error_reason)
    return "\n".join(lines)


def summary_view(
    job: ShroodlerJob,
    *,
    thread_id: int | None = None,
    attach_report: bool = True,
) -> tuple[discord.ui.LayoutView, list[discord.File]]:
    files: list[discord.File] = []
    items: list[discord.ui.Item] = [discord.ui.TextDisplay(summary_markdown(job, thread_id=thread_id))]
    attachments: list[discord.File] = []
    if attach_report:
        report_file = report_discord_file(job)
        if report_file is not None:
            attachments.append(report_file)
        log_file = log_discord_file(job)
        if log_file is not None:
            attachments.append(log_file)
    if attachments:
        files.extend(attachments)
        items.append(discord.ui.Separator(visible=True, spacing=discord.SeparatorSpacing.small))
        for attached in attachments:
            items.append(discord.ui.File(f"attachment://{attached.filename}"))
    elif not job.report_file.is_file() or job.report_file.stat().st_size == 0:
        tail = "\n".join(job.stderr_tail) or "no output"
        items.append(discord.ui.Separator(visible=True, spacing=discord.SeparatorSpacing.small))
        items.append(discord.ui.TextDisplay(format_code_block(tail)))
    container = discord.ui.Container(*items, accent_color=summary_accent(job))
    return layout_view(container), files


def status_view(jobs: list[ShroodlerJob]) -> discord.ui.LayoutView:
    if not jobs:
        return message_view("No active scans.")
    blocks: list[str] = []
    for job in jobs:
        extras: list[str] = []
        jump = job_jump_url(job)
        if jump:
            extras.append(f"[open]({jump})")
        if job.live_thread_id:
            extras.append(f"<#{job.live_thread_id}>")
        extra = f"  {' · '.join(extras)}" if extras else ""
        blocks.append(
            f"`{job.job_id}`  {job.target}\n"
            f"{format_duration(job.started_at)} · {len(job.findings)} findings{extra}"
        )
    return message_view("\n\n".join(blocks)[:4000], accent=discord.Color.blurple())


async def safe_send(
    dest: discord.abc.Messageable,
    **kwargs: Any,
) -> discord.Message | None:
    try:
        return await dest.send(**kwargs)
    except discord.HTTPException:
        logger.exception("Discord send failed")
        return None
    except discord.ClientException:
        logger.exception("Discord client error while sending")
        return None


async def send_view(
    dest: discord.abc.Messageable,
    view: discord.ui.LayoutView,
    *,
    files: list[discord.File] | None = None,
    allowed_mentions: discord.AllowedMentions | None = None,
) -> discord.Message | None:
    kwargs: dict[str, Any] = {"view": view}
    if files:
        kwargs["files"] = files
    if allowed_mentions is not None:
        kwargs["allowed_mentions"] = allowed_mentions
    return await safe_send(dest, **kwargs)


async def respond_view(
    interaction: discord.Interaction,
    view: discord.ui.LayoutView,
    *,
    ephemeral: bool = False,
) -> None:
    try:
        if interaction.response.is_done():
            await interaction.followup.send(view=view, ephemeral=ephemeral)
        else:
            await interaction.response.send_message(view=view, ephemeral=ephemeral)
    except discord.HTTPException:
        logger.exception("Failed to respond with layout view")


async def edit_view(
    message: discord.Message,
    view: discord.ui.LayoutView,
    *,
    files: list[discord.File] | None = None,
    allowed_mentions: discord.AllowedMentions | None = None,
) -> discord.Message | None:
    kwargs: dict[str, Any] = {"view": view}
    if files is not None:
        kwargs["attachments"] = files
    if allowed_mentions is not None:
        kwargs["allowed_mentions"] = allowed_mentions
    try:
        return await message.edit(**kwargs)
    except discord.HTTPException:
        logger.exception("Discord edit failed")
        return None
    except discord.ClientException:
        logger.exception("Discord client error while editing")
        return None


async def durable_message(message: discord.Message) -> discord.Message:
    """Re-fetch so later edits use the bot token, not a 15-minute interaction webhook."""
    channel = message.channel
    fetch = getattr(channel, "fetch_message", None)
    if fetch is None:
        return message
    try:
        return await fetch(message.id)
    except discord.HTTPException:
        logger.exception("Failed to re-fetch command message %s", message.id)
        return message


async def fetch_job_message(client: discord.Client, job: ShroodlerJob) -> discord.Message | None:
    if not job.channel_id or not job.message_id:
        return None
    channel = client.get_channel(job.channel_id)
    if channel is None:
        try:
            channel = await client.fetch_channel(job.channel_id)
        except discord.HTTPException:
            logger.exception("Failed to fetch channel for job %s", job.job_id)
            return None
    fetch = getattr(channel, "fetch_message", None)
    if fetch is None:
        return None
    try:
        return await fetch(job.message_id)
    except discord.HTTPException:
        logger.exception("Failed to fetch command message for job %s", job.job_id)
        return None


async def edit_job_message(
    client: discord.Client,
    job: ShroodlerJob,
    view: discord.ui.LayoutView,
    *,
    files: list[discord.File] | None = None,
    allowed_mentions: discord.AllowedMentions | None = None,
    message: discord.Message | None = None,
) -> discord.Message | None:
    target = message
    if target is None or target.id != job.message_id:
        target = await fetch_job_message(client, job)
    if target is None:
        return None
    return await edit_view(target, view, files=files, allowed_mentions=allowed_mentions)


async def edit_completion(
    message: discord.Message,
    job: ShroodlerJob,
    *,
    thread_id: int | None = None,
) -> bool:
    live = thread_id if thread_id else job.live_thread_id
    mentions = discord.AllowedMentions(users=True, roles=False, everyone=False)
    view, files = summary_view(job, thread_id=live)
    edited = await edit_view(
        message,
        view,
        files=files if files else [],
        allowed_mentions=mentions,
    )
    if edited is not None:
        return True

    fallback_view, _unused = summary_view(job, thread_id=live, attach_report=False)
    text_edited = await edit_view(
        message,
        fallback_view,
        files=[],
        allowed_mentions=mentions,
    )
    report = report_discord_file(job)
    log = log_discord_file(job)
    leftover = [item for item in (report, log) if item is not None]
    if leftover:
        sent = await safe_send(message.channel, files=leftover)
        if sent is None:
            logger.warning("Failed to attach report/log followup for job %s", job.job_id)
    return text_edited is not None


class OutputStreamer:
    def __init__(self, dest: discord.abc.Messageable | None) -> None:
        self._dest = dest
        self._queue: asyncio.Queue[str | None] = asyncio.Queue()
        self._task: asyncio.Task[None] | None = None
        self._closed = False
        self._last_post = 0.0
        self._batch: list[str] = []
        self._batch_size = 0
        self._deadline: float | None = None

    def start(self) -> None:
        self._task = asyncio.create_task(self._run(), name="shroodler-output-streamer")

    async def on_line(self, line: str) -> None:
        if self._closed:
            return
        if should_forward_line(line):
            await self._queue.put(line)

    async def close(self) -> None:
        if self._closed:
            if self._task is not None:
                await self._task
            return
        self._closed = True
        await self._queue.put(None)
        if self._task is not None:
            await self._task

    async def _run(self) -> None:
        try:
            while True:
                timeout = None
                if self._batch and self._deadline is not None:
                    remaining = self._deadline - time.monotonic()
                    if remaining <= 0:
                        await self._flush_batch()
                        continue
                    timeout = remaining
                try:
                    if timeout is None:
                        item = await self._queue.get()
                    else:
                        item = await asyncio.wait_for(self._queue.get(), timeout=timeout)
                except asyncio.TimeoutError:
                    await self._flush_batch()
                    continue

                if item is None:
                    await self._flush_batch()
                    break

                formatted = format_live_line(item)
                extra = len(formatted) + (1 if self._batch else 0)
                if self._batch and self._batch_size + extra > 1800:
                    await self._flush_batch()
                    extra = len(formatted)
                if not self._batch:
                    self._deadline = time.monotonic() + 2.0
                self._batch.append(formatted)
                self._batch_size += extra
                if self._batch_size >= 1800:
                    await self._flush_batch()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Output streamer crashed")

    async def _flush_batch(self) -> None:
        if not self._batch:
            self._deadline = None
            return
        text = "\n".join(self._batch)[:1900]
        self._batch = []
        self._batch_size = 0
        self._deadline = None
        if self._dest is None:
            return
        await self._rate_limit()
        await safe_send(
            self._dest,
            content=text,
            allowed_mentions=discord.AllowedMentions.none(),
        )
        self._last_post = time.monotonic()

    async def _rate_limit(self) -> None:
        if self._last_post <= 0:
            return
        wait = 2.0 - (time.monotonic() - self._last_post)
        if wait > 0:
            await asyncio.sleep(wait)


def _compact_live_line(line: str) -> str:
    """Collapse a streamed line to a single short status line for the summary."""
    formatted = format_live_line(line)
    first = next((part for part in formatted.splitlines() if part.strip()), "")
    return first.strip()[:180]


class LiveSummaryEditor:
    """No-thread live status: edit the command message in place with a minimal
    running summary instead of posting new messages.

    Used in DMs and any context where the app should not (or cannot) stream new
    messages. Shares OutputStreamer's start/on_line/close interface so callers
    can swap the two. The final completion view is written separately by the
    caller, so close() just stops the loop.
    """

    def __init__(
        self,
        message: discord.Message,
        job: ShroodlerJob,
        *,
        interval: float = 3.0,
    ) -> None:
        self._message = message
        self._job = job
        self._interval = max(1.0, interval)
        self._latest = ""
        self._dirty = False
        self._closed = False
        self._task: asyncio.Task[None] | None = None

    def start(self) -> None:
        self._task = asyncio.create_task(self._run(), name="shroodler-live-summary")

    async def on_line(self, line: str) -> None:
        if self._closed or not should_forward_line(line):
            return
        compact = _compact_live_line(line)
        if compact:
            self._latest = compact
            self._dirty = True

    async def _run(self) -> None:
        try:
            while not self._closed:
                await asyncio.sleep(self._interval)
                if self._dirty and not self._closed:
                    self._dirty = False
                    await self._push()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Live summary editor crashed")

    async def _push(self) -> None:
        findings = len(self._job.findings)
        head = f"{findings} finding{'' if findings == 1 else 's'} so far"
        preview = f"{head}\n{self._latest}" if self._latest else head
        await edit_view(self._message, running_view(self._job, preview=preview))

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
