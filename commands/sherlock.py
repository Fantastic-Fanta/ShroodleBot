from __future__ import annotations

import io
import logging
from typing import TYPE_CHECKING

import discord
from discord import app_commands
from discord.ext import commands

from commands import is_authorized
from formatter import edit_view, message_view, respond_view
from sherlock_runner import (
    MAX_USERNAMES,
    SherlockResult,
    parse_usernames,
    run as run_sherlock,
)

if TYPE_CHECKING:
    from bot import ShroodleBot

logger = logging.getLogger("shroodler-bot.commands.sherlock")

# Accounts shown inline per username before the full list is moved to an
# attached text file.
_MAX_INLINE_ACCOUNTS = 12


class SherlockCog(commands.Cog):
    def __init__(self, bot: ShroodleBot) -> None:
        self.bot = bot

    @app_commands.command(
        name="sherlock",
        description="Hunt a username (or several) across social networks with Sherlock",
    )
    @app_commands.allowed_installs(guilds=True, users=True)
    @app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
    @app_commands.describe(
        usernames="One or more usernames, separated by spaces or commas",
    )
    async def sherlock(self, interaction: discord.Interaction, usernames: str) -> None:
        if not getattr(self.bot, "sherlock_available", False):
            await respond_view(interaction, message_view("sherlock not installed"), ephemeral=True)
            return

        if not await is_authorized(
            interaction.user,
            client=self.bot,
            config=self.bot.config,
            interaction_guild_id=interaction.guild_id,
        ):
            await respond_view(
                interaction,
                message_view("Not authorized to run lookups"),
                ephemeral=True,
            )
            return

        valid, rejected = parse_usernames(usernames)
        if not valid:
            await respond_view(
                interaction,
                message_view("No valid usernames given"),
                ephemeral=True,
            )
            return

        overflow = valid[MAX_USERNAMES:]
        targets = valid[:MAX_USERNAMES]

        notes: list[str] = []
        if rejected:
            notes.append("skipped invalid: " + ", ".join(f"`{u}`" for u in rejected[:10]))
        if overflow:
            notes.append(f"only first {MAX_USERNAMES} searched")

        await interaction.response.send_message(
            view=message_view(
                _header(targets, notes) + "\nsearching…",
                accent=discord.Color.blurple(),
            )
        )
        try:
            message = await interaction.original_response()
        except discord.HTTPException:
            logger.exception("Failed to capture sherlock command message")
            return

        results: list[SherlockResult] = []
        for username in targets:
            result = await run_sherlock(username)
            results.append(result)
            if result.status == "missing":
                # Binary disappeared mid-run; report and stop.
                await edit_view(message, message_view("sherlock not installed"))
                return
            await edit_view(
                message,
                _summary_view(targets, results, notes, done=len(results) == len(targets)),
            )

        view, files = _final_view(targets, results, notes)
        await edit_view(message, view, files=files)


def _header(targets: list[str], notes: list[str]) -> str:
    names = " ".join(f"`{u}`" for u in targets)
    lines = [f"Sherlock · {names}"]
    lines.extend(notes)
    return "\n".join(lines)


def _status_label(result: SherlockResult) -> str:
    if result.status == "done":
        return f"{result.count} found"
    if result.status == "timeout":
        return "timed out"
    if result.status == "cancelled":
        return "cancelled"
    if result.status == "error":
        return result.error_reason or "error"
    return "…"


def _result_block(result: SherlockResult, *, finished: bool) -> str:
    lines = [f"`{result.username}` — {_status_label(result)}"]
    if finished and result.found:
        shown = result.found[:_MAX_INLINE_ACCOUNTS]
        for site, url in shown:
            lines.append(f"• {site}: {url}")
        remaining = result.count - len(shown)
        if remaining > 0:
            lines.append(f"…+{remaining} more (see attachment)")
    return "\n".join(lines)


def _summary_view(
    targets: list[str],
    results: list[SherlockResult],
    notes: list[str],
    *,
    done: bool,
) -> discord.ui.LayoutView:
    blocks = [_header(targets, notes)]
    for result in results:
        blocks.append(_result_block(result, finished=done))
    remaining = len(targets) - len(results)
    if remaining > 0:
        blocks.append(f"searching {remaining} more…")
    body = "\n\n".join(blocks)[:3900]
    accent = discord.Color.green() if done else discord.Color.blurple()
    return message_view(body, accent=accent)


def _final_view(
    targets: list[str],
    results: list[SherlockResult],
    notes: list[str],
) -> tuple[discord.ui.LayoutView, list[discord.File]]:
    view = _summary_view(targets, results, notes, done=True)
    # Attach a full text report whenever any username has more accounts than we
    # show inline, so nothing is silently dropped.
    if not any(r.count > _MAX_INLINE_ACCOUNTS for r in results):
        return view, []

    report = _text_report(results)
    filename = f"sherlock-{targets[0]}.txt" if len(targets) == 1 else "sherlock.txt"
    file = discord.File(io.BytesIO(report.encode("utf-8")), filename=filename)
    body = "\n\n".join(
        [_header(targets, notes)]
        + [_result_block(r, finished=True) for r in results]
    )[:3500]
    container = discord.ui.Container(
        discord.ui.TextDisplay(body),
        discord.ui.Separator(visible=True, spacing=discord.SeparatorSpacing.small),
        discord.ui.File(f"attachment://{filename}"),
        accent_color=discord.Color.green(),
    )
    wrapped = discord.ui.LayoutView(timeout=None)
    wrapped.add_item(container)
    return wrapped, [file]


def _text_report(results: list[SherlockResult]) -> str:
    parts: list[str] = []
    for result in results:
        parts.append(f"# {result.username} — {_status_label(result)}")
        if result.found:
            for site, url in result.found:
                parts.append(f"{site}: {url}")
        else:
            parts.append("(no accounts found)")
        parts.append("")
    return "\n".join(parts).rstrip() + "\n"
