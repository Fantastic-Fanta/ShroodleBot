from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import discord
from discord import app_commands
from discord.ext import commands

from commands import is_authorized
from formatter import edit_job_message, message_view, respond_view, send_view
from runner import ShroodlerJob, cancel as cancel_job

if TYPE_CHECKING:
    from bot import ShroodleBot

logger = logging.getLogger("shroodler-bot.commands.cancel")


class CancelCog(commands.Cog):
    def __init__(self, bot: ShroodleBot) -> None:
        self.bot = bot

    @app_commands.command(name="cancel", description="Cancel a running Shroodler scan by job ID")
    @app_commands.allowed_installs(guilds=True, users=True)
    @app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
    @app_commands.describe(job_id="Job ID shown when the scan started")
    async def cancel(self, interaction: discord.Interaction, job_id: str) -> None:
        job_id = job_id.strip().strip("`")
        job = self.bot.job_store.get(job_id)
        if job is None or job.status not in {"pending", "running"}:
            await respond_view(
                interaction,
                message_view("No running scan with that id"),
                ephemeral=True,
            )
            return

        allowed = await is_authorized(
            interaction.user,
            client=self.bot,
            config=self.bot.config,
            interaction_guild_id=interaction.guild_id,
        )
        if not allowed:
            await respond_view(
                interaction,
                message_view("Not allowed"),
                ephemeral=True,
            )
            return

        await interaction.response.defer(ephemeral=True)
        await cancel_job(job)
        await edit_job_message(
            self.bot,
            job,
            message_view(
                f"{job.target}\ncancelling · `{job.job_id}`",
                accent=discord.Color.red(),
            ),
        )
        await _notify_thread(self.bot, job, interaction.user)
        await interaction.followup.send(
            view=message_view(f"cancelled `{job.job_id}`"),
            ephemeral=True,
        )


async def _notify_thread(
    bot: commands.Bot,
    job: ShroodlerJob,
    user: discord.abc.User,
) -> None:
    if not job.thread_id:
        return
    channel = bot.get_channel(job.thread_id)
    if channel is None:
        try:
            channel = await bot.fetch_channel(job.thread_id)
        except discord.HTTPException:
            logger.exception("Failed to fetch thread for cancelled job %s", job.job_id)
            return
    if not isinstance(channel, discord.abc.Messageable):
        return
    await send_view(channel, message_view(f"cancelled by {user.mention}"))
