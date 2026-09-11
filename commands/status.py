from __future__ import annotations

from typing import TYPE_CHECKING

import discord
from discord import app_commands
from discord.ext import commands

from commands import is_authorized
from formatter import message_view, respond_view, status_view

if TYPE_CHECKING:
    from bot import ShroodleBot


class StatusCog(commands.Cog):
    def __init__(self, bot: ShroodleBot) -> None:
        self.bot = bot

    @app_commands.command(name="status", description="List running Shroodler scans")
    @app_commands.allowed_installs(guilds=True, users=True)
    @app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
    async def status(self, interaction: discord.Interaction) -> None:
        if not await is_authorized(
            interaction.user,
            client=self.bot,
            config=self.bot.config,
            interaction_guild_id=interaction.guild_id,
        ):
            await respond_view(
                interaction,
                message_view("Not authorized"),
                ephemeral=True,
            )
            return

        jobs = self.bot.job_store.list_running()
        if not jobs:
            await respond_view(interaction, message_view("No active scans."), ephemeral=True)
            return

        await respond_view(interaction, status_view(jobs), ephemeral=True)
