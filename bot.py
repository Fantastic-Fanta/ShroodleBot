from __future__ import annotations

import asyncio
import logging
import os
import shutil
import signal
import sys
from pathlib import Path

import discord
from discord.ext import commands

from commands.cancel import CancelCog
from commands.pentest import PentestCog
from commands.status import StatusCog
from config import Config, load as load_config
from job_store import JobStore
from runner import cancel as cancel_job

logger = logging.getLogger("shroodler-bot")


class ShroodleBot(commands.Bot):
    def __init__(self, config: Config) -> None:
        intents = discord.Intents.default()
        intents.message_content = True
        intents.guilds = True
        intents.guild_messages = True
        super().__init__(command_prefix="!", intents=intents, help_command=None)
        self.config = config
        self.job_store = JobStore()
        resolved = Path(config.shroodler_bin)
        which = shutil.which(config.shroodler_bin)
        if which:
            self.shroodler_path = which
        elif resolved.is_file() and os.access(resolved, os.X_OK):
            self.shroodler_path = str(resolved)
        else:
            self.shroodler_path = None
        self.shroodler_available = self.shroodler_path is not None
        self._shutting_down = False

    async def setup_hook(self) -> None:
        await self.add_cog(PentestCog(self))
        await self.add_cog(StatusCog(self))
        await self.add_cog(CancelCog(self))
        guild = discord.Object(id=self.config.discord_guild_id)
        # Guild + global copies of the same slash commands show up twice.
        # Keep one global set (guilds and DMs) and delete leftover guild copies.
        self.tree.clear_commands(guild=guild)
        await self.tree.sync(guild=guild)
        synced = await self.tree.sync()
        self.tree.error(self._on_tree_error)
        logger.info(
            "Removed guild-scoped slash commands; synced %s global commands for guild %s and DMs",
            len(synced),
            self.config.discord_guild_id,
        )

    async def on_ready(self) -> None:
        location = self.shroodler_path or "not found"
        print(f"shroodler-bot ready. shroodler at: {location}")
        logger.info("Logged in as %s (%s)", self.user, getattr(self.user, "id", "?"))
        if not self.shroodler_available:
            logger.warning(
                "shroodler binary %r not found on PATH; /pentest is disabled",
                self.config.shroodler_bin,
            )

    async def _on_tree_error(
        self,
        interaction: discord.Interaction,
        error: discord.app_commands.AppCommandError,
    ) -> None:
        logger.error("App command error: %s", error, exc_info=error)
        message = "command failed"
        try:
            if interaction.response.is_done():
                await interaction.followup.send(message, ephemeral=True)
            else:
                await interaction.response.send_message(message, ephemeral=True)
        except discord.HTTPException:
            logger.exception("Failed to send command error response")

    async def close(self) -> None:
        if not self._shutting_down:
            self._shutting_down = True
            running = self.job_store.list_running()
            if running:
                logger.info("Shutting down; cancelling %s running job(s)", len(running))
            for job in running:
                try:
                    await cancel_job(job)
                except Exception:
                    logger.exception("Failed to cancel job %s during shutdown", job.job_id)
        await super().close()


async def _amain() -> None:
    config = load_config()
    bot = ShroodleBot(config)
    async with bot:
        loop = asyncio.get_running_loop()
        def _request_shutdown() -> None:
            asyncio.create_task(bot.close())

        try:
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, _request_shutdown)
        except NotImplementedError:
            logger.info("Signal handlers are not supported on this platform")
        await bot.start(config.discord_token)


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    try:
        asyncio.run(_amain())
    except KeyboardInterrupt:
        logger.info("Interrupted")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        logger.exception("Fatal error")
        sys.exit(1)
