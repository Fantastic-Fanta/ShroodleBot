from __future__ import annotations

from typing import TYPE_CHECKING

import discord

if TYPE_CHECKING:
    from config import Config


async def is_authorized(
    user: discord.abc.User,
    *,
    client: discord.Client,
    config: Config,
    interaction_guild_id: int | None = None,
) -> bool:
    """Authorized if on the user allowlist or a member of the home guild.

    The allowlist covers DM and user-installed-app use (where there may be no
    shared guild); the guild check preserves the original server behavior.
    """
    if user.id in config.authorized_user_ids:
        return True
    if config.discord_guild_id:
        return await in_home_guild(
            user,
            client=client,
            guild_id=config.discord_guild_id,
            interaction_guild_id=interaction_guild_id,
        )
    return False


async def in_home_guild(
    user: discord.abc.User,
    *,
    client: discord.Client,
    guild_id: int,
    interaction_guild_id: int | None = None,
) -> bool:
    if interaction_guild_id == guild_id:
        return True
    if interaction_guild_id is not None:
        return False

    guild = client.get_guild(guild_id)
    if guild is None:
        try:
            guild = await client.fetch_guild(guild_id)
        except discord.HTTPException:
            return False

    member = guild.get_member(user.id)
    if member is not None:
        return True
    try:
        await guild.fetch_member(user.id)
    except discord.HTTPException:
        return False
    return True
